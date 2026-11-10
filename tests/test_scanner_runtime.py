"""Actual pinned upstream binaries against an authored loopback application."""

import json
from pathlib import Path

import pytest

from test_web_research import web_lab
from atlas.config import settings
from atlas.db import Document, canonical, digest
from atlas.scanner_runtime import ScannerInput, run, pins


@pytest.mark.sandbox
@pytest.mark.parametrize("tool", ["httpx", "katana", "ffuf", "nuclei"])
def test_pinned_http_binary_uses_only_policy_relay(db, web_lab, tool):
    settings().research_tools_dir = str(Path(".runtime/research-tools").resolve())
    policy = db.get(Document, web_lab.run.value()["policy_id"])
    value = policy.value()
    value["scope"]["test_classes"].append("scanners")
    policy.data = canonical(value)
    rv = web_lab.run.value()
    rv["tool_pins"] = pins(db, web_lab.run.owner)
    rv["policy_hash"] = digest(canonical(value["scope"]))
    web_lab.run.data = canonical(rv)
    db.commit()
    result = run(
        db,
        web_lab.run,
        ScannerInput(
            tool=tool,
            url=web_lab.origin + "/",
            max_requests=8,
            timeout_seconds=25,
            words=["graphql", "robots.txt"],
        ),
    )
    assert result["exit_code"] == 0, result
    assert not result["timed_out"] and result["observation_ids"], result
    assert result["request_attempts"] <= 8
    assert all(url.startswith("/") for method, url in web_lab.calls)
    for id in result["observation_ids"]:
        observation = db.get(Document, id).value()
        assert observation["run_id"] == web_lab.run.id
        assert observation["url"].startswith(web_lab.origin)
