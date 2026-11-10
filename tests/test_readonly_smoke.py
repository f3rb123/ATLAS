"""Execution guards tested against local fixtures; no live target requests."""

import time

import pytest

from atlas.db import Document, canonical, digest, document, session
from atlas.policy import Denied, Rule, Scope, readonly_target_request
from atlas.relay import TargetRequest, execute


@pytest.mark.parametrize(
    "method,url",
    [
        ("DELETE", "https://example.invalid/"),
        ("POST", "https://example.invalid/"),
        ("GET", "https://example.invalid/delete/account"),
        ("GET", "https://example.invalid/api/drop-table"),
        ("GET", "https://example.invalid/?action=delete"),
        ("GET", "https://example.invalid/?_method=DELETE"),
        ("GET", "https://example.invalid/?q=DROP%20TABLE%20customers"),
        ("GET", "https://example.invalid/?q=DELETE%20FROM%20customers"),
        ("GET", "https://example.invalid/?cmd=rm%20-rf%20%2Fdata"),
        ("GET", "https://example.invalid/?q=DROP/**/TABLE%20customers"),
        ("GET", "https://example.invalid/?cmd=ls"),
    ],
)
def test_destructive_target_actions_are_unavailable(method, url):
    with pytest.raises(Denied):
        readonly_target_request(url, method)


def smoke_run(db):
    scope = Scope(
        allow=[Rule(host="127.0.0.1")], lab_networks=["127.0.0.0/8"], max_requests=100
    ).model_dump()
    campaign = document(
        db, "campaign", "owner", {"mode": "lab", "assessment_profile": "smoke_readonly"}
    )
    policy = document(db, "policy", "owner", {"scope": scope})
    run = document(
        db,
        "run",
        "owner",
        {
            "campaign_id": campaign.id,
            "policy_id": policy.id,
            "policy_hash": digest(canonical(scope)),
            "status": "running",
            "deadline": time.time() + 60,
            "assessment_profile": "smoke_readonly",
        },
    )
    db.commit()
    return run


@pytest.mark.parametrize(
    "url,method,headers",
    [
        ("https://127.0.0.1/", "GET", {}),
        ("https://127.0.0.1/login", "HEAD", {}),
        ("https://127.0.0.1/?parameter=value", "HEAD", {}),
        ("https://127.0.0.1/", "HEAD", {"Cookie": "synthetic-session"}),
        ("https://127.0.0.1/", "HEAD", {"Authorization": "synthetic-fixture"}),
    ],
)
def test_smoke_rejects_bodies_paths_queries_and_auth_before_egress(
    db, monkeypatch, url, method, headers
):
    run = smoke_run(db)
    calls = []
    monkeypatch.setattr("atlas.relay.request", lambda *a, **k: calls.append(a))
    with pytest.raises(Denied):
        execute(
            TargetRequest(run_id=run.id, url=url, method=method, headers=headers),
            "test",
        )
    assert calls == []


def test_smoke_metadata_request_limit_is_two_even_with_larger_scope_limit(
    db, monkeypatch
):
    run = smoke_run(db)
    calls = []

    def respond(*args, **kwargs):
        calls.append(args)
        return 200, {"Content-Type": "text/html"}, b""

    monkeypatch.setattr("atlas.relay.request", respond)
    for _ in range(2):
        with session() as other:
            current = other.get(Document, run.id)
            value = current.value()
            value["last_request"] = 0
            current.data = canonical(value)
            other.commit()
        result = execute(
            TargetRequest(run_id=run.id, url="https://127.0.0.1/", method="HEAD"),
            "test",
        )
        assert result["body"] == ""
    with pytest.raises(Denied, match="quota"):
        execute(
            TargetRequest(run_id=run.id, url="https://127.0.0.1/", method="HEAD"),
            "test",
        )
    assert len(calls) == 2


def test_models_have_no_database_admin_or_arbitrary_shell_tool(db):
    from atlas.tools import broker

    run = smoke_run(db)
    for name in (
        "delete_database",
        "drop_table",
        "delete_file",
        "delete_server",
        "arbitrary_shell",
    ):
        with pytest.raises(Denied, match="registered"):
            broker(db, run, None, name, {}, "synthetic-adversarial-model")
