#!/usr/bin/env python3
"""Opt-in paid acceptance against the existing application ledger and corpus.

Creates only an authored local source lab; never requests a public target. No
adapter mocking, corpus replacement, ledger cloning/reset or secret output.
"""

import argparse
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from atlas.db import Document, Journal, SwarmTask, canonical, digest, document, session
from atlas.knowledge import availability
from atlas.model_routing import approved_pools
from atlas.policy import Scope
from atlas.skills import install_references
from atlas.swarm import execute_one, initialize
from atlas.token_budget import summarize
from atlas.tools import Repository

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--execute-paid", action="store_true", required=True)
parser.add_argument("--label", default="initial", choices=["initial", "timeout-fixed", "schema-fixed", "typed-hypotheses"])
args = parser.parse_args()
root = Path(".runtime/readiness/real-provider-lab-" + args.label)
root.mkdir(mode=0o700, parents=True, exist_ok=False)
for sub in ("proof", "control"):
    (root / sub).mkdir()
(root / "app.py").write_text(
    "# Controlled GraphQL-style invoice resolver fixture.\ndef allowed(actor, owner, secure=False):\n    return actor == owner if secure else True\n"
)
(root / "proof/test_authz.py").write_text(
    "import unittest\nfrom app import allowed\nclass Proof(unittest.TestCase):\n    def test_cross_tenant(self):\n        self.assertTrue(allowed('attacker', 'victim'))\n"
)
(root / "control/test_authz.py").write_text(
    "import unittest\nfrom app import allowed\nclass Control(unittest.TestCase):\n    def test_secure_control(self):\n        self.assertFalse(allowed('attacker', 'victim', secure=True))\n"
)
for name in (
    "identity",
    "api",
    "input",
    "routes",
    "dependencies",
    "research",
    "validation",
):
    (root / (name + ".md")).write_text(
        "ATLAS-authored isolated lab. Inspect app.py, proof/test_authz.py and control/test_authz.py. No live target or customer data. The secure=True control enforces actor == owner.\n"
    )
repo = Repository(root.resolve())
metadata = json.loads(
    Path(".runtime/readiness/hackerai-model-discovery.json").read_text()
)
owner = metadata["owner_id"]
with session() as db:
    before = summarize(db)
    assert (
        before["cap"] == 50000000
        and before["allocation"] == 2000000
        and not before["blocked"]
    )
    kb = availability(db, owner)
    assert (
        kb["status"] == "available"
        and kb["retrieval_mode"] == "semantic_hybrid"
        and kb["visible_records"] >= 21012
    )
    models = {}
    for row in db.query(Document).filter_by(kind="alias", owner=owner):
        pin = row.value()
        provider = db.get(Document, pin["provider_id"])
        model = db.get(Document, pin["model_id"])
        assert (
            provider.value()["health_status"] == "tested"
            and model.value()["verified_structured"]
        )
        models[pin["alias"]] = {
            **pin,
            "provider_version": provider.version,
            "model_version": model.version,
        }
    assert (
        db.get(Document, models["reasoning"]["model_id"]).value()["model_id"]
        == "deepseek-v4.1-flash"
    )
    assert (
        db.get(Document, models["verifier"]["model_id"]).value()["model_id"]
        == "deepseek-v4-pro"
    )
    campaign = document(
        db,
        "campaign",
        owner,
        {
            "name": "Real HackerAI acceptance on authored local source lab",
            "mode": "repository",
            "authorization_attested": True,
            "authorization_ref": "Owner-authorized controlled acceptance; ATLAS-authored local files only",
            "budget_limit": 10,
        },
    )
    scope = Scope(allow=[], deny=[]).model_dump()
    policy = document(
        db,
        "policy",
        owner,
        {"campaign_id": campaign.id, "scope": scope, "hash": digest(canonical(scope))},
    )
    snapshot = document(
        db,
        "repository",
        owner,
        {
            "campaign_id": campaign.id,
            "path": str(root.resolve()),
            "snapshot_hash": repo.inventory()["snapshot_hash"],
        },
    )
    instructions = """The complete lab source is provided here to every role: app.py defines allowed(actor, owner, secure=False) as actor == owner if secure else True. proof/test_authz.py runs unittest and asserts allowed('attacker','victim') is True. control/test_authz.py asserts allowed('attacker','victim',secure=True) is False. All three files are in the authorized source snapshot and can be checked through the broker. Prefer your supplied knowledge and source context; do not request more tools if sufficient. At your final reasoning round return a final schema-valid result, not another tool request. Do not spawn coding/fast specialists in this controlled exercise: only the cited GraphQL discovery should activate its single subscriber.
Controlled acceptance on ATLAS-authored source only. Each role must use the shared attributed knowledge/skill context and cite the record/source references it actually receives. Keep the final summary under 180 words. No public network requests, no destructive tools, no recursive task requests.
For the recon role only: inspect app.py, proof/test_authz.py and control/test_authz.py through bounded tools as needed. If the evidence supports it, publish exactly one technology discovery topic graphql with app.py citations, propose one precise cross-owner authorization hypothesis, and propose the existing python_unittest experiment with test_path proof, control_test_path control, hypothesis_index 0. Do not claim a confirmed finding.
Other initial and dynamic roles: inspect the supplied source and shared observations, challenge the claim and discuss missing evidence. Do not propose further discoveries, hypotheses or experiments. The independent proof-validation role must challenge the actual proof and secure control, cite both supplied independent artifact IDs and return confirmed only if the source and replay genuinely support it. No finding about a real site is implied."""
    run = document(
        db,
        "run",
        owner,
        {
            "campaign_id": campaign.id,
            "policy_id": policy.id,
            "policy_hash": policy.value()["hash"],
            "repository_id": snapshot.id,
            "execution_mode": "swarm",
            "agent_count": 8,
            "instructions": instructions,
            "model_mode": "auto",
            "models": models,
            "routing_candidates": approved_pools(models),
            "skills": [],
            "status": "queued",
            "state": "SWARM_RUNNING",
            "deadline": time.time() + 900,
            "budget_limit": 10,
            "budget_used": 0,
            "max_model_calls": 24,
            "max_tool_calls": 100,
            "offline_execution_approved": True,
            "workflow_version": "2.0-swarm",
        },
    )
    install_references(db, owner)
    initialize(db, run)
    db.commit()
    run_id = run.id
    Path(".runtime/readiness/real-provider-run-" + args.label + ".json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "campaign_id": campaign.id,
                "knowledge": kb,
                "budget_before": before,
            },
            indent=2,
        )
    )
print(json.dumps({"status": "created", "run_id": run_id}), flush=True)
with ThreadPoolExecutor(max_workers=8) as pool:
    for iteration in range(16):
        outcomes = list(pool.map(execute_one, ["research"] * 7 + ["verify"]))
        with session() as db:
            run = db.get(Document, run_id)
            rows = db.query(SwarmTask).filter_by(run_id=run_id).all()
            state = {
                name: sum(t.status == name for t in rows)
                for name in (
                    "queued",
                    "running",
                    "completed",
                    "dead_letter",
                    "cancelled",
                )
            }
            print(
                json.dumps(
                    {
                        "iteration": iteration,
                        "run_status": run.value()["status"],
                        "tasks": state,
                    }
                ),
                flush=True,
            )
            if run.value()["status"] not in ("queued", "running"):
                break
        if not any(outcomes):
            break
with session() as db:
    run = db.get(Document, run_id)
    task_rows = db.query(SwarmTask).filter_by(run_id=run_id).all()
    events = [
        json.loads(row.payload)
        for row in db.query(Journal).filter_by(stream=run_id).order_by(Journal.sequence)
    ]
    after = summarize(db)
    findings = [
        row
        for row in db.query(Document).filter_by(kind="finding", owner=owner)
        if row.value().get("run_id") == run_id
    ]
    result = {
        "evidence_kind": "actual_provider_and_database; authored_local_source_fixture",
        "run_id": run_id,
        "run_status": run.value()["status"],
        "partial": run.value().get("partial"),
        "knowledge": kb,
        "tasks": [
            {
                "id": t.id,
                "role": t.role,
                "status": t.status,
                "error_type": json.loads(t.result).get("error_type"),
            }
            for t in task_rows
        ],
        "events_by_type": {
            kind: sum(e["type"] == kind for e in events)
            for kind in sorted({e["type"] for e in events})
        },
        "findings": [
            {
                "id": f.id,
                "status": f.value()["status"],
                "evidence_count": len(f.value()["evidence_ids"]),
            }
            for f in findings
        ],
        "budget_after": after,
        "acceptance_tokens": after["used"]["total_tokens"]
        - before["used"]["total_tokens"],
        "target_requests": 0,
        "pricing_confirmed": False,
    }
    evidence = Path(
        ".runtime/readiness/real-provider-acceptance-" + args.label + ".json"
    )
    evidence.write_text(json.dumps(result, indent=2))
    evidence.chmod(0o600)
    print(json.dumps(result), flush=True)
