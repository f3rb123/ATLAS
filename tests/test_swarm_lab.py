"""Isolated vulnerable source lab: real sandbox/replay, synthetic model and corpus."""

import json

import pytest
from test_knowledge_runtime import seed
from test_swarm import prepare

from atlas.db import Document, Journal, SwarmTask, canonical, document
from atlas.gateway import ModelResponse
from atlas.skills import install_references
from atlas.swarm import execute_one
from atlas.tools import Repository


@pytest.mark.sandbox
@pytest.mark.parametrize("false_candidate", [False, True])
def test_eight_role_discovery_knowledge_specialist_and_independent_replay(
    db, tmp_path, monkeypatch, false_candidate
):
    root = tmp_path / "lab"
    root.mkdir()
    for name in ("proof", "control"):
        (root / name).mkdir()
    (root / "app.py").write_text(
        "def allowed(actor,owner,patched=False):\n return actor==owner if patched else True\n"
    )
    call = (
        "allowed('attacker','victim',patched=True)"
        if false_candidate
        else "allowed('attacker','victim')"
    )
    (root / "proof/test_authz.py").write_text(
        "import unittest\nfrom app import allowed\nclass Proof(unittest.TestCase):\n def test_cross_tenant(self):self.assertTrue("
        + call
        + ")\n"
    )
    (root / "control/test_authz.py").write_text(
        "import unittest\nfrom app import allowed\nclass Control(unittest.TestCase):\n def test_secure(self):self.assertFalse(allowed('attacker','victim',patched=True))\n"
    )
    repo = Repository(root)
    run = prepare(db)
    source = document(
        db,
        "repository",
        run.owner,
        {
            "campaign_id": run.value()["campaign_id"],
            "path": str(root),
            "snapshot_hash": repo.inventory()["snapshot_hash"],
        },
    )
    run.data = canonical(
        {
            **run.value(),
            "repository_id": source.id,
            "offline_execution_approved": True,
            "max_tool_calls": 100,
        }
    )
    seed(db, tmp_path)
    install_references(db, run.owner)
    provider = document(
        db, "provider", run.owner, {"adapter_type": "custom_openai_compatible"}
    )
    model = document(
        db,
        "provider_model",
        run.owner,
        {"model_id": "synthetic-lab-model", "max_output_tokens": 2048},
    )
    db.commit()
    monkeypatch.setattr("atlas.workflow.model_binding", lambda *_: (provider, model))
    verified = []

    def fixture_generate(db, p, m, request, run, alias):
        body = json.loads(request.messages[1]["content"])
        context = body["context"]
        assert "knowledge.search_skills" in context["knowledge"]["capabilities"]
        assert (
            context["knowledge"]["availability"]["retrieval_mode"]
            == "lexical_hash_test"
        )
        if body["stage"] == "INDEPENDENT_VERIFICATION":
            verified.append(context)
            assert context["proof"]["result"]["exit_code"] == 0
            assert context["secure_control"]["result"]["exit_code"] == 0
            output = {
                "status": "confirmed",
                "reason": "Real sandbox replay reproduced synthetic lab access flaw",
                "counterfactual": "Patched control rejects cross-owner access",
                "evidence_ids": [
                    context["proof"]["artifact_id"],
                    context["secure_control"]["artifact_id"],
                ],
            }
        elif context["task"]["role"] == "recon":
            output = {
                "summary": "Synthetic model found fixture boundary to verify",
                "discoveries": [
                    {
                        "kind": "technology",
                        "topic": "graphql",
                        "title": "Synthetic GraphQL boundary",
                        "text": "Review the lab ownership function",
                        "citations": ["app.py:1-2"],
                    }
                ],
                "hypotheses": [
                    {
                        "claim": "Cross-owner fixture access",
                        "preconditions": ["isolated synthetic repository"],
                        "expected_vulnerable": "Other owner allowed",
                        "expected_secure": "Other owner rejected",
                        "impact": "Synthetic tenant boundary",
                        "citations": ["app.py:1-2"],
                    }
                ],
                "experiment": {
                    "template": "python_unittest",
                    "test_path": "proof",
                    "control_test_path": "control",
                    "hypothesis_index": 0,
                },
            }
        else:
            output = {
                "summary": "Synthetic specialist review; no claim of confirmation"
            }
        return ModelResponse(content=canonical(output), structured_content=output)

    monkeypatch.setattr("atlas.workflow.generate_budgeted", fixture_generate)
    for _ in range(16):
        execute_one("research")
        execute_one("verify")
    db.expire_all()
    saved = db.get(Document, run.id).value()
    assert saved["status"] == "completed" and not saved["partial"]
    assert (
        db.query(SwarmTask).filter_by(role="graphql", status="completed").count() == 1
    )
    assert (
        db.query(SwarmTask)
        .filter_by(role="proof-validation", status="completed")
        .count()
        == 1
    )
    assert db.query(SwarmTask).filter_by(status="completed").count() == 10
    searches = [
        json.loads(j.payload)
        for j in db.query(Journal).filter_by(stream=run.id)
        if json.loads(j.payload)["type"] == "knowledge_search"
    ]
    assert len(searches) >= 9
    findings = db.query(Document).filter_by(kind="finding").all()
    assert len(findings) == (0 if false_candidate else 1)
    assert bool(verified) != false_candidate
    if findings:
        assert findings[0].value()["status"] == "confirmed"
        assert len(findings[0].value()["evidence_ids"]) == 2
