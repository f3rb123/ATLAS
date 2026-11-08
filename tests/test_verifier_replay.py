"""Real offline independent proof/control replay; model judgements are test doubles only."""

import pytest
from atlas.db import Document, document, canonical
from atlas.tools import Repository, broker
from atlas.verification import verify_candidates, successful_test
from atlas.workflow import VerificationOutput


@pytest.mark.sandbox
@pytest.mark.parametrize("false_candidate", [False, True])
def test_independent_verifier_confirms_proof_and_refutes_false_claim(
    db, tmp_path, monkeypatch, false_candidate
):
    tmp_path = tmp_path / "repo"
    tmp_path.mkdir()
    for name in ("proof", "control"):
        (tmp_path / name).mkdir()
    (tmp_path / "app.py").write_text(
        "def allowed(actor,owner,patched=False):\n return actor==owner if patched else True\n"
    )
    proof = """import unittest
from app import allowed
class Proof(unittest.TestCase):
 def test_cross_tenant(self):self.assertTrue(allowed('attacker','victim'))
"""
    control = """import unittest
from app import allowed
class Control(unittest.TestCase):
 def test_secure_boundary(self):self.assertFalse(allowed('attacker','victim',patched=True))
"""
    if false_candidate:
        proof = proof.replace(
            "allowed('attacker','victim')", "allowed('attacker','victim',patched=True)"
        )
    (tmp_path / "proof" / "test_authz.py").write_text(proof)
    (tmp_path / "control" / "test_authz.py").write_text(control)
    repo = Repository(tmp_path)
    run = document(
        db,
        "run",
        "u",
        {
            "state": "INDEPENDENT_VERIFICATION",
            "status": "running",
            "campaign_id": "c",
            "policy_hash": "fixture",
            "offline_execution_approved": True,
        },
    )
    h = document(
        db,
        "hypothesis",
        "u",
        {
            "run_id": run.id,
            "claim": "Cross-tenant fixture access",
            "citations": ["app.py:1-2"],
        },
    )
    db.commit()
    # Prior research cannot establish confirmation, even if it falsely claims a passing proof.
    passing = {"result": {"exit_code": 0, "output": "Ran 1 test\n\nOK"}}
    done = [
        document(
            db,
            "stage",
            "u",
            {
                "state": "SAFE_EXECUTION",
                "result": {
                    "experiment": {
                        "hypothesis_id": h.id,
                        "test_path": "proof",
                        "control_test_path": "control",
                    },
                    "proof": passing,
                    "control": passing,
                },
            },
        )
    ]
    db.commit()
    called = []

    def judgement(db, run, stage, context, alias):
        called.append(context)
        assert (
            alias == "verifier"
            and successful_test(context["proof"])
            and successful_test(context["secure_control"])
        )
        return VerificationOutput(
            status="confirmed",
            reason="Independent synthetic proof reproduced cross-tenant access",
            counterfactual="Secure control denies cross-tenant access",
            evidence_ids=[
                context["proof"]["artifact_id"],
                context["secure_control"]["artifact_id"],
            ],
        )

    monkeypatch.setattr("atlas.workflow.role", judgement)
    result = verify_candidates(db, run, repo, done)
    db.commit()
    if false_candidate:
        assert result["status"] == "refuted" and not called
        assert db.query(Document).filter_by(kind="finding").count() == 0
    else:
        assert result["status"] == "confirmed" and called
        finding = db.get(Document, result["finding_id"]).value()
        assert len(finding["evidence_ids"]) == 2
        for id in finding["evidence_ids"]:
            assert (
                db.get(Document, id).value()["payload"]["snapshot"]
                == repo.inventory()["snapshot_hash"]
            )
