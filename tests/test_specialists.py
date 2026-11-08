import pytest
from atlas.workflow import RoleOutput, SpecialistRequest, ThreatModel, execute_stage
from atlas.db import document, canonical, digest
from atlas.policy import Denied
import time


def prepare(db):
    c = document(
        db,
        "campaign",
        "u",
        {
            "authorization_ref": "fixture",
            "authorization_attested": True,
            "mode": "knowledge",
        },
    )
    scope = {"allow": [], "deny": []}
    p = document(db, "policy", "u", {"scope": scope})
    run = document(
        db,
        "run",
        "u",
        {
            "campaign_id": c.id,
            "policy_id": p.id,
            "policy_hash": digest(canonical(scope)),
            "state": "CREATED",
            "status": "queued",
            "deadline": time.time() + 100,
            "budget_limit": 1,
            "budget_used": 0,
        },
    )
    db.commit()
    return run


def test_unapproved_model_specialist_cannot_dispatch(db, monkeypatch):
    run = prepare(db)
    v = run.value()
    v["state"] = "FOCUSED_INVESTIGATION"
    v["status"] = "running"
    run.data = canonical(v)
    db.commit()
    calls = []

    def respond(*args, **kwargs):
        calls.append(kwargs.get("alias", "reasoning"))
        return RoleOutput(
            summary="Requires focused code review",
            specialist_requests=[
                SpecialistRequest(
                    role="coding",
                    question="Check this boundary",
                    reason="Source expert needed",
                )
            ],
        )

    monkeypatch.setattr("atlas.workflow.role", respond)
    with pytest.raises(Denied, match="not authorized"):
        execute_stage(db, run, "research")
    assert calls == ["reasoning"]


def test_approved_specialist_returns_cited_observations_only(db, monkeypatch):
    from atlas.db import Document

    run = prepare(db)
    v = run.value()
    v.update(
        state="FOCUSED_INVESTIGATION", status="running", specialist_roles=["coding"]
    )
    run.data = canonical(v)
    db.commit()
    calls = []

    def respond(*args, **kwargs):
        alias = args[4] if len(args) > 4 else "reasoning"
        calls.append(alias)
        if alias == "reasoning":
            return RoleOutput(
                summary="Review boundary",
                specialist_requests=[
                    SpecialistRequest(
                        role="coding",
                        question="Check invariant",
                        reason="Review source",
                    )
                ],
            )
        return RoleOutput(
            summary="Source boundary observation only", citations=["fixture.py:1"]
        )

    monkeypatch.setattr("atlas.workflow.role", respond)
    execute_stage(db, run, "research")
    db.commit()
    result = db.query(Document).filter_by(kind="stage_result").one().value()["result"]
    assert calls == ["reasoning", "coding"] and result["specialist_reviews"][0][
        "output"
    ]["citations"] == ["fixture.py:1"]
