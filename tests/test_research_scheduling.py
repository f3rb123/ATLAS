import json
import time

import pytest

from atlas.db import Document, SwarmTask, canonical, digest, document
from atlas.policy import Denied
from atlas.research_artifacts import ChainLink, ResearchNote, link_chain, store_note
from atlas.scheduling import dependency_state, score
from atlas.swarm import claim_one, enqueue


def run_fixture(db):
    c = document(
        db, "campaign", "u", {"mode": "knowledge", "authorization_attested": True}
    )
    scope = {"allow": [], "deny": []}
    p = document(db, "policy", "u", {"scope": scope})
    r = document(
        db,
        "run",
        "u",
        {
            "campaign_id": c.id,
            "policy_id": p.id,
            "policy_hash": digest(canonical(scope)),
            "status": "queued",
            "deadline": time.time() + 1000,
            "execution_mode": "swarm",
            "agent_count": 8,
        },
    )
    db.commit()
    return r


def test_dependencies_gate_then_release_without_forward_edges(db):
    run = run_fixture(db)
    parent = enqueue(db, run, "recon", {}, "parent")
    child = enqueue(db, run, "authentication", {"depends_on": [parent.id]}, "child", 10)
    db.commit()
    assert dependency_state(db, child) == "waiting"
    assert claim_one(db, "research")[0] == parent.id
    assert claim_one(db, "research") is None
    parent.status = "completed"
    db.commit()
    assert claim_one(db, "research")[0] == child.id
    with pytest.raises(Denied, match="outside"):
        enqueue(db, run, "recon", {"depends_on": ["missing"]}, "forward")


def test_failed_dependency_cancels_followup_and_does_not_execute(db):
    run = run_fixture(db)
    parent = enqueue(db, run, "recon", {}, "parent")
    child = enqueue(db, run, "authentication", {"depends_on": [parent.id]}, "child")
    parent.status = "dead_letter"
    db.commit()
    assert claim_one(db, "research") is None
    db.refresh(child)
    assert (
        child.status == "cancelled"
        and json.loads(child.result)["error"] == "dependency_failed"
    )


def test_priority_explains_evidence_decay_age_cost_and_fairness(db):
    run = run_fixture(db)
    task = enqueue(
        db,
        run,
        "recon",
        {
            "signals": {
                "confidence": 0.9,
                "evidence_count": 4,
                "relevance": 1,
                "estimated_effort": 0.1,
                "hypothesis": True,
            }
        },
        "one",
    )
    initial = score(task, timestamp=task.created_at + 1)
    stale = score(task, timestamp=task.created_at + 4000)
    busy = score(task, active_in_run=3, recent_in_run=6, timestamp=task.created_at + 1)
    assert stale["terms"]["freshness"] < initial["terms"]["freshness"]
    assert stale["terms"]["waiting_age"] > initial["terms"]["waiting_age"]
    assert busy["score"] < initial["score"] and initial["terms"]["evidence_quality"] > 0
    with pytest.raises(Denied, match="finite"):
        enqueue(db, run, "recon", {"signals": {"confidence": float("nan")}}, "bad")


def test_research_and_chain_preserve_sources_without_promoting_findings(db):
    run = run_fixture(db)
    note = store_note(
        db,
        run,
        ResearchNote(
            title="Competing explanations",
            text="Observation only",
            citations=["fixture.py:1"],
            competing_explanations=["Intentional trust boundary"],
            missing_information=["Ownership check"],
            next_steps=["Inspect source"],
        ),
        "deep-research",
    )
    first = document(db, "hypothesis", "u", {"run_id": run.id, "status": "candidate"})
    second = document(db, "finding", "u", {"run_id": run.id, "status": "inconclusive"})
    link = ChainLink(
        source_id=first.id,
        target_id=second.id,
        relationship="enables",
        rationale="Needs combined evidence",
        citations=["fixture.py:1"],
    )
    edge = link_chain(db, run, link, "validation-review")
    assert link_chain(db, run, link, "validation-review") == edge
    db.commit()
    db.expire_all()
    assert db.get(Document, note["note_id"]).value()["citations"] == ["fixture.py:1"]
    assert (
        not edge["finding_confirmed"]
        and db.get(Document, second.id).value()["status"] == "inconclusive"
    )
    other = document(db, "hypothesis", "another-owner", {"run_id": run.id})
    with pytest.raises(Denied, match="owned"):
        link_chain(db, run, link.model_copy(update={"target_id": other.id}), "model")
