"""Real SQL scheduling/concurrency with explicitly synthetic model output."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from atlas.db import Document, SwarmTask, canonical, digest, document, session
from atlas.policy import Denied
from atlas.swarm import (
    Discovery,
    SwarmOutput,
    check_fence,
    claim_one,
    execute_one,
    initialize,
    publish,
)
from atlas.workflow import control


def prepare(db, count=8):
    c = document(
        db,
        "campaign",
        "owner",
        {
            "authorization_ref": "synthetic isolated source fixture",
            "authorization_attested": True,
            "mode": "knowledge",
        },
    )
    scope = {"allow": [], "deny": []}
    p = document(db, "policy", "owner", {"scope": scope})
    r = document(
        db,
        "run",
        "owner",
        {
            "campaign_id": c.id,
            "policy_id": p.id,
            "policy_hash": digest(canonical(scope)),
            "status": "queued",
            "state": "SWARM_RUNNING",
            "execution_mode": "swarm",
            "agent_count": count,
            "deadline": time.time() + 300,
            "budget_limit": 1,
            "budget_used": 0,
        },
    )
    initialize(db, r)
    db.commit()
    return r


@pytest.mark.parametrize("count", [1, 2, 4, 8, 12, 16])
def test_requested_agent_counts_are_persistent_and_idempotent(db, count):
    run = prepare(db, count)
    initialize(db, run)
    db.commit()
    assert db.query(SwarmTask).filter_by(run_id=run.id).count() == count
    if count == 8:
        assert len({t.role for t in db.query(SwarmTask)}) == 8
    with session() as restarted:
        assert (
            restarted.query(SwarmTask).filter_by(run_id=run.id, status="queued").count()
            == count
        )


def test_independent_tasks_actually_overlap_and_one_failure_does_not_abort_peers(
    db, monkeypatch
):
    run = prepare(db, 4)
    rendezvous = threading.Barrier(4, timeout=10)
    seen = []
    lock = threading.Lock()

    def model(db, run, stage, context, alias, response_schema=None):
        with lock:
            seen.append((context["task"]["id"], context["task"]["role"]))
        rendezvous.wait()
        if context["task"]["role"] == "authentication":
            raise ValueError("synthetic malformed output")
        return SwarmOutput(summary="Synthetic local model fixture; no findings")

    monkeypatch.setattr("atlas.workflow.role", model)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda _: execute_one("research"), range(4)))
    db.expire_all()
    assert len(seen) == len(set(seen)) == 4
    states = [t.status for t in db.query(SwarmTask)]
    assert states.count("completed") == 3 and states.count("dead_letter") == 1
    value = db.get(Document, run.id).value()
    assert (
        value["status"] == "completed"
        and value["partial"]
        and value["task_errors"] == 1
    )
    assert db.query(Document).filter_by(kind="finding").count() == 0


def test_cited_discovery_activates_specialist_once_with_shared_knowledge_harness(
    db, monkeypatch
):
    prepare(db, 2)
    discovery = Discovery(
        kind="technology",
        topic="graphql",
        title="GraphQL resolver",
        text="Synthetic source fixture",
        citations=["fixture.py:1"],
    )
    seen = []

    def model(db, run, stage, context, alias, response_schema=None):
        seen.append(context)
        return SwarmOutput(summary="Synthetic observation", discoveries=[discovery])

    monkeypatch.setattr("atlas.workflow.role", model)
    for _ in range(4):
        execute_one("research")
    db.expire_all()
    specialist = db.query(SwarmTask).filter_by(role="graphql").all()
    assert len(specialist) == 1 and specialist[0].status == "completed"
    assert db.query(Document).filter_by(kind="swarm_event").count() == 1
    context = next(c for c in seen if c["task"]["role"] == "graphql")
    assert context["discovery"]["topic"] == "graphql"
    assert context["discovery"]["status"] == "unverified"
    assert "instructions" in context["task"]


def test_expired_claim_recovery_fences_stale_worker_and_survives_restart(db):
    run = prepare(db, 1)
    first = claim_one(db, "research")
    task = db.get(SwarmTask, first[0], populate_existing=True)
    task.lease_until = time.time() - 1
    db.commit()
    with session() as restarted:
        second = claim_one(restarted, "research")
        assert first[0] == second[0] and first[1] != second[1]
        assert restarted.get(SwarmTask, second[0]).attempts == 2
    run._swarm_claim = first
    with pytest.raises(Denied, match="lease lost"):
        check_fence(db, run)


def test_cancel_pause_kill_and_policy_integrity_stop_dispatch(db):
    run = prepare(db, 1)
    control(db, run, "pause", "owner")
    db.commit()
    assert claim_one(db, "research") is None
    control(db, run, "resume", "owner")
    db.commit()
    claimed = claim_one(db, "research")
    assert claimed
    run._swarm_claim = claimed
    control(db, run, "cancel", "owner")
    db.commit()
    with pytest.raises(Denied, match="stopped"):
        check_fence(db, run)
    fresh = prepare(db, 1)
    policy = db.get(Document, fresh.value()["policy_id"])
    policy.data = canonical({"scope": {"allow": [{"host": "forbidden.invalid"}]}})
    db.commit()
    assert claim_one(db, "research") is None
    assert (
        db.query(SwarmTask).filter_by(run_id=fresh.id, status="cancelled").count() == 1
    )


def test_swarm_cannot_promote_finding_or_expand_tools_from_model_output(db):
    with pytest.raises(ValueError):
        SwarmOutput.model_validate(
            {"summary": "pretend confirmed", "finding_confirmed": True}
        )
    with pytest.raises(ValueError):
        Discovery(
            kind="finding", title="Unproved", text="Model confidence is not proof"
        )
    run = prepare(db, 1)
    claim = claim_one(db, "research")
    task = db.get(SwarmTask, claim[0])
    run._swarm_claim = claim
    event = publish(
        db,
        run,
        task,
        Discovery(
            kind="technology",
            topic="oauth",
            title="Uncited claim",
            text="No evidence",
            citations=[],
        ),
    )
    db.commit()
    assert event.value()["status"] == "unverified"
    assert db.query(SwarmTask).count() == 1  # no specialist from an uncited claim
