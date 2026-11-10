"""Bounded, explainable scheduling signals. Scores never confer tool authority."""

import json
import math
import time

from .db import SwarmTask
from .policy import Denied


def validate_dependencies(db, run, payload):
    dependencies = payload.get("depends_on", [])
    if (
        not isinstance(dependencies, list)
        or len(dependencies) > 12
        or len(set(dependencies)) != len(dependencies)
    ):
        raise Denied(
            "Task dependencies require at most twelve distinct existing task IDs"
        )
    for id in dependencies:
        row = db.get(SwarmTask, id)
        if not row or row.run_id != run.id or row.owner != run.owner:
            raise Denied("Task dependency is outside this run")
    # Dependencies can only refer to existing immutable tasks: no forward edges
    # or dependency edits, so the enqueue interface cannot introduce cycles.
    signals = payload.get("signals", {})
    if not isinstance(signals, dict) or set(signals) - {
        "confidence",
        "evidence_count",
        "relevance",
        "estimated_effort",
        "hypothesis",
    }:
        raise Denied("Unknown scheduling signal")
    for key in ("confidence", "relevance", "estimated_effort"):
        value = signals.get(key, 0.5)
        if (
            not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 1
        ):
            raise Denied(
                "Scheduling signals must be finite values between zero and one"
            )
    if (
        not isinstance(signals.get("evidence_count", 0), int)
        or not 0 <= signals.get("evidence_count", 0) <= 50
    ):
        raise Denied("Invalid evidence count")


def dependency_state(db, task):
    rows = [
        db.get(SwarmTask, id) for id in json.loads(task.payload).get("depends_on", [])
    ]
    if any(
        not row
        or row.run_id != task.run_id
        or row.owner != task.owner
        or row.status in ("dead_letter", "cancelled")
        for row in rows
    ):
        return "failed"
    return "ready" if all(row.status == "completed" for row in rows) else "waiting"


def score(task, active_in_run=0, recent_in_run=0, timestamp=None):
    timestamp = timestamp or time.time()
    signals = json.loads(task.payload).get("signals", {})
    age = max(0, timestamp - task.created_at)
    freshness = 2 ** (-age / (1800 if signals.get("hypothesis") else 7200))
    terms = {
        "base_priority": max(0, min(10, task.priority)),
        "confidence": 2 * signals.get("confidence", 0.5),
        "evidence_quality": 0.3 * min(4, signals.get("evidence_count", 0)),
        "specialist_relevance": signals.get("relevance", 0.5),
        "freshness": 1.5 * freshness,
        "waiting_age": min(8, age / 300),
        "effort_penalty": -signals.get("estimated_effort", 0.5),
        "active_run_fairness": -2 * active_in_run,
        "recent_run_fairness": -0.25 * min(8, recent_in_run),
    }
    return {
        "score": round(sum(terms.values()), 6),
        "terms": terms,
        "depends_on": json.loads(task.payload).get("depends_on", []),
        "note": "Signals prioritize research, not vulnerability validity or authorization",
    }


def order_candidates(db, candidates):
    timestamp = time.time()
    running, recent = {}, {}
    run_ids = {t.run_id for t in candidates}
    for row in (
        db.query(SwarmTask)
        .filter(SwarmTask.run_id.in_(run_ids), SwarmTask.updated_at > timestamp - 60)
        .limit(4096)
    ):
        if row.status == "running" and row.lease_until > timestamp:
            running[row.run_id] = running.get(row.run_id, 0) + 1
        if row.status in ("running", "completed"):
            recent[row.run_id] = recent.get(row.run_id, 0) + 1
    values = [
        (score(t, running.get(t.run_id, 0), recent.get(t.run_id, 0), timestamp), t)
        for t in candidates
    ]
    return sorted(
        values, key=lambda pair: (-pair[0]["score"], pair[1].created_at, pair[1].id)
    )
