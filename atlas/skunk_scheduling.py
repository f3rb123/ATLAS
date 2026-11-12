"""Coalesce cited follow-ups without recursive specialist task multiplication."""

import json
import re
import time

from .db import append, canonical, digest, SwarmTask, transaction_lock


def followup(db, run, parent, role, payload, citations=(), priority=1):
    from .swarm import enqueue, check_fence, tasks
    check_fence(db, run)
    transaction_lock(db, "swarm:" + run.id)
    policy = run.value().get("followup_policy", {})
    depth = json.loads(parent.payload).get("followup_depth", 0) + 1
    evidence = sorted(set(str(item) for item in citations))[:12]
    question = re.sub(r"\s+", " ", payload.get("instructions", "")).strip()
    key = digest("skunk-followup:" + role + ":" + canonical(evidence if evidence else question))
    existing = tasks(db, run.id).filter_by(role=role).all()
    for row in existing:
        old = json.loads(row.payload)
        if row.dedupe_key == key or key in old.get("coalesced_keys", []):
            return row

    def deferred(reason):
        append(db, run.id, "scheduler", "swarm_followup_deferred", {
            "role": role, "reason": reason, "parent_task": parent.id,
            "event_id": payload.get("event_id"), "depth": depth,
            "evidence": "Original discovery remains on the shared board",
        }, run.value()["campaign_id"])
        value = run.value()
        warnings = value.get("tool_warnings", [])
        warning = {"tool": "swarm_followup", "code": reason, "task_id": parent.id}
        if warning not in warnings:
            value["tool_warnings"] = (warnings + [warning])[-100:]
            run.data = canonical(value)
            db.flush()
        return None

    if parent.role == "report":
        return deferred("report_followup")
    if depth > min(3, policy.get("max_depth", 2)):
        return deferred("followup_depth")
    queued = [row for row in existing if row.status == "queued" and json.loads(row.payload).get("followup_depth") == depth]
    if len(queued) >= policy.get("coalesce_after_pending", policy.get("max_pending_per_role", 2)):
        for row in queued:
            old = json.loads(row.payload)
            events = list(dict.fromkeys([*old.get("event_ids", []), *([old["event_id"]] if old.get("event_id") else []), *([payload["event_id"]] if payload.get("event_id") else [])]))
            questions = list(dict.fromkeys([*old.get("additional_questions", []), *([payload["instructions"]] if payload.get("parent_task") else [])]))
            keys = old.get("coalesced_keys", [])
            if len(events) <= 8 and len(questions) <= 4 and len(keys) < 8:
                old.update(event_ids=events, additional_questions=questions, coalesced_keys=[*keys, key])
                row.payload, row.updated_at = canonical(old), time.time()
                append(db, run.id, "scheduler", "swarm_followup_coalesced", {
                    "role": role, "task_id": row.id, "parent_task": parent.id,
                    "event_count": len(events), "question_count": len(questions),
                }, run.value()["campaign_id"])
                return row
    if len(existing) >= min(16, policy.get("max_tasks_per_role", 8)):
        return deferred("followup_role_limit")
    return enqueue(db, run, role, {**payload, "followup_depth": depth, "parent_task": parent.id}, key, priority)
