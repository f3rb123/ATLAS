"""Explicit host-owned recovery of saved SKUNK work, with frozen authorization."""

import json
import time

from .db import Document, SwarmTask, append, canonical, digest, document, now, session, transaction_lock
from .policy import Scope, match, normalize
from .skunk_runtime import Controller


RECOVERABLE = {
    "model_schema_invalid", "structured_output_invalid_accounted", "context_limit",
    "model_call_limit", "tool_call_limit", "token_allocation_exhausted",
    "provider_timeout", "provider_transport", "provider_response_parse",
    "provider_rate_limited", "connection_or_timeout", "database_operational_error",
    "provider_http_408", "provider_http_409", "provider_http_425", "provider_http_429",
    "provider_http_500", "provider_http_502", "provider_http_503", "provider_http_504",
}


def frozen_scope(db, run):
    value = run.value()
    policy = db.get(Document, value.get("policy_id", ""))
    campaign = db.get(Document, value.get("campaign_id", ""))
    if not policy or policy.owner != run.owner or not campaign or campaign.owner != run.owner or not campaign.value().get("authorization_attested"):
        raise ValueError("Saved campaign authorization is unavailable. No work was resumed.")
    if digest(canonical(policy.value()["scope"])) != value.get("policy_hash"):
        raise ValueError("Saved policy integrity failed. No work was resumed.")
    scope = Scope.model_validate(policy.value()["scope"])
    if scope.expires and scope.expires <= time.time():
        raise ValueError("The saved scope authorization expired. No work was resumed.")
    if campaign.value().get("mode") not in ("passive", "safe-active", "lab"):
        raise ValueError("Saved campaign mode does not permit this work.")
    _, hostname, port, path, scheme = normalize(value.get("target_url", ""))
    if not any(match(rule, hostname, port, path, scheme, "GET") for rule in scope.allow) or any(match(rule, hostname, port, path, scheme, "GET") for rule in scope.deny):
        raise ValueError("Saved target is outside the frozen scope.")
    kill = db.get(Document, "kill-switch")
    if kill and kill.value().get("enabled"):
        raise ValueError("Emergency stop is active. No work was resumed.")
    return scope


def eligible_tasks(db, run):
    rows = db.query(SwarmTask).filter_by(run_id=run.id, owner=run.owner).all()
    if any(t.status == "running" and t.lease_until > time.time() for t in rows):
        raise ValueError("A task still has an active worker lease. Stop the old controller and wait for its lease before resuming.")
    eligible = []
    for task in rows:
        result = json.loads(task.result or "{}")
        diagnostic = result.get("diagnostic_code", {})
        code = diagnostic.get("code") if isinstance(diagnostic, dict) else diagnostic
        if task.status == "dead_letter" and code in RECOVERABLE:
            eligible.append(task)
        elif task.status in ("queued", "running"):
            eligible.append(task)
    # Reopen only cancelled dependents of the recoverable tasks, never policy
    # denials or operator-cancelled work. Completed tasks remain completed.
    ready = {t.id for t in rows if t.status == "completed"} | {t.id for t in eligible}
    for _ in range(len(rows)):
        extra = [t for t in rows if t.id not in ready and t.status == "cancelled"
            and json.loads(t.result or "{}").get("error") == "dependency_failed"
            and json.loads(t.payload).get("depends_on")
            and set(json.loads(t.payload)["depends_on"]) <= ready]
        if not extra:
            break
        eligible.extend(extra)
        ready.update(t.id for t in extra)
    return eligible


def activate(db, run):
    """No external calls. All recovery/audit changes commit together."""
    transaction_lock(db, "swarm:" + run.id)
    db.refresh(run, with_for_update=True)
    value = run.value()
    if value.get("harness") != "skunk/1" or value.get("execution_mode") != "swarm" or value.get("status") == "cancelled":
        raise ValueError("Only an uncancelled saved SKUNK assessment can be resumed.")
    frozen_scope(db, run)
    selected = eligible_tasks(db, run)
    if not selected:
        raise ValueError("This run has no recoverable unfinished tasks. Completed work and policy denials were preserved.")
    cycle = int(value.get("resume_cycle", 0)) + 1
    if cycle > 100:
        raise ValueError("Saved run recovery history is full; start a separately authorized new run.")
    from .queueing import admit
    from .skunk_usage import default_policy
    admit(db, run.owner, value["campaign_id"], run.id)
    for task in selected:
        history = document(db, "task_resume_history", run.owner, {
            "run_id": run.id, "task_id": task.id, "resume_cycle": cycle,
            "status": task.status, "attempts": task.attempts,
            "result": json.loads(task.result or "{}"), "payload": json.loads(task.payload), "saved_at": now(),
        })
        payload = json.loads(task.payload)
        payload.update(resume_attempt_floor=task.attempts, resume_cycle=cycle)
        task.payload = canonical(payload)
        task.status, task.available_at, task.lease_until = "queued", time.time(), 0
        task.lease_token = ""
        task.updated_at = time.time()
        task.result = canonical({"resume_cycle": cycle, "prior_failure_history": history.id})
    value.update(status="queued", state="SWARM_RUNNING", resume_cycle=cycle,
        resumed_at=now(), deadline=time.time() + min(7200, max(60, int(value.get("max_seconds", 1800)))),
        workflow_version="skunk-swarm/5", max_model_calls=None, max_tool_calls=None,
        usage_policy=default_policy(),
        retry_policy={"max_attempts": 4, "retry_unknown_billing": True,
            "authorization": "Host owner explicitly resumed saved work with separately billed bounded retries; prior reservations retained"})
    value.pop("finished", None)
    value.pop("blocked_reason", None)
    # Usage, uncertain holds, HTTP quotas, evidence, pins and scope are unchanged.
    run.data = canonical(value)
    campaign = db.get(Document, value["campaign_id"])
    campaign_value = campaign.value()
    campaign_value["target_url"] = value["target_url"]
    campaign.data = canonical(campaign_value)
    append(db, run.id, "skunk-operator", "skunk_saved_run_resumed", {
        "resume_cycle": cycle, "task_ids": [t.id for t in selected],
        "completed_tasks_preserved": True, "prior_billing_reservations": "retained",
        "policy_hash": value["policy_hash"], "model_pins": "unchanged",
    }, value["campaign_id"])
    return len(selected)


class SavedController(Controller):
    def __init__(self, run_id=None):
        from .provider_setup import local_owner
        from .skunk_diagnose import read_engine
        from sqlalchemy.orm import Session
        readonly_engine = read_engine()
        if readonly_engine is None:
            raise ValueError("No saved SKUNK database was found.")
        try:
            with Session(readonly_engine) as db:
                owner = local_owner(db)
                rows = db.query(Document).filter_by(kind="run", owner=owner.id).order_by(Document.created.desc()).all()
                run = next((row for row in rows if (not run_id or row.id == run_id) and row.value().get("harness") == "skunk/1" and row.value().get("execution_mode") == "swarm"), None)
                if not run:
                    raise ValueError("No matching saved SKUNK assessment was found for the local owner.")
                if run.value().get("status") == "cancelled":
                    raise ValueError("The saved run was cancelled. Start a new run only with your intended scope.")
                scope = frozen_scope(db, run)
                if not eligible_tasks(db, run):
                    raise ValueError("The latest run has no recoverable unfinished tasks. Use skunk diagnose to inspect its coverage.")
                value = run.value()
                campaign = db.get(Document, value["campaign_id"]).value()
                super().__init__(value["target_url"], value.get("agent_count", 8), campaign.get("mode") == "safe-active", value.get("instructions", ""))
                self.scope = scope
                self.saved_id, self.owner_id, self.campaign_id = run.id, run.owner, value["campaign_id"]
                self.scope_text = value["target_url"] + " (saved scope)"
                self.wildcard = False  # Resume never enumerates or adds new targets.
        finally:
            readonly_engine.dispose()

    def setup(self):
        self.wait()
        from .embeddings import verify_model
        from .workflow import model_binding, control
        verify_model()
        with session() as db:
            run = db.get(Document, self.saved_id)
            frozen_scope(db, run)
            for alias in run.value().get("models", {}):
                model_binding(db, run, alias)
            # Retain the old provider credential and exact model pins. A token
            # change requires a new run; resume cannot silently repin it.
            for other in db.query(Document).filter_by(kind="run", owner=self.owner_id):
                if other.id != self.saved_id and other.value().get("harness") == "skunk/1" and other.value().get("status") in ("queued", "running"):
                    control(db, other, "pause", "skunk-resume-isolation")
            db.commit()
        self.note("Resuming saved work with the original frozen scope, models, credentials and evidence. Completed tasks will not repeat.")

    def discover(self):
        with session() as db:
            return [db.get(Document, self.saved_id).value()["target_url"]]

    def new_run(self, target, discovery=False):
        with self.lock, session() as db:
            run = db.get(Document, self.saved_id)
            if discovery or target != run.value().get("target_url"):
                raise ValueError("Saved-run resume cannot create another target.")
            count = activate(db, run)
            self.run_ids.append(run.id)
            self.current_run = run.id
            db.commit()
        self.note("Recovered " + str(count) + " unfinished tasks. Prior attempts, usage and uncertain holds were retained.")
        return self.saved_id
