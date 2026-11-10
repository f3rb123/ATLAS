"""SQL-authoritative, bounded event-driven research tasks.

No event, model or reference can grant tool authority. Existing run policies,
gateway budgets and independent proof/control verification remain authoritative.
"""

import json
import threading
import time
from types import SimpleNamespace

from pydantic import Field
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError

from .db import (
    Document,
    SwarmTask,
    append,
    canonical,
    digest,
    document,
    now,
    session,
    transaction_lock,
    uid,
)
from .policy import Denied, Strict
from .workflow import Hypothesis, RoleOutput

INITIAL_ROLES = {
    "recon": "Map authorized assets and source entrypoints. Publish cited endpoint and technology observations; no unregistered scanning.",
    "authentication": "Investigate identity, OAuth and session boundaries from available evidence; distinguish hypotheses from proof.",
    "api-business-logic": "Trace API object ownership and business invariants; request focused help for cited boundary ambiguities.",
    "input-handling": "Trace untrusted input to sinks and controls; publish narrow source-backed hypotheses, never confirmed findings.",
    "content-discovery": "Inspect available route manifests and content paths using registered tools; no arbitrary fuzzing or shell.",
    "vulnerability-research": "Use attributed advisory knowledge and dependency evidence; version similarity is not exploitability proof.",
    "deep-research": "Retrieve reports and methodologies, compare explanations and identify evidence needed to falsify hypotheses.",
    "validation-review": "Challenge assumptions, citations and secure counterfactuals independently. Only the proof/control replay gate can confirm findings.",
}
SPECIALISTS = {
    "graphql": "Analyze GraphQL resolver ownership and nested object authorization in the cited evidence.",
    "oauth": "Analyze redirect URI, state and identity boundaries in the cited OAuth evidence.",
    "idor": "Trace object identity and tenant ownership checks in the cited API evidence.",
    "ssrf": "Inspect request destinations, redirects and allowlist controls in the cited evidence; scope remains fixed.",
    "sqli": "Trace query construction and parameter binding in the cited source evidence.",
    "javascript": "Inspect relevant JavaScript source and API entrypoints with bounded read tools.",
    "file-upload": "Inspect file type, storage and authorization boundaries without uploading or executing payloads.",
    "session": "Inspect session issuance, expiry, rotation and access control from cited evidence.",
    "cloud": "Research cited cloud configuration boundaries; no external cloud account actions.",
    "infrastructure": "Review cited infrastructure configuration, exposure and trust boundaries.",
    "api": "Investigate cited API schema, endpoint and authorization observations.",
}
ROLES = {**INITIAL_ROLES, **SPECIALISTS}
ROLES.update(
    {
        "coding-review": "Review cited code boundaries and return independent observations.",
        "fast-triage": "Triage a narrow cited observation; do not confirm findings.",
    }
)
TERMINAL = {"completed", "dead_letter", "cancelled"}
MAX_TASKS = 128
LEASE_SECONDS = 300
MAX_ATTEMPTS = 3


class Discovery(Strict):
    kind: str = Field(
        pattern="^(asset|endpoint|technology|observation|hypothesis|research_note)$"
    )
    topic: str = Field(
        default="general",
        pattern="^(general|graphql|oauth|idor|ssrf|sqli|javascript|file-upload|session|cloud|infrastructure|api)$",
    )
    title: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=4000)
    citations: list[str] = Field(default=[], max_length=12)
    confidence: float = Field(default=0.5, ge=0, le=1, allow_inf_nan=False)


class SwarmOutput(RoleOutput):
    discoveries: list[Discovery] = Field(default=[], max_length=8)


def tasks(db, run_id):
    return db.query(SwarmTask).filter_by(run_id=run_id)


def enqueue(db, run, role, payload, key, priority=1):
    check_fence(db, run)
    if role not in ROLES and role != "proof-validation":
        raise Denied("Specialist capability is not registered")
    transaction_lock(db, "swarm:" + run.id)
    from .scheduling import validate_dependencies

    validate_dependencies(db, run, payload)
    old = tasks(db, run.id).filter_by(dedupe_key=key).first()
    if old:
        return old
    if tasks(db, run.id).count() >= MAX_TASKS:
        append(
            db,
            run.id,
            "scheduler",
            "swarm_task_limit",
            {"limit": MAX_TASKS},
            run.value()["campaign_id"],
        )
        return None
    t = SwarmTask(
        id=uid(),
        run_id=run.id,
        owner=run.owner,
        role=role,
        worker_kind="verify"
        if role in ("validation-review", "proof-validation")
        else "research",
        dedupe_key=key,
        payload=canonical(payload),
        priority=priority,
        created_at=time.time(),
        updated_at=time.time(),
    )
    db.add(t)
    db.flush()
    append(
        db,
        run.id,
        "scheduler",
        "swarm_task_created",
        {
            "task_id": t.id,
            "role": role,
            "reason": payload.get("reason", "initial responsibility"),
            "parent_event": payload.get("event_id"),
            "priority": priority,
        },
        run.value()["campaign_id"],
    )
    return t


def initialize(db, run):
    count = run.value().get("agent_count", 8)
    if not 1 <= count <= 16:
        raise Denied("Agent count must be between 1 and 16")
    roles = list(INITIAL_ROLES)
    for i in range(count):
        name = roles[i % len(roles)]
        enqueue(
            db,
            run,
            name,
            {
                "instructions": ROLES[name],
                "partition": i // len(roles),
                "reason": "Initial differentiated responsibility",
            },
            digest("initial:" + str(i)),
        )


def active(db, run):
    db.refresh(run)
    value = run.value()
    kill = db.get(Document, "kill-switch", populate_existing=True)
    if (
        value["status"] not in ("queued", "running")
        or time.time() > value["deadline"]
        or (kill and kill.value()["enabled"])
    ):
        raise Denied("Swarm stopped, paused, expired or emergency stop active")
    policy = db.get(Document, value["policy_id"])
    campaign = db.get(Document, value["campaign_id"])
    if (
        not policy
        or policy.owner != run.owner
        or not campaign
        or campaign.owner != run.owner
        or not campaign.value().get("authorization_attested")
        or digest(canonical(policy.value()["scope"])) != value["policy_hash"]
    ):
        raise Denied("Swarm authorization or frozen policy integrity failed")


def check_fence(db, run, claim=None):
    claim = claim or getattr(run, "_swarm_claim", None)
    if claim is None:
        return
    t = db.get(SwarmTask, claim[0], populate_existing=True)
    if (
        not t
        or t.run_id != run.id
        or t.owner != run.owner
        or t.status != "running"
        or t.lease_token != claim[1]
        or t.lease_until <= time.time()
    ):
        raise Denied("Task lease lost; stale worker cannot publish or execute tools")
    active(db, run)


def claim_one(db, worker_kind):
    # Candidate reads carry no locks across external work. A short per-run claim
    # transaction enforces concurrency, fencing and duplicate suppression.
    candidates = (
        db.query(SwarmTask)
        .filter(
            SwarmTask.worker_kind == worker_kind,
            SwarmTask.available_at <= time.time(),
            or_(
                SwarmTask.status == "queued",
                (SwarmTask.status == "running") & (SwarmTask.lease_until < time.time()),
            ),
        )
        .order_by((SwarmTask.priority + (time.time() - SwarmTask.created_at) / 300).desc(), SwarmTask.created_at)
        .limit(100)
        .all()
    )
    from .scheduling import dependency_state, order_candidates

    for explanation, candidate in order_candidates(db, candidates):
        transaction_lock(db, "swarm:" + candidate.run_id)
        run = db.get(Document, candidate.run_id, populate_existing=True)
        t = db.get(
            SwarmTask, candidate.id, with_for_update=True, populate_existing=True
        )
        if t.status not in ("queued", "running") or (
            t.status == "running" and t.lease_until > time.time()
        ):
            db.commit()
            continue
        try:
            active(db, run)
        except Denied:
            value = run.value()
            if value["status"] == "paused":
                db.commit()
                continue
            if value["status"] in ("queued", "running"):
                kill = db.get(Document, "kill-switch", populate_existing=True)
                if kill and kill.value()["enabled"]:
                    value.update(status="cancelled", finished=now())
                else:
                    value.update(
                        status="blocked",
                        blocked_reason="Swarm deadline, authorization or frozen policy check failed",
                    )
                run.data = canonical(value)
            t.status, t.updated_at = "cancelled", time.time()
            db.commit()
            continue
        if t.attempts >= MAX_ATTEMPTS:
            t.status = "dead_letter"
            t.result = canonical({"error": "lease_attempt_limit"})
            db.commit()
            finish_run(db, run)
            continue
        dependency = dependency_state(db, t)
        if dependency != "ready":
            if dependency == "failed":
                t.status, t.updated_at = "cancelled", time.time()
                t.result = canonical({"error": "dependency_failed", "depends_on": json.loads(t.payload).get("depends_on", [])})
                append(db, run.id, "scheduler", "swarm_dependency_failed", {"task_id": t.id}, run.value()["campaign_id"])
                db.commit()
                finish_run(db, run)
            else:
                db.commit()
            continue
        if t.attempts:
            budget = db.get(Document, "budget-global", populate_existing=True)
            if budget and any(
                r.get("task_id") == t.id for r in budget.value()["reserved"].values()
            ):
                t.status = "dead_letter"
                t.result = canonical(
                    {"error": "unknown_billing_outcome_requires_reconciliation"}
                )
                db.commit()
                finish_run(db, run)
                continue
        concurrent = (
            tasks(db, run.id)
            .filter(SwarmTask.status == "running", SwarmTask.lease_until > time.time())
            .count()
        )
        if concurrent >= run.value().get("agent_count", 8):
            db.commit()
            continue
        t.status, t.lease_token, t.lease_until = (
            "running",
            uid(),
            time.time() + LEASE_SECONDS,
        )
        t.attempts += 1
        t.updated_at = time.time()
        value = run.value()
        value["status"] = "running"
        run.data = canonical(value)
        append(
            db,
            run.id,
            "scheduler",
            "swarm_task_claimed",
            {"task_id": t.id, "role": t.role, "attempt": t.attempts, "priority_explanation": explanation},
            value["campaign_id"],
        )
        db.commit()
        return t.id, t.lease_token
    return None


def publish(db, run, task, discovery):
    check_fence(db, run)
    transaction_lock(db, "swarm:" + run.id)
    payload = discovery.model_dump()
    id = digest("swarm-event:" + run.id + canonical(payload))[:36]
    old = db.get(Document, id)
    if old:
        return old
    event = document(
        db,
        "swarm_event",
        run.owner,
        {
            "run_id": run.id,
            "campaign_id": run.value()["campaign_id"],
            "task_id": task.id,
            "agent": task.role,
            "status": "unverified",
            "created_at": now(),
            **payload,
        },
        id,
    )
    append(
        db,
        run.id,
        task.role,
        "swarm_discovery",
        {"event_id": id, "task_id": task.id, **payload},
        run.value()["campaign_id"],
    )
    if (
        discovery.topic in SPECIALISTS
        and discovery.citations
        and discovery.confidence >= 0.5
        and discovery.topic != task.role
    ):
        enqueue(
            db,
            run,
            discovery.topic,
            {
                "event_id": id,
                "instructions": ROLES[discovery.topic],
                "reason": "Cited " + discovery.topic + " discovery from " + task.role,
                "signals": {"confidence": discovery.confidence, "evidence_count": len(discovery.citations), "relevance": 1.0,
                            "estimated_effort": 0.5, "hypothesis": discovery.kind == "hypothesis"},
            },
            digest("subscription:" + discovery.topic + ":" + id),
            discovery.confidence,
        )
    if discovery.kind == "hypothesis" and task.role != "deep-research":
        enqueue(
            db,
            run,
            "deep-research",
            {
                "event_id": id,
                "instructions": ROLES["deep-research"],
                "reason": "Challenge and research cited hypothesis",
                "signals": {"confidence": discovery.confidence, "evidence_count": len(discovery.citations), "relevance": 1.0,
                            "estimated_effort": 0.8, "hypothesis": True},
            },
            digest("research:" + id),
            discovery.confidence,
        )
    return event


def task_context(db, run, task):
    value = run.value()
    payload = json.loads(task.payload)
    context = {
        "task": {"id": task.id, "role": task.role, **payload},
        "operator_instructions": value.get("instructions", ""),
        "campaign": db.get(Document, value["campaign_id"]).value(),
        "policy": db.get(Document, value["policy_id"]).value(),
        "constraint": "Research only. Return cited discoveries; no self-confirmed findings. Each task has an independent context.",
    }
    if payload.get("event_id"):
        event = db.get(Document, payload["event_id"])
        if event and event.owner == run.owner and event.value()["run_id"] == run.id:
            context["discovery"] = event.value()
    # Only a small, explicit shared view; never whole agent histories.
    context["shared_observations"] = [
        d.value()
        for d in db.query(Document)
        .filter_by(kind="swarm_event", owner=run.owner)
        .filter(Document.data.contains('"run_id":"' + run.id + '"'))
        .order_by(Document.created.desc())
        .limit(MAX_TASKS * 8)
        if d.value()["run_id"] == run.id
    ][:5]
    for observation in context["shared_observations"]:
        observation["text"] = observation["text"][:800]
    repo = None
    if value.get("repository_id"):
        from .tools import ReadInput, Repository

        source = db.get(Document, value["repository_id"])
        if not source or source.owner != run.owner:
            raise Denied("Repository not authorized")
        repo = Repository(source.value()["path"])
        inventory = repo.inventory()
        context["inventory"] = {
            "files": inventory["files"][:120],
            "total_files": len(inventory["files"]),
            "snapshot_hash": inventory["snapshot_hash"],
        }
        files = inventory["files"]
        index = (
            list(ROLES).index(task.role) if task.role in ROLES else 0
        ) + payload.get("partition", 0) * len(INITIAL_ROLES)
        selected = files[index :: max(1, value.get("agent_count", 8))][:4]
        context["source"] = [repo.read(ReadInput(path=f, end=100)) for f in selected]
        for source in context["source"]:
            if len(source["text"]) > 4000:
                source["text"] = source["text"][:4000]
                source["truncated"] = True
    return context, repo


def finish_run(db, run):
    transaction_lock(db, "swarm:" + run.id)
    db.refresh(run, with_for_update=True)
    value = run.value()
    if (
        value["status"] not in ("queued", "running")
        or tasks(db, run.id).filter(SwarmTask.status.not_in(TERMINAL)).count()
    ):
        db.commit()
        return
    from .reporting import generate_report

    errors = tasks(db, run.id).filter_by(status="dead_letter").count()
    report = generate_report(db, run, "markdown")
    value.update(
        state="COMPLETED",
        status="completed",
        partial=bool(errors),
        task_errors=errors,
        report_id=report.id,
        finished=now(),
    )
    run.data = canonical(value)
    append(
        db,
        run.id,
        "scheduler",
        "swarm_completed",
        {"task_errors": errors, "report_id": report.id},
        value["campaign_id"],
    )
    db.commit()


def execute_one(worker_kind):
    with session() as db:
        claim = claim_one(db, worker_kind)
        if claim is None:
            # Recover the crash window after task completion commits but before
            # the final report/run status commits. Completion is idempotent.
            for run in (
                db.query(Document)
                .filter(
                    Document.kind == "run",
                    Document.data.contains('"execution_mode":"swarm"'),
                    Document.data.contains('"status":"running"'),
                )
                .limit(100)
                .all()
            ):
                finish_run(db, run)
            return False
        task = db.get(SwarmTask, claim[0])
        run = db.get(Document, task.run_id)
        run._swarm_claim = claim
        stopped = threading.Event()
        keeper = threading.Thread(target=keep_lease, args=(claim, stopped), daemon=True)
        keeper.start()
        try:
            check_fence(db, run)
            context, repo = task_context(db, run, task)
            if task.role == "proof-validation":
                from .verification import verify_candidates

                original = json.loads(task.payload)["execution"]
                done = [
                    SimpleNamespace(
                        value=lambda: {"state": "SAFE_EXECUTION", "result": original}
                    )
                ]
                result = verify_candidates(db, run, repo, done)
            else:
                from .workflow import role

                alias = "verifier" if worker_kind == "verify" else "reasoning"
                requested_alias = {
                    "deep-research": "deep_research",
                    "coding-review": "coding",
                    "fast-triage": "fast",
                }.get(task.role)
                if worker_kind != "verify" and requested_alias in run.value().get(
                    "models", {}
                ):
                    alias = requested_alias
                output = role(
                    db, run, "SWARM_TASK", context, alias, response_schema=SwarmOutput
                )
                check_fence(db, run)
                for request in output.tool_requests:
                    from .tools import broker

                    broker(db, run, repo, request.name, request.input, task.role)
                result = output.model_dump()
                for request in output.specialist_requests:
                    target = (
                        "coding-review" if request.role == "coding" else "fast-triage"
                    )
                    enqueue(
                        db,
                        run,
                        target,
                        {
                            "instructions": request.question,
                            "reason": request.reason,
                            "parent_task": task.id,
                        },
                        digest("request:" + request.role + ":" + request.question),
                    )
                for discovery in output.discoveries:
                    publish(db, run, task, discovery)
                hypotheses = []
                for value in output.hypotheses:
                    h = Hypothesis.model_validate(value)
                    id = digest("hypothesis:" + run.id + canonical(h.model_dump()))[:36]
                    item = db.get(Document, id) or document(
                        db,
                        "hypothesis",
                        run.owner,
                        {
                            "run_id": run.id,
                            "task_id": task.id,
                            **h.model_dump(),
                            "status": "candidate",
                        },
                        id,
                    )
                    hypotheses.append(item.id)
                if output.experiment:
                    from .tools import broker

                    e = output.experiment
                    if set(e) - {
                        "template",
                        "test_path",
                        "control_test_path",
                        "hypothesis_id",
                        "hypothesis_index",
                    }:
                        raise Denied("Unsupported experiment fields")
                    hypothesis_id = e.get("hypothesis_id")
                    if hypothesis_id is None and hypotheses:
                        index = e.get("hypothesis_index", 0)
                        if not isinstance(index, int) or not 0 <= index < len(
                            hypotheses
                        ):
                            raise Denied("Invalid experiment hypothesis index")
                        hypothesis_id = hypotheses[index]
                    h = db.get(Document, hypothesis_id) if hypothesis_id else None
                    if (
                        not h
                        or h.kind != "hypothesis"
                        or h.owner != run.owner
                        or h.value()["run_id"] != run.id
                    ):
                        raise Denied("Experiment hypothesis provenance invalid")
                    if (
                        not repo
                        or e.get("template") != "python_unittest"
                        or not e.get("control_test_path")
                    ):
                        raise Denied(
                            "Reproduction needs repository, test and secure control"
                        )
                    proof = broker(
                        db,
                        run,
                        repo,
                        "run_local_reproduction",
                        {"template": "python_unittest", "test_path": e["test_path"]},
                        task.role,
                    )
                    control = broker(
                        db,
                        run,
                        repo,
                        "run_local_reproduction",
                        {
                            "template": "python_unittest",
                            "test_path": e["control_test_path"],
                        },
                        task.role,
                    )
                    e = {k: v for k, v in e.items() if k != "hypothesis_index"}
                    e["hypothesis_id"] = hypothesis_id
                    enqueue(
                        db,
                        run,
                        "proof-validation",
                        {
                            "execution": {
                                "experiment": e,
                                "proof": proof,
                                "control": control,
                            },
                            "reason": "Fresh independent proof/control replay",
                        },
                        digest("verify:" + hypothesis_id),
                    )
            check_fence(db, run)
            task.status, task.result = "completed", canonical(result)
            task.lease_until, task.updated_at = 0, time.time()
            append(
                db,
                run.id,
                task.role,
                "swarm_task_completed",
                {"task_id": task.id},
                run.value()["campaign_id"],
            )
            db.commit()
            finish_run(db, run)
        except Exception as exc:
            import logging

            from .gateway import CapacityWait, RunInterrupted

            if not isinstance(exc, (RunInterrupted, CapacityWait)):
                logging.getLogger("atlas").warning("swarm_task_failed", extra={"error_type": type(exc).__name__, "task_id": claim[0]})
            db.rollback()
            # Stale/cancelled workers must not overwrite a newer claim or results.
            transaction_lock(db, "swarm:" + run.id)
            task = db.get(
                SwarmTask, claim[0], with_for_update=True, populate_existing=True
            )
            run = db.get(Document, task.run_id, populate_existing=True)
            if task.status == "running" and task.lease_token == claim[1]:
                value = run.value()
                if isinstance(exc, CapacityWait) and value["status"] in (
                    "queued",
                    "running",
                ):
                    task.status, task.available_at = "queued", time.time() + 1
                    task.attempts = max(0, task.attempts - 1)
                elif value["status"] == "paused" or (
                    isinstance(exc, RunInterrupted)
                    and value["status"] in ("queued", "running")
                ):
                    task.status = "queued"
                elif value["status"] not in ("queued", "running"):
                    task.status = "cancelled"
                else:
                    # Provider errors may have a billed/unknown outcome. Do not
                    # automatically re-dispatch them and multiply paid requests.
                    task.status = "dead_letter"
                task.result = canonical(
                    {
                        "error_type": type(exc).__name__,
                        "reason": "Task failed; inspect policy/provider diagnostics",
                        "model_output_trusted": False,
                    }
                )
                task.lease_until, task.updated_at = 0, time.time()
                append(
                    db,
                    run.id,
                    task.role,
                    "swarm_task_error",
                    {
                        "task_id": task.id,
                        "error_type": type(exc).__name__,
                        "status": task.status,
                    },
                    value["campaign_id"],
                )
                db.commit()
                finish_run(db, run)
        finally:
            stopped.set()
            keeper.join(timeout=1)
        return True


def keep_lease(claim, stopped):
    from sqlalchemy import update

    while not stopped.wait(10):
        try:
            with session() as db:
                changed = db.execute(
                    update(SwarmTask)
                    .where(
                        SwarmTask.id == claim[0],
                        SwarmTask.lease_token == claim[1],
                        SwarmTask.status == "running",
                        SwarmTask.lease_until > time.time(),
                    )
                    .values(
                        lease_until=time.time() + LEASE_SECONDS, updated_at=time.time()
                    )
                ).rowcount
                db.commit()
                if changed != 1:
                    return
        except SQLAlchemyError:
            # A failed heartbeat cannot renew a lost lease. Subsequent tool,
            # dispatch and publication checks fail closed if it expires.
            return
