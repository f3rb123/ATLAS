"""Read recorded execution counts; no models, target requests or prompt reconstruction."""

import json
import re
from collections import Counter
from urllib.parse import urlsplit

from .db import Document, Journal, SwarmTask


EXPLANATIONS = {
    "no_target_responses": "No target responses were recorded. Inspect discovery or transport failures.",
    "no_registered_checks": "Responses exist, but no registered validation check has completed.",
    "no_replayable_candidate": "Completed checks produced no candidate eligible for independent replay.",
    "replay_pending": "A candidate exists; independent replay is queued or running.",
    "replay_failed": "Independent replay has failed tasks. Inspect the compact task error counts.",
    "refuted_on_replay": "Fresh independent checks refuted the recorded candidates.",
    "no_verification_verdict": "A candidate exists without a stored independent verification verdict.",
    "unconfirmed_after_review": "Independent review has not confirmed a vulnerability.",
    "confirmed_findings": "Independent verification has confirmed findings.",
}


def collect(db, run):
    value = run.value()
    kinds = ("artifact", "http_observation", "web_candidate", "verification_review", "finding", "hypothesis", "swarm_event")
    docs = db.query(Document).filter(Document.owner == run.owner, Document.kind.in_(kinds), Document.data.contains(run.id))
    tools, checks, scanners, candidates, reviews, findings, responses = (Counter() for _ in range(7))
    urls, hosts = set(), set()
    hypotheses, experiments = 0, 0
    for row in docs:
        data = row.value()
        if data.get("run_id") != run.id:
            continue
        if row.kind == "http_observation" and data.get("response"):
            status = data["response"].get("status")
            if type(status) is int and 100 <= status <= 599:
                responses[str(status // 100) + "xx"] += 1
            url = data.get("url", "")
            try:
                parsed = urlsplit(url)
                if parsed.hostname:
                    urls.add(url)
                    hosts.add(parsed.hostname)
            except ValueError:
                pass
        elif row.kind == "artifact":
            name = data.get("tool_name", "")
            if not isinstance(name, str) or not re.fullmatch(r"[a-z_]+(?:\.[a-z_]+)?", name):
                continue
            tools[name] += 1
            payload = data.get("payload", {})
            if not isinstance(payload, dict):
                continue
            if name == "web.check":
                kind = payload.get("kind")
                checks[kind if kind in {"headers", "redirect", "cors", "reflection", "graphql", "authorization"} else "other"] += 1
            elif name == "web.experiment":
                experiments += 1
            elif name == "scanner.run":
                tool = payload.get("tool")
                scanners[tool if tool in {"httpx", "katana", "nuclei", "subfinder", "dnsx", "naabu", "gau", "ffuf", "waybackurls"} else "other"] += 1
        elif row.kind == "web_candidate":
            status = data.get("status")
            candidates[status if status in {"candidate", "refuted", "confirmed", "inconclusive", "likely", "duplicate", "blocked_by_policy"} else "other"] += 1
        elif row.kind == "verification_review":
            status = data.get("effective_status")
            reviews[status if status in {"confirmed", "refuted", "inconclusive", "likely", "duplicate", "blocked_by_policy"} else "other"] += 1
        elif row.kind == "finding":
            findings["confirmed" if data.get("verification", {}).get("status") == "confirmed" else "unconfirmed"] += 1
        elif row.kind == "hypothesis" or (row.kind == "swarm_event" and data.get("kind") == "hypothesis"):
            hypotheses += 1
    replay, errors, task_counts = Counter(), Counter(), Counter()
    for task in db.query(SwarmTask).filter_by(run_id=run.id, owner=run.owner):
        task_counts[task.status] += 1
        if task.role in {"web-verification", "source-verification", "proof-validation"}:
            replay[task.status] += 1
        if task.status == "dead_letter":
            diagnostic = json.loads(task.result or "{}").get("diagnostic_code", {})
            code = diagnostic.get("code") if isinstance(diagnostic, dict) else None
            errors[code if isinstance(code, str) and re.fullmatch(r"[a-z_0-9]{1,80}", code) else "unspecified"] += 1
    denied = Counter()
    for row in db.query(Journal).filter_by(stream=run.id).filter(Journal.payload.contains('"type":"policy_decision"')):
        event = json.loads(row.payload)
        payload = event.get("payload", {})
        if event.get("type") != "policy_decision" or payload.get("decision") != "deny":
            continue
        reason = payload.get("reason", "") or ""
        if "Differential experiments are outside" in reason:
            denied["paired_experiment_absent_from_frozen_scope"] += 1
        elif "POST requires" in reason or "POST path" in reason:
            denied["post_purpose_or_path_not_authorized"] += 1
        elif reason == "invalid_tool_arguments":
            denied["invalid_tool_arguments"] += 1
        elif reason == "tool_execution_failed":
            denied["tool_execution_failed"] += 1
        elif "Scanner sandbox failed" in reason or "sandbox" in reason.lower():
            denied["scanner_sandbox_unavailable"] += 1
        else:
            denied["other_denial"] += 1
    if findings["confirmed"]:
        code = "confirmed_findings"
    elif not sum(responses.values()):
        code = "no_target_responses"
    elif not sum(checks.values()) + experiments:
        code = "no_registered_checks"
    elif not sum(candidates.values()):
        code = "no_replayable_candidate"
    elif replay["queued"] or replay["running"]:
        code = "replay_pending"
    elif replay["dead_letter"]:
        code = "replay_failed"
    elif candidates["refuted"] == sum(candidates.values()):
        code = "refuted_on_replay"
    elif not sum(reviews.values()):
        code = "no_verification_verdict"
    else:
        code = "unconfirmed_after_review"
    policy = db.get(Document, value.get("policy_id", ""))
    classes = policy.value().get("scope", {}).get("test_classes", []) if policy else []
    return {"run_id": run.id, "status": value.get("status"), "resume_cycle": value.get("resume_cycle", 0),
        "recorded_model_calls": value.get("model_calls", 0), "recorded_request_reservations": value.get("http_requests", 0),
        "response_status_groups": dict(responses), "responding_hosts": len(hosts), "responding_urls": len(urls),
        "completed_tool_runs": dict(tools), "completed_registered_checks": dict(checks), "completed_paired_experiments": experiments,
        "completed_scanner_processes": dict(scanners), "hypothesis_records": hypotheses,
        "replayable_candidates": dict(candidates), "independent_replay_tasks": dict(replay), "verification_verdicts": dict(reviews),
        "finding_counts": dict(findings), "task_counts": dict(task_counts), "task_errors": dict(errors),
        "denied_event_counts": dict(denied), "paired_experiments_allowed_by_saved_scope": "differential" in classes,
        "bottleneck": code, "explanation": EXPLANATIONS[code]}


def inspect():
    from sqlalchemy import text
    from sqlalchemy.orm import Session
    from .provider_setup import local_owner
    from .skunk_diagnose import read_engine
    engine = read_engine()
    if engine is None:
        return {"status": "no_existing_database", "model_calls_performed": 0, "target_requests_performed": 0}
    try:
        with Session(engine) as db:
            db.execute(text("PRAGMA query_only=ON" if engine.dialect.name == "sqlite" else "SET TRANSACTION READ ONLY"))
            owner = local_owner(db)
            runs = db.query(Document).filter_by(kind="run", owner=owner.id).order_by(Document.created.desc())
            run = next((row for row in runs if row.value().get("harness") == "skunk/1" and row.value().get("execution_mode") == "swarm"), None)
            return {"activity": collect(db, run) if run else None, "model_calls_performed": 0, "target_requests_performed": 0, "writes_performed": 0}
    finally:
        engine.dispose()
