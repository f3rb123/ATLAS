"""Read-only local diagnosis. No model calls, target traffic or embedding inference."""

import json
from collections import Counter
from pathlib import Path


class InspectionComplete(BaseException):
    pass


def read_engine():
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url, URL
    from .config import settings
    url = make_url(settings().database_url)
    if url.drivername.startswith("sqlite"):
        path = Path(url.database).expanduser().resolve()
        if not path.is_file():
            return None
        url = URL.create("sqlite", database="file:" + str(path), query={"mode": "ro", "uri": "true"})
    return create_engine(url, hide_parameters=True)


def provider_diagnosis():
    """An explicit GET /models checks current authentication without inference."""
    import os
    from sqlalchemy import text
    from sqlalchemy.orm import Session
    from .db import Document
    from .config import settings
    from .gateway import Adapter, ProviderHTTPError, provider_scope
    from .policy import request
    from .skunk_failures import describe
    from .skunk_prompts import BASE_URL, MODELS
    engine = read_engine()
    if engine is None:
        return {"status": "no_existing_database", "model_calls_performed": 0}
    try:
        with Session(engine) as db:
            db.execute(text("PRAGMA query_only=ON" if engine.dialect.name == "sqlite" else "SET TRANSACTION READ ONLY"))
            candidates = db.query(Document).filter_by(kind="provider").order_by(Document.created.desc()).all()
            provider = next((row for row in candidates if row.value().get("managed_by") == "skunk-cli" and row.value().get("base_url", "").rstrip("/") == BASE_URL), None)
            if provider is None:
                return {"status": "managed_provider_not_found", "model_calls_performed": 0}
            adapter = Adapter(provider)
            url = adapter.path("models")
            headers = adapter.headers()
            key = os.environ.get("hacker-ai-token") or os.environ.get("HACKER_AI_TOKEN")
            path = Path(settings().data_dir) / "hacker-ai-token"
            if not key and path.is_file():
                key = path.read_text().strip()
            if key:
                headers["Authorization"] = "Bearer " + key
            db.rollback()
            try:
                status, received, body = request(url, "GET", headers, scope=provider_scope(url), max_bytes=256000, timeout=15)
                if status != 200:
                    raise ProviderHTTPError(status, received, body)
                payload = json.loads(body)
                catalog = payload.get("data", payload.get("models", []))
                ids = {item.get("id", item.get("name")) for item in catalog if isinstance(item, dict)}
                return {"status": "metadata_reachable", "http_status": 200, "model_calls_performed": 0,
                    "credential_source": "current terminal/token file" if key else "saved encrypted provider",
                    "models": {name: {"listed": name in ids} for name in sorted(set(MODELS.values()))},
                    "note": "GET /models does not prove inference/JSON support. An unlisted alias may still be accepted by the provider."}
            except Exception as exc:
                return {"status": "metadata_check_failed", "failure": describe(exc), "model_calls_performed": 0}
    finally:
        engine.dispose()


def diagnose():
    import socket
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url, URL
    from sqlalchemy.orm import Session
    from .config import settings
    from .db import Document, SwarmTask, Journal, canonical
    from .skunk_failures import describe
    from .skunk_models import runtime_contract
    from .skunk_prompts import alias_for

    cfg = settings()
    url = make_url(cfg.database_url)
    if url.drivername.startswith("sqlite"):
        path = Path(url.database).expanduser().resolve()
        if not path.is_file():
            return {"diagnostic": "No existing SKUNK database was found; nothing was created.", "model_calls": 0, "target_requests": 0}
        url = URL.create("sqlite", database="file:" + str(path), query={"mode": "ro", "uri": "true"})
    engine = create_engine(url, hide_parameters=True)
    report = {"diagnostic": "SKUNK local read-only preflight", "hotfix": "retry1",
        "model_calls_performed": 0, "target_requests_performed": 0,
        "writes_performed": 0, "tasks": [], "models": [], "preflight": [],
        "note": "Cached context/configuration inspection is not proof that the API credential or provider is working."}
    from .skunk_usage import default_policy
    report["hotfix"] = "flow3"
    report["new_run_usage_policy"] = default_policy()
    report["new_run_model_presets"] = __import__("atlas.skunk_prompts", fromlist=["MODELS"]).MODELS
    report["new_run_model_call_cap"] = None
    report["new_run_tool_call_cap"] = None

    def no_network(*_args, **_kwargs):
        raise RuntimeError("Network is disabled in skunk diagnose")

    saved_connect, saved_connect_ex, saved_create = socket.socket.connect, socket.socket.connect_ex, socket.create_connection
    socket.socket.connect = socket.socket.connect_ex = socket.create_connection = no_network
    try:
        with Session(engine) as db:
            db.execute(text("PRAGMA query_only=ON" if url.drivername.startswith("sqlite") else "SET TRANSACTION READ ONLY"))
            runs = db.query(Document).filter_by(kind="run").order_by(Document.created.desc()).limit(100).all()
            run = next((row for row in runs if row.value().get("harness") == "skunk/1" and row.value().get("execution_mode") == "swarm"), None)
            if run is None:
                report["note"] = "No SKUNK assessment was found in this runtime. No database was created or changed."
                return report
            value = run.value()
            report["run"] = {"id": run.id, **{name: value.get(name) for name in ("status", "state", "partial", "task_errors", "model_calls", "max_model_calls", "tool_calls", "max_tool_calls", "workflow_version", "retry_policy", "usage_policy")}}
            rows = db.query(SwarmTask).filter_by(run_id=run.id).order_by(SwarmTask.created_at).all()
            report["task_counts"] = dict(Counter(row.status for row in rows))
            for task in rows:
                result = json.loads(task.result or "{}")
                report["tasks"].append({"role": task.role, "status": task.status, "attempts": task.attempts,
                    "error_type": result.get("error_type"), "diagnostic": result.get("diagnostic_code"), "error_code": result.get("error")})
            for alias, pin in value.get("models", {}).items():
                if alias not in {"orchestrator", "recon", "classifier", "exploit", "report", "verifier"}:
                    continue
                provider, model = db.get(Document, pin["provider_id"]), db.get(Document, pin["model_id"])
                item = {"alias": alias, "provider_exists": bool(provider), "model_exists": bool(model)}
                if provider and model:
                    p, m = provider.value(), model.value()
                    item.update(model=m.get("model_id"), provider_enabled=p.get("enabled"),
                        provider_health=p.get("health_status"), secret_configured=bool(p.get("secret")),
                        pins_match=provider.version == pin["provider_version"] and model.version == pin["model_version"],
                        managed_contract=runtime_contract(provider, model, run), context_window=m.get("context_window"),
                        max_output_tokens=m.get("max_output_tokens"), verified_structured=m.get("verified_structured"))
                    circuit = db.get(Document, __import__("atlas.model_routing", fromlist=["circuit_id"]).circuit_id(provider.id))
                    if circuit:
                        c = circuit.value()
                        item["circuit"] = {key: c.get(key) for key in ("failures", "unavailable_until", "last_outcome")}
                report["models"].append(item)
            ledger = db.get(Document, "token-budget-global")
            if ledger:
                budget = ledger.value()
                reserved = sum(item["ceiling"] for item in budget.get("reserved", {}).values())
                report["token_budget"] = {"cap": budget["cap"], "allocation": budget["allocation"],
                    "used_tokens": budget["used"]["total_tokens"], "reserved_tokens": reserved,
                    "remaining_allocation": max(0, budget["allocation"] - budget["used"]["total_tokens"] - reserved),
                    "unknown_billing_holds": sum(item.get("state") == "unknown_billing" for item in budget.get("reserved", {}).values()),
                    "contract_violation": budget.get("contract_violation", False)}
                report["token_budget"]["limits_enforced_for_new_skunk_runs"] = False
                report["token_budget"]["historical_counters_and_holds_preserved"] = True
            recent = db.query(Journal).filter_by(stream=run.id).order_by(Journal.sequence.desc()).limit(100).all()
            report["recent_failures"] = []
            for row in recent:
                event = json.loads(row.payload)
                if event.get("type") in {"swarm_task_error", "swarm_task_retry_scheduled", "model_output_repair"}:
                    payload = event.get("payload", {})
                    report["recent_failures"].append({"type": event["type"], "role": event.get("actor"),
                        **{key: payload[key] for key in ("error_type", "diagnostic_code", "attempt", "fields", "status") if key in payload}})
                if len(report["recent_failures"]) >= 15:
                    break

            from . import workflow, knowledge
            from .swarm import task_context, SwarmOutput
            from .knowledge import CAPABILITIES, POLICY_VERSION, availability, skill_results, task_query
            saved_dispatch, saved_prepare = workflow.dispatch_role_request, knowledge.prepare_context
            current = {}

            def cached_context(db, run, stage, context, actor):
                context = dict(context)
                memory = {"policy_version": POLICY_VERSION, "trust": "untrusted_attributed_knowledge",
                    "capabilities": {name: schema.model_json_schema() for name, schema in CAPABILITIES.items()},
                    "availability": availability(db, run.owner),
                    "skills": skill_results(db, run.owner, task_query(stage, context), 3)}
                if current.get("cache") is not None:
                    memory["task_research"] = current["cache"]
                context["knowledge"] = memory
                return context

            def inspect_request(db, run, provider, model, request, alias):
                size = sum(len(message["content"].encode()) for message in request.messages)
                current.update(status="request_constructed_without_dispatch", alias=alias,
                    model=model.value()["model_id"], request_bytes=size, output_limit=request.max_tokens,
                    context_bound=model.value()["context_window"], fits_context_bound=size + request.max_tokens <= model.value()["context_window"])
                raise InspectionComplete()

            workflow.dispatch_role_request, knowledge.prepare_context = inspect_request, cached_context
            try:
                seen = set()
                for task in sorted(rows, key=lambda row: row.status != "dead_letter"):
                    if task.role in {"web-discovery", "web-verification", "source-verification", "proof-validation"}:
                        continue
                    alias = alias_for(task.role)
                    if alias in seen:
                        continue
                    seen.add(alias)
                    current = {"role": task.role, "alias": alias, "cache": None}
                    artifacts = db.query(Document).filter_by(kind="artifact", owner=run.owner).filter(Document.data.contains(run.id)).order_by(Document.created.desc()).limit(150).all()
                    for artifact in artifacts:
                        a = artifact.value()
                        if a.get("task_id") == task.id and a.get("tool_name") == "knowledge.search":
                            current["cache"] = a.get("payload")
                            break
                    try:
                        context, _ = task_context(db, run, task)
                        workflow.role(db, run, "SWARM_TASK", context, alias, response_schema=SwarmOutput)
                    except InspectionComplete:
                        pass
                    except Exception as exc:
                        current.update(status="preflight_failed", failure=describe(exc))
                    cache_available = current.pop("cache", None) is not None
                    report["preflight"].append({**current, "cached_retrieval_available": cache_available})
                    db.rollback()
                    db.execute(text("PRAGMA query_only=ON" if url.drivername.startswith("sqlite") else "SET TRANSACTION READ ONLY"))
            finally:
                workflow.dispatch_role_request, knowledge.prepare_context = saved_dispatch, saved_prepare
            db.rollback()
    finally:
        socket.socket.connect, socket.socket.connect_ex, socket.create_connection = saved_connect, saved_connect_ex, saved_create
        engine.dispose()
    return report
