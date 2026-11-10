"""Read-only cached-context preflight. No inference, tools, targets or DB writes."""

import json
import socket
from sqlalchemy import text
from atlas.db import Document, SwarmTask, session, canonical
from atlas import workflow, tools, model_routing
from atlas.swarm import task_context, SwarmOutput
from atlas.gateway import ProviderError


class InspectionFinished(BaseException):
    pass


def no_network(*args, **kwargs):
    raise RuntimeError("Python network dispatch disabled in diagnostic")


# PostgreSQL uses libpq; block Python networking for providers/targets.
socket.socket.connect = no_network
socket.socket.connect_ex = no_network
socket.create_connection = no_network
current = {}


def sections(context):
    return sorted(
        [(key, len(canonical(value).encode())) for key, value in context.items()],
        key=lambda item: -item[1],
    )[:5]


original_rank = model_routing.rank


def inspect_rank(db, run, alias, stage, context, input_bytes, output_tokens):
    ranked, rejected = original_rank(
        db, run, alias, stage, context, input_bytes, output_tokens
    )
    print(
        json.dumps(
            {
                "stage": "routing_preflight",
                "alias": alias,
                "input_bytes": input_bytes,
                "requested_output_tokens": output_tokens,
                "eligible_candidates": len(ranked),
                "rejected": rejected,
                "largest_context_sections_bytes": sections(context),
            }
        )
    )
    raise InspectionFinished()


def stop_dispatch(db, run, provider, model, request, alias):
    print(
        json.dumps(
            {
                "stage": "dispatch_preflight",
                "alias": alias,
                "input_bytes": sum(
                    len(item["content"].encode()) for item in request.messages
                ),
                "output_tokens": request.max_tokens,
                "model": model.value()["model_id"],
                "context_window": model.value()["context_window"],
                "dispatch_performed": False,
            }
        )
    )
    raise InspectionFinished()


def cached_broker(db, run, repo, name, payload, actor):
    if name != "knowledge.search":
        raise InspectionFinished("Unexpected tool blocked")
    cached = current.get("cache")
    if cached is None:
        raise ValueError("No saved retrieval artifact; no replacement search performed")
    return {"result": cached}


model_routing.rank = inspect_rank
workflow.dispatch_role_request = stop_dispatch
tools.broker = cached_broker

with session() as db:
    db.execute(text("SET TRANSACTION READ ONLY"))
    run = (
        db.query(Document)
        .filter_by(kind="run")
        .order_by(Document.created.desc())
        .first()
    )
    if not run:
        raise SystemExit("No run found")
    print(
        json.dumps(
            {
                "run_id": run.id,
                "mode": run.value().get("model_mode"),
                "web_enabled": run.value().get("web", {}).get("enabled", False),
                "diagnostic": "cached-context reconstruction only; provider dispatch prohibited",
            }
        )
    )
    artifacts = [
        row.value()
        for row in db.query(Document)
        .filter_by(kind="artifact", owner=run.owner)
        .filter(Document.data.contains(run.id))
        if row.value().get("run_id") == run.id
        and row.value().get("tool_name") == "knowledge.search"
    ]
    for task in (
        db.query(SwarmTask).filter_by(run_id=run.id, status="dead_letter").limit(3)
    ):
        current["cache"] = next(
            (row["payload"] for row in artifacts if row.get("task_id") == task.id), None
        )
        print(
            json.dumps(
                {
                    "task_role": task.role,
                    "cached_knowledge_available": current["cache"] is not None,
                }
            )
        )
        try:
            context, _ = task_context(db, run, task)
            alias = (
                "verifier"
                if task.worker_kind == "verify"
                else {
                    "deep-research": "deep_research",
                    "coding-review": "coding",
                    "fast-triage": "fast",
                }.get(task.role, "reasoning")
            )
            workflow.role(
                db, run, "SWARM_TASK", context, alias, response_schema=SwarmOutput
            )
        except InspectionFinished:
            pass
        except ProviderError as error:
            allowed = {
                "Context size limit exceeded",
                "No approved, verified model fits the request and current provider health",
                "Pinned provider/model version unavailable",
                "Structured output capability unverified",
                "Test the configured provider/key before resuming research",
            }
            result = {
                "preflight_error": str(error)
                if str(error) in allowed
                else type(error).__name__
            }
            trace = error.__traceback__
            while trace:
                if trace.tb_frame.f_code.co_name == "role":
                    values = trace.tb_frame.f_locals
                    prompt = values.get("prompt")
                    if isinstance(prompt, str):
                        result["prompt_bytes"] = len(prompt.encode())
                        result["prompt_characters"] = len(prompt)
                    if isinstance(values.get("context"), dict):
                        result["largest_context_sections_bytes"] = sections(
                            values["context"]
                        )
                trace = trace.tb_next
            print(json.dumps(result))
        except Exception as error:
            print(
                json.dumps(
                    {
                        "preflight_error_type": type(error).__name__,
                        "raw_error_withheld": True,
                    }
                )
            )
    db.rollback()
print("Diagnostic ended. No provider/target requests or database changes performed.")
