"""Internal model gateway: distinct credentials for research and verifier services."""

import hmac
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from .config import settings
from .db import session, Document
from .policy import Strict
from .gateway import (
    ModelRequest,
    generate_budgeted,
    RunInterrupted,
    CapacityWait,
    StructuredOutputError,
)
from .workflow import selected_model_binding

app = FastAPI(docs_url=None, openapi_url=None)


class Generate(Strict):
    run_id: str
    alias: str
    request: ModelRequest
    task_id: str | None = None
    lease_token: str | None = None
    model_record_id: str | None = None


class IntegrationRead(Strict):
    run_id: str
    capability: str
    input: dict
    task_id: str | None = None
    lease_token: str | None = None


@app.post("/integration-read")
def integration_read(body: IntegrationRead, request: Request):
    from .db import SwarmTask
    from .swarm import active, check_fence
    from .tool_registry import IntelligenceLookup, MCPRead, MCPToolLookup, execute

    service = service_role(request)
    schemas = {
        "external_intelligence_lookup": IntelligenceLookup,
        "mcp_read_resource": MCPRead,
        "mcp_intelligence_lookup": MCPToolLookup,
    }
    if body.capability not in schemas:
        raise HTTPException(403)
    with session() as db:
        run = db.get(Document, body.run_id)
        if not run or run.kind != "run":
            raise HTTPException(403)
        try:
            active(db, run)
            if run.value().get("execution_mode") == "swarm":
                task = db.get(SwarmTask, body.task_id) if body.task_id else None
                if not task or task.worker_kind != service or not body.lease_token:
                    raise HTTPException(403)
                run._swarm_claim = (task.id, body.lease_token)
                check_fence(db, run)
            if run.value().get("tool_calls", 0) > run.value().get("max_tool_calls", 50):
                raise HTTPException(403)
            return execute(
                db,
                run,
                body.capability,
                schemas[body.capability].model_validate(body.input),
            )
        except Exception:
            raise HTTPException(403, "Integration read denied or failed") from None


def service_role(request):
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    if not token:
        raise HTTPException(401)
    for role, path in [
        ("research", settings().research_token_file),
        ("verify", settings().verify_token_file),
    ]:
        if path and hmac.compare_digest(token, Path(path).read_text().strip()):
            return role
    raise HTTPException(401)


@app.get("/health/live")
def health():
    return {"status": "alive"}


@app.post("/generate")
def generate(body: Generate, request: Request):
    role = service_role(request)
    if (body.alias == "verifier") != (role == "verify"):
        raise HTTPException(403)
    with session() as db:
        run = db.get(Document, body.run_id)
        if (
            not run
            or run.kind != "run"
            or run.value()["status"] not in ("queued", "running")
        ):
            raise HTTPException(403)
        kill = db.get(Document, "kill-switch")
        if kill and kill.value()["enabled"]:
            raise HTTPException(403)
        p, m = selected_model_binding(db, run, body.alias, body.model_record_id)
        if body.task_id or body.lease_token:
            from .swarm import check_fence

            if not body.task_id or not body.lease_token:
                raise HTTPException(403)
            run._swarm_claim = (body.task_id, body.lease_token)
            check_fence(db, run)
        if (
            body.request.model != m.value()["model_id"]
            or body.request.max_tokens > m.value()["max_output_tokens"]
        ):
            raise HTTPException(403)
        try:
            return generate_budgeted(
                db, p, m, body.request, run, body.alias
            ).model_dump()
        except RunInterrupted:
            db.commit()
            raise HTTPException(409, detail={"code": "run_interrupted"}) from None
        except CapacityWait:
            db.rollback()
            raise HTTPException(409, detail={"code": "capacity_wait"}) from None
        except StructuredOutputError as exc:
            # The completed response is already charged. The worker may make
            # one separately budgeted schema correction; never replay timeouts.
            return exc.response.model_dump()
        except Exception:
            db.commit()
            raise HTTPException(409, "Provider request blocked or failed") from None
