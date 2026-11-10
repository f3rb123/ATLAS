"""Target-only egress service; independent research/verifier service identities."""

import hmac
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from .config import settings
from .policy import Denied, request
from .target_transport import TargetRequest, execute as execute_transport

app = FastAPI(docs_url=None, openapi_url=None)


def service_identity(req):
    token=req.headers.get('authorization','').removeprefix('Bearer ')
    for name,filename in [('research',settings().research_token_file),('verify',settings().verify_token_file)]:
        if filename and token and hmac.compare_digest(token,Path(filename).read_text().strip()):return name
    raise HTTPException(401)


from .network_research import NetworkRequest


@app.post('/network')
def network(body: NetworkRequest, req: Request):
    service=service_identity(req)
    try:
        if body.task_id:
            from .db import session,SwarmTask
            with session() as db:
                task=db.get(SwarmTask,body.task_id)
                if not task or task.worker_kind!=service:raise Denied('Worker identity mismatch')
        from .network_research import execute
        return execute(body,service+'_service')
    except (Denied,ValueError):raise HTTPException(403,'Network discovery denied by policy') from None


@app.get("/health/live")
def health():
    return {"status": "alive"}


def execute(body, actor):
    return execute_transport(body, actor, transport=request)


@app.post("/request")
def relay(body: TargetRequest, req: Request):
    token = req.headers.get("authorization", "").removeprefix("Bearer ")
    service = None
    for name, filename in [
        ("research", settings().research_token_file),
        ("verify", settings().verify_token_file),
    ]:
        if (
            filename
            and token
            and hmac.compare_digest(token, Path(filename).read_text().strip())
        ):
            service = name
            break
    if service is None:
        raise HTTPException(401)
    try:
        if body.task_id:
            from .db import session, SwarmTask

            with session() as db:
                task = db.get(SwarmTask, body.task_id)
                if not task or task.worker_kind != service:
                    raise Denied("Service cannot execute another worker's task")
        return execute(body, service + "_service")
    except (Denied, ValueError):
        raise HTTPException(403, "Target request denied by policy") from None
