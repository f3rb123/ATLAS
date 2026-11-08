"""Internal model gateway: distinct credentials for research and verifier services."""

import hmac
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from .config import settings
from .db import session, Document
from .policy import Strict
from .gateway import ModelRequest, generate_budgeted
from .workflow import model_binding

app = FastAPI(docs_url=None, openapi_url=None)


class Generate(Strict):
    run_id: str
    alias: str
    request: ModelRequest


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
        p, m = model_binding(db, run, body.alias)
        if (
            body.request.model != m.value()["model_id"]
            or body.request.max_tokens > m.value()["max_output_tokens"]
        ):
            raise HTTPException(403)
        try:
            return generate_budgeted(
                db, p, m, body.request, run, body.alias
            ).model_dump()
        except Exception:
            db.commit()
            raise HTTPException(409, "Provider request blocked or failed") from None
