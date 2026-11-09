"""Authenticated versioned HTTP API shared by the Web UI and CLI."""

import asyncio, json, secrets, time, io, zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Request, Response, HTTPException, Depends, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.exceptions import RequestValidationError
from pydantic import Field
from sqlalchemy import text
from .config import settings
from .source_policy import SourcePolicy
from .research import ThreatModel
from .db import (
    session,
    engine,
    User,
    Session,
    Document,
    Journal,
    Knowledge,
    Chunk,
    Alias,
    document,
    append,
    canonical,
    digest,
    uid,
    now,
)
from . import auth
from .policy import Strict, Scope, Denied
from .gateway import (
    ProviderInput,
    ModelInput,
    create_provider,
    safe_metadata,
    Adapter,
    ADAPTERS,
    ProviderError,
    ModelRequest,
    snapshot_provider,
    snapshot_model,
    construct_adapter,
    secret_identity,
)
from .workflow import control
from .vault import master, seal


@asynccontextmanager
async def lifespan(app):
    from .logging import configure

    configure()
    app.state.request_gate = asyncio.Semaphore(settings().max_concurrent_http)
    if settings().production and not settings().external_url.startswith("https://"):
        raise RuntimeError("Production requires an HTTPS external origin")
    master()
    with engine().connect() as c:
        c.execute(text("SELECT 1"))
    yield


app = FastAPI(
    title="ATLAS",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


from .http_limits import BodyLimitMiddleware

app.add_middleware(BodyLimitMiddleware)


def cookie_name():
    return auth.COOKIE if settings().production else "atlas_dev"


def db_dep():
    with session() as db:
        try:
            yield db
        finally:
            db.close()


def identity(request: Request, db=Depends(db_dep)):
    bearer = request.headers.get("authorization", "")
    token = (
        bearer[7:]
        if bearer.startswith("Bearer ")
        else request.cookies.get(cookie_name(), "")
    )
    if not token:
        raise HTTPException(401, "Authentication required")
    try:
        u, s = auth.identify(db, token)
    except ValueError:
        raise HTTPException(401, "Authentication required")
    if bearer:
        if s.scopes == "browser":
            raise HTTPException(401, "Use a dedicated CLI token")
        collection = request.url.path.split("/")[3]
        needed = (
            "read"
            if request.method == "GET"
            else {
                "campaigns": "campaign",
                "runs": "run",
                "providers": "provider",
                "skills": "skill",
                "budgets": "budget",
                "model-configs": "model-config",
                "corpus": "corpus",
                "registries": "knowledge",
                "knowledge": "knowledge",
                "knowledge-feedback": "knowledge",
                "findings": "finding",
                "reports": "report",
                "repositories": "repo",
                "benchmarks": "benchmark",
            }.get(collection, collection)
        )
        if needed not in json.loads(s.scopes):
            raise HTTPException(403, "Token scope denied")
    elif request.method not in ("GET", "HEAD"):
        if request.headers.get("origin") != settings().external_url:
            raise HTTPException(403, "Origin denied")
        if digest(request.headers.get("x-csrf-token", "")) != s.csrf_hash:
            raise HTTPException(403, "CSRF validation failed")
    if u.role == "read_only" and request.method not in ("GET", "HEAD"):
        raise HTTPException(403, "Read-only identity")
    if request.method not in ("GET", "HEAD"):
        auth.throttle(db, "mutation:" + u.id, 120, 60)
    db.commit()
    return u, s


def enrolled(request: Request, who=Depends(identity), db=Depends(db_dep)):
    u, s = who
    passkey = db.query(Document).filter_by(kind="passkey", owner=u.id).first()
    if not settings().require_mfa and not u.mfa and not passkey:
        return who
    if not s.mfa:
        raise HTTPException(403, "Complete MFA authentication/enrollment")
    if settings().require_mfa and not passkey:
        raise HTTPException(403, "Passkey enrollment required")
    if settings().require_mfa and settings().production and not settings().passkey_only_recovery:
        if (
            not u.totp
            or not db.query(Document).filter_by(kind="recovery", owner=u.id).first()
        ):
            raise HTTPException(
                403, "Complete TOTP fallback and recovery code setup in Security"
            )
    return who


def admin(who=Depends(enrolled)):
    if who[0].role != "owner_admin":
        raise HTTPException(403, "Owner administrator required")
    return who


def stepup(who=Depends(admin)):
    if (settings().require_mfa or who[1].mfa) and who[1].stepup < time.time() - 300:
        raise HTTPException(403, "Recent WebAuthn step-up required")
    return who


def security_stepup(who=Depends(identity), db=Depends(db_dep)):
    u, s = who
    if (
        u.role != "owner_admin"
        or not s.mfa
        or s.stepup < time.time() - 300
        or not db.query(Document).filter_by(kind="passkey", owner=u.id).first()
    ):
        raise HTTPException(403, "Recent owner WebAuthn step-up required")
    return who


def own(db, id, kind, owner, lock=False):
    q = db.query(Document).filter_by(id=id, kind=kind, owner=owner)
    d = q.with_for_update().first() if lock else q.first()
    if not d:
        raise HTTPException(404, "Resource not found")
    return d


def expose(d):
    return {"id": d.id, "version": d.version, **d.value()}


def audit(db, owner, action, data):
    append(db, owner, owner, action, data)


def set_session(response, s, token, csrf):
    response.set_cookie(
        cookie_name(),
        token,
        secure=settings().production,
        httponly=True,
        samesite="strict",
        path="/",
        max_age=int(s.expires - time.time()),
    )
    return {"csrf_token": csrf, "mfa": bool(s.mfa)}


@app.middleware("http")
async def security(request, call_next):
    correlation = uid()
    started = time.monotonic()
    if len(request.headers.get("content-length", "0")) > 12:
        return JSONResponse({"error": "Request too large"}, 413)
    try:
        if int(request.headers.get("content-length", "0")) > 21 * 1024 * 1024:
            return JSONResponse({"error": "Request too large"}, 413)
    except ValueError:
        return JSONResponse({"error": "Invalid request length"}, 400)
    if (
        settings().production
        and request.headers.get("host")
        != __import__("urllib.parse", fromlist=["urlsplit"])
        .urlsplit(settings().external_url)
        .netloc
    ):
        return JSONResponse({"error": "Unknown host"}, 400)
    gate = getattr(app.state, "request_gate", None)
    if gate is None:
        response = await call_next(request)
    else:
        async with gate:
            response = await call_next(request)
    for k, v in {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "X-Correlation-ID": correlation,
    }.items():
        response.headers[k] = v
    if settings().production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    import logging

    route = request.scope.get("route")
    route_name = getattr(route, "path", "[unmatched]")
    logging.getLogger("atlas").info(
        "http_request",
        extra={
            "correlation_id": correlation,
            "route": route_name,
            "method": request.method,
            "status": response.status_code,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        },
    )
    return response


@app.exception_handler(RequestValidationError)
async def invalid_request(request, exc):
    return JSONResponse(
        {
            "error": {
                "code": "invalid_request",
                "details": [
                    {"location": e["loc"], "message": e["msg"], "type": e["type"]}
                    for e in exc.errors()
                ],
            }
        },
        422,
    )


@app.exception_handler(ValueError)
async def invalid(request, exc):
    return JSONResponse(
        {"error": {"code": "validation_failed", "message": str(exc)[:300]}}, 400
    )


@app.exception_handler(Denied)
async def denied(request, exc):
    return JSONResponse(
        {"error": {"code": "policy_denied", "message": str(exc)[:300]}}, 403
    )


@app.exception_handler(ProviderError)
async def provider_error(request, exc):
    return JSONResponse(
        {"error": {"code": "provider_error", "message": str(exc)[:200]}}, 409
    )


@app.get("/health/live")
def live():
    return {"status": "alive"}


@app.get("/health/ready")
def ready(db=Depends(db_dep)):
    try:
        master()
        db.execute(text("SELECT 1"))
        if settings().production:
            u = db.query(User).filter_by(role="owner_admin").first()
            if not u:
                raise HTTPException(503, "Owner setup required")
            if (
                settings().require_mfa and (
                not db.query(Document).filter_by(kind="passkey", owner=u.id).first()
                or (
                    not settings().passkey_only_recovery
                    and (
                        not u.totp
                        or not db.query(Document)
                        .filter_by(kind="recovery", owner=u.id)
                        .first()
                    )
                ))
            ):
                raise HTTPException(503, "Owner security enrollment required")
        return {"status": "ready"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Dependency unavailable")


@app.get("/api/v1/schema")
def schema(who=Depends(enrolled)):
    return app.openapi()


class Bootstrap(Strict):
    token: str = Field(repr=False, max_length=200)
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(repr=False, max_length=1024)


class Login(Strict):
    email: str = Field(max_length=254)
    password: str = Field(repr=False, max_length=1024)


class Code(Strict):
    code: str = Field(repr=False)


class Credential(Strict):
    credential: dict


@app.post("/api/v1/auth/bootstrap")
def bootstrap(
    body: Bootstrap, response: Response, request: Request, db=Depends(db_dep)
):
    auth.throttle(db, "bootstrap:" + str(request.client.host), 5)
    u = auth.bootstrap(db, body.token, body.email, body.password)
    document(
        db,
        "bootstrap_complete",
        "system",
        {"completed": now()},
        "owner-bootstrap-complete",
    )
    s, t, c = auth.issue(db, u)
    db.commit()
    return set_session(response, s, t, c)


@app.post("/api/v1/auth/login")
def login(body: Login, response: Response, request: Request, db=Depends(db_dep)):
    auth.throttle(db, "login-ip:" + str(request.client.host), 30)
    auth.throttle(db, "login-account:" + body.email.lower(), 8)
    s, t, c = auth.login(db, body.email, body.password)
    db.commit()
    return set_session(response, s, t, c)


@app.get("/api/v1/users/me")
def me(who=Depends(identity), db=Depends(db_dep)):
    u, s = who
    csrf = secrets.token_urlsafe(32)
    s = db.get(Session, s.id)
    s.csrf_hash = digest(csrf)
    db.commit()
    passkeys = db.query(Document).filter_by(kind="passkey", owner=u.id).count()
    required = settings().require_mfa or bool(u.mfa) or bool(passkeys)
    return {
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "mfa": bool(s.mfa),
        "mfa_required": required,
        "operator_access": not required or bool(s.mfa),
        "stepup_recent": s.stepup > time.time() - 300,
        "passkey_count": db.query(Document)
        .filter_by(kind="passkey", owner=u.id)
        .count(),
        "totp_enrolled": bool(u.totp),
        "csrf_token": csrf,
    }


@app.post("/api/v1/auth/logout")
def logout(response: Response, who=Depends(identity), db=Depends(db_dep)):
    db.delete(db.get(Session, who[1].id))
    db.commit()
    response.delete_cookie(cookie_name(), path="/")
    return {"status": "logged_out"}


class PasswordChange(Strict):
    current_password: str = Field(min_length=1, max_length=1024, repr=False)
    new_password: str = Field(min_length=15, max_length=1024, repr=False)


@app.post("/api/v1/auth/password")
def password_change(body: PasswordChange, response: Response, who=Depends(enrolled), db=Depends(db_dep)):
    auth.throttle(db, "password-change:" + who[0].id, 8)
    result = auth.change_password(db, db.get(User, who[0].id), body.current_password,
                                  body.new_password, mfa=bool(who[1].mfa))
    db.commit()
    return set_session(response, *result)


@app.post("/api/v1/auth/webauthn/{kind}/options")
def options(kind: str, who=Depends(identity), db=Depends(db_dep)):
    if kind not in ("registration", "authentication"):
        raise HTTPException(404)
    u, s = who
    auth.throttle(db, "passkey:" + s.id, 20)
    result = auth.challenge(db, db.get(User, u.id), db.get(Session, s.id), kind)
    db.commit()
    return result


@app.post("/api/v1/auth/webauthn/{kind}/verify")
def verify(
    kind: str,
    body: Credential,
    response: Response,
    who=Depends(identity),
    db=Depends(db_dep),
):
    if kind not in ("registration", "authentication"):
        raise HTTPException(404)
    u, s = who
    u = db.get(User, u.id)
    s = db.get(Session, s.id)
    try:
        auth.verify_passkey(db, u, s, body.credential, kind)
    except Exception:
        db.commit()
        raise HTTPException(400, "Passkey verification failed") from None
    if kind == "authentication":
        old = s
        s, t, c = auth.issue(db, u, True)
        s.stepup = time.time()
        db.delete(old)
        db.commit()
        return set_session(response, s, t, c)
    previous_mfa = bool(s.mfa)
    db.query(Session).filter_by(user_id=u.id).delete()
    s, t, c = auth.issue(db, u, previous_mfa)
    db.commit()
    return {
        **set_session(response, s, t, c),
        "status": "enrolled",
        "next": "Authenticate with passkey to complete MFA",
    }


@app.post("/api/v1/auth/totp/setup")
def totp_setup(who=Depends(identity), db=Depends(db_dep)):
    auth.throttle(db, "totp-setup:" + who[0].id, 5)
    result = auth.totp_setup(db, db.get(User, who[0].id), db.get(Session, who[1].id))
    db.commit()
    return {"provisioning_uri": result}


@app.post("/api/v1/auth/totp/{action}")
def totp_verify(
    action: str,
    body: Code,
    response: Response,
    who=Depends(identity),
    db=Depends(db_dep),
):
    if action not in ("enroll", "verify"):
        raise HTTPException(404)
    u = db.get(User, who[0].id)
    s = db.get(Session, who[1].id)
    auth.throttle(db, "totp:" + u.id, 5)
    auth.totp_verify(db, u, s, body.code, enroll=action == "enroll")
    if action == "verify":
        old = s
        s, t, c = auth.issue(db, u, True)
        db.delete(old)
        db.commit()
        return set_session(response, s, t, c)
    previous_mfa = bool(s.mfa)
    db.query(Session).filter_by(user_id=u.id).delete()
    s, t, c = auth.issue(db, u, previous_mfa)
    db.commit()
    return {**set_session(response, s, t, c), "status": "totp_enrolled"}


@app.post("/api/v1/auth/recovery-codes/regenerate")
def codes(who=Depends(security_stepup), db=Depends(db_dep)):
    auth.throttle(db, "recovery-regenerate:" + who[0].id, 3)
    result = auth.recovery_codes(db, db.get(User, who[0].id))
    db.commit()
    return {"codes": result, "notice": "Store securely; displayed only once"}


@app.post("/api/v1/auth/recovery/consume")
def recover(body: Code, response: Response, who=Depends(identity), db=Depends(db_dep)):
    u = db.get(User, who[0].id)
    s = db.get(Session, who[1].id)
    auth.throttle(db, "recovery:" + u.id, 5)
    auth.recovery_consume(db, u, s, body.code)
    old = s
    s, t, c = auth.issue(db, u, True)
    db.delete(old)
    db.commit()
    return set_session(response, s, t, c)


@app.get("/api/v1/auth/sessions")
def sessions(who=Depends(enrolled), db=Depends(db_dep)):
    return [
        {
            "id": s.id,
            "created": s.created,
            "last_used": s.used,
            "expires": s.expires,
            "scopes": s.scopes,
            "current": s.id == who[1].id,
        }
        for s in db.query(Session).filter_by(user_id=who[0].id)
    ]


@app.delete("/api/v1/auth/sessions/{id}")
def revoke_session(id: str, who=Depends(stepup), db=Depends(db_dep)):
    s = db.get(Session, id)
    if not s or s.user_id != who[0].id:
        raise HTTPException(404)
    db.delete(s)
    audit(db, who[0].id, "session_revoked", {"id": id})
    db.commit()
    return {"status": "revoked"}


class TokenInput(Strict):
    scopes: list[
        Literal[
            "read",
            "campaign",
            "run",
            "knowledge",
            "provider",
            "corpus",
            "skill",
            "budget",
            "model-config",
            "benchmark",
            "finding",
            "repo",
            "report",
        ]
    ] = ["read"]
    expires_hours: int = Field(default=24, ge=1, le=168)


@app.post("/api/v1/auth/cli-tokens")
def cli_token(body: TokenInput, who=Depends(stepup), db=Depends(db_dep)):
    auth.throttle(db, "token-create:" + who[0].id, 5)
    sensitive = bool(
        set(body.scopes)
        & {
            "provider",
            "corpus",
            "skill",
            "budget",
            "model-config",
            "benchmark",
            "report",
        }
    )
    s, t, c = auth.issue(
        db,
        who[0],
        True,
        canonical(body.scopes),
        300 if sensitive else body.expires_hours * 3600,
    )
    if sensitive:
        s.stepup = who[1].stepup
    audit(db, who[0].id, "cli_token_created", {"id": s.id, "scopes": body.scopes})
    db.commit()
    return {"id": s.id, "token": t, "expires": s.expires}


class CampaignInput(Strict):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    mode: Literal["knowledge", "repository", "passive", "safe-active", "lab"] = (
        "repository"
    )
    authorization_ref: str = Field(min_length=1, max_length=2000)
    authorization_attested: bool
    scope: Scope = Field(default_factory=Scope)
    policy_notes: str = ""
    budget_limit: float = Field(default=10, gt=0, le=1000)


@app.post("/api/v1/campaigns")
def campaign_create(body: CampaignInput, who=Depends(enrolled), db=Depends(db_dep)):
    if not body.authorization_attested:
        raise Denied("Explicit authorization attestation required")
    if (
        body.scope.allow
        or body.scope.lab_networks
        or body.mode in ("passive", "safe-active")
    ) and who[1].stepup < time.time() - 300:
        raise Denied("Recent WebAuthn step-up required for target scope authorization")
    v = body.model_dump()
    scope = v.pop("scope")
    c = document(db, "campaign", who[0].id, v)
    p = document(
        db,
        "policy",
        who[0].id,
        {
            "campaign_id": c.id,
            "scope": scope,
            "hash": digest(canonical(scope)),
            "approved_by": who[0].id,
        },
    )
    v["policy_id"] = p.id
    c.data = canonical(v)
    audit(
        db,
        who[0].id,
        "campaign_created",
        {"id": c.id, "policy_hash": p.value()["hash"]},
    )
    db.commit()
    return expose(c)


@app.post("/api/v1/campaigns/{id}/scope/validate")
def scope_validate(id: str, body: Scope, who=Depends(enrolled), db=Depends(db_dep)):
    own(db, id, "campaign", who[0].id)
    from .policy import host

    for rule in body.allow + body.deny:
        if "/" in rule.host:
            __import__("ipaddress").ip_network(rule.host, strict=False)
        else:
            host(rule.host.removeprefix("*."))
    return {
        "normalized": body.model_dump(),
        "hash": digest(canonical(body.model_dump())),
    }


@app.post("/api/v1/campaigns/{id}/scope/versions")
def scope_version(id: str, body: Scope, who=Depends(stepup), db=Depends(db_dep)):
    c = own(db, id, "campaign", who[0].id, True)
    p = document(
        db,
        "policy",
        who[0].id,
        {
            "campaign_id": id,
            "scope": body.model_dump(),
            "hash": digest(canonical(body.model_dump())),
            "approved_by": who[0].id,
        },
    )
    v = c.value()
    v["policy_id"] = p.id
    c.data = canonical(v)
    c.version += 1
    audit(
        db, who[0].id, "scope_version_created", {"campaign_id": id, "policy_id": p.id}
    )
    db.commit()
    return expose(p)


@app.post("/api/v1/campaigns/{id}/repositories")
async def repository_upload(
    id: str, file: UploadFile = File(...), who=Depends(enrolled), db=Depends(db_dep)
):
    own(db, id, "campaign", who[0].id)
    from .tools import upload_snapshot, Repository

    data = await file.read(20 * 1024 * 1024 + 1)
    root = upload_snapshot(data)
    inventory = Repository(root).inventory()
    d = document(
        db,
        "repository",
        who[0].id,
        {
            "campaign_id": id,
            "path": str(root),
            "inventory": inventory,
            "origin": "owner_upload",
            "snapshot_hash": inventory["snapshot_hash"],
        },
    )
    db.commit()
    return {"id": d.id, "inventory": inventory}


class RunInput(Strict):
    execution_mode: Literal["swarm", "legacy"] = "swarm"
    agent_count: int = Field(default=8, ge=1, le=16)
    instructions: str = Field(default="", max_length=4000)
    model_mode: Literal["single", "capability"] = "single"
    repository_id: str | None = None
    budget_limit: float = Field(default=1, gt=0, le=100)
    max_seconds: int = Field(default=1800, ge=30, le=86400)
    max_tool_calls: int = Field(default=50, ge=1, le=500)
    offline_execution_approved: bool = False
    knowledge_ids: list[str] = []
    max_model_calls: int = Field(default=20, ge=1, le=100)
    role_budgets: dict[str, float] = {}
    specialist_roles: list[Literal["coding", "fast"]] = Field(default=[], max_length=2)


@app.post("/api/v1/campaigns/{id}/runs")
def run_start(
    id: str, body: RunInput, request: Request, who=Depends(enrolled), db=Depends(db_dep)
):
    c = own(db, id, "campaign", who[0].id)
    from .skills import install_references

    install_references(db, who[0].id)
    if c.value().get("status") == "archived":
        raise Denied("Campaign is archived")
    p = own(db, c.value()["policy_id"], "policy", who[0].id)
    kill = db.get(Document, "kill-switch")
    if kill and kill.value()["enabled"]:
        raise Denied("Emergency stop active")
    if body.repository_id:
        repo = own(db, body.repository_id, "repository", who[0].id)
        if repo.value()["campaign_id"] != id:
            raise Denied("Repository belongs to another campaign")
    key = request.headers.get("idempotency-key")
    if key:
        key = digest(who[0].id + ":run:" + id + ":" + key)[:36]
        old = db.get(Document, key)
        if old:
            return expose(old)
    from .queueing import admit

    admit(db, who[0].id, id)
    if any(
        not __import__("math").isfinite(value)
        or value <= 0
        or value > body.budget_limit
        for value in body.role_budgets.values()
    ):
        raise Denied("Role budgets must be positive and within the run cap")
    models = {}
    for d in db.query(Document).filter_by(kind="alias", owner=who[0].id):
        a = d.value()
        provider = own(db, a["provider_id"], "provider", who[0].id)
        model = own(db, a["model_id"], "provider_model", who[0].id)
        models[a["alias"]] = {
            **a,
            "provider_version": provider.version,
            "model_version": model.version,
        }
    if body.model_mode == "single" and "reasoning" in models:
        for alias in ("coding", "fast", "verifier"):
            models[alias] = {**models["reasoning"], "alias": alias}
    if any(alias not in models for alias in body.specialist_roles):
        raise Denied(
            "Configure and test every authorized specialist alias before starting"
        )
    v = {
        **body.model_dump(),
        "campaign_id": id,
        "policy_id": p.id,
        "policy_hash": p.value()["hash"],
        "state": "SWARM_RUNNING" if body.execution_mode == "swarm" else "CREATED",
        "status": "queued",
        "budget_used": 0,
        "models": models,
        "deadline": time.time() + body.max_seconds,
        "started_at": now(),
        "workflow_version": "2.0-swarm" if body.execution_mode == "swarm" else "1.0",
    }
    pinned_skills = [
        d
        for d in db.query(Document).filter_by(kind="skill", owner=who[0].id)
        if d.value().get("enabled") and d.value().get("status") == "validated"
    ][:3]
    v["skills"] = [
        {
            "id": d.id,
            "skill_id": d.value()["skill_id"],
            "version": d.value()["version"],
            "hash": d.value()["content_hash"],
        }
        for d in pinned_skills
    ]
    d = document(db, "run", who[0].id, v, key if key else None)
    if body.execution_mode == "swarm":
        from .swarm import initialize

        initialize(db, d)
    for skill in v["skills"]:
        append(
            db,
            d.id,
            who[0].id,
            "skill_loaded",
            {
                **skill,
                "reason": "Validated enabled source-review procedure; subordinate to campaign policy",
            },
            id,
        )
    append(db, d.id, who[0].id, "run_created", {"policy_hash": p.value()["hash"]}, id)
    db.commit()
    return expose(d)


@app.post("/api/v1/runs/{id}/control/{action}")
def run_control(id: str, action: str, who=Depends(enrolled), db=Depends(db_dep)):
    run = own(db, id, "run", who[0].id, True)
    if action not in ("pause", "resume", "cancel", "approve", "reject"):
        raise HTTPException(404)
    if action in ("approve", "reject"):
        v = run.value()
        v["offline_execution_approved"] = action == "approve"
        run.data = canonical(v)
        append(
            db,
            id,
            who[0].id,
            "execution_approval",
            {"decision": action},
            v["campaign_id"],
        )
        if action == "approve":
            control(db, run, "resume", who[0].id)
    else:
        control(db, run, action, who[0].id)
    db.commit()
    return expose(run)


@app.get("/api/v1/runs/{id}/events")
async def events(
    id: str, request: Request, after: int = 0, who=Depends(enrolled), db=Depends(db_dep)
):
    own(db, id, "run", who[0].id)
    try:
        after = max(after, int(request.headers.get("last-event-id", "0")))
    except ValueError:
        raise HTTPException(400, "Invalid event cursor")

    async def stream():
        cursor = after
        for _ in range(120):
            if await request.is_disconnected():
                return
            with session() as s:
                rows = (
                    s.query(Journal)
                    .filter(Journal.stream == id, Journal.sequence > cursor)
                    .order_by(Journal.sequence)
                    .limit(100)
                    .all()
                )
                for e in rows:
                    cursor = e.sequence
                    yield f"id: {e.sequence}\ndata: {e.payload}\n\n"
            yield ": heartbeat\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/v1/providers/adapters")
def adapters(who=Depends(enrolled)):
    return {"adapters": ADAPTERS, "adapter_version": "1.0"}


@app.post("/api/v1/providers")
def provider_add(body: ProviderInput, who=Depends(stepup), db=Depends(db_dep)):
    d = create_provider(db, who[0].id, body)
    snapshot_provider(db, d)
    db.commit()
    return safe_metadata(d)


@app.post("/api/v1/providers/{id}/models")
def model_add(id: str, body: ModelInput, who=Depends(stepup), db=Depends(db_dep)):
    own(db, id, "provider", who[0].id)
    d = document(
        db,
        "provider_model",
        who[0].id,
        {
            "provider_id": id,
            **body.model_dump(),
            "verified_structured": False,
            "capability_status": "user_declared_unverified",
        },
    )
    snapshot_model(db, d)
    db.commit()
    return expose(d)


@app.get("/api/v1/providers/{id}/models")
def models(id: str, who=Depends(enrolled), db=Depends(db_dep)):
    own(db, id, "provider", who[0].id)
    return [
        expose(d)
        for d in db.query(Document).filter_by(kind="provider_model", owner=who[0].id)
        if d.value()["provider_id"] == id
    ]


class TestInput(Strict):
    model_id: str | None = None


@app.post("/api/v1/providers/{id}/test")
def provider_test(id: str, body: TestInput, who=Depends(stepup), db=Depends(db_dep)):
    d = own(db, id, "provider", who[0].id)
    auth.throttle(db, "provider-test:" + who[0].id, 5)
    if body.model_id:
        m = own(db, body.model_id, "provider_model", who[0].id)
        if m.value()["provider_id"] != id:
            raise Denied("Model/provider mismatch")
        req = ModelRequest(
            model=m.value()["model_id"],
            messages=[{"role": "user", "content": 'Return only {"ok":true} as JSON.'}],
            max_tokens=32,
        )
        from .gateway import reserve, settle

        mv = m.value()
        estimate = (128 * mv["input_price"] + 32 * mv["output_price"]) / 1000000
        reservation = reserve(db, who[0].id, "provider_test", estimate)
        result = construct_adapter(d).generate(req)
        settle(
            db,
            reservation,
            max(
                estimate,
                (
                    result.input_tokens * mv["input_price"]
                    + result.output_tokens * mv["output_price"]
                )
                / 1000000,
            ),
        )
        if result.structured_content != {"ok": True}:
            raise ProviderError("Structured capability probe failed")
        v = m.value()
        v["verified_structured"] = True
        v["capability_status"] = "structured_output_verified"
        m.data = canonical(v)
        result = {"status": "structured_output_verified"}
    else:
        result = construct_adapter(d).health_check()
    v = d.value()
    v["health_status"] = "tested"
    v["last_tested"] = now()
    d.data = canonical(v)
    audit(db, who[0].id, "provider_test", {"id": id, "status": "success"})
    db.commit()
    return result


@app.post("/api/v1/providers/{id}/models/discover")
def discover(id: str, who=Depends(stepup), db=Depends(db_dep)):
    d = own(db, id, "provider", who[0].id)
    auth.throttle(db, "provider-discover:" + who[0].id, 5)
    return construct_adapter(d).list_models()


class KeyInput(Strict):
    api_key: str = Field(min_length=1, max_length=8192, repr=False)


def active_provider(db, owner, id):
    return any(
        v["provider_id"] == id
        for r in db.query(Document).filter_by(kind="run", owner=owner)
        if r.value()["status"] not in ("completed", "cancelled")
        for v in r.value().get("models", {}).values()
    )


@app.post("/api/v1/providers/{id}/secret")
def rotate(id: str, body: KeyInput, who=Depends(stepup), db=Depends(db_dep)):
    d = own(db, id, "provider", who[0].id, True)
    if active_provider(db, who[0].id, id):
        raise HTTPException(409, "Provider pinned by active run")
    snapshot_provider(db, d)
    v = d.value()
    v["secret"] = seal(body.api_key, secret_identity(d.owner, d.id, v))
    v["fingerprint"] = digest(body.api_key)[:12]
    v["health_status"] = "untested"
    d.data = canonical(v)
    d.version += 1
    snapshot_provider(db, d)
    audit(
        db,
        who[0].id,
        "provider_key_rotated",
        {"id": id, "fingerprint": v["fingerprint"]},
    )
    db.commit()
    return safe_metadata(d)


@app.patch("/api/v1/providers/{id}")
def provider_edit(
    id: str, body: ProviderInput, who=Depends(stepup), db=Depends(db_dep)
):
    old = own(db, id, "provider", who[0].id, True)
    if active_provider(db, who[0].id, id):
        raise HTTPException(409, "Provider pinned by active run")
    # New immutable connection version preserves historical metadata.
    snapshot_provider(db, old)
    d = create_provider(db, who[0].id, body)
    snapshot_provider(db, d)
    v = old.value()
    v["enabled"] = False
    old.data = canonical(v)
    old.version += 1
    db.commit()
    return safe_metadata(d)


@app.delete("/api/v1/providers/{id}")
def provider_delete(id: str, who=Depends(stepup), db=Depends(db_dep)):
    d = own(db, id, "provider", who[0].id, True)
    if active_provider(db, who[0].id, id):
        raise HTTPException(409, "Provider pinned by active run")
    snapshot_provider(db, d)
    v = d.value()
    v["enabled"] = False
    v["deleted"] = True
    v["secret"] = None
    v["secret_headers"] = seal("{}", secret_identity(d.owner, d.id, v, "headers"))
    d.data = canonical(v)
    d.version += 1
    snapshot_provider(db, d)
    audit(db, who[0].id, "provider_deleted", {"id": id})
    db.commit()
    return {"status": "deleted", "historical_metadata_retained": True}


class AliasInput(Strict):
    alias: Literal["fast", "reasoning", "verifier", "embedding", "vision", "coding"]
    provider_id: str
    model_id: str


@app.put("/api/v1/model-configs")
def alias_set(body: AliasInput, who=Depends(stepup), db=Depends(db_dep)):
    own(db, body.provider_id, "provider", who[0].id)
    m = own(db, body.model_id, "provider_model", who[0].id)
    if m.value()["provider_id"] != body.provider_id:
        raise Denied("Model/provider mismatch")
    for d in db.query(Document).filter_by(kind="alias", owner=who[0].id):
        if d.value()["alias"] == body.alias:
            db.delete(d)
    d = document(db, "alias", who[0].id, body.model_dump())
    db.commit()
    return expose(d)


@app.get("/api/v1/corpus/stats")
def corpus_stats(who=Depends(enrolled), db=Depends(db_dep)):
    from .corpus import stats

    return stats(db, who[0].id)


@app.get("/api/v1/corpus/sources")
def corpus_sources(who=Depends(enrolled)):
    from .corpus import SOURCES

    return SOURCES


class SearchFilters(Strict):
    package: str | None = Field(default=None, max_length=200)
    ecosystem: str | None = Field(default=None, max_length=80)
    record_type: str | None = Field(default=None, max_length=80)
    language: str | None = Field(default=None, max_length=80)
    trust_boundary: str | None = Field(default=None, max_length=200)
    cwe: str | None = Field(default=None, max_length=40)
    cve: str | None = Field(default=None, max_length=40)
    ghsa: str | None = Field(default=None, max_length=40)


class Search(Strict):
    query: str = Field(min_length=1, max_length=500)
    source: str | None = None
    limit: int = Field(default=5, ge=1, le=20)
    filters: SearchFilters = Field(default_factory=SearchFilters)


@app.post("/api/v1/knowledge/search")
def knowledge_search(body: Search, who=Depends(enrolled), db=Depends(db_dep)):
    from .corpus import search

    return search(
        db,
        body.query,
        body.source,
        body.limit,
        who[0].id,
        body.filters.model_dump(exclude_none=True),
    )


@app.post("/api/v1/knowledge/ingest")
async def knowledge_import(
    request: Request,
    file: UploadFile = File(...),
    license: str = "unknown",
    source_url: str = "owner:upload",
    who=Depends(enrolled),
    db=Depends(db_dep),
):
    data = await file.read(20 * 1024 * 1024 + 1)
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(413)
    if license.lower() == "unknown":
        raise Denied("Confirm the source license/permission before import")
    filename = Path(file.filename or "import.txt").name
    if Path(filename).suffix.lower() not in (
        ".md",
        ".txt",
        ".html",
        ".htm",
        ".json",
        ".jsonl",
        ".csv",
        ".pdf",
        ".docx",
        ".zip",
    ):
        raise Denied("Unsupported document format")
    id = uid()
    root = Path(settings().data_dir) / "imports" / id
    root.mkdir(mode=0o700, parents=True)
    path = root / filename
    path.write_bytes(data)
    path.chmod(0o600)
    d = document(
        db,
        "file_import_request",
        who[0].id,
        {
            "status": "queued",
            "path": str(path),
            "filename": filename,
            "license": license,
            "source_url": source_url,
            "record_type": "research_report",
            "lease_until": 0,
            "attempts": 0,
        },
        id,
    )
    audit(
        db,
        who[0].id,
        "knowledge_import_queued",
        {"job_id": id, "sha256": digest(data), "bytes": len(data)},
    )
    db.commit()
    return {
        "job_id": d.id,
        "status": "queued",
        "counts": {},
        "notice": "Import is processed by the corpus worker; inspect persisted job status for actual counts",
    }


class CorpusSync(Strict):
    source: Literal["ghsa", "cve", "nvd", "osv", "kev"]
    limit: int = Field(default=1000, ge=1, le=100000)


@app.post("/api/v1/corpus/sync")
def corpus_sync(body: CorpusSync, who=Depends(stepup), db=Depends(db_dep)):
    d = document(
        db, "corpus_request", who[0].id, {**body.model_dump(), "status": "queued"}
    )
    db.commit()
    return expose(d)


@app.post("/api/v1/runs/{id}/reports")
def report(
    id: str,
    format: Literal["markdown", "json", "html", "sarif", "pdf"] = "markdown",
    who=Depends(stepup),
    db=Depends(db_dep),
):
    from .reporting import generate_report

    run = own(db, id, "run", who[0].id)
    d = generate_report(db, run, format)
    audit(db, who[0].id, "report_export", {"id": d.id})
    db.commit()
    return expose(d)


@app.get("/api/v1/budgets")
def budgets(who=Depends(enrolled), db=Depends(db_dep)):
    d = db.get(Document, "budget-global")
    return (
        d.value()
        if d
        else {"cap": settings().monthly_budget, "spent": {}, "reserved": {}}
    )


class BudgetInput(Strict):
    cap: float = Field(gt=0, le=10000)


@app.patch("/api/v1/budgets")
def budget_set(body: BudgetInput, who=Depends(stepup), db=Depends(db_dep)):
    d = db.query(Document).filter_by(id="budget-global").with_for_update().first()
    if not d:
        d = document(
            db,
            "budget",
            "system",
            {"cap": body.cap, "spent": {}, "reserved": {}},
            "budget-global",
        )
    else:
        v = d.value()
        v["cap"] = body.cap
        d.data = canonical(v)
    audit(db, who[0].id, "budget_changed", {"cap": body.cap})
    db.commit()
    return d.value()


@app.post("/api/v1/admin/kill-switch")
def kill(enabled: bool = True, who=Depends(stepup), db=Depends(db_dep)):
    d = db.get(Document, "kill-switch")
    if d:
        d.data = canonical({"enabled": enabled})
    else:
        document(db, "kill_switch", "system", {"enabled": enabled}, "kill-switch")
    if enabled:
        for r in db.query(Document).filter_by(kind="run"):
            if r.value()["status"] not in ("completed", "cancelled"):
                control(db, r, "cancel", who[0].id)
    audit(db, who[0].id, "kill_switch_changed", {"enabled": enabled})
    db.commit()
    return {"enabled": enabled}


@app.get("/api/v1/doctor")
def doctor(who=Depends(enrolled), db=Depends(db_dep)):
    try:
        master()
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(503, "Dependency unavailable") from None
    workers = {
        d.id: time.time() - d.value()["timestamp"] < 10
        for d in db.query(Document).filter_by(kind="heartbeat")
    }
    return {
        "database": "ready",
        "master_key": "ready",
        "workers": workers,
        "production": settings().production,
        "passkey_count": db.query(Document)
        .filter_by(kind="passkey", owner=who[0].id)
        .count(),
        "totp_enrolled": bool(who[0].totp),
        "target_traffic": "GET/HEAD through scoped relay; source-only modes deny target requests",
        "sandbox": "requires_linux_user_namespaces",
        "public_registration": False,
    }


# Bounded object APIs share ownership policy. Internal documents and secrets are excluded.
KINDS = {
    "campaigns": "campaign",
    "runs": "run",
    "findings": "finding",
    "repositories": "repository",
    "reports": "report",
    "providers": "provider",
    "model-configs": "alias",
    "skills": "skill",
    "skill-references": "skill_reference",
    "knowledge-feedback": "knowledge_feedback",
    "benchmarks": "benchmark",
    "approvals": "approval",
    "usage": "usage",
}


@app.get("/api/v1/{collection}")
def list_objects(
    collection: str,
    offset: int = 0,
    limit: int = 50,
    who=Depends(enrolled),
    db=Depends(db_dep),
):
    if collection not in KINDS:
        raise HTTPException(404)
    rows = (
        db.query(Document)
        .filter_by(kind=KINDS[collection], owner=who[0].id)
        .order_by(Document.created.desc())
        .offset(max(0, offset))
        .limit(min(100, max(1, limit)))
        .all()
    )
    return [
        safe_metadata(d)
        if collection == "providers"
        else {k: v for k, v in expose(d).items() if k != "path"}
        for d in rows
    ]


@app.get("/api/v1/{collection}/{id}")
def get_object(collection: str, id: str, who=Depends(enrolled), db=Depends(db_dep)):
    if collection not in KINDS:
        raise HTTPException(404)
    d = own(db, id, KINDS[collection], who[0].id)
    return (
        safe_metadata(d)
        if collection == "providers"
        else {k: v for k, v in expose(d).items() if k != "path"}
    )


# Explicit registry routes are inserted before the generic collection routes below.
class SkillImport(Strict):
    package: str = Field(max_length=200000)


class FeedbackReview(Strict):
    decision: Literal["accepted", "rejected"]
    reason: str = Field(min_length=1, max_length=2000)


@app.patch("/api/v1/knowledge-feedback/{id}/review")
def review_feedback(id: str, body: FeedbackReview, who=Depends(admin), db=Depends(db_dep)):
    from .vault import redact

    d = own(db, id, "knowledge_feedback", who[0].id, True)
    value = d.value()
    if value["status"] != "pending_review":
        raise Denied("Feedback was already reviewed")
    value.update(status=body.decision, reviewed_by=who[0].id, reviewed_at=now(), review_reason=redact(body.reason))
    d.data = canonical(value)
    audit(db, who[0].id, "knowledge_feedback_reviewed", {"id": id, "decision": body.decision})
    db.commit()
    # Reviewing usefulness is not proof of a vulnerability or a corpus rewrite.
    return {**expose(d), "trusted_source_modified": False}


@app.post("/api/v1/skills/import")
def skill_import(body: SkillImport, who=Depends(stepup), db=Depends(db_dep)):
    from .skills import parse_skill, import_skill

    d = import_skill(db, who[0].id, parse_skill(body.package))
    db.commit()
    return expose(d)


@app.post("/api/v1/skills/{id}/control/{action}")
def skill_control(
    id: str,
    action: Literal["review", "validate", "enable", "disable", "rollback"],
    who=Depends(stepup),
    db=Depends(db_dep),
):
    from .skills import review, validate, enable

    d = own(db, id, "skill", who[0].id, True)
    if action == "review":
        review(db, d, who[0].id)
    elif action == "validate":
        validate(db, d, who[0].id)
    elif action in ("enable", "disable"):
        enable(db, d, who[0].id, action == "enable")
    else:
        v = d.value()
        others = [
            s
            for s in db.query(Document).filter_by(kind="skill", owner=who[0].id)
            if s.value()["skill_id"] == v["skill_id"]
            and s.id != d.id
            and s.value()["status"] == "validated"
        ]
        if not others:
            raise Denied("No previously validated version")
        for s in db.query(Document).filter_by(kind="skill", owner=who[0].id):
            if s.value()["skill_id"] == v["skill_id"]:
                enable(db, s, who[0].id, False)
        enable(db, sorted(others, key=lambda s: s.created)[-1], who[0].id, True)
    db.commit()
    return expose(d)


@app.post("/api/v1/benchmarks/run")
def benchmark_run(who=Depends(stepup), db=Depends(db_dep)):
    d = document(
        db,
        "sandbox_benchmark_request",
        who[0].id,
        {"status": "queued", "lease_until": 0},
    )
    db.commit()
    return expose(d)


@app.post("/api/v1/corpus/validate")
def corpus_validate(who=Depends(admin), db=Depends(db_dep)):
    from .records import Record

    passed = failed = 0
    for record in (
        db.query(Knowledge)
        .filter(Knowledge.owner.in_(["public", who[0].id]))
        .yield_per(200)
    ):
        try:
            Record.model_validate_json(record.record)
            passed += 1
        except ValueError:
            failed += 1
    return {"validated": passed, "failed": failed}


@app.post("/api/v1/corpus/dedupe")
def corpus_dedupe(who=Depends(stepup), db=Depends(db_dep)):
    from .corpus import near_duplicates

    return {
        "candidates": near_duplicates(db),
        "action": "review_only_no_destructive_merge",
    }


@app.get("/api/v1/corpus/errors")
def corpus_errors(
    offset: int = 0, limit: int = 50, who=Depends(admin), db=Depends(db_dep)
):
    return [
        expose(d)
        for d in db.query(Document)
        .filter_by(kind="import_error")
        .offset(max(0, offset))
        .limit(min(100, max(1, limit)))
    ]


class FindingUpdate(Strict):
    status: Literal["reported", "fixed", "closed"]
    review_notes: str = Field(min_length=1, max_length=6000)


@app.patch("/api/v1/findings/{id}")
def finding_update(
    id: str, body: FindingUpdate, who=Depends(enrolled), db=Depends(db_dep)
):
    if who[0].role not in ("owner_admin", "reviewer"):
        raise HTTPException(403)
    d = own(db, id, "finding", who[0].id, True)
    v = d.value()
    transitions = {
        "confirmed": ["reported", "fixed", "closed"],
        "reported": ["fixed", "closed"],
        "fixed": ["closed"],
    }
    if body.status not in transitions.get(v["status"], []):
        raise Denied(
            "Only evidence-confirmed findings may enter reporting/fix workflow"
        )
    v.update(body.model_dump())
    d.data = canonical(v)
    audit(db, who[0].id, "finding_status_changed", {"id": id, "status": body.status})
    db.commit()
    return expose(d)


@app.get("/api/v1/findings/{id}/evidence")
def finding_evidence(id: str, who=Depends(enrolled), db=Depends(db_dep)):
    d = own(db, id, "finding", who[0].id)
    return [
        expose(own(db, x, "artifact", who[0].id)) for x in d.value()["evidence_ids"]
    ]


@app.get("/api/v1/repositories/{id}/inventory")
def repository_inventory(id: str, who=Depends(enrolled), db=Depends(db_dep)):
    d = own(db, id, "repository", who[0].id)
    return d.value()["inventory"]


class SourceRead(Strict):
    path: str
    start: int = Field(default=1, ge=1)
    end: int = Field(default=200, ge=1)


@app.post("/api/v1/repositories/{id}/read")
def repository_read(
    id: str, body: SourceRead, who=Depends(enrolled), db=Depends(db_dep)
):
    from .tools import Repository, ReadInput

    d = own(db, id, "repository", who[0].id)
    return Repository(d.value()["path"]).read(ReadInput(**body.model_dump()))


@app.get("/api/v1/runs/{id}/objects/{kind}")
def run_objects(
    id: str,
    kind: Literal["hypotheses", "stages", "tools", "slices"],
    who=Depends(enrolled),
    db=Depends(db_dep),
):
    own(db, id, "run", who[0].id)
    if kind == "stages":
        return [
            expose(d)
            for d in db.query(Document).filter_by(kind="stage_result", owner=id)
        ]
    if kind == "slices":
        return [
            expose(d)
            for d in db.query(Document).filter_by(
                kind="research_slice", owner=who[0].id
            )
            if d.value()["run_id"] == id
        ]
    if kind == "hypotheses":
        return [
            expose(d)
            for d in db.query(Document).filter_by(kind="hypothesis", owner=who[0].id)
            if d.value()["run_id"] == id
        ]
    return [
        json.loads(e.payload)
        for e in db.query(Journal).filter_by(stream=id).order_by(Journal.sequence)
        if json.loads(e.payload)["type"] == "policy_decision"
    ]


@app.get("/api/v1/runs/{id}/swarm")
def swarm_state(id: str, who=Depends(enrolled), db=Depends(db_dep)):
    from .db import SwarmTask

    run = own(db, id, "run", who[0].id)
    task_rows = db.query(SwarmTask).filter_by(run_id=id, owner=who[0].id).order_by(SwarmTask.created_at).all()
    events = [json.loads(e.payload) for e in db.query(Journal).filter_by(stream=id).order_by(Journal.sequence.desc()).limit(300)]
    usage = [u.value() for u in db.query(Document).filter_by(kind="usage", owner=who[0].id) if u.value().get("run_id") == id]
    return {
        "run_id": id, "execution_mode": run.value().get("execution_mode", "legacy"),
        "agent_count": run.value().get("agent_count", 1),
        "tasks": [{"id": t.id, "role": t.role, "worker_kind": t.worker_kind,
                   "status": t.status, "attempts": t.attempts, "priority": t.priority,
                   "reason": json.loads(t.payload).get("reason"),
                   "parent_event": json.loads(t.payload).get("event_id"),
                   "result": {k: v for k, v in json.loads(t.result).items() if k in ("summary", "status", "reason", "error_type", "finding_id")},
                   "updated_at": t.updated_at} for t in task_rows],
        "events": [e for e in reversed(events) if e["type"].startswith(("swarm_", "knowledge_", "skill_"))],
        "usage": {"input_tokens": sum(u["input_tokens"] for u in usage),
                  "output_tokens": sum(u["output_tokens"] for u in usage),
                  "cost": sum(u["cost"] for u in usage), "requests": len(usage),
                  "includes_estimates": any(u.get("estimated") for u in usage)},
    }


@app.post("/api/v1/skills/starter")
def skill_starter(who=Depends(stepup), db=Depends(db_dep)):
    from .skills import STARTER, import_skill

    d = import_skill(db, who[0].id, STARTER)
    db.commit()
    return expose(d)


@app.post("/api/v1/skills/{id}/benchmark")
def skill_benchmark(id: str, who=Depends(stepup), db=Depends(db_dep)):
    from .skills import benchmark_skill

    d = own(db, id, "skill", who[0].id, True)
    b = benchmark_skill(db, d, who[0].id)
    db.commit()
    return expose(b)


@app.post("/api/v1/skills/import-archive")
async def skill_archive(
    file: UploadFile = File(...), who=Depends(stepup), db=Depends(db_dep)
):
    from .skills import parse_skill, import_skill

    data = await file.read(5 * 1024 * 1024 + 1)
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(413)
    results = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if (
            len(z.infolist()) > 200
            or sum(i.file_size for i in z.infolist()) > 10 * 1024 * 1024
        ):
            raise Denied("Skill archive quota exceeded")
        for info in z.infolist():
            if ".." in Path(info.filename).parts or Path(info.filename).is_absolute():
                raise Denied("Unsafe skill reference path")
            if info.filename.endswith((".sh", ".py", ".js")):
                raise Denied(
                    "Executable skill package requires separate offline review; import its declarative SKILL.md alone"
                )
            if info.filename.endswith("SKILL.md"):
                results.append(
                    expose(
                        import_skill(db, who[0].id, parse_skill(z.read(info).decode()))
                    )
                )
    if not results:
        raise ValueError("No SKILL.md found")
    db.commit()
    return results


class ResumeCorpus(Strict):
    job_id: str
    limit: int = Field(default=1000, ge=1, le=100000)


@app.post("/api/v1/corpus/resume")
def corpus_resume(body: ResumeCorpus, who=Depends(stepup), db=Depends(db_dep)):
    job = db.get(Document, body.job_id)
    if not job or job.kind != "corpus_job":
        raise HTTPException(404)
    d = document(
        db,
        "corpus_request",
        who[0].id,
        {
            "source": job.value()["source"],
            "limit": body.limit,
            "resume_id": job.id,
            "status": "queued",
        },
    )
    db.commit()
    return expose(d)


@app.post("/api/v1/corpus/embed")
def corpus_embed(who=Depends(stepup), db=Depends(db_dep)):
    d = document(
        db,
        "index_request",
        who[0].id,
        {"status": "queued", "cursor": "", "processed": 0, "limit": 100000},
    )
    db.commit()
    return expose(d)


@app.get("/api/v1/corpus/jobs")
def corpus_jobs(
    offset: int = 0, limit: int = 50, who=Depends(admin), db=Depends(db_dep)
):
    return [
        expose(d)
        for d in db.query(Document)
        .filter(
            Document.kind.in_(
                [
                    "corpus_job",
                    "corpus_request",
                    "index_request",
                    "file_import_request",
                    "source_acquisition_request",
                ]
            ),
            Document.owner.in_(["system", who[0].id]),
        )
        .order_by(Document.created.desc())
        .offset(max(0, offset))
        .limit(min(100, max(1, limit)))
    ]


@app.get("/api/v1/corpus/export")
def corpus_export(who=Depends(stepup)):
    owner = who[0].id

    def generate():
        with session() as db:
            for k in (
                db.query(Knowledge)
                .filter(Knowledge.owner.in_(["public", owner]))
                .yield_per(200)
            ):
                yield k.record + "\n"

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="atlas-corpus.jsonl"'},
    )


@app.get("/api/v1/capabilities")
def capabilities(who=Depends(enrolled)):
    from .capabilities import CAPABILITIES, TOOLS

    return {
        "categories": CAPABILITIES,
        "tools": TOOLS,
        "advanced_adapters": "disabled until fixture, sandbox and verifier support are available",
    }


class ModelBenchmarkInput(Strict):
    model_ids: list[str] = Field(min_length=1, max_length=5)
    budget_per_model: float = Field(default=1, gt=0, le=10)


@app.post("/api/v1/benchmarks/models")
def benchmark_models(
    body: ModelBenchmarkInput, who=Depends(stepup), db=Depends(db_dep)
):
    from .model_benchmarks import create

    result = create(db, who[0].id, body.model_ids, body.budget_per_model)
    db.commit()
    return {
        "run_ids": result,
        "note": "Budgeted synthetic benchmark, not live target testing or a universal ranking",
    }


@app.post("/api/v1/corpus/sources")
def register_source(body: SourcePolicy, who=Depends(stepup), db=Depends(db_dep)):
    from .source_policy import register

    d = register(db, who[0].id, body)
    db.commit()
    return expose(d)


@app.get("/api/v1/corpus/sources/reviewed")
def reviewed_sources(who=Depends(admin), db=Depends(db_dep)):
    return [
        expose(d)
        for d in db.query(Document).filter_by(kind="source_policy", owner=who[0].id)
    ]


@app.post("/api/v1/corpus/sources/{id}/sync")
def acquire_source(id: str, who=Depends(stepup), db=Depends(db_dep)):
    d = own(db, id, "source_policy", who[0].id)
    if not d.value()["enabled"] or not d.value()["owner_reviewed"]:
        raise Denied("Source review and enablement required")
    native = d.value().get("native_source")
    job = document(
        db,
        "corpus_request" if native else "source_acquisition_request",
        who[0].id,
        {
            "source_id": id,
            "source": native,
            "limit": 1000,
            "status": "queued",
            "lease_until": 0,
        },
    )
    db.commit()
    return expose(job)


@app.get("/api/v1/auth/passkeys")
def passkeys(who=Depends(identity), db=Depends(db_dep)):
    return [
        {
            "id": d.id,
            "created": d.created,
            "fingerprint": digest(d.value()["credential_id"])[:12],
            "backed_up": d.value().get("backed_up", False),
            "signature_counter": d.value()["sign_count"],
        }
        for d in db.query(Document).filter_by(kind="passkey", owner=who[0].id)
    ]


@app.delete("/api/v1/auth/passkeys/{id}")
def remove_passkey(
    id: str, response: Response, who=Depends(security_stepup), db=Depends(db_dep)
):
    d = own(db, id, "passkey", who[0].id, True)
    if db.query(Document).filter_by(kind="passkey", owner=who[0].id).count() <= 1:
        raise Denied(
            "Keep at least one passkey; privileged host recovery is required for complete reset"
        )
    db.delete(d)
    audit(db, who[0].id, "passkey_removed", {"id": id})
    db.query(Session).filter_by(user_id=who[0].id).delete()
    s, t, c = auth.issue(db, who[0], True)
    db.commit()
    return set_session(response, s, t, c)


@app.post("/api/v1/auth/sessions/revoke-all")
def revoke_all_sessions(
    response: Response, who=Depends(security_stepup), db=Depends(db_dep)
):
    db.query(Session).filter_by(user_id=who[0].id).delete()
    audit(db, who[0].id, "all_sessions_revoked", {})
    db.commit()
    response.delete_cookie(cookie_name(), path="/")
    return {"status": "revoked"}


class CloneRepository(Strict):
    url: str = Field(max_length=4096)
    ref: str = "HEAD"


@app.post("/api/v1/campaigns/{id}/repositories/clone")
def clone_repo(
    id: str, body: CloneRepository, who=Depends(enrolled), db=Depends(db_dep)
):
    own(db, id, "campaign", who[0].id)
    from .repositories import clone_snapshot

    result = clone_snapshot(body.url, body.ref)
    d = document(db, "repository", who[0].id, {"campaign_id": id, **result})
    audit(
        db,
        who[0].id,
        "repository_acquired",
        {"id": d.id, "commit": result["commit_hash"]},
    )
    db.commit()
    return {
        "id": d.id,
        "origin": result["origin"],
        "commit_hash": result["commit_hash"],
        "inventory": result["inventory"],
    }


class CampaignEdit(Strict):
    budget_limit: float | None = Field(default=None, gt=0, le=1000)
    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=6000)
    status: Literal["active", "archived"] | None = None


@app.patch("/api/v1/campaigns/{id}")
def edit_campaign(
    id: str, body: CampaignEdit, who=Depends(enrolled), db=Depends(db_dep)
):
    if body.budget_limit is not None and (settings().require_mfa or who[1].mfa) and who[1].stepup < time.time() - 300:
        raise Denied("Recent passkey step-up required to change campaign budget")
    d = own(db, id, "campaign", who[0].id, True)
    v = d.value()
    v.update(body.model_dump(exclude_none=True))
    d.data = canonical(v)
    d.version += 1
    audit(db, who[0].id, "campaign_edited", {"id": id, "version": d.version})
    db.commit()
    return expose(d)


class HypothesisEdit(Strict):
    status: Literal["refuted", "inconclusive", "duplicate", "promoted_to_candidate"]
    notes: str = Field(min_length=1, max_length=4000)


@app.patch("/api/v1/hypotheses/{id}")
def edit_hypothesis(
    id: str, body: HypothesisEdit, who=Depends(enrolled), db=Depends(db_dep)
):
    d = own(db, id, "hypothesis", who[0].id, True)
    v = d.value()
    v.update(body.model_dump())
    d.data = canonical(v)
    audit(db, who[0].id, "hypothesis_reviewed", {"id": id, "status": body.status})
    db.commit()
    return expose(d)


@app.put("/api/v1/runs/{id}/threat-model")
def edit_threat_model(
    id: str, body: ThreatModel, who=Depends(enrolled), db=Depends(db_dep)
):
    run = own(db, id, "run", who[0].id, True)
    old = [
        d
        for d in db.query(Document).filter_by(kind="threat_model", owner=who[0].id)
        if d.value()["run_id"] == id
    ]
    d = document(
        db,
        "threat_model",
        who[0].id,
        {
            "run_id": id,
            "version": len(old) + 1,
            "model": body.model_dump(),
            "hash": digest(canonical(body.model_dump())),
        },
    )
    append(
        db,
        id,
        who[0].id,
        "threat_model_versioned",
        {"id": d.id, "version": len(old) + 1},
        run.value()["campaign_id"],
    )
    db.commit()
    return expose(d)


@app.get("/api/v1/runs/{id}/threat-model")
def get_threat_model(id: str, who=Depends(enrolled), db=Depends(db_dep)):
    own(db, id, "run", who[0].id)
    versions = [
        d
        for d in db.query(Document)
        .filter_by(kind="threat_model", owner=who[0].id)
        .order_by(Document.created)
        if d.value()["run_id"] == id
    ]
    return [expose(d) for d in versions]


@app.get("/api/v1/auth/audit")
def security_audit(who=Depends(enrolled), db=Depends(db_dep)):
    return [
        {"sequence": e.sequence, "hash": e.hash, **json.loads(e.payload)}
        for e in db.query(Journal)
        .filter_by(stream=who[0].id)
        .order_by(Journal.sequence.desc())
        .limit(100)
    ]


class ApprovalDecision(Strict):
    decision: Literal["approve", "reject"]


@app.post("/api/v1/approvals/{id}/decision")
def approval_decision(
    id: str, body: ApprovalDecision, who=Depends(stepup), db=Depends(db_dep)
):
    d = own(db, id, "approval", who[0].id, True)
    v = d.value()
    run = own(db, v["run_id"], "run", who[0].id, True)
    rv = run.value()
    if (
        v["status"] != "pending"
        or v["expires"] < time.time()
        or v["policy_hash"] != rv["policy_hash"]
    ):
        raise Denied("Approval expired or no longer matches frozen policy")
    if rv["status"] in ("completed", "cancelled"):
        raise Denied("Run is terminal")
    if body.decision == "approve":
        action = v["action"]
        if action["type"] == "budget":
            amount = action.get("requested_usd")
            if (
                not isinstance(amount, (int, float))
                or not 0 < amount <= settings().monthly_budget
            ):
                raise Denied("Invalid requested budget")
            rv["budget_limit"] = amount
        elif action["type"] == "offline_execution":
            rv["offline_execution_approved"] = True
        else:
            raise Denied("Approval cannot grant unknown capabilities")
        run.data = canonical(rv)
        control(db, run, "resume", who[0].id)
    v.update(
        status="approved" if body.decision == "approve" else "rejected",
        approved_by=who[0].id,
        decided_at=now(),
    )
    d.data = canonical(v)
    append(
        db,
        run.id,
        who[0].id,
        "approval_decided",
        {"approval_id": d.id, "decision": body.decision, "action": v["action"]},
        rv["campaign_id"],
    )
    db.commit()
    return expose(d)


class ProviderEnable(Strict):
    enabled: bool


@app.post("/api/v1/providers/{id}/enablement")
def provider_enable(
    id: str, body: ProviderEnable, who=Depends(stepup), db=Depends(db_dep)
):
    d = own(db, id, "provider", who[0].id, True)
    if active_provider(db, who[0].id, id):
        raise HTTPException(
            409, "Stop or migrate active runs before changing the pinned connection"
        )
    v = d.value()
    if v.get("deleted"):
        raise Denied("Deleted credentials cannot be restored; create a new connection")
    snapshot_provider(db, d)
    v["enabled"] = body.enabled
    d.data = canonical(v)
    d.version += 1
    snapshot_provider(db, d)
    audit(
        db,
        who[0].id,
        "provider_enablement_changed",
        {"id": id, "enabled": body.enabled},
    )
    db.commit()
    return safe_metadata(d)


@app.get("/api/v1/providers/{id}/versions")
def provider_versions(id: str, who=Depends(enrolled), db=Depends(db_dep)):
    own(db, id, "provider", who[0].id)
    return [
        expose(d)
        for d in db.query(Document).filter_by(kind="provider_version", owner=who[0].id)
        if d.value()["provider_id"] == id
    ]


@app.patch("/api/v1/providers/{id}/models/{model_id}")
def model_edit(
    id: str, model_id: str, body: ModelInput, who=Depends(stepup), db=Depends(db_dep)
):
    own(db, id, "provider", who[0].id)
    d = own(db, model_id, "provider_model", who[0].id, True)
    if d.value()["provider_id"] != id:
        raise Denied("Model/provider mismatch")
    if active_provider(db, who[0].id, id):
        raise HTTPException(409, "Model pinned by an active run")
    snapshot_model(db, d)
    d.data = canonical(
        {
            "provider_id": id,
            **body.model_dump(),
            "verified_structured": False,
            "capability_status": "user_declared_unverified",
        }
    )
    d.version += 1
    snapshot_model(db, d)
    db.commit()
    return expose(d)


@app.get("/api/v1/knowledge/{id}")
def knowledge_record(id: str, who=Depends(enrolled), db=Depends(db_dep)):
    k = db.get(Knowledge, id)
    if not k or k.owner not in ("public", who[0].id):
        raise HTTPException(404)
    return json.loads(k.record)


@app.get("/api/v1/knowledge/{id}/sources")
def knowledge_lineage(id: str, who=Depends(enrolled), db=Depends(db_dep)):
    k = db.get(Knowledge, id)
    if not k or k.owner not in ("public", who[0].id):
        raise HTTPException(404)
    return [
        expose(d)
        for d in db.query(Document).filter_by(kind="corpus_provenance", owner=id)
    ]


class Curation(Strict):
    status: Literal["proposed", "reviewed", "validated", "deprecated"]
    reason: str = Field(min_length=1, max_length=2000)


@app.patch("/api/v1/knowledge/{id}")
def curate_record(id: str, body: Curation, who=Depends(stepup), db=Depends(db_dep)):
    k = db.get(Knowledge, id)
    if not k or k.owner not in ("public", who[0].id):
        raise HTTPException(404)
    r = json.loads(k.record)
    r.update(curation_status=body.status, updated_at=now())
    k.record = canonical(r)
    audit(
        db,
        who[0].id,
        "knowledge_curated",
        {"id": id, "status": body.status, "reason": body.reason},
    )
    db.commit()
    return r


@app.delete("/api/v1/knowledge/{id}")
def delete_record(id: str, reason: str, who=Depends(stepup), db=Depends(db_dep)):
    from .corpus import remove_record

    k = db.get(Knowledge, id)
    if not k or k.owner not in ("public", who[0].id):
        raise HTTPException(404)
    audit(
        db,
        who[0].id,
        "knowledge_deletion_requested",
        {"id": id, "reason": reason[:2000]},
    )
    remove_record(db, id, reason[:2000])
    return {"status": "removed", "record_id": id}


# Specific API contracts must take precedence over generic collection readers.
@app.post("/api/v1/registries/seeds/import")
async def seed_import(
    file: UploadFile = File(...), who=Depends(stepup), db=Depends(db_dep)
):
    from .registries import import_manifest

    result = import_manifest(
        db,
        who[0].id,
        await file.read(1024 * 1024 + 1),
        file.filename or "manifest.json",
    )
    db.commit()
    return result


@app.get("/api/v1/registries/seeds")
def seed_list(who=Depends(admin), db=Depends(db_dep)):
    return [
        expose(d)
        for d in db.query(Document).filter_by(kind="seed_resource", owner=who[0].id)
    ]


class ReservationReconciliation(Strict):
    actual_cost: float = Field(ge=0, le=10000)
    billing_reference: str = Field(min_length=10, max_length=500)


@app.post("/api/v1/budgets/reservations/{id}/reconcile")
def reconcile_reservation(
    id: str, body: ReservationReconciliation, who=Depends(stepup), db=Depends(db_dep)
):
    from .gateway import settle

    budget = db.query(Document).filter_by(id="budget-global").with_for_update().first()
    reservation = budget.value()["reserved"].get(id) if budget else None
    if not reservation or reservation.get("owner") != who[0].id:
        raise HTTPException(404)
    run = (
        db.query(Document)
        .filter_by(id=reservation["run_id"], kind="run", owner=who[0].id)
        .with_for_update()
        .first()
    )
    if run and run.value()["status"] in ("running", "queued"):
        raise Denied(
            "Stop the run and verify provider billing before reconciling an unknown outcome"
        )
    settle(db, id, body.actual_cost)
    if run:
        v = run.value()
        v["budget_used"] = v.get("budget_used", 0) + body.actual_cost
        role = reservation.get("role") or "unknown"
        v.setdefault("role_spent", {})[role] = (
            v.get("role_spent", {}).get(role, 0) + body.actual_cost
        )
        run.data = canonical(v)
    document(
        db,
        "usage",
        who[0].id,
        {
            "run_id": reservation["run_id"],
            "campaign_id": run.value().get("campaign_id") if run else None,
            "role": reservation.get("role"),
            "cost": body.actual_cost,
            "estimated": False,
            "source": "owner_billing_reconciliation",
            "billing_reference": body.billing_reference,
        },
    )
    audit(
        db,
        who[0].id,
        "budget_reservation_reconciled",
        {
            "reservation_id": id,
            "actual_cost": body.actual_cost,
            "billing_reference": body.billing_reference,
        },
    )
    db.commit()
    return {"status": "reconciled", "charged_cost": body.actual_cost}


app.router.routes.sort(
    key=lambda r: int(
        getattr(r, "path", "") in ("/api/v1/{collection}", "/api/v1/{collection}/{id}")
    )
)
