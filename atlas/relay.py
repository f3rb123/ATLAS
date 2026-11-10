"""Target-only egress service. Frozen policy, pinned DNS, audit and durable quotas."""

import hmac, time
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from fastapi import FastAPI, Request, HTTPException
from .config import settings
from .policy import Strict, Scope, Denied, request, normalize
from .db import session, Document, canonical, digest, append, transaction_lock
from .vault import redact

app = FastAPI(docs_url=None, openapi_url=None)


class TargetRequest(Strict):
    run_id: str
    url: str
    method: str = "GET"
    headers: dict[str, str] = {}
    body: str | None = None
    max_redirects: int = 0


@app.get("/health/live")
def health():
    return {"status": "alive"}


def execute(body, actor):
    if body.method not in ("GET", "HEAD"):
        raise Denied(
            "State-changing target traffic disabled; requires dedicated approved adapter"
        )
    if body.body or body.max_redirects < 0 or body.max_redirects > 3:
        raise Denied("Unsafe request")
    if any(
        k.lower() not in ("accept", "user-agent", "content-type")
        or "\r" in v
        or "\n" in v
        for k, v in body.headers.items()
    ):
        raise Denied("Target headers denied")
    url = body.url
    start = time.monotonic()
    chain = []
    for hop in range(body.max_redirects + 1):
        with session() as db:
            transaction_lock(db, "relay:" + body.run_id)
            run = (
                db.query(Document)
                .filter_by(id=body.run_id, kind="run")
                .with_for_update()
                .first()
            )
            if not run:
                raise Denied("Run unavailable")
            v = run.value()
            decision = "deny"
            try:
                kill = db.get(Document, "kill-switch")
                if kill and kill.value()["enabled"]:
                    raise Denied("Emergency stop active")
                if (
                    v["status"] not in ("running", "queued")
                    or v["deadline"] < time.time()
                ):
                    raise Denied("Inactive or expired run")
                campaign = db.get(Document, v["campaign_id"])
                if campaign.value()["mode"] not in ("passive", "safe-active", "lab"):
                    raise Denied("Campaign mode prohibits target traffic")
                policy = db.get(Document, v["policy_id"])
                scope = Scope.model_validate(policy.value()["scope"])
                if digest(canonical(scope.model_dump())) != v["policy_hash"]:
                    raise Denied("Policy integrity failure")
                from .policy import authorize, readonly_target_request

                readonly_target_request(url, body.method)
                profile = v.get("assessment_profile", campaign.value().get("assessment_profile", "standard"))
                if profile == "smoke_readonly":
                    parsed = urlsplit(url)
                    if body.method != "HEAD" or parsed.path not in ("", "/") or parsed.query:
                        raise Denied("Smoke profile permits only metadata HEAD requests to the verified root URL")
                    if any(k.lower() not in ("accept", "user-agent") for k in body.headers):
                        raise Denied("Smoke profile prohibits authentication, cookies and method overrides")
                authorize(scope, url, body.method)
                request_limit = min(scope.max_requests, 2) if profile == "smoke_readonly" else scope.max_requests
                if v.get("http_requests", 0) >= request_limit:
                    raise Denied("HTTP quota exhausted")
                if time.time() - v.get("last_request", 0) < 1:
                    raise Denied("Rate/concurrency limit: one request per second")
                v["http_requests"] = v.get("http_requests", 0) + 1
                v["last_request"] = time.time()
                run.data = canonical(v)
                decision = "allow"
            finally:
                append(
                    db,
                    run.id,
                    actor,
                    "policy_decision",
                    {
                        "url_hash": digest(url),
                        "method": body.method,
                        "decision": decision,
                    },
                    v["campaign_id"],
                )
                db.commit()
        status, headers, content = request(
            url,
            body.method,
            body.headers,
            scope=scope,
            max_bytes=scope.max_response_bytes,
            timeout=min(scope.max_seconds, 15),
            return_redirect=True,
        )
        chain.append({"url": url, "status": status, "sha256": digest(content)})
        if 300 <= status < 400:
            if hop == body.max_redirects:
                raise Denied("Redirect budget exceeded")
            location = next(
                (v for k, v in headers.items() if k.lower() == "location"), None
            )
            if not location:
                raise Denied("Missing redirect location")
            target = urljoin(url, location)
            if (
                normalize(target)[1:3] != normalize(url)[1:3]
                or urlsplit(target).scheme != urlsplit(url).scheme
            ):
                raise Denied("Cross-origin or downgrade redirect denied")
            url = target
            time.sleep(1)
            continue
        return {
            "status": status,
            "headers": {
                k: v
                for k, v in headers.items()
                if k.lower() in ("content-type", "content-length")
            },
            "body": redact(content.decode("utf-8", errors="replace")),
            "chain": chain,
            "elapsed": time.monotonic() - start,
            "trust": "untrusted_target_data",
        }
    raise Denied("No response")


@app.post("/request")
def relay(body: TargetRequest, req: Request):
    token = req.headers.get("authorization", "").removeprefix("Bearer ")
    if not settings().research_token_file or not hmac.compare_digest(
        token, Path(settings().research_token_file).read_text().strip()
    ):
        raise HTTPException(401)
    try:
        return execute(body, "research_service")
    except (Denied, ValueError):
        raise HTTPException(403, "Target request denied by policy") from None
