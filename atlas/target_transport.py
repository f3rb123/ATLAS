"""Scoped web transport with durable rate reservations and credential-free evidence."""

import json
import time
from urllib.parse import urljoin, urlsplit

from pydantic import Field

from .db import Document, append, canonical, digest, document, session, transaction_lock
from .policy import (
    Denied,
    Scope,
    Strict,
    authorize,
    nondestructive_target_request,
    normalize,
)
from .target_auth import resolve_headers, credential_fragments
from .vault import redact


class TargetRequest(Strict):
    run_id: str
    url: str = Field(max_length=4096)
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict, max_length=10)
    body: str | None = Field(default=None, max_length=16384, repr=False)
    max_redirects: int = Field(default=0, ge=0, le=3)
    purpose: str = "navigation"
    identity_id: str | None = None
    task_id: str | None = None
    lease_token: str | None = Field(default=None, repr=False)


def validate_run(db, run, body):
    value = run.value()
    kill = db.get(Document, "kill-switch", populate_existing=True)
    if kill and kill.value().get("enabled"):
        raise Denied("Emergency stop active")
    if (
        value.get("status") not in ("queued", "running")
        or value.get("deadline", 0) < time.time()
    ):
        raise Denied("Inactive or expired run")
    if body.task_id or body.lease_token:
        from .swarm import check_fence

        run._swarm_claim = (body.task_id, body.lease_token)
        check_fence(db, run)
    campaign = db.get(Document, value["campaign_id"])
    if (
        not campaign
        or campaign.owner != run.owner
        or campaign.value().get("mode") not in ("passive", "safe-active", "lab")
    ):
        raise Denied("Campaign mode prohibits target traffic")
    policy = db.get(Document, value["policy_id"])
    if (
        not policy
        or policy.owner != run.owner
        or digest(canonical(policy.value()["scope"])) != value["policy_hash"]
    ):
        raise Denied("Frozen policy integrity failure")
    scope = Scope.model_validate(policy.value()["scope"])
    return value, scope, campaign


def execute(body, actor, transport, private_capture=None):
    allowed_headers = {
        "accept",
        "user-agent",
        "content-type",
        "origin",
        "referer",
        "range",
        "if-none-match",
        "if-modified-since",
    }
    if any(
        k.lower() not in allowed_headers
        or len(v) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in k + v)
        for k, v in body.headers.items()
    ):
        raise Denied(
            "Target headers denied; credentials require an owned identity binding"
        )
    url = body.url
    started = time.monotonic()
    chain = []
    for hop in range(body.max_redirects + 1):
        if body.identity_id:
            from .target_sessions import prepare

            prepare(body, url, actor)
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
            decision = "deny"
            value = run.value()
            try:
                value, scope, campaign = validate_run(db, run, body)
                nondestructive_target_request(
                    scope, url, body.method, body.body, body.purpose
                )
                profile = value.get(
                    "assessment_profile",
                    campaign.value().get("assessment_profile", "standard"),
                )
                if profile == "smoke_readonly":
                    parsed = urlsplit(url)
                    if (
                        body.method != "HEAD"
                        or parsed.path not in ("", "/")
                        or parsed.query
                        or body.identity_id
                        or body.body
                        or any(
                            k.lower() not in ("accept", "user-agent")
                            for k in body.headers
                        )
                    ):
                        raise Denied(
                            "Smoke profile permits two unauthenticated root HEAD requests only"
                        )
                if campaign.value().get("mode") == "passive" and (
                    body.method not in ("GET", "HEAD") or body.purpose != "navigation"
                ):
                    raise Denied("Passive campaign prohibits active checks")
                authorize(scope, url, body.method)
                credentials = resolve_headers(db, run, body.identity_id, url)
                limit = (
                    min(scope.max_requests, 2)
                    if profile == "smoke_readonly"
                    else scope.max_requests
                )
                if value.get("http_requests", 0) >= limit:
                    raise Denied("HTTP quota exhausted")
                timestamp = time.time()
                slot = max(
                    timestamp,
                    value.get(
                        "next_request_at",
                        value.get("last_request", 0) + scope.min_request_interval,
                    ),
                )
                if slot + min(scope.max_seconds, 15) > value["deadline"]:
                    raise Denied("Insufficient run time for reserved request")
                value.update(
                    http_requests=value.get("http_requests", 0) + 1,
                    last_request=slot,
                    next_request_at=slot + scope.min_request_interval,
                )
                run.data = canonical(value)
                observation = document(
                    db,
                    "http_observation",
                    run.owner,
                    {
                        "run_id": run.id,
                        "campaign_id": value["campaign_id"],
                        "task_id": body.task_id,
                        "url": redact(url),
                        "method": body.method,
                        "purpose": body.purpose,
                        "identity_id": body.identity_id,
                        "request_body_sha256": digest(body.body or ""),
                        "state": "reserved",
                        "reserved_at": slot,
                    },
                )
                observation_id = observation.id
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
                    value.get("campaign_id"),
                )
                db.commit()
        # No SQL lock is held while waiting for a rate slot or doing network I/O.
        while (remaining := slot - time.time()) > 0:
            time.sleep(min(remaining, 0.25))
        with session() as db:
            current = db.get(Document, body.run_id, populate_existing=True)
            validate_run(db, current, body)
            # Re-check credential revocation/version immediately before dispatch.
            credentials = resolve_headers(db, current, body.identity_id, url)
        try:
            status, headers, content = transport(
                url,
                body.method,
                {**body.headers, **credentials, "Accept-Encoding": "identity"},
                body=body.body.encode() if body.body else None,
                scope=scope,
                max_bytes=scope.max_response_bytes,
                timeout=min(scope.max_seconds, 15),
                return_redirect=True,
            )
        except Exception as exc:
            with session() as db:
                row = db.get(Document, observation_id)
                v = row.value()
                v.update(state="failed", error_type=type(exc).__name__)
                row.data = canonical(v)
                db.commit()
            raise
        try:
            private_fragments = (
                private_capture(status, headers, content) if private_capture else []
            )
        except Exception as exc:
            with session() as db:
                row = db.get(Document, observation_id)
                value = row.value()
                value.update(
                    state="failed",
                    error_type=type(exc).__name__,
                    error_code="target_session_contract_rejected",
                    response_status=status,
                    response_sha256=digest(content),
                )
                row.data = canonical(value)
                db.commit()
            raise Denied(
                "Target login response did not satisfy the configured session contract"
            ) from None
        text = content.decode("utf-8", errors="replace")
        for secret in private_fragments:
            if secret:
                text = text.replace(secret, "[REDACTED TARGET CREDENTIAL]")
        for secret in credential_fragments(credentials):
            text = text.replace(secret, "[REDACTED TARGET CREDENTIAL]")
        public_headers = {
            k.lower(): redact(v)
            for k, v in headers.items()
            if k.lower()
            not in (
                "set-cookie",
                "authorization",
                "cookie",
                "www-authenticate",
                "proxy-authenticate",
            )
        }
        for key, value in list(public_headers.items()):
            for secret in credential_fragments(credentials) + private_fragments:
                if not secret:
                    continue
                value = value.replace(secret, "[REDACTED TARGET CREDENTIAL]")
            public_headers[key] = value[:4096]
        result = {
            "observation_id": observation_id,
            "url": redact(url),
            "status": status,
            "headers": public_headers,
            "body": redact(text)[:65536],
            "body_sha256": digest(content),
            "bytes": len(content),
            "identity_id": body.identity_id,
            "elapsed": time.monotonic() - started,
            "trust": "untrusted_target_data",
        }
        chain.append(
            {
                "url": redact(url),
                "status": status,
                "sha256": digest(content),
                "observation_id": observation_id,
            }
        )
        with session() as db:
            row = db.get(Document, observation_id)
            v = row.value()
            v.update(state="completed", response=result)
            row.data = canonical(v)
            db.commit()
        if 300 <= status < 400 and body.max_redirects:
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
            continue
        result["chain"] = chain
        return result
    raise Denied("No target response")
