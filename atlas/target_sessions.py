"""Explicit JSON-login flows and encrypted, run-bound target sessions."""

import json
import time
from http.cookies import SimpleCookie

from .db import Document, append, canonical, digest, document, session, transaction_lock
from .policy import Denied, request
from .target_auth import (
    LoginConfig,
    credential_fragments,
    identity,
    pinned_identity,
    target_key,
)
from .vault import open_secret, seal


def session_id(run_id, profile_id, version):
    return digest("target-session:" + run_id + ":" + profile_id + ":" + str(version))[
        :36
    ]


def session_identity(row):
    return "target-session:" + row.owner + ":" + row.id


def prepare(body, url, actor):
    from .target_transport import TargetRequest, execute, validate_run

    if not body.identity_id:
        return
    for attempt in range(120):
        with session() as db:
            run = db.get(Document, body.run_id)
            if not run:
                raise Denied("Run unavailable")
            run_value, run_scope, _ = validate_run(db, run, body)
            profile = pinned_identity(db, run, body.identity_id, url)
            if profile.value().get("kind") != "json_login":
                return
            login = LoginConfig.model_validate(
                json.loads(
                    open_secret(
                        profile.value()["secret"], identity(profile), key=target_key()
                    )
                )["login"]
            )
            id = session_id(run.id, profile.id, profile.version)
            transaction_lock(db, "target-session:" + id)
            cached = db.query(Document).filter_by(id=id).with_for_update().first()
            value = cached.value() if cached else {}
            if (
                value.get("state") == "active"
                and value.get("expires_at", 0) > time.time()
            ):
                return
            if (
                value.get("state") == "refreshing"
                and value.get("lease_until", 0) > time.time()
            ):
                db.commit()
                waiting = True
            else:
                if value.get("refreshes", 0) >= login.max_refreshes:
                    raise Denied(
                        "Target login refresh quota exhausted; operator session update required"
                    )
                cached = cached or document(db, "target_session", run.owner, {}, id)
                cached.data = canonical(
                    {
                        "run_id": run.id,
                        "profile_id": profile.id,
                        "state": "refreshing",
                        "lease_until": max(
                            time.time() + 45, run_value.get("next_request_at", 0) + 30
                        ),
                        "refreshes": value.get("refreshes", 0) + 1,
                    }
                )
                append(
                    db,
                    run.id,
                    actor,
                    "target_login_reserved",
                    {"identity_id": profile.id, "session_id": id},
                    run.value()["campaign_id"],
                )
                db.commit()
                waiting = False
        if not waiting:
            break
        time.sleep(0.25)
    else:
        raise Denied("Target login is busy; no credential replay attempted")

    def capture(status, headers, content):
        if not 200 <= status < 300:
            raise Denied("Target login rejected; response details withheld")
        if login.cookie_names:
            cookies = SimpleCookie()
            for key, value in headers.items():
                if key.lower() == "set-cookie":
                    for line in value.splitlines():
                        cookies.load(line)
            if not all(name in cookies for name in login.cookie_names):
                raise Denied(
                    "Target login did not return the configured session cookies"
                )
            credential = {
                "Cookie": "; ".join(
                    name + "=" + cookies[name].value for name in login.cookie_names
                )
            }
            ttl = login.max_session_seconds
        else:
            try:
                data = json.loads(content)
                token = data
                for key in login.token_path:
                    token = token[key]
                if (
                    not isinstance(token, str)
                    or not 1 <= len(token) <= 8192
                    or any(ord(c) < 33 or ord(c) == 127 for c in token)
                ):
                    raise ValueError("Invalid token")
                credential = {"Authorization": "Bearer " + token}
                ttl = (
                    min(
                        login.max_session_seconds,
                        int(data.get("expires_in", login.max_session_seconds)),
                    )
                    if isinstance(data, dict)
                    else login.max_session_seconds
                )
                if ttl < 10:
                    raise ValueError("Expired token")
            except (ValueError, TypeError, KeyError):
                raise Denied(
                    "Target login response does not match the configured token path"
                ) from None
        with session() as db:
            cached = db.get(Document, id)
            value = cached.value()
            value.update(
                state="active",
                expires_at=time.time() + ttl - 5,
                secret=seal(
                    canonical(credential), session_identity(cached), key=target_key()
                ),
            )
            cached.data = canonical(value)
            db.commit()
        return credential_fragments(credential) + list(login.credentials.values())

    try:
        execute(
            TargetRequest(
                run_id=body.run_id,
                url=login.url,
                method="POST",
                body=canonical(login.credentials),
                headers={"Content-Type": "application/json"},
                purpose="authentication",
                task_id=body.task_id,
                lease_token=body.lease_token,
                request_deadline=body.request_deadline,
            ),
            actor,
            transport=request,
            private_capture=capture,
        )
    except Exception:
        with session() as db:
            cached = db.get(Document, id)
            value = cached.value()
            value.update(state="failed", lease_until=0)
            value.pop("secret", None)
            cached.data = canonical(value)
            db.commit()
        raise
