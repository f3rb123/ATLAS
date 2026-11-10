"""Write-only, origin-bound target identities. Never included in model context."""

import json
import stat
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import Field, model_validator

from .config import settings
from .db import Document, append, canonical, document, now
from .policy import Denied, Strict, Scope, match, normalize
from .vault import master, open_secret, seal


class LoginConfig(Strict):
    url: str = Field(max_length=4096)
    credentials: dict[str, str] = Field(min_length=1, max_length=10, repr=False)
    token_path: list[str] = Field(default=["access_token"], max_length=5)
    cookie_names: list[str] = Field(default=[], max_length=5)
    max_session_seconds: int = Field(default=600, ge=30, le=3600)
    max_refreshes: int = Field(default=2, ge=1, le=5)

    @model_validator(mode="after")
    def explicit_endpoint(self):
        normalize(self.url)
        if urlsplit(self.url).query or urlsplit(self.url).fragment:
            raise ValueError(
                "Login credentials belong in the protected body, never in URL parameters"
            )
        if any(
            not name or len(name) > 100 or any(ord(c) < 33 for c in name)
            for name in self.cookie_names + self.token_path
        ):
            raise ValueError("Invalid configured token or cookie field")
        return self


class TargetIdentityInput(Strict):
    name: str = Field(min_length=1, max_length=100)
    origin: str = Field(max_length=4096)
    paths: list[str] = Field(default=["/"], min_length=1, max_length=50)
    headers: dict[str, str] = Field(default_factory=dict, max_length=3, repr=False)
    login: LoginConfig | None = Field(default=None, repr=False)
    owned_test_account: bool
    expires: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_identity(self):
        _, _, _, path, _ = normalize(self.origin)
        if path != "/" or urlsplit(self.origin).query or urlsplit(self.origin).fragment:
            raise ValueError("Identity origin cannot have a path/query/fragment")
        if not self.owned_test_account:
            raise ValueError("Target identities must be authorized owned test accounts")
        if any(not p.startswith("/") or "?" in p or "#" in p for p in self.paths):
            raise ValueError("Identity paths must be explicit URL paths")
        if any(
            k.lower() not in ("authorization", "cookie", "x-api-key")
            or not v
            or len(v) > 8192
            or any(ord(c) < 32 or ord(c) > 126 for c in k + v)
            for k, v in self.headers.items()
        ):
            raise ValueError(
                "Only bounded Authorization, Cookie and X-API-Key bindings are supported"
            )
        if bool(self.headers) == bool(self.login):
            raise ValueError(
                "Select exactly one static credential or explicit login flow"
            )
        if self.login:
            login_url, _, _, _, _ = normalize(self.login.url)
            origin_url = normalize(self.origin)[0].rstrip("/")
            if login_url.split("/", 3)[:3] != origin_url.split("/", 3)[:3]:
                raise ValueError("Login must use the exact target identity origin")
            if any(
                not key or len(key) > 100 or len(value) > 8192
                for key, value in self.login.credentials.items()
            ):
                raise ValueError("Login credential fields exceed their bounds")
        return self


def derive_key(master_bytes):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"ATLAS-target-identities-v1",
        info=b"target-credentials-only",
    ).derive(master_bytes)


def target_key():
    filename = settings().target_key_file
    if filename:
        p = Path(filename)
        info = p.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or len(data := p.read_bytes()) != 32
        ):
            raise Denied(
                "Target credential key is unavailable or has unsafe permissions"
            )
        return data
    if settings().production:
        raise Denied("Production target credential key requires its dedicated selector")
    return derive_key(master())


def identity(row):
    return f"target-identity:{row.owner}:{row.id}:{row.value()['campaign_id']}"


def credential_fragments(headers):
    import base64
    from urllib.parse import quote

    fragments = []
    for name, value in headers.items():
        fragments.append(value)
        if name.lower() == "authorization" and " " in value:
            scheme, token = value.split(" ", 1)
            fragments.append(token)
            if scheme.lower() == "basic":
                try:
                    fragments.extend(
                        base64.b64decode(token, validate=True).decode().split(":", 1)
                    )
                except (ValueError, UnicodeError):
                    pass
        if name.lower() == "cookie":
            fragments.extend(
                item.split("=", 1)[1].strip()
                for item in value.split(";")
                if "=" in item
            )
    fragments += [quote(item, safe="") for item in fragments]
    return sorted({item for item in fragments if len(item) >= 4}, key=len, reverse=True)


def safe(row):
    return {
        "id": row.id,
        "version": row.version,
        **{k: v for k, v in row.value().items() if k != "secret"},
        "credential_configured": True,
    }


def create(db, campaign, body, actor):
    policy = db.get(Document, campaign.value()["policy_id"])
    scope = Scope.model_validate(policy.value()["scope"])
    origin, h, p, _, scheme = normalize(body.origin)
    if not any(
        any(match(r, h, p, path, scheme, "GET") for r in scope.allow)
        and not any(match(r, h, p, path, scheme, "GET") for r in scope.deny)
        for path in body.paths
    ):
        raise Denied("Identity origin must be in the campaign's authorized scope")
    if body.login:
        from .policy import nondestructive_target_request

        nondestructive_target_request(
            scope,
            body.login.url,
            "POST",
            canonical(body.login.credentials),
            "authentication",
        )
        _, lh, lp, lpath, lscheme = normalize(body.login.url)
        if not any(
            match(r, lh, lp, lpath, lscheme, "POST") for r in scope.allow
        ) or any(match(r, lh, lp, lpath, lscheme, "POST") for r in scope.deny):
            raise Denied("Login endpoint requires explicit POST scope authorization")
    row = document(
        db,
        "target_identity",
        campaign.owner,
        {
            "name": body.name,
            "campaign_id": campaign.id,
            "origin": origin.rstrip("/"),
            "paths": body.paths,
            "owned_test_account": True,
            "expires": body.expires,
            "enabled": True,
            "created_at": now(),
            "header_names": list(body.headers),
            "kind": "json_login" if body.login else "static",
            "login_url": body.login.url if body.login else None,
        },
    )
    value = row.value()
    value["secret"] = seal(
        canonical({"login": body.login.model_dump()})
        if body.login
        else canonical(body.headers),
        identity(row),
        key=target_key(),
    )
    row.data = canonical(value)
    append(
        db,
        campaign.id,
        actor,
        "target_identity_created",
        {"id": row.id, "name": body.name},
    )
    return row


def pinned_identity(db, run, identity_id, url):
    import time

    if not identity_id:
        return None
    row = db.get(Document, identity_id)
    pin = run.value().get("target_identities", {}).get(identity_id)
    if (
        not row
        or row.kind != "target_identity"
        or row.owner != run.owner
        or pin != row.version
    ):
        raise Denied("Target identity is not pinned to this run")
    value = row.value()
    normalized, _, _, path, _ = normalize(url)
    if (
        value["campaign_id"] != run.value()["campaign_id"]
        or not value.get("enabled")
        or (value.get("expires") and value["expires"] < time.time())
    ):
        raise Denied("Target identity is disabled, expired or outside this campaign")
    if normalized.split("/", 3)[:3] != (value["origin"] + "/").split("/", 3)[
        :3
    ] or not any(
        path == p or path.startswith(p.rstrip("/") + "/") for p in value["paths"]
    ):
        raise Denied("Target identity cannot be sent outside its pinned origin/paths")
    return row


def resolve_headers(db, run, identity_id, url):
    import time

    row = pinned_identity(db, run, identity_id, url)
    if row is None:
        return {}
    if row.value().get("kind") == "json_login":
        from .target_sessions import session_id, session_identity

        current = db.get(Document, session_id(run.id, row.id, row.version))
        if (
            not current
            or current.value().get("state") != "active"
            or current.value().get("expires_at", 0) <= time.time()
        ):
            raise Denied("Target login session is unavailable or expired")
        return json.loads(
            open_secret(
                current.value()["secret"], session_identity(current), key=target_key()
            )
        )
    return json.loads(
        open_secret(row.value()["secret"], identity(row), key=target_key())
    )
