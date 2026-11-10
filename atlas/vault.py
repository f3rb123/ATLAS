"""Per-secret AES256-GCM DEK, KEK wrapping, identity-bound AAD. No read-back API."""

import base64, json, os, re
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import settings
from .db import digest


def b64(b):
    return base64.b64encode(b).decode()


def un64(s):
    return base64.b64decode(s, validate=True)


def master():
    p = Path(settings().master_key_file)
    if not p.is_file():
        raise RuntimeError("Missing secrets master key file")
    if p.stat().st_mode & 0o077:
        raise RuntimeError("Master key file must be mode 0600 or 0400")
    k = p.read_bytes()
    if len(k) != 32:
        raise RuntimeError("Invalid master key")
    return k


def seal(text, identity, key=None):
    dek = os.urandom(32)
    n = os.urandom(12)
    w = os.urandom(12)
    aad = identity.encode()
    return json.dumps(
        {
            "version": 1,
            "key_version": digest(key or master())[:12],
            "nonce": b64(n),
            "wrapped_nonce": b64(w),
            "ciphertext": b64(AESGCM(dek).encrypt(n, text.encode(), aad)),
            "wrapped_dek": b64(AESGCM(key or master()).encrypt(w, dek, aad)),
        }
    )


def open_secret(blob, identity, key=None):
    d = json.loads(blob)
    aad = identity.encode()
    dek = AESGCM(key or master()).decrypt(
        un64(d["wrapped_nonce"]), un64(d["wrapped_dek"]), aad
    )
    return AESGCM(dek).decrypt(un64(d["nonce"]), un64(d["ciphertext"]), aad).decode()


def rewrap(blob, identity, old, new):
    d = json.loads(blob)
    aad = identity.encode()
    dek = AESGCM(old).decrypt(un64(d["wrapped_nonce"]), un64(d["wrapped_dek"]), aad)
    n = os.urandom(12)
    d.update(
        wrapped_nonce=b64(n),
        wrapped_dek=b64(AESGCM(new).encrypt(n, dek, aad)),
        key_version=digest(new)[:12],
    )
    return json.dumps(d)


def redact(text):
    # Public advisory text can contain credentials copied from source examples.
    # Redact recognizable credential forms before normalized content is indexed.
    text = re.sub(
        (
            r"(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
            r".*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        "[REDACTED PRIVATE KEY]",
        text,
    )
    text = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED AWS KEY]", text)
    text = re.sub(r"\bsgp_[A-Za-z0-9]{20,}\b", "[REDACTED SOURCEGRAPH TOKEN]", text)
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b",
        "[REDACTED JWT]",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:aws_secret_access_key|aws_session_token|x-amz-security-token)\b\s*[=:]\s*[\"']?)[^\s,;\"']+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(\bcurl\b[^\r\n]*?\s(?:-u|--user)(?:\s+|=)[\"']?)[^\s\"']+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(https?://)[^/\s@]+@", r"\1[REDACTED]@", text)
    text = re.sub(
        r"(?i)([?&](?:api[_-]?key|access[_-]?token|token|password|secret)=)[^&\s]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(bearer\s+|[\"']?\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret(?:[_-]?key|[_-]?token)?|token|password|authorization)\b[\"']?\s*[=:]\s*[\"']?)[^\s,;\"']+",
        r"\1[REDACTED]",
        text,
    )
    return re.sub(
        r"\b(?:sk-|ghp_|gho_|github_pat_|glpat-|xox[baprs]-)[A-Za-z0-9_-]+",
        "[REDACTED]",
        text,
    )


def rotate_database_keys(db, new_key, old_key=None):
    """Transactional DEK rewrapping. Operator freezes services and switches KEK after commit."""
    if len(new_key) != 32:
        raise ValueError("New KEK must be 32 bytes")
    from .db import User, Document, canonical, append

    old_key = old_key or master()
    count = 0
    from .gateway import secret_identity

    for d in db.query(Document).filter_by(kind="provider").with_for_update():
        v = d.value()
        for field, identity in [
            ("secret", secret_identity(d.owner, d.id, v)),
            ("secret_headers", secret_identity(d.owner, d.id, v, "headers")),
        ]:
            if v.get(field):
                v[field] = rewrap(v[field], identity, old_key, new_key)
                count += 1
        d.data = canonical(v)
    for u in db.query(User).with_for_update():
        if u.totp:
            u.totp = rewrap(u.totp, f"totp:{u.id}", old_key, new_key)
            count += 1
    from .tool_registry import identity as integration_identity

    for row in db.query(Document).filter_by(kind="tool_integration").with_for_update():
        value = row.value()
        if value.get("secret"):
            value["secret"] = rewrap(
                value["secret"], integration_identity(row), old_key, new_key
            )
            row.data = canonical(value)
            count += 1
    if not settings().target_key_file:
        from .target_auth import derive_key, identity as target_identity

        for row in (
            db.query(Document).filter_by(kind="target_identity").with_for_update()
        ):
            value = row.value()
            value["secret"] = rewrap(
                value["secret"],
                target_identity(row),
                derive_key(old_key),
                derive_key(new_key),
            )
            row.data = canonical(value)
            count += 1
        from .target_sessions import session_identity

        for row in (
            db.query(Document).filter_by(kind="target_session").with_for_update()
        ):
            value = row.value()
            if value.get("secret"):
                value["secret"] = rewrap(
                    value["secret"],
                    session_identity(row),
                    derive_key(old_key),
                    derive_key(new_key),
                )
                row.data = canonical(value)
                count += 1
    for d in db.query(Document).filter_by(kind="totp_pending").with_for_update():
        s = db.get(__import__("atlas.db", fromlist=["Session"]).Session, d.owner)
        if not s:
            db.delete(d)
            continue
        v = d.value()
        v["secret"] = rewrap(v["secret"], f"totp:{s.user_id}", old_key, new_key)
        d.data = canonical(v)
        count += 1
    append(
        db,
        "key-management",
        "host_operator",
        "kek_rewrapped",
        {
            "old_version": digest(old_key)[:12],
            "new_version": digest(new_key)[:12],
            "envelopes": count,
        },
    )
    return count
