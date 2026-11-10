"""Host-only raw-file credential loading and explicit provider provisioning.

No credential value is returned, logged, placed in process arguments or written
to dotenv files. ProviderInput.api_key is the existing write-only encrypted
application binding; ATLAS_PROVIDER_KEY_FILE selects its raw input file.
"""

import hmac
import json
import os
import re
import secrets
import stat
from pathlib import Path

from .config import settings
from .db import Document, User, canonical, digest, document, now
from .gateway import (
    ModelInput,
    ProviderInput,
    construct_adapter,
    create_provider,
    secret_identity,
)
from .vault import open_secret


def read_key_file(filename=None):
    selector = filename or settings().provider_key_file
    if not selector:
        raise ValueError(
            "Set ATLAS_PROVIDER_KEY_FILE or pass the exact raw-key file path"
        )
    path = Path(selector)
    if path.is_symlink():
        raise ValueError(
            "Credential selector must name a regular file, not a symbolic link"
        )
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or not 1 <= info.st_size <= 8192
        ):
            raise ValueError(
                "Credential file requires restrictive permissions and a bounded raw key"
            )
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(8193)
        try:
            key = raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError:
            raise ValueError("Credential file is not a valid raw UTF-8 key") from None
        if not key or any(ord(c) < 33 or ord(c) == 127 for c in key):
            raise ValueError(
                "Credential file must contain one raw key with optional trailing newlines"
            )
        return key
    finally:
        os.close(fd)


def local_owner(db, email=None, bootstrap=False):
    owners = db.query(User).filter_by(role="owner_admin").all()
    if email:
        owners = [u for u in owners if u.email == email.strip().lower()]
    if len(owners) == 1:
        return owners[0]
    if owners or db.query(User).first():
        raise ValueError(
            "Select the existing owner email explicitly; no accounts were modified"
        )
    if not bootstrap or settings().production:
        raise ValueError(
            "Bootstrap the owner first; generated owner setup is limited to explicit local development"
        )
    from .auth import bootstrap as create_owner
    from .auth import bootstrap_token

    credential_path = Path(settings().data_dir) / "operator-access.json"
    credential_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    password = secrets.token_urlsafe(48)
    selected_email = email or "owner@atlas.local"
    token = bootstrap_token(db)
    owner = create_owner(db, token, selected_email, password)
    fd = os.open(credential_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(
            {
                "email": selected_email,
                "password": password,
                "purpose": "Private local operator setup; never include in release artifacts",
                "created_at": now(),
            },
            output,
        )
        output.write("\n")
    db.commit()
    return owner


def configure_provider(
    db,
    key_file,
    base_url,
    primary_model,
    verifier_model,
    owner_email=None,
    bootstrap=False,
):
    key = read_key_file(key_file)
    owner = local_owner(db, owner_email, bootstrap)
    id = digest("managed-provider:" + owner.id + ":" + base_url)[:36]
    provider = db.get(Document, id)
    if provider:
        v = provider.value()
        if (
            provider.kind != "provider"
            or provider.owner != owner.id
            or v["base_url"] != base_url
        ):
            raise ValueError("Managed provider identity collision")
        previous = open_secret(v["secret"], secret_identity(owner.id, provider.id, v))
        if not hmac.compare_digest(previous, key):
            raise ValueError(
                "Existing provider key differs; use the explicit protected rotation flow"
            )
    else:
        provider = create_provider(
            db,
            owner.id,
            ProviderInput(
                display_name="HackerAI",
                base_url=base_url,
                adapter_type="custom_openai_compatible",
                api_key=key,
            ),
            id=id,
        )
        db.commit()
    result = {
        "provider_id": provider.id,
        "owner_id": owner.id,
        "credential_selector": "ATLAS_PROVIDER_KEY_FILE",
        "application_binding": "ProviderInput.api_key -> encrypted provider secret",
        "credential_loaded": True,
        "credential_file_unchanged": True,
        "credential_value_exposed": False,
        "base_url": base_url,
        "protocol": "custom_openai_compatible",
    }
    try:
        models = construct_adapter(provider).list_models()
    except (ValueError, OSError):
        return {
            **result,
            "status": "configured_discovery_blocked_or_failed",
            "requested_models_available": None,
            "requested_model_ids": [primary_model, verifier_model],
            "models_verified": False,
            "inference_calls": 0,
            "substituted_models": False,
        }
    available = {
        m.get("id") or m.get("model_id") for m in models if isinstance(m, dict)
    }
    available = {
        m
        for m in available
        if isinstance(m, str) and re.fullmatch(r"[a-zA-Z0-9_.:/-]+", m) and key not in m
    }
    missing = sorted({primary_model, verifier_model} - available)
    result.update(
        available_model_ids=sorted(x for x in available if isinstance(x, str)),
        requested_models_available=not missing,
        missing_models=missing,
    )
    if missing:
        return {
            **result,
            "status": "requested_models_unavailable",
            "substituted_models": False,
        }
    aliases = {
        "reasoning": primary_model,
        "fast": primary_model,
        "coding": primary_model,
        "verifier": verifier_model,
        "deep_research": verifier_model,
    }
    model_rows = {}
    for remote in {primary_model, verifier_model}:
        model_id = digest("managed-model:" + provider.id + ":" + remote)[:36]
        row = db.get(Document, model_id)
        if row is None:
            spec = ModelInput(
                model_id=remote,
                display_name=remote,
                context_window=64000,
                max_output_tokens=4096,
                capabilities={"structured": True, "tools": True},
                pricing_status="unverified",
            )
            row = document(
                db,
                "provider_model",
                owner.id,
                {
                    **spec.model_dump(),
                    "provider_id": provider.id,
                    "verified_structured": False,
                    "verified_tools": False,
                    "capability_status": "requires_probe",
                },
                model_id,
            )
        model_rows[remote] = row
    for alias, remote in aliases.items():
        rows = [
            r
            for r in db.query(Document).filter_by(kind="alias", owner=owner.id)
            if r.value()["alias"] == alias
        ]
        if rows:
            existing = rows[0].value()
            if (
                existing["provider_id"] != provider.id
                or existing["model_id"] != model_rows[remote].id
            ):
                raise ValueError(
                    "An existing capability alias differs; explicit operator reassignment required"
                )
        else:
            document(
                db,
                "alias",
                owner.id,
                {
                    "alias": alias,
                    "provider_id": provider.id,
                    "model_id": model_rows[remote].id,
                },
            )
    v = provider.value()
    v.update(health_status="tested", last_tested=now())
    provider.data = canonical(v)
    db.commit()
    return {
        **result,
        "status": "configured_models_require_probe",
        "aliases": aliases,
        "model_record_ids": {name: row.id for name, row in model_rows.items()},
        "pricing_status": "unverified",
        "substituted_models": False,
    }
