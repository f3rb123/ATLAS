"""Bounded resumable corpus upload; durable restoration runs in the corpus worker."""

import math
import os
from pathlib import Path
from uuid import UUID

from pydantic import Field

from .config import settings
from .corpus_package import MAX_ARCHIVE_BYTES, file_digest
from .db import Document, Knowledge, canonical, digest, document, now, transaction_lock
from .policy import Strict

PART_BYTES = 8 * 1024**2


class UploadInput(Strict):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    byte_size: int = Field(gt=0, le=MAX_ARCHIVE_BYTES)
    filename: str = Field(default="corpus.zip", min_length=1, max_length=200)


def root_for(id):
    if len(id) != 36 or str(UUID(id)) != id:
        raise ValueError("Invalid upload identity")
    root = Path(settings().data_dir).resolve() / "corpus_uploads" / id
    if root.is_symlink() or root.parent.is_symlink():
        raise ValueError("Unsafe upload destination")
    return root


def status(row):
    value = row.value()
    return {
        "id": row.id,
        "status": value["status"],
        "sha256": value["sha256"],
        "filename": value["filename"],
        "byte_size": value["byte_size"],
        "uploaded_bytes": sum(p["bytes"] for p in value.get("parts", [])),
        "uploaded_parts": len(value.get("parts", [])),
        "total_parts": math.ceil(value["byte_size"] / PART_BYTES),
        "part_bytes": PART_BYTES,
        "job_id": value.get("job_id"),
        "result": value.get("result"),
    }


def start(db, owner, body):
    transaction_lock(db, "corpus:uploads")
    if db.query(Knowledge).first():
        raise ValueError(
            "Package restore requires an empty corpus; existing knowledge is preserved"
        )
    active = [
        d
        for d in db.query(Document).filter_by(kind="corpus_upload")
        if d.value()["status"] in ("uploading", "queued", "running")
    ]
    if len(active) >= 2:
        raise ValueError("Two corpus transfers are already active")
    retained = sum(
        d.value()["byte_size"]
        for d in db.query(Document).filter_by(kind="corpus_upload")
        if d.value()["status"] != "cancelled"
    )
    if retained + body.byte_size > 2 * MAX_ARCHIVE_BYTES:
        raise ValueError(
            "Corpus upload storage quota reached; cancel blocked uploads first"
        )
    row = document(
        db,
        "corpus_upload",
        owner,
        {**body.model_dump(), "status": "uploading", "parts": [], "created_at": now()},
    )
    root_for(row.id).mkdir(mode=0o700, parents=True)
    return row


def accept_part(db, row, index, data):
    transaction_lock(db, "corpus:uploads")
    db.refresh(row, with_for_update=True)
    value = row.value()
    if value["status"] != "uploading":
        raise ValueError("Upload is not accepting parts")
    count = math.ceil(value["byte_size"] / PART_BYTES)
    if not 0 <= index < count:
        raise ValueError("Part index outside declared archive")
    expected = min(PART_BYTES, value["byte_size"] - index * PART_BYTES)
    if len(data) != expected:
        raise ValueError("Part size differs from declared archive")
    parts = value["parts"]
    part = {"index": index, "bytes": len(data), "sha256": digest(data)}
    if index < len(parts):
        if parts[index] != part:
            raise ValueError("An existing part has different contents")
        return status(row)
    if index != len(parts):
        raise ValueError("Upload parts in order; resume from uploaded_parts")
    path = root_for(row.id) / f"{index:04d}.part"
    if path.is_symlink():
        raise ValueError("Unsafe upload part")
    if path.exists():
        if file_digest(path) != part["sha256"]:
            raise ValueError("Upload part collision")
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    parts.append(part)
    row.data = canonical(value)
    db.flush()
    return status(row)


def finish(db, row):
    transaction_lock(db, "corpus:uploads")
    db.refresh(row, with_for_update=True)
    value = row.value()
    if value["status"] in ("queued", "running", "completed"):
        return status(row)
    if value["status"] != "uploading" or len(value["parts"]) != math.ceil(
        value["byte_size"] / PART_BYTES
    ):
        raise ValueError("Upload all declared parts before completing")
    root = root_for(row.id)
    path = root / "corpus.zip"
    temporary = root / "assembling.tmp"
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            for part in value["parts"]:
                source_path = root / f"{part['index']:04d}.part"
                if (
                    source_path.is_symlink()
                    or file_digest(source_path) != part["sha256"]
                ):
                    raise ValueError("Upload part changed before assembly")
                with source_path.open("rb") as source:
                    for block in iter(lambda: source.read(1024**2), b""):
                        output.write(block)
            output.flush()
            os.fsync(output.fileno())
        if (
            temporary.stat().st_size != value["byte_size"]
            or file_digest(temporary) != value["sha256"]
        ):
            raise ValueError(
                "Archive checksum mismatch; cancel and upload the correct package"
            )
        if path.is_symlink():
            raise ValueError("Unsafe archive destination")
        if path.exists() and file_digest(path) != value["sha256"]:
            raise ValueError("Existing uploaded archive differs")
        os.replace(temporary, path)
        job = document(
            db,
            "corpus_transfer_request",
            row.owner,
            {
                "status": "queued",
                "path": str(path),
                "sha256": value["sha256"],
                "upload_id": row.id,
                "lease_until": 0,
                "attempts": 0,
            },
        )
        value.update(status="queued", job_id=job.id)
        row.data = canonical(value)
        db.flush()
        return status(row)
    finally:
        temporary.unlink(missing_ok=True)


def cancel(db, row):
    transaction_lock(db, "corpus:uploads")
    db.refresh(row, with_for_update=True)
    value = row.value()
    if value["status"] not in ("uploading", "blocked", "cancelled"):
        raise ValueError(
            "A queued/running restore must finish before its archive can be removed"
        )
    root = root_for(row.id)
    for path in root.iterdir():
        if path.name in ("assembling.tmp", "corpus.zip") or (
            len(path.name) == 9 and path.name[:4].isdigit() and path.suffix == ".part"
        ):
            path.unlink(missing_ok=True)
    value.update(status="cancelled", parts=[])
    row.data = canonical(value)
    db.flush()
    return status(row)
