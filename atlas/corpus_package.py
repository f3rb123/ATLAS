"""Verified, identity-preserving corpus restore into an empty application store.

Archives are data. Restoration never executes package code, runs import jobs,
re-embeds text, changes the model registry, or replaces an existing corpus.
"""

import hashlib
import json
import math
import os
import re
import stat
import tempfile
import zipfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from uuid import UUID

from sqlalchemy import insert, text

from .config import settings
from .db import (
    Alias,
    Chunk,
    Document,
    Knowledge,
    append,
    canonical,
    digest,
    document,
    now,
    session,
    transaction_lock,
)
from .embeddings import cache_root, manifest
from .records import Record
from .vector_transfer import VectorRow

MAX_ARCHIVE_BYTES = 1024**3
MAX_EXPANDED_BYTES = 2 * 1024**3
MAX_ENTRIES = 100000
MAX_LINE_BYTES = 1024**2
MAX_RECORDS = 100000
MAX_VECTORS = 250000
MAX_ALIASES = 500000
MAX_TEXT_BYTES = 128 * 1024**2
SHA256 = re.compile(r"^[a-f0-9]{64}$")
RECORDS = "corpus.semantic.records.jsonl"
VECTORS = "corpus.semantic.vectors.jsonl"
GOVERNANCE = "corpus.governance.jsonl"
GOVERNANCE_KINDS = {
    "corpus_exclusion_review",
    "corpus_job",
    "corpus_provenance",
    "import_error",
}


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024**2), b""):
            h.update(block)
    return h.hexdigest()


@contextmanager
def package(path, expected_sha256):
    path = Path(path)
    if not SHA256.fullmatch(expected_sha256 or ""):
        raise ValueError("An explicit SHA256 is required")
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > MAX_ARCHIVE_BYTES
    ):
        raise ValueError("Corpus archive missing, unsafe or exceeds 1 GiB")
    # Keep one descriptor open across preflight and import to prevent path swaps.
    with path.open("rb") as source:
        h = hashlib.sha256()
        for block in iter(lambda: source.read(1024**2), b""):
            h.update(block)
        if h.hexdigest() != expected_sha256:
            raise ValueError("Corpus archive checksum mismatch")
        source.seek(0)
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            names = set()
            expanded = 0
            for info in infos:
                p = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if (
                    p.is_absolute()
                    or ".." in p.parts
                    or "\\" in info.filename
                    or "\x00" in info.filename
                    or info.filename in names
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or info.flag_bits & 1
                ):
                    raise ValueError("Unsafe or duplicate archive member")
                names.add(info.filename)
                expanded += info.file_size
            if len(infos) > MAX_ENTRIES or expanded > MAX_EXPANDED_BYTES:
                raise ValueError("Corpus archive expansion quota exceeded")
            if (
                not {RECORDS, VECTORS, GOVERNANCE, "knowledge/embedding_model.json"}
                <= names
            ):
                raise ValueError("Corpus archive missing required components")
            yield archive


def json_rows(archive, name):
    with archive.open(name) as source:
        while line := source.readline(MAX_LINE_BYTES + 1):
            if len(line) > MAX_LINE_BYTES:
                raise ValueError("Corpus row exceeds quota")
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError()  # noqa: TRY004 - public package-validation boundary
            except (ValueError, UnicodeDecodeError):
                raise ValueError("Invalid corpus JSON object") from None
            yield value


def raw_member(reference):
    if not isinstance(reference, str) or not reference:
        return None
    parts = PurePosixPath(reference).parts
    if "\\" in reference or ".." in parts or "\x00" in reference:
        raise ValueError("Unsafe corpus artifact reference")
    if "corpus_raw" not in parts:
        raise ValueError("Unrecognized corpus artifact reference")
    tail = parts[parts.index("corpus_raw") :]
    if len(tail) != 3 or not SHA256.fullmatch(tail[2]) or tail[1] != tail[2][:2]:
        raise ValueError("Invalid content-addressed artifact reference")
    return "/".join(tail)


def governance_data(row):
    if set(row) != {"created", "data", "id", "kind", "owner", "version"}:
        raise ValueError("Invalid governance document shape")
    if row["kind"] not in GOVERNANCE_KINDS:
        raise ValueError("Unexpected governance document type")
    if not isinstance(row["id"], str) or not 1 <= len(row["id"]) <= 36:
        raise ValueError("Invalid governance identity")
    if not isinstance(row["owner"], str) or not 1 <= len(row["owner"]) <= 36:
        raise ValueError("Invalid governance owner")
    data = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
    if not isinstance(data, dict):
        raise ValueError("Invalid governance payload")  # noqa: TRY004 - public validation boundary
    return data


def preflight(archive):
    """Validate every record, vector, CRC and pinned artifact before any writes."""
    from .corpus import category

    pinned = manifest()
    for name in ("knowledge/embedding_model.json", "CORPUS_REDACTIONS.json"):
        if name in archive.namelist() and archive.getinfo(name).file_size > 4 * 1024**2:
            raise ValueError("Corpus metadata exceeds quota")
    if json.loads(archive.read("knowledge/embedding_model.json")) != pinned:
        raise ValueError("Corpus model manifest differs from pinned registry")
    version = pinned["model"] + "@" + pinned["revision"]
    redactions = (
        json.loads(archive.read("CORPUS_REDACTIONS.json"))
        if "CORPUS_REDACTIONS.json" in archive.namelist()
        else {}
    )
    omitted_rows = redactions.get("withheld_raw_artifacts", [])
    omitted = {r.get("sha256") for r in omitted_rows}
    if len(omitted) != len(omitted_rows) or any(
        not isinstance(h, str) or not SHA256.fullmatch(h) for h in omitted
    ):
        raise ValueError("Invalid withheld artifact manifest")
    hashes = {}
    for info in archive.infolist():
        h = hashlib.sha256()
        with archive.open(info) as source:
            for block in iter(lambda: source.read(1024**2), b""):
                h.update(block)
        hashes[info.filename] = h.hexdigest()
        if info.filename.startswith("corpus_raw/"):
            member = raw_member(info.filename)
            if member != info.filename or PurePosixPath(member).name != h.hexdigest():
                raise ValueError("Raw artifact checksum mismatch")
            if h.hexdigest() in omitted:
                raise ValueError("Withheld artifact unexpectedly present")
    for name, expected in pinned["files_sha256"].items():
        member = "models/" + pinned["snapshot_relative_path"] + "/" + name
        if hashes.get(member) != expected:
            raise ValueError("Pinned model artifact checksum mismatch")
    ids, keys, aliases, chunks = set(), set(), {}, {}
    references = []
    categories = Counter()
    text_bytes = 0
    for value in json_rows(archive, RECORDS):
        try:
            r = Record.model_validate(value)
            UUID(r.record_id)
        except (ValueError, TypeError):
            raise ValueError("Record schema or identity validation failed") from None
        if (
            len(r.record_id) != 36
            or r.record_id in ids
            or r.canonical_key in keys
            or r.access_owner != "public"
            or not 1 <= len(r.canonical_key) <= 255
            or len(r.source.source_id) > 50
        ):
            raise ValueError("Duplicate, private or invalid record identity")
        ids.add(r.record_id)
        keys.add(r.canonical_key)
        if len(ids) > MAX_RECORDS:
            raise ValueError("Record quota exceeded")
        for alias in set(r.deduplication.source_aliases + [r.canonical_key]):
            if (
                not 1 <= len(alias) <= 255
                or aliases.setdefault(alias, r.record_id) != r.record_id
            ):
                raise ValueError("Alias collision or storage limit exceeded")
            if len(aliases) > MAX_ALIASES:
                raise ValueError("Alias quota exceeded")
        if not 1 <= len(r.content.chunks) <= 2000:
            raise ValueError("Record chunk quota exceeded")
        for i, chunk in enumerate(r.content.chunks):
            if (
                type(chunk.get("index")) is not int
                or chunk["index"] != i
                or not isinstance(chunk.get("text"), str)
                or chunk.get("embedding_version") != version
                or chunk.get("hash") != digest(chunk["text"])
            ):
                raise ValueError("Canonical chunk integrity mismatch")
            chunks[r.record_id, i] = chunk["text"]
            text_bytes += len(chunk["text"].encode("utf-8"))
            if len(chunks) > MAX_VECTORS or text_bytes > MAX_TEXT_BYTES:
                raise ValueError("Canonical chunk quota exceeded")
        references.append(
            (raw_member(r.content.raw_artifact_ref), r.source.content_hash_sha256)
        )
        if r.source.acquisition_artifact_ref:
            references.append(
                (
                    raw_member(r.source.acquisition_artifact_ref),
                    r.source.acquisition_hash_sha256,
                )
            )
        categories[category(r)] += 1
    if not ids:
        raise ValueError("Corpus package contains no records")
    vector_ids, vector_keys, parents, finished_groups = set(), set(), set(), set()
    previous = None
    for value in json_rows(archive, VECTORS):
        try:
            v = VectorRow.model_validate(value)
            UUID(v.id)
        except (ValueError, TypeError):
            raise ValueError("Vector schema or identity validation failed") from None
        key = v.record_id, v.position
        if (
            len(v.id) != 36
            or v.id in vector_ids
            or key in vector_keys
            or v.record_id not in ids
        ):
            raise ValueError("Duplicate vector identity or unknown parent")
        if previous != v.record_id:
            if v.record_id in finished_groups:
                raise ValueError("Vector parent groups must be contiguous")
            if previous:
                finished_groups.add(previous)
            previous = v.record_id
        if (
            v.embedding_model != version
            or len(v.embedding) != pinned["dimension"]
            or any(
                type(x) not in (float, int) or not math.isfinite(x)
                for x in value["embedding"]
            )
            or abs(math.sqrt(sum(x * x for x in v.embedding)) - 1) > 0.001
        ):
            raise ValueError("Vector model, dimension or numeric integrity mismatch")
        if key not in chunks or v.text != chunks[key]:
            raise ValueError("Vector text does not match canonical chunk")
        vector_ids.add(v.id)
        vector_keys.add(key)
        parents.add(v.record_id)
        if len(vector_ids) > MAX_VECTORS:
            raise ValueError("Vector quota exceeded")
    if vector_keys != set(chunks) or parents != ids:
        raise ValueError("Incomplete record/vector coverage")
    governance_ids = set()
    for row in json_rows(archive, GOVERNANCE):
        data = governance_data(row)
        if row["id"] in governance_ids:
            raise ValueError("Duplicate governance identity")
        governance_ids.add(row["id"])
        if len(governance_ids) > 10000:
            raise ValueError("Governance quota exceeded")
        if row["kind"] == "corpus_provenance":
            if row["owner"] not in ids:
                raise ValueError("Unknown provenance parent")
            source = data.get("record", {}).get("source", data.get("source", {}))
            ref = data.get("raw") or data.get("record", {}).get("content", {}).get(
                "raw_artifact_ref"
            )
            if ref:
                references.append((raw_member(ref), source.get("content_hash_sha256")))
        if row["kind"] == "corpus_exclusion_review" and data.get("raw_artifact_ref"):
            references.append(
                (raw_member(data["raw_artifact_ref"]), data.get("content_hash"))
            )
    encountered_omissions = set()
    for member, expected in references:
        if member is None:
            raise ValueError("Missing canonical raw artifact reference")
        if member in hashes:
            if expected and hashes[member] != expected:
                raise ValueError("Source/raw artifact hash mismatch")
        elif PurePosixPath(member).name in omitted:
            encountered_omissions.add(PurePosixPath(member).name)
        else:
            raise ValueError("Unexplained missing raw artifact")
    if encountered_omissions != omitted:
        raise ValueError("Unreconciled raw omission manifest")
    return {
        "records": len(ids),
        "vectors": len(vector_ids),
        "aliases": len(aliases),
        "governance_documents": len(governance_ids),
        "categories": dict(categories),
        "raw_artifacts": sum(n.startswith("corpus_raw/") for n in hashes),
        "withheld_raw_artifacts": sorted(omitted),
        "embedding_model": version,
        "dimension": pinned["dimension"],
        "model_artifacts_verified": True,
        "component_sha256": {n: hashes[n] for n in (RECORDS, VECTORS, GOVERNANCE)},
    }


def inspect_package(path, expected_sha256):
    with package(path, expected_sha256) as archive:
        result = preflight(archive)
    return {"sha256": expected_sha256, **result}


def install_file(root, relative, source, expected):
    """Exclusive atomic creation; never overwrite a recovered artifact."""
    root = Path(root).resolve()
    relative = PurePosixPath(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Unsafe artifact destination")
    target = root / relative
    for p in [target, *target.parents]:
        if p == root.parent:
            break
        if p.is_symlink():
            raise ValueError("Artifact destination contains a symbolic link")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.exists():
        if not target.is_file() or file_digest(target) != expected:
            raise ValueError("Existing artifact differs; refusing overwrite")
        return
    fd, temporary = tempfile.mkstemp(prefix=".atlas-transfer-", dir=target.parent)
    try:
        h = hashlib.sha256()
        with os.fdopen(fd, "wb") as output:
            for block in iter(lambda: source.read(1024**2), b""):
                output.write(block)
                h.update(block)
            output.flush()
            os.fsync(output.fileno())
        if h.hexdigest() != expected:
            raise ValueError("Artifact changed during transfer")
        try:
            os.link(temporary, target)
        except FileExistsError:
            if file_digest(target) != expected:
                raise ValueError("Concurrent artifact collision") from None
    finally:
        Path(temporary).unlink(missing_ok=True)


def relocate(value, root):
    """Only known artifact-reference fields are relocated, never source text."""
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if key in {"raw", "raw_artifact_ref", "acquisition_artifact_ref"} and child:
                result[key] = str(root / raw_member(child))
            else:
                result[key] = (
                    relocate(child, root) if isinstance(child, (dict, list)) else child
                )
        return result
    if isinstance(value, list):
        return [relocate(v, root) for v in value]
    return value


def fingerprint(db, governance_ids):
    h = hashlib.sha256()
    for model, columns, order in (
        (
            Knowledge,
            (
                Knowledge.id,
                Knowledge.owner,
                Knowledge.canonical_key,
                Knowledge.category,
                Knowledge.source,
                Knowledge.title,
                Knowledge.content_hash,
                Knowledge.record,
            ),
            Knowledge.id,
        ),
        (Alias, (Alias.alias, Alias.record_id), Alias.alias),
        (
            Chunk,
            (
                Chunk.id,
                Chunk.record_id,
                Chunk.position,
                Chunk.text,
                Chunk.embedding,
                Chunk.embedding_model,
            ),
            Chunk.id,
        ),
    ):
        h.update(model.__tablename__.encode())
        for row in db.query(*columns).order_by(order).yield_per(100):
            h.update(canonical(list(row)).encode())
            h.update(b"\n")
    for row in (
        db.query(Document).filter(Document.id.in_(governance_ids)).order_by(Document.id)
    ):
        h.update(
            canonical(
                [row.id, row.kind, row.owner, row.data, row.version, row.created]
            ).encode()
        )
    return h.hexdigest()


def restore_package(path, expected_sha256, actor="host_operator"):
    """Preflight then add an entire verified package in one SQL transaction."""
    pinned = manifest()
    if settings().embedding_model != pinned["model"]:
        raise ValueError("Corpus restore requires the pinned semantic model")
    with package(path, expected_sha256) as archive:
        checked = preflight(archive)
        root = Path(settings().data_dir).resolve()
        transfer_id = digest("corpus-transfer:" + expected_sha256)[:36]
        with session() as db:
            transaction_lock(db, "corpus:ingest")
            prior = db.get(Document, transfer_id)
            if prior:
                value = prior.value()
                if (
                    fingerprint(db, value["governance_ids"])
                    != value["store_fingerprint"]
                ):
                    raise ValueError(
                        "Previously restored corpus changed; refusing replacement"
                    )
                install_review_policy(db, expected_sha256)
                db.commit()
                return {
                    "status": "already_restored",
                    "sha256": expected_sha256,
                    **{
                        k: value[k]
                        for k in (
                            "records",
                            "vectors",
                            "aliases",
                            "raw_artifacts",
                            "dimension",
                            "embedding_model",
                        )
                    },
                    "withheld_raw_artifacts": len(value["withheld_raw_artifacts"]),
                }
            if (
                db.query(Knowledge).first()
                or db.query(Chunk).first()
                or db.query(Alias).first()
            ):
                raise ValueError(
                    "Corpus restore requires an empty store; existing knowledge is preserved"
                )
            # Copy verified files first. A SQL failure can leave valid unreferenced
            # files, but never a partial database or an overwritten original.
            for info in archive.infolist():
                if info.filename.startswith("corpus_raw/"):
                    with archive.open(info) as source:
                        install_file(
                            root,
                            info.filename,
                            source,
                            PurePosixPath(info.filename).name,
                        )
            for name, expected in pinned["files_sha256"].items():
                relative = pinned["snapshot_relative_path"] + "/" + name
                with archive.open("models/" + relative) as source:
                    install_file(cache_root(), relative, source, expected)
            from .corpus import category

            parents, aliases = [], []
            for value in json_rows(archive, RECORDS):
                r = Record.model_validate(value)
                parents.append(
                    {
                        "id": r.record_id,
                        "owner": "public",
                        "canonical_key": r.canonical_key,
                        "category": category(r),
                        "source": r.source.source_id,
                        "title": r.title,
                        "content_hash": r.source.content_hash_sha256,
                        "record": canonical(relocate(value, root)),
                    }
                )
                aliases.extend(
                    {"alias": a, "record_id": r.record_id}
                    for a in set(r.deduplication.source_aliases + [r.canonical_key])
                )
                if len(parents) >= 200:
                    db.execute(insert(Knowledge), parents)
                    db.execute(insert(Alias), aliases)
                    parents.clear()
                    aliases.clear()
            if parents:
                db.execute(insert(Knowledge), parents)
                db.execute(insert(Alias), aliases)
            batch = []
            for value in json_rows(archive, VECTORS):
                batch.append({**value, "embedding": canonical(value["embedding"])})
                if len(batch) >= 200:
                    db.execute(insert(Chunk), batch)
                    batch.clear()
            if batch:
                db.execute(insert(Chunk), batch)
            if db.bind.dialect.name == "postgresql":
                db.execute(
                    text(
                        "UPDATE knowledge_chunks SET embedding_vector=CAST(embedding AS vector)"
                    )
                )
            governance_ids = []
            for row in json_rows(archive, GOVERNANCE):
                data = relocate(governance_data(row), root)
                expected = {**row, "data": canonical(data)}
                existing = db.get(Document, row["id"])
                if existing:
                    if any(getattr(existing, k) != v for k, v in expected.items()):
                        raise ValueError("Existing governance document collision")
                else:
                    db.execute(insert(Document), [expected])
                governance_ids.append(row["id"])
            value = {
                **checked,
                "sha256": expected_sha256,
                "status": "restored",
                "restored_at": now(),
                "governance_ids": governance_ids,
                "store_fingerprint": fingerprint(db, governance_ids),
                "corpus_reembedded": False,
                "source_archive_unchanged": True,
            }
            document(db, "corpus_transfer", "public", value, transfer_id)
            install_review_policy(db, expected_sha256)
            append(
                db,
                transfer_id,
                actor,
                "corpus_restored",
                {
                    "sha256": expected_sha256,
                    "records": checked["records"],
                    "vectors": checked["vectors"],
                    "withheld_artifacts": len(checked["withheld_raw_artifacts"]),
                },
            )
            db.commit()
        return {
            "status": "restored",
            "sha256": expected_sha256,
            **{
                k: checked[k]
                for k in (
                    "records",
                    "vectors",
                    "aliases",
                    "raw_artifacts",
                    "dimension",
                    "embedding_model",
                )
            },
            "withheld_raw_artifacts": len(checked["withheld_raw_artifacts"]),
        }


def install_review_policy(db, source_sha256):
    """Apply the source-specific reviewed output masks, never alter stored text."""
    review = Path(__file__).parent / "data" / "corpus_reviews" / (source_sha256 + ".json")
    if review.is_file():
        from .corpus_privacy import register_review

        register_review(db, review)
