#!/usr/bin/env python3
"""Build a credential-free, portable public-corpus transfer archive."""

import argparse
import gzip
import hashlib
import json
import os
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".runtime"
MANIFEST = json.loads((ROOT / "atlas/data/embedding_model.json").read_text())
INVENTORY = json.loads((ROOT / "knowledge/corpus_inventory.json").read_text())


def line_count(path: Path) -> int:
    with path.open("rb") as stream:
        return sum(1 for _ in stream)


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_canonical(stream, value: dict) -> None:
    stream.write(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )
    stream.write("\n")


def sanitize_value(value, path: str, changed: list, record_id: str):
    from atlas.vault import redact

    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            value[key] = sanitize_value(child, child_path, changed, record_id)
        return value
    if isinstance(value, list):
        return [
            sanitize_value(child, f"{path}[{index}]", changed, record_id)
            for index, child in enumerate(value)
        ]
    if isinstance(value, str):
        cleaned = redact(value)
        if cleaned != value:
            changed.append({"record_id": record_id, "field": path})
        return cleaned
    return value


def sanitize_exports(
    records: Path, vectors: Path, staging: Path
) -> tuple[Path, Path, dict]:
    """Redact only the private delivery copies and re-embed changed semantic chunks."""
    from atlas.embeddings import embed_many, embedding_version, dimension

    clean_records = staging / "corpus.semantic.records.jsonl"
    clean_vectors = staging / "corpus.semantic.vectors.jsonl"
    changed_fields = []
    chunk_texts = {}
    with (
        records.open(encoding="utf-8") as source,
        clean_records.open("w", encoding="utf-8") as destination,
    ):
        for line in source:
            original = json.loads(line)
            record = json.loads(line)
            record_id = record["record_id"]
            record = sanitize_value(record, "", changed_fields, record_id)
            original_chunks = original.get("content", {}).get("chunks", [])
            clean_chunks = record.get("content", {}).get("chunks", [])
            if len(original_chunks) != len(clean_chunks):
                raise ValueError("Canonical chunk count changed during redaction")
            for original_chunk, chunk in zip(original_chunks, clean_chunks):
                if "text" in chunk:
                    chunk["hash"] = file_hash_text(chunk["text"])
                    chunk_texts[(record_id, int(chunk["index"]))] = (
                        original_chunk["text"],
                        chunk["text"],
                    )
            write_canonical(destination, record)

    changed_vectors = 0
    reembedded = 0
    model = embedding_version()
    with (
        vectors.open(encoding="utf-8") as source,
        clean_vectors.open("w", encoding="utf-8") as destination,
    ):
        pending = []
        for line in source:
            row = json.loads(line)
            key = (row["record_id"], row["position"])
            if key not in chunk_texts:
                raise ValueError("Vector row has no canonical chunk mapping")
            original_text, cleaned_text = chunk_texts[key]
            if row["text"] != original_text:
                raise ValueError("Vector text differs from its canonical record chunk")
            if cleaned_text != original_text:
                row["text"] = cleaned_text
                pending.append((row, True))
                changed_vectors += 1
            else:
                pending.append((row, False))
            if len(pending) >= 64:
                reembedded += write_vector_batch(
                    destination, pending, model, dimension(), embed_many
                )
                pending.clear()
        if pending:
            reembedded += write_vector_batch(
                destination, pending, model, dimension(), embed_many
            )

    summary = {
        "version": 1,
        "redacted_fields": len(changed_fields),
        "reembedded_vectors": reembedded,
        "withheld_raw_artifacts": [],
        "redactions": changed_fields,
    }
    return clean_records, clean_vectors, summary


def file_hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_vector_batch(
    destination,
    pending: list[tuple[dict, bool]],
    expected_model: str,
    expected_dimension: int,
    embed_many,
) -> int:
    changed = [row for row, needs_embedding in pending if needs_embedding]
    vectors = embed_many([row["text"] for row in changed])
    if len(vectors) != len(changed):
        raise ValueError("Embedding model returned an incomplete redaction batch")
    for row, vector in zip(changed, vectors):
        if (
            row["embedding_model"] != expected_model
            or len(vector) != expected_dimension
        ):
            raise ValueError("Sanitized corpus vector model/dimension mismatch")
        row["embedding"] = vector
    for row, _ in pending:
        write_canonical(destination, row)
    return len(changed)


def add_regular_file(archive: tarfile.TarFile, source: Path, name: str) -> None:
    resolved = source.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"Expected a regular source file: {name}")
    info = tarfile.TarInfo(name)
    info.size = resolved.stat().st_size
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    with resolved.open("rb") as stream:
        archive.addfile(info, stream)


def add_tree(archive: tarfile.TarFile, source: Path, name: str) -> int:
    if source.is_symlink():
        raise ValueError(f"Source tree contains a symlink: {name}")
    if source.is_file():
        add_regular_file(archive, source, name)
        return 1
    if not source.is_dir():
        raise ValueError(f"Missing public source tree: {name}")
    info = tarfile.TarInfo(name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    archive.addfile(info)
    files = 0
    for child in sorted(source.iterdir(), key=lambda p: p.name):
        files += add_tree(archive, child, f"{name.rstrip('/')}/{child.name}")
    return files


def add_public_raw_tree(
    archive: tarfile.TarFile, source: Path, name: str, redactions: dict
) -> int:
    from atlas.vault import redact

    if source.is_symlink() or not source.is_dir():
        raise ValueError("Missing or unsafe public raw artifact tree")
    info = tarfile.TarInfo(name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    archive.addfile(info)
    files = 0
    for child in sorted(source.iterdir(), key=lambda item: item.name):
        child_name = f"{name.rstrip('/')}/{child.name}"
        if child.is_symlink():
            raise ValueError(f"Source tree contains a symlink: {child_name}")
        if child.is_dir():
            files += add_public_raw_tree(archive, child, child_name, redactions)
            continue
        if not child.is_file():
            raise ValueError(f"Unexpected raw artifact type: {child_name}")
        raw = child.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Raw public artifacts must be UTF-8 text") from exc
        if redact(text) != text:
            redactions["withheld_raw_artifacts"].append(
                {
                    "sha256": file_hash(child),
                    "reason": (
                        "Credential-like source text; original withheld from transfer"
                    ),
                }
            )
            continue
        add_regular_file(archive, child, child_name)
        files += 1
    return files


def verify_archive(path: Path) -> dict:
    records = vectors = governance = 0
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = set()
        allowed = (
            "corpus_raw/",
            "models/",
            "knowledge/",
            "docs/CORPUS_INGESTION_REPORT.md",
        )
        exact = {
            "CORPUS_TRANSFER.md",
            "CORPUS_REDACTIONS.json",
            "corpus.semantic.records.jsonl",
            "corpus.semantic.vectors.jsonl",
            "corpus.governance.jsonl",
        }
        for member in members:
            name = member.name.rstrip("/")
            candidate = Path(name)
            if (
                candidate.is_absolute()
                or ".." in candidate.parts
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError(f"Unsafe path or link in corpus archive: {name}")
            if name in names:
                raise ValueError(f"Duplicate corpus archive member: {name}")
            names.add(name)
            if (
                name not in exact
                and name != "corpus_raw"
                and not any(name.startswith(p) for p in allowed)
            ):
                raise ValueError(f"Unexpected item in public corpus archive: {name}")
            if any(
                value in name.lower()
                for value in (
                    "master_key",
                    "session.db",
                    "users.db",
                    ".env",
                    "private_campaign",
                )
            ):
                raise ValueError(f"Sensitive-looking path in corpus archive: {name}")
        for name, expected in (
            ("corpus.semantic.records.jsonl", INVENTORY["unique_normalized_records"]),
            ("corpus.semantic.vectors.jsonl", INVENTORY["active_embedding_chunks"]),
        ):
            member = archive.getmember(name)
            count = sum(1 for _ in archive.extractfile(member))
            if count != expected:
                raise ValueError(f"{name} has {count} rows; expected {expected}")
            if name.endswith("records.jsonl"):
                records = count
            else:
                vectors = count
        governance = sum(
            1 for _ in archive.extractfile(archive.getmember("corpus.governance.jsonl"))
        )
        if not any(
            member.name.rstrip("/") == "corpus_raw" and member.isdir()
            for member in members
        ):
            raise ValueError("Public source artifact directory is missing")
        if not any(m.name.startswith("models/") and m.isfile() for m in members):
            raise ValueError("Pinned embedding model files are missing")
        redactions = json.load(
            archive.extractfile(archive.getmember("CORPUS_REDACTIONS.json"))
        )
        if redactions.get("redacted_fields", -1) < 0:
            raise ValueError("Corpus redaction manifest is invalid")
        if redactions.get("reembedded_vectors", -1) < 0:
            raise ValueError("Corpus redaction vector count is invalid")
        included_raw = sum(
            1
            for member in members
            if member.isfile() and member.name.startswith("corpus_raw/")
        )
        if not included_raw:
            raise ValueError("Sanitized public raw artifacts are missing")
    return {
        "archive": str(path),
        "bytes": path.stat().st_size,
        "sha256": file_hash(path),
        "members": len(members),
        "records": records,
        "vectors": vectors,
        "governance_documents": governance,
        "raw_files": included_raw,
        "redacted_fields": redactions["redacted_fields"],
        "reembedded_vectors": redactions["reembedded_vectors"],
        "withheld_raw_artifacts": len(redactions["withheld_raw_artifacts"]),
        "model_revision": MANIFEST["revision"],
        "symlinks": 0,
    }


def build(output: Path, replace: bool = False) -> dict:
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.exists() and not replace:
        raise FileExistsError(
            "Refusing to overwrite an existing archive without --replace"
        )
    if output.exists() and output.with_name(output.name + ".previous").exists():
        raise FileExistsError("Refusing to overwrite the existing archive backup")

    records = RUNTIME / "corpus.semantic.records.jsonl"
    vectors = RUNTIME / "corpus.semantic.vectors.jsonl"
    if line_count(records) != INVENTORY["unique_normalized_records"]:
        raise ValueError("Canonical record export does not match reviewed inventory")
    if line_count(vectors) != INVENTORY["active_embedding_chunks"]:
        raise ValueError("Vector export does not match reviewed inventory")

    model_root = RUNTIME / "models" / MANIFEST["snapshot_relative_path"]
    model_files = {}
    for relative, expected in MANIFEST["files_sha256"].items():
        source = model_root / relative
        resolved = source.resolve(strict=True)
        if not resolved.is_file():
            raise ValueError(f"Pinned model file is missing: {relative}")
        digest = file_hash(resolved)
        if digest != expected:
            raise ValueError(f"Pinned model checksum mismatch: {relative}")
        model_files[relative] = resolved

    temporary = output.with_name(output.name + f".building-{os.getpid()}")
    if temporary.exists():
        raise FileExistsError("Temporary archive path already exists")
    try:
        with tempfile.TemporaryDirectory(
            prefix="atlas-public-corpus-", dir=output.parent
        ) as temp:
            staging = Path(temp)
            clean_records, clean_vectors, redactions = sanitize_exports(
                records, vectors, staging
            )
            with temporary.open("xb") as raw_output:
                with gzip.GzipFile(
                    filename="", fileobj=raw_output, mode="wb", compresslevel=6, mtime=0
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                    ) as archive:
                        add_public_raw_tree(
                            archive, RUNTIME / "corpus_raw", "corpus_raw", redactions
                        )
                        redaction_file = staging / "CORPUS_REDACTIONS.json"
                        redaction_file.write_text(
                            json.dumps(
                                redactions, sort_keys=True, separators=(",", ":")
                            )
                            + "\n",
                            encoding="utf-8",
                        )
                        add_regular_file(
                            archive, clean_records, "corpus.semantic.records.jsonl"
                        )
                        add_regular_file(
                            archive, clean_vectors, "corpus.semantic.vectors.jsonl"
                        )
                        add_regular_file(
                            archive,
                            RUNTIME / "corpus.governance.jsonl",
                            "corpus.governance.jsonl",
                        )
                        add_regular_file(
                            archive,
                            RUNTIME / "CORPUS_TRANSFER.md",
                            "CORPUS_TRANSFER.md",
                        )
                        add_regular_file(
                            archive, redaction_file, "CORPUS_REDACTIONS.json"
                        )
                        for source, name in (
                            (
                                ROOT / "knowledge/embedding_model.json",
                                "knowledge/embedding_model.json",
                            ),
                            (
                                ROOT / "knowledge/source_registry.yaml",
                                "knowledge/source_registry.yaml",
                            ),
                            (
                                ROOT / "knowledge/corpus_inventory.json",
                                "knowledge/corpus_inventory.json",
                            ),
                            (
                                ROOT / "docs/CORPUS_INGESTION_REPORT.md",
                                "docs/CORPUS_INGESTION_REPORT.md",
                            ),
                        ):
                            add_regular_file(archive, source, name)
                        add_tree(
                            archive, ROOT / "knowledge/licenses", "knowledge/licenses"
                        )
                        snapshot = f"models/{MANIFEST['snapshot_relative_path']}"
                        for relative, source in sorted(model_files.items()):
                            add_regular_file(archive, source, f"{snapshot}/{relative}")
            summary = verify_archive(temporary)
        if output.exists():
            backup = output.with_name(output.name + ".previous")
            backup.write_bytes(output.read_bytes())
        os.replace(temporary, output)
        summary["archive"] = str(output)
        summary["bytes"] = output.stat().st_size
        summary["sha256"] = file_hash(output)
        return summary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".runtime/delivery/atlas-v3-public-corpus.tar.gz"),
    )
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build((ROOT / args.output).resolve(), args.replace), indent=2))


if __name__ == "__main__":
    main()
