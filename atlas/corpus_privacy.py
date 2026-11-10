"""Withhold audited content candidates from model/UI views without changing data.

Review manifests contain identities and field paths only. Original records,
vectors and raw artifacts remain intact; metadata false positives are recorded
individually, never suppressed by a blanket scanner rule.
"""

import json
import re
from copy import deepcopy
from pathlib import Path

from .db import Document, Knowledge, canonical, digest, document, now
from .policy import Denied
from .vault import redact

PLACEHOLDER = "[SOURCE CONTENT WITHHELD: credential candidate requires review]"


def review_id(record_id):
    return digest("corpus-content-review:" + record_id)[:36]


def register_review(db, path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2:
        raise ValueError("Unsafe or oversized content review manifest")
    policy = json.loads(path.read_text())
    sha = policy.get("source_archive_sha256", "")
    if not re.fullmatch(r"[a-f0-9]{64}", sha):
        raise ValueError("Content review requires a source archive SHA256")
    transfer = db.get(Document, digest("corpus-transfer:" + sha)[:36])
    if not transfer or transfer.kind != "corpus_transfer":
        raise ValueError("Content review does not match an installed package")
    rows = policy.get("records", [])
    quarantined = set(policy.get("quarantined_record_ids", []))
    records = {r["record_id"]: r for r in rows}
    if len(records) != len(rows):
        raise ValueError("Duplicate review identity")
    for id in quarantined:
        records.setdefault(id, {"record_id": id, "paths": [], "rules": []})
    count = 0
    for id, entry in records.items():
        k = db.get(Knowledge, id)
        if not k or k.owner != "public":
            raise ValueError("Unknown review record")
        r = json.loads(k.record)
        for field in entry.get("paths", []):
            if field == ["summary"]:
                continue
            if not (
                len(field) == 4
                and field[:2] == ["content", "chunks"]
                and field[3] == "text"
                and type(field[2]) is int
                and 0 <= field[2] < len(r["content"]["chunks"])
            ):
                raise ValueError("Content review can mask only summary/chunk text")
        value = {
            "record_id": id,
            "paths": entry.get("paths", []),
            "rules": entry.get("rules", []),
            "quarantined": id in quarantined,
            "source_archive_sha256": sha,
            "scanner": policy.get("scanner"),
            "recorded_at": now(),
        }
        current = db.get(Document, review_id(id))
        if current:
            if current.kind != "corpus_content_review" or current.owner != "public":
                raise ValueError("Content review identity collision")
            current.data = canonical(value)
        else:
            document(db, "corpus_content_review", "public", value, review_id(id))
        count += len(value["paths"])
    raw = policy.get("raw_artifacts_to_withhold", [])
    if any(not re.fullmatch(r"[a-f0-9]{64}", h) for h in raw):
        raise ValueError("Invalid raw artifact review identity")
    root_id = digest("corpus-content-policy:" + sha)[:36]
    summary = {
        "source_archive_sha256": sha,
        "scanner": policy.get("scanner"),
        "metadata_false_positives": policy.get("metadata_false_positives", {}),
        "normalized_content_findings": policy.get("normalized_content_findings", 0),
        "raw_content_findings": policy.get("raw_content_findings", 0),
        "raw_artifacts_to_withhold": raw,
        "masked_records": len(records),
        "masked_fields": count,
        "quarantined_records": len(quarantined),
        "original_corpus_modified": False,
        "recorded_at": now(),
    }
    current = db.get(Document, root_id)
    if current:
        current.data = canonical(summary)
    else:
        document(db, "corpus_content_policy", "public", summary, root_id)
    db.flush()
    return {k: v for k, v in summary.items() if k != "raw_artifacts_to_withhold"}


def policy_for(db, record_id):
    row = db.get(Document, review_id(record_id))
    if row and row.kind == "corpus_content_review":
        return row.value()
    return {"paths": [], "quarantined": False}


def record_view(db, record):
    policy = policy_for(db, record["record_id"])
    if policy.get("quarantined"):
        raise Denied("Knowledge content withheld pending review")
    view = deepcopy(record)
    paths = {tuple(p) for p in policy.get("paths", [])}
    changed = False
    for name in ("title", "summary"):
        original = view[name]
        view[name] = PLACEHOLDER if (name,) in paths else redact(original)
        changed |= view[name] != original
    for index, chunk in enumerate(view.get("content", {}).get("chunks", [])):
        if "text" not in chunk:
            continue
        original = chunk["text"]
        chunk["text"] = (
            PLACEHOLDER
            if ("content", "chunks", index, "text") in paths
            else redact(original)
        )
        if chunk["text"] != original:
            changed = True
            chunk["original_hash"] = chunk.get("hash")
            chunk["hash"] = digest(chunk["text"])
    if changed:
        view["content"]["redaction_status"] = "redacted"
    return view


def result_views(db, hits):
    safe = []
    for hit in hits:
        policy = policy_for(db, hit["record_id"])
        if policy.get("quarantined"):
            continue
        paths = {tuple(p) for p in policy.get("paths", [])}
        original = hit["text"]
        text = (
            PLACEHOLDER
            if ("content", "chunks", hit["chunk_index"], "text") in paths
            else redact(original)
        )
        safe.append(
            {
                **hit,
                "title": redact(hit["title"]),
                "text": text,
                "content_redacted": text != original,
                "excerpt_sha256": digest(text),
            }
        )
    return safe
