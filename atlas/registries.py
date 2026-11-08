"""Review-only historical seed manifests. Importing a URL never authorizes acquisition."""

import csv, io, json
from typing import Literal
from pydantic import Field
from .policy import Strict, normalize, Denied
from .db import Document, document, digest, append


class Seed(Strict):
    name: str = Field(min_length=1, max_length=300)
    url: str = Field(max_length=4096)
    kind: Literal["report", "training", "skill", "infrastructure"]
    license: str = Field(default="unknown", max_length=200)
    notes: str = Field(default="", max_length=4000)


def import_manifest(db, owner, data, filename):
    if len(data) > 1024 * 1024:
        raise Denied("Manifest exceeds 1 MiB")
    text = data.decode("utf-8-sig")
    if filename.lower().endswith(".csv"):
        rows = list(csv.DictReader(io.StringIO(text)))
    elif filename.lower().endswith(".jsonl"):
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        rows = json.loads(text)
        if isinstance(rows, dict):
            rows = rows.get("resources")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
        raise ValueError("Manifest requires 1–500 resources")
    seeds = [Seed.model_validate(row) for row in rows]
    created = []
    linked = 0
    existing = {
        (d.value()["url"], d.value()["kind"])
        for d in db.query(Document).filter_by(kind="seed_resource", owner=owner)
    }
    for seed in seeds:
        url, *_ = normalize(seed.url)
        if not url.startswith("https://"):
            raise Denied("Seed URLs require HTTPS")
        if (url, seed.kind) in existing:
            linked += 1
            continue
        existing.add((url, seed.kind))
        item = document(
            db,
            "seed_resource",
            owner,
            {
                **seed.model_dump(),
                "url": url,
                "status": "owner_review_required",
                "enabled": False,
                "provenance": "owner_supplied_manifest",
                "manifest_sha256": digest(data),
            },
        )
        created.append(item.id)
    append(
        db,
        owner,
        owner,
        "seed_manifest_imported",
        {
            "sha256": digest(data),
            "created": len(created),
            "linked": linked,
            "historical_mapping": "unconfirmed",
        },
    )
    return {
        "created": created,
        "linked": linked,
        "historical_mapping": "unconfirmed",
        "acquisition_authorized": False,
    }
