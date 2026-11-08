"""Validate persisted public records and raw hashes without trusting inventory claims."""

import json, hashlib
from pathlib import Path
from atlas.db import session, Knowledge, Chunk, Document, canonical
from atlas.records import Record
from atlas.embeddings import embedding_version, dimension, verify_model
from atlas.corpus import stats
import numpy as np

with session() as db:
    records = 0
    raw_files = 0
    missing = []
    bad = []
    for k in db.query(Knowledge).filter_by(owner="public").yield_per(200):
        r = Record.model_validate_json(k.record)
        records += 1
        path = Path(r.content.raw_artifact_ref or "")
        if not path.is_file():
            missing.append(k.id)
            continue
        raw_files += 1
        if (
            hashlib.sha256(path.read_bytes()).hexdigest()
            != r.source.content_hash_sha256
        ):
            bad.append(k.id)
    invalid_vectors = 0
    parents = set()
    chunks = 0
    for c in (
        db.query(Chunk)
        .join(Knowledge, Knowledge.id == Chunk.record_id)
        .filter(
            Knowledge.owner == "public", Chunk.embedding_model == embedding_version()
        )
        .yield_per(500)
    ):
        chunks += 1
        parents.add(c.record_id)
        vector = json.loads(c.embedding)
        invalid_vectors += int(
            len(vector) != dimension() or not np.isfinite(vector).all()
        )
    verify_model()
    result = {
        "records_validated": records,
        "raw_files_validated": raw_files,
        "missing_raw": missing,
        "bad_hashes": bad,
        "active_chunks": chunks,
        "indexed_records": len(parents),
        "invalid_vectors": invalid_vectors,
        "statistics": stats(db),
    }
print(json.dumps(result, indent=2))
if missing or bad or invalid_vectors or records != len(parents):
    raise SystemExit(1)
