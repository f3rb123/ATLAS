import io, json
from atlas.db import session, Knowledge, Chunk, canonical
from atlas.corpus import source_record, ingest
from atlas.vector_transfer import load
from atlas.embeddings import embedding_version, embed


def test_atomic_index_transfer_is_idempotent(db):
    raw = b'{"id":"GHSA-aaaa-bbbb-cccc"}'
    r = source_record(
        "ghsa",
        {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "Fixture vector transfer",
            "details": "A synthetic authorization boundary",
        },
        raw,
    )
    ingest(db, r, raw)
    db.commit()
    c = db.query(Chunk).first()
    row = {
        "id": c.id,
        "record_id": c.record_id,
        "position": c.position,
        "text": c.text,
        "embedding": json.loads(c.embedding),
        "embedding_model": embedding_version(),
    }
    result = load(io.StringIO(canonical(row) + "\n"))
    assert result["vectors_already_identical"] == 1
    row["text"] = "Updated synthetic boundary"
    row["embedding"] = embed(row["text"])
    assert load(io.StringIO(canonical(row) + "\n"))["vectors_loaded"] == 1
    db.expire_all()
    assert db.get(Chunk, c.id).text == row["text"]
