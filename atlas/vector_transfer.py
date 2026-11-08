"""Bounded, idempotent semantic-index transfer in atomic record batches."""

import json
from itertools import groupby, islice
import numpy as np
from pydantic import Field
from sqlalchemy import insert, text
from atlas.db import session, Chunk, Knowledge, canonical
from atlas.embeddings import embedding_version, dimension
from atlas.policy import Strict


class VectorRow(Strict):
    id: str = Field(max_length=36)
    record_id: str = Field(max_length=36)
    position: int = Field(ge=0)
    text: str = Field(max_length=100000)
    embedding: list[float] = Field(max_length=4096)
    embedding_model: str = Field(max_length=192)


def load(stream):
    def rows():
        while line := stream.readline(1024 * 1024 + 1):
            if len(line) > 1024 * 1024:
                raise ValueError("Vector row exceeds quota")
            yield VectorRow.model_validate_json(line)

    def groups():
        for record_id, items in groupby(rows(), lambda r: r.record_id):
            values = list(islice(items, 2001))
            if len(values) > 2000:
                raise ValueError("Chunk quota exceeded")
            yield record_id, values

    pending = iter(groups())
    count = 0
    skipped = 0
    with session() as db:
        while batch := list(islice(pending, 200)):
            ids = [id for id, _ in batch]
            public = {
                k.id
                for k in db.query(Knowledge).filter(
                    Knowledge.id.in_(ids), Knowledge.owner == "public"
                )
            }
            if public != set(ids):
                raise ValueError("Unknown/nonpublic vector parent")
            values = [v for _, group in batch for v in group]
            for v in values:
                if (
                    v.embedding_model != embedding_version()
                    or len(v.embedding) != dimension()
                    or not np.isfinite(v.embedding).all()
                ):
                    raise ValueError("Vector model/dimension/integrity mismatch")
            current = {
                c.id: (c.record_id, c.position, c.text, c.embedding, c.embedding_model)
                for c in db.query(Chunk).filter(Chunk.record_id.in_(ids))
            }
            expected = {
                v.id: (
                    v.record_id,
                    v.position,
                    v.text,
                    canonical(v.embedding),
                    v.embedding_model,
                )
                for v in values
            }
            if len(expected) != len(values):
                raise ValueError("Duplicate chunk identity")
            if current == expected:
                skipped += len(values)
                continue
            db.query(Chunk).filter(Chunk.record_id.in_(ids)).delete(
                synchronize_session=False
            )
            db.execute(
                insert(Chunk),
                [
                    {
                        "id": v.id,
                        "record_id": v.record_id,
                        "position": v.position,
                        "text": v.text,
                        "embedding": canonical(v.embedding),
                        "embedding_model": v.embedding_model,
                    }
                    for v in values
                ],
            )
            if db.bind.dialect.name == "postgresql":
                from sqlalchemy import bindparam

                stmt = text(
                    "UPDATE knowledge_chunks SET embedding_vector=CAST(embedding AS vector) WHERE record_id IN :ids"
                ).bindparams(bindparam("ids", expanding=True))
                db.execute(stmt, {"ids": ids})
            db.commit()
            count += len(values)
    return {
        "vectors_loaded": count,
        "vectors_already_identical": skipped,
        "model": embedding_version(),
    }


if __name__ == "__main__":
    import sys

    print(json.dumps(load(sys.stdin)))
