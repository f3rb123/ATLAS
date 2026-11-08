"""Five labelled diagnostic checks, no claims of broad research precision."""

import json, time
from atlas.db import session, Knowledge, Alias
from atlas.corpus import search
from pathlib import Path

queries = json.loads(Path("knowledge/retrieval_queries_v1.json").read_text())
results = []
with session() as db:
    for item in queries["queries"]:
        if "expected_identifier" in item:
            expected = db.get(Alias, item["expected_identifier"]).record_id
        else:
            expected = (
                db.query(Knowledge)
                .filter_by(canonical_key=item["expected_canonical_key"])
                .one()
                .id
            )
        started = time.monotonic()
        hits = search(db, item["query"], limit=5)
        elapsed = time.monotonic() - started
        ids = [hit["record_id"] for hit in hits]
        results.append(
            {
                "query": item["query"],
                "kind": item["kind"],
                "precision_at_1": float(bool(ids) and ids[0] == expected),
                "hit_at_5": expected in ids,
                "reciprocal_rank": 1 / (ids.index(expected) + 1)
                if expected in ids
                else 0,
                "elapsed_seconds": round(elapsed, 3),
                "results": [
                    {
                        "id": h["record_id"],
                        "title": h["title"],
                        "source_url": h["source_url"],
                        "license": h["license"],
                        "chunk_sha256": h["chunk_sha256"],
                    }
                    for h in hits
                ],
            }
        )
print(
    json.dumps(
        {
            "dataset": queries["version"],
            "scope": queries["scope"],
            "precision_at_1": sum(r["precision_at_1"] for r in results) / len(results),
            "hit_at_5": sum(r["hit_at_5"] for r in results) / len(results),
            "mean_reciprocal_rank": sum(r["reciprocal_rank"] for r in results)
            / len(results),
            "checks": results,
        },
        indent=2,
    )
)
