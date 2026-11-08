import json, pytest
from atlas.registries import import_manifest
from atlas.db import Document
from atlas.policy import Denied


def test_seed_manifest_is_review_only_and_idempotent(db):
    data = json.dumps(
        [
            {
                "name": "Owner seed",
                "url": "https://example.invalid/report",
                "kind": "report",
            }
        ]
    ).encode()
    result = import_manifest(db, "a", data, "seeds.json")
    db.commit()
    assert len(result["created"]) == 1 and not result["acquisition_authorized"]
    assert import_manifest(db, "a", data, "seeds.json")["linked"] == 1
    item = db.get(Document, result["created"][0]).value()
    assert item["status"] == "owner_review_required" and item["enabled"] is False
    assert import_manifest(db, "b", data, "seeds.json")["created"]
    with pytest.raises(Denied):
        import_manifest(
            db,
            "a",
            b'[{"name":"bad","url":"file:///etc/passwd","kind":"skill"}]',
            "seed.json",
        )
