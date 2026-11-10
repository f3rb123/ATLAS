"""Synthetic transfer fixtures exercise preservation, rejection and SQL atomicity.

Dummy model bytes are hashed but never executed. Real-candidate/model acceptance
is performed separately against the delivered archive.
"""

import json
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from atlas import corpus_package as transfer
from atlas.config import settings
from atlas.db import Alias, Chunk, Document, Knowledge, canonical, digest
from atlas.records import Record, Source


@pytest.fixture
def candidate(db, tmp_path, monkeypatch):
    monkeypatch.setenv(
        "ATLAS_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
    )
    monkeypatch.setenv("ATLAS_EMBEDDING_CACHE_DIR", str(tmp_path / "models"))
    settings.cache_clear()
    assets = {
        name: ("Dummy fixture " + name).encode()
        for name in (
            "model.onnx",
            "tokenizer.json",
            "config.json",
            "tokenizer_config.json",
            "special_tokens_map.json",
        )
    }
    pinned = {
        "model": "sentence-transformers/all-MiniLM-L6-v2",
        "revision": "fixture-revision",
        "dimension": 384,
        "snapshot_relative_path": "fixture/snapshots/pinned",
        "files_sha256": {n: digest(b) for n, b in assets.items()},
    }
    monkeypatch.setattr(transfer, "manifest", lambda: pinned)
    raw = b"Synthetic authorization research transfer fixture"
    raw_hash = digest(raw)
    text = "Synthetic tenant authorization reference"
    r = Record(
        canonical_key="fixture:report",
        record_type="training_reference",
        title="Synthetic fixture",
        summary=text,
        source=Source(
            source_id="fixture",
            source_name="Fixture",
            source_url="https://example.invalid/report",
            license="MIT",
            full_text_policy="allowed",
            parser_name="fixture",
            content_hash_sha256=raw_hash,
        ),
    )
    version = pinned["model"] + "@" + pinned["revision"]
    r.content.raw_artifact_ref = ".runtime/corpus_raw/" + raw_hash[:2] + "/" + raw_hash
    r.content.chunks = [
        {"index": 0, "text": text, "hash": digest(text), "embedding_version": version}
    ]
    vector = {
        "id": str(uuid4()),
        "record_id": r.record_id,
        "position": 0,
        "text": text,
        "embedding": [1.0] + [0.0] * 383,
        "embedding_model": version,
    }
    gov = {
        "id": str(uuid4()),
        "owner": r.record_id,
        "kind": "corpus_provenance",
        "version": 1,
        "created": r.created_at,
        "data": canonical(
            {
                "raw": r.content.raw_artifact_ref,
                "source": {"content_hash_sha256": raw_hash},
            }
        ),
    }
    members = {
        transfer.RECORDS: canonical(r.model_dump(by_alias=True)) + "\n",
        transfer.VECTORS: canonical(vector) + "\n",
        transfer.GOVERNANCE: canonical(gov) + "\n",
        "knowledge/embedding_model.json": canonical(pinned),
        "corpus_raw/" + raw_hash[:2] + "/" + raw_hash: raw,
    }
    members.update(
        {
            "models/" + pinned["snapshot_relative_path"] + "/" + n: b
            for n, b in assets.items()
        }
    )

    def write(values=None, filename="candidate.zip"):
        path = tmp_path / filename
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for name, value in (values if values is not None else members).items():
                z.writestr(name, value)
        return path, transfer.file_digest(path)

    return {
        "write": write,
        "members": members,
        "record": r,
        "vector": vector,
        "governance": gov,
        "raw_hash": raw_hash,
        "pinned": pinned,
    }


def test_restore_preserves_identities_vectors_raw_hashes_and_idempotence(db, candidate):
    path, sha = candidate["write"]()
    result = transfer.restore_package(path, sha)
    assert (
        result["status"] == "restored" and result["records"] == result["vectors"] == 1
    )
    db.expire_all()
    r, v = candidate["record"], candidate["vector"]
    stored = db.get(Knowledge, r.record_id)
    assert stored.canonical_key == r.canonical_key
    assert db.get(Alias, r.canonical_key).record_id == r.record_id
    chunk = db.get(Chunk, v["id"])
    assert (
        chunk.record_id == r.record_id and json.loads(chunk.embedding) == v["embedding"]
    )
    record = json.loads(stored.record)
    raw_path = Path(record["content"]["raw_artifact_ref"])
    assert (
        raw_path.is_file() and transfer.file_digest(raw_path) == candidate["raw_hash"]
    )
    assert raw_path.is_relative_to(Path(settings().data_dir).resolve())
    assert db.get(Document, candidate["governance"]["id"]).value()["raw"] == str(
        raw_path
    )
    assert transfer.restore_package(path, sha)["status"] == "already_restored"
    assert transfer.file_digest(path) == sha


@pytest.mark.parametrize(
    "mutation", ["parent", "dimension", "text", "model", "nan", "duplicate"]
)
def test_vector_corruption_is_rejected_before_writing_any_corpus(
    db, candidate, mutation
):
    row = json.loads(candidate["members"][transfer.VECTORS])
    if mutation == "parent":
        row["record_id"] = str(uuid4())
    if mutation == "dimension":
        row["embedding"] = [1.0]
    if mutation == "text":
        row["text"] = "Mismatched fixture"
    if mutation == "model":
        row["embedding_model"] = "different"
    if mutation == "nan":
        row["embedding"][1] = float("nan")
    members = dict(candidate["members"])
    members[transfer.VECTORS] = canonical(row) + "\n"
    if mutation == "duplicate":
        members[transfer.VECTORS] *= 2
    path, sha = candidate["write"](members)
    with pytest.raises(ValueError):
        transfer.restore_package(path, sha)
    assert db.query(Knowledge).count() == db.query(Chunk).count() == 0
    assert not (Path(settings().data_dir) / "corpus_raw").exists()


def test_checksum_and_traversal_are_rejected_without_side_effects(db, candidate):
    path, sha = candidate["write"]()
    with pytest.raises(ValueError, match="checksum"):
        transfer.restore_package(path, "0" * 64)
    members = {**candidate["members"], "../escape.txt": "untrusted"}
    path, sha = candidate["write"](members)
    with pytest.raises(ValueError, match="Unsafe"):
        transfer.restore_package(path, sha)
    assert db.query(Knowledge).count() == 0


def test_populated_store_is_preserved_and_never_replaced(db, candidate):
    r = candidate["record"]
    db.add(
        Knowledge(
            id=r.record_id,
            owner="private-owner",
            canonical_key="existing:private",
            category="training_and_reference_resources",
            source="fixture",
            title="Keep me",
            content_hash="0" * 64,
            record="{}",
        )
    )
    db.commit()
    path, sha = candidate["write"]()
    with pytest.raises(ValueError, match="empty store"):
        transfer.restore_package(path, sha)
    db.expire_all()
    assert db.get(Knowledge, r.record_id).title == "Keep me"
    assert db.query(Chunk).count() == 0


def test_corrupted_existing_artifact_is_not_overwritten(db, candidate):
    h = candidate["raw_hash"]
    p = Path(settings().data_dir) / "corpus_raw" / h[:2] / h
    p.parent.mkdir(parents=True)
    p.write_bytes(b"Existing content must remain untouched")
    path, sha = candidate["write"]()
    with pytest.raises(ValueError, match="refusing overwrite"):
        transfer.restore_package(path, sha)
    assert p.read_bytes() == b"Existing content must remain untouched"
    assert db.query(Knowledge).count() == 0


def test_governance_collision_rolls_back_parent_alias_and_vector_rows(db, candidate):
    gov = candidate["governance"]
    db.add(Document(id=gov["id"], kind="existing", owner="owner", data="{}"))
    db.commit()
    path, sha = candidate["write"]()
    with pytest.raises(ValueError, match="governance document collision"):
        transfer.restore_package(path, sha)
    assert (
        db.query(Knowledge).count()
        == db.query(Alias).count()
        == db.query(Chunk).count()
        == 0
    )
    assert db.get(Document, gov["id"]).kind == "existing"


def test_declared_raw_omission_is_preserved_and_reported(db, candidate):
    h = candidate["raw_hash"]
    members = dict(candidate["members"])
    del members["corpus_raw/" + h[:2] + "/" + h]
    members["CORPUS_REDACTIONS.json"] = canonical(
        {"withheld_raw_artifacts": [{"sha256": h}]}
    )
    path, sha = candidate["write"](members)
    result = transfer.restore_package(path, sha)
    assert result["withheld_raw_artifacts"] == 1
    assert db.query(Knowledge).count() == db.query(Chunk).count() == 1
    assert not Path(
        json.loads(db.query(Knowledge).one().record)["content"]["raw_artifact_ref"]
    ).exists()


def test_idempotent_retry_detects_changed_data_without_replacing_it(db, candidate):
    path, sha = candidate["write"]()
    transfer.restore_package(path, sha)
    db.expire_all()
    chunk = db.get(Chunk, candidate["vector"]["id"])
    chunk.text = "Changed after restore"
    db.commit()
    with pytest.raises(ValueError, match="refusing replacement"):
        transfer.restore_package(path, sha)
    db.expire_all()
    assert chunk.text == "Changed after restore"


def test_resumable_upload_api_runs_real_restore_and_persists_progress(db, candidate):
    from test_auth_api import authenticated

    from atlas.corpus_worker import tick

    client, _user, _ = authenticated(db)
    path, sha = candidate["write"]()
    body = path.read_bytes()
    response = client.post(
        "/api/v1/corpus/transfers", json={"sha256": sha, "byte_size": len(body)}
    )
    assert response.status_code == 200, response.text
    upload = response.json()
    url = "/api/v1/corpus/transfers/" + upload["id"]
    first = client.put(url + "/parts/0", content=body)
    assert first.status_code == 200 and first.json()["uploaded_bytes"] == len(body)
    assert client.put(url + "/parts/0", content=body).status_code == 200
    wrong = bytearray(body)
    wrong[-1] ^= 1
    assert client.put(url + "/parts/0", content=bytes(wrong)).status_code == 400
    queued = client.post(url + "/complete", json={})
    assert queued.status_code == 200 and queued.json()["status"] == "queued"
    assert (
        client.post(url + "/complete", json={}).json()["job_id"]
        == queued.json()["job_id"]
    )
    tick()
    result = client.get(url).json()
    assert (
        result["status"] == "completed" and result["result"]["counts"]["vectors"] == 1
    )
    assert client.get("/api/v1/corpus/transfers").json()["restored"][0]["records"] == 1
    db.expire_all()
    assert db.get(Knowledge, candidate["record"].record_id)


def test_upload_quota_bounds_and_owner_isolation(db, candidate):
    from atlas.corpus_transfers import UploadInput, accept_part, cancel, start

    path, sha = candidate["write"]()
    body = path.read_bytes()
    row = start(db, "owner", UploadInput(sha256=sha, byte_size=len(body)))
    db.commit()
    with pytest.raises(ValueError, match="Part index"):
        accept_part(db, row, 5, body)
    with pytest.raises(ValueError, match="Part size"):
        accept_part(db, row, 0, body[:-1])
    assert cancel(db, row)["status"] == "cancelled"
    db.commit()
    # Only the authenticated owner can select a transfer through the API.
    from test_auth_api import authenticated

    client, _user, _ = authenticated(db)
    other = start(db, "other-owner", UploadInput(sha256=sha, byte_size=len(body)))
    db.commit()
    assert client.get("/api/v1/corpus/transfers/" + other.id).status_code == 404
    assert (
        client.put(
            "/api/v1/corpus/transfers/" + other.id + "/parts/0", content=body
        ).status_code
        == 404
    )
