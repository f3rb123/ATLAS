"""Synthetic official-schema fixtures only; never included in the real corpus inventory."""

import json, io, urllib.error
import pytest
from atlas import corpus
from atlas.db import *


def nvd_item(n):
    return {
        "cve": {
            "id": f"CVE-2099-{100000 + n}",
            "published": "2099-01-01T00:00:00Z",
            "descriptions": [
                {"lang": "en", "value": f"Synthetic native NVD fixture {n}"}
            ],
        }
    }


def test_nvd_pagination_and_durable_resume(db, monkeypatch):
    calls = []

    def fetch(source, url, etag=None, capture=None):
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(url).query)
        start = int(q["startIndex"][0])
        size = int(q["resultsPerPage"][0])
        calls.append(start)
        return {
            "vulnerabilities": [nvd_item(n) for n in range(start, start + size)],
            "totalResults": 1000,
        }, None

    monkeypatch.setattr(corpus, "fetch_json", fetch)
    monkeypatch.setattr(corpus.time, "sleep", lambda _: None)
    first = corpus.sync_api("nvd", 2)
    assert first["counts"]["ingested"] == 2
    second = corpus.sync_api("nvd", 4, job_id=first["job_id"])
    assert second["cursor"] == 4 and calls == [0, 2]
    db.expire_all()
    assert db.query(Knowledge).count() == 4


def test_osv_immutable_id_cursor_and_no_alias_inflation(db, monkeypatch):
    ids = ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "GHSA-gggg-hhhh-jjjj"]

    def fetch(source, url, etag=None, capture=None):
        id = url.rsplit("/", 1)[-1]
        return {
            "id": id,
            "aliases": [],
            "summary": "Synthetic OSV fixture",
            "details": "A controlled fixture description",
        }, None

    monkeypatch.setattr(corpus, "fetch_json", fetch)
    monkeypatch.setattr(corpus.time, "sleep", lambda _: None)
    first = corpus.sync_api("osv", 1, ids=ids)
    assert first["cursor"] == 1
    second = corpus.sync_api("osv", 3, ids=list(reversed(ids)), job_id=first["job_id"])
    assert second["cursor"] == 3
    db.expire_all()
    assert db.query(Knowledge).count() == 3


def test_kev_resume_slices_full_feed_at_checkpoint(db, monkeypatch):
    items = [
        {
            "cveID": f"CVE-2099-{200000 + i}",
            "vulnerabilityName": f"Synthetic KEV {i}",
            "shortDescription": "Controlled test advisory",
            "vendorProject": "Fixture",
            "product": "Test",
        }
        for i in range(4)
    ]
    monkeypatch.setattr(
        corpus, "fetch_json", lambda *a, **k: ({"vulnerabilities": items}, None)
    )
    monkeypatch.setattr(corpus.time, "sleep", lambda _: None)
    a = corpus.sync_api("kev", 2)
    b = corpus.sync_api("kev", 4, job_id=a["job_id"])
    assert b["cursor"] == 4
    db.expire_all()
    assert db.query(Knowledge).count() == 4


def test_source_retry_honors_backoff_and_retains_wire_artifact(db, monkeypatch):
    calls = []
    sleeps = []

    class Response:
        headers = {"ETag": "test-etag"}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, _):
            return b'{ "fixture": true }'

    def opener(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                "https://example.invalid", 429, "rate limit", {"Retry-After": "2"}, None
            )
        return Response()

    monkeypatch.setattr(corpus.urllib.request, "urlopen", opener)
    monkeypatch.setattr(corpus.time, "sleep", sleeps.append)
    capture = {}
    value, etag = corpus.fetch_json(
        "ghsa", "https://api.github.com/fixture", capture=capture
    )
    assert value == {"fixture": True} and sleeps == [2] and etag == "test-etag"
    raw = __import__("pathlib").Path(capture["acquisition_artifact_ref"]).read_bytes()
    assert (
        raw == b'{ "fixture": true }'
        and digest(raw) == capture["acquisition_hash_sha256"]
    )
