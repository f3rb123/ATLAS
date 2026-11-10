import sqlite3

import pytest
from sqlalchemy import text

from atlas import corpus_worker
from atlas.db import Document


def test_corpus_worker_recovers_after_real_temporary_writer_lock(db, monkeypatch):
    # Use the existing pooled connection with a short test-only busy timeout.
    db.execute(text("PRAGMA busy_timeout=10"))
    db.commit()
    blocker = sqlite3.connect(db.bind.url.database)
    blocker.execute("BEGIN IMMEDIATE")
    original = corpus_worker.tick
    calls = []

    def tick():
        calls.append(1)
        original()
        raise StopIteration("Recovered tick completed")

    def release(_):
        blocker.rollback()

    monkeypatch.setattr(corpus_worker, "tick", tick)
    monkeypatch.setattr(corpus_worker.time, "sleep", release)
    try:
        with pytest.raises(StopIteration, match="Recovered"):
            corpus_worker.main()
    finally:
        blocker.close()
    assert len(calls) == 2 and db.query(Document).count() == 0
