"""Dedicated durable source/index worker. No target/model egress or model credentials."""

import time
from .db import session, Document, canonical, document, now
from .corpus import sync_bulk, sync_api, reindex_job


def tick():
    with session() as db:
        rows = (
            db.query(Document)
            .filter(
                Document.kind.in_(
                    [
                        "corpus_request",
                        "index_request",
                        "source_acquisition_request",
                        "file_import_request",
                    ]
                )
            )
            .with_for_update(skip_locked=True)
            .all()
        )
        request = next(
            (
                r
                for r in rows
                if r.value()["status"] == "queued"
                or (
                    r.value()["status"] == "running"
                    and r.value().get("lease_until", 0) < time.time()
                )
            ),
            None,
        )
        if not request:
            return
        v = request.value()
        v.update(
            status="running",
            lease_until=time.time() + 600,
            attempts=v.get("attempts", 0) + 1,
        )
        if v["attempts"] > 3:
            v.update(status="blocked", error="retry_limit")
            request.data = canonical(v)
            db.commit()
            return
        if request.kind == "corpus_request" and not v.get("resume_id"):
            source_job = document(
                db,
                "corpus_job",
                "system",
                {
                    "source": v["source"],
                    "cursor": 0,
                    "counts": {},
                    "status": "queued",
                    "started": now(),
                    "etag": None,
                },
            )
            v["resume_id"] = source_job.id
        request.data = canonical(v)
        db.commit()
        id = request.id
        kind = request.kind
    import threading

    stopped = threading.Event()

    def renew():
        while not stopped.wait(30):
            try:
                with session() as lease_db:
                    current = (
                        lease_db.query(Document)
                        .filter_by(id=id)
                        .with_for_update()
                        .one()
                    )
                    value = current.value()
                    if value["status"] != "running":
                        return
                    value["lease_until"] = time.time() + 600
                    current.data = canonical(value)
                    lease_db.commit()
            except Exception:
                pass  # next bounded heartbeat retries; lease expiry is conservative

    heartbeat = threading.Thread(target=renew, daemon=True)
    heartbeat.start()
    try:
        if kind == "file_import_request":
            from .corpus import import_file

            with session() as db:
                counts = import_file(
                    db,
                    v["path"],
                    v["license"],
                    v["source_url"],
                    v["record_type"],
                    owner=request.owner,
                )
                db.commit()
                result = {"status": "completed", "counts": counts}
        elif kind == "source_acquisition_request":
            from .source_policy import acquire

            with session() as db:
                policy = db.get(Document, v["source_id"])
                counts = acquire(db, policy)
                db.commit()
                result = {"status": "completed", "counts": counts}
        elif kind == "index_request":
            result = reindex_job(id)
        else:
            result = (
                sync_bulk(v["source"], v["limit"], v["resume_id"])
                if v["source"] in ("cve", "ghsa")
                else sync_api(v["source"], v["limit"], job_id=v["resume_id"])
            )
    except Exception as e:
        result = {"status": "blocked", "error": type(e).__name__}
    finally:
        stopped.set()
        heartbeat.join(timeout=1)
    with session() as db:
        d = db.get(Document, id)
        v = d.value()
        v.update(status=result["status"], result=result)
        d.data = canonical(v)
        db.commit()


if __name__ == "__main__":
    while True:
        tick()
        time.sleep(2)
