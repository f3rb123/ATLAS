"""Dedicated durable source/index worker. No target/model egress or model credentials."""

import time
from .db import session, Document, canonical, document, now, uid, transaction_lock
from .corpus import sync_bulk, sync_api, reindex_job


def tick():
    with session() as db:
        transaction_lock(db, "corpus:worker")
        rows = (
            db.query(Document)
            .filter(
                Document.kind.in_(
                    [
                        "corpus_request",
                        "index_request",
                        "source_acquisition_request",
                        "file_import_request",
                        "corpus_transfer_request",
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
            lease_token=uid(),
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
        if request.kind == "corpus_transfer_request" and v.get("upload_id"):
            upload = db.get(Document, v["upload_id"])
            if upload and upload.owner == request.owner and upload.kind == "corpus_upload":
                value = upload.value()
                value["status"] = "running"
                upload.data = canonical(value)
        db.commit()
        id = request.id
        kind = request.kind
        lease_token = v["lease_token"]
    import threading

    stopped = threading.Event()

    def renew():
        while not stopped.wait(30):
            try:
                with session() as lease_db:
                    transaction_lock(lease_db, "corpus:worker")
                    current = (
                        lease_db.query(Document)
                        .filter_by(id=id)
                        .with_for_update()
                        .one()
                    )
                    value = current.value()
                    if value["status"] != "running" or value.get("lease_token") != lease_token:
                        return
                    value["lease_until"] = time.time() + 600
                    current.data = canonical(value)
                    lease_db.commit()
            except Exception:
                pass  # next bounded heartbeat retries; lease expiry is conservative

    heartbeat = threading.Thread(target=renew, daemon=True)
    heartbeat.start()
    try:
        if kind == "corpus_transfer_request":
            from .corpus_package import restore_package

            counts = restore_package(v["path"], v["sha256"], request.owner)
            result = {"status": "completed", "counts": counts}
        elif kind == "file_import_request":
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
        transaction_lock(db, "corpus:worker")
        d = db.query(Document).filter_by(id=id).with_for_update().one()
        v = d.value()
        if v.get("lease_token") != lease_token or v["status"] != "running":
            return
        v.update(status=result["status"], result=result)
        d.data = canonical(v)
        if kind == "corpus_transfer_request" and v.get("upload_id"):
            upload = db.get(Document, v["upload_id"])
            if upload and upload.owner == d.owner and upload.kind == "corpus_upload":
                value = upload.value()
                value.update(status=result["status"], result=result)
                upload.data = canonical(value)
        db.commit()
    if kind == "corpus_transfer_request" and v.get("upload_id"):
        from .corpus_transfers import root_for

        for part in root_for(v["upload_id"]).glob("[0-9][0-9][0-9][0-9].part"):
            part.unlink(missing_ok=True)


if __name__ == "__main__":
    while True:
        tick()
        time.sleep(2)
