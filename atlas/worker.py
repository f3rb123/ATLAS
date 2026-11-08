"""DB-authoritative workers; Redis hints improve wakeups but never own run state."""

import sys, time, signal, logging
from .db import session, Document, canonical, document, now
from .workflow import execute_stage, blocked
from .config import settings
from .gateway import ProviderError
from .policy import Denied

alive = True


def stop(*_):
    global alive
    alive = False


def tick(role):
    with session() as db:
        rows = (
            db.query(Document)
            .filter_by(kind="run")
            .with_for_update(skip_locked=True)
            .all()
        )
        for run in rows:
            db.refresh(run, with_for_update=True)
            v = run.value()
            if (
                v["status"] not in ("queued", "running")
                or v.get("lease_until", 0) > time.time()
            ):
                continue
            if (v["state"] == "INDEPENDENT_VERIFICATION") != (role == "verify"):
                continue
            v["lease_until"] = time.time() + 600
            run.data = canonical(v)
            db.commit()
            try:
                if v["state"] == "BENCHMARK":
                    from .model_benchmarks import step

                    step(db, run)
                else:
                    execute_stage(db, run, role)
            except (ValueError, Denied, ProviderError) as e:
                # Exception messages are controlled locally; provider payloads never logged.
                db.rollback()
                run = db.get(Document, run.id)
                if run.value()["status"] not in ("paused", "cancelled"):
                    blocked(db, run, type(e).__name__ + ": " + str(e)[:200])
            except Exception:
                logging.getLogger("atlas").error("worker_stage_failed", exc_info=True)
                db.rollback()
                run = db.get(Document, run.id)
                blocked(db, run, "Internal stage error; inspect worker diagnostics")
            current = run.value()
            current["lease_until"] = 0
            run.data = canonical(current)
            db.commit()
        if role == "research":
            for job in (
                db.query(Document)
                .filter_by(kind="sandbox_benchmark_request")
                .with_for_update(skip_locked=True)
                .all()
            ):
                value = job.value()
                if value["status"] != "queued" and not (
                    value["status"] == "running"
                    and value.get("lease_until", 0) < time.time()
                ):
                    continue
                value.update(status="running", lease_until=time.time() + 120)
                job.data = canonical(value)
                db.commit()
                from .benchmarks import run_local

                result = run_local(db, job.owner)
                value.update(
                    status="completed" if result.value()["passed"] else "blocked",
                    result_id=result.id,
                )
                job.data = canonical(value)
                db.commit()
        id = "heartbeat-" + role
        d = db.get(Document, id)
        if d:
            d.data = canonical({"role": role, "timestamp": time.time()})
        else:
            document(
                db, "heartbeat", "system", {"role": role, "timestamp": time.time()}, id
            )
        db.commit()


def main(role=None):
    role = role or (sys.argv[1] if len(sys.argv) > 1 else "research")
    if role not in ("research", "verify"):
        raise SystemExit("Expected research or verify")
    from .logging import configure

    configure()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    import redis

    r = redis.from_url(settings().redis_url, socket_connect_timeout=1, socket_timeout=2)
    while alive:
        tick(role)
        try:
            r.blpop("atlas:wake:" + role, timeout=1)
        except redis.RedisError:
            time.sleep(1)


if __name__ == "__main__":
    main()
