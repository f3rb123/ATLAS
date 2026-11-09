"""Opt-in integration against a disposable local atlas_test database only."""

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from atlas import db as store
from atlas.config import settings
from atlas.db import Document, SwarmTask, session
from atlas.swarm import SwarmOutput, execute_one

pytestmark = pytest.mark.skipif(
    not os.environ.get("ATLAS_TEST_POSTGRES_URL_FILE"),
    reason="Disposable PostgreSQL selector not supplied",
)


@pytest.fixture
def postgres(tmp_path, monkeypatch):
    url = make_url(Path(os.environ["ATLAS_TEST_POSTGRES_URL_FILE"]).read_text().strip())
    if url.database != "atlas_test" or url.host != "127.0.0.1" or url.port != 55432:
        pytest.fail(
            "Use the disposable local atlas_test container; application databases are prohibited"
        )
    admin = create_engine(url, hide_parameters=True)
    schema = "atlas_test_" + uuid.uuid4().hex
    with admin.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public"))
        conn.execute(text('CREATE SCHEMA "' + schema + '"'))
    scoped = url.update_query_dict({"options": "-csearch_path=" + schema + ",public"})
    monkeypatch.setenv(
        "ATLAS_DATABASE_URL", scoped.render_as_string(hide_password=False)
    )
    monkeypatch.setenv("ATLAS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ATLAS_EMBEDDING_MODEL", "hash")
    settings.cache_clear()
    if store._engine:
        store._engine.dispose()
    store._engine = store._factory = None
    try:
        command.upgrade(Config("alembic.ini"), "head")
        command.upgrade(Config("alembic.ini"), "head")  # idempotent refresh
        yield store.engine()
    finally:
        if store._engine:
            store._engine.dispose()
        store._engine = store._factory = None
        settings.cache_clear()
        with admin.begin() as conn:
            conn.execute(text('DROP SCHEMA "' + schema + '" CASCADE'))
        admin.dispose()


def test_postgres_migrations_real_concurrency_and_restart(postgres, monkeypatch):
    # Same creation/overlap assertions as SQLite, on actual PG row/advisory locks.
    from test_swarm import prepare

    with session() as db:
        run = prepare(db, 4)
        run_id = run.id
        assert (
            db.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            == "0005"
        )
        assert db.execute(
            text("SELECT extversion FROM pg_extension WHERE extname='vector'")
        ).scalar_one()
    barrier = threading.Barrier(4, timeout=10)

    def model(*args, **kwargs):
        barrier.wait()
        return SwarmOutput(
            summary="Synthetic model response; actual PostgreSQL scheduling"
        )

    monkeypatch.setattr("atlas.workflow.role", model)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda _: execute_one("research"), range(4)))
    postgres.dispose()  # force fresh physical connections, not an ORM identity map
    with session() as restarted:
        assert (
            restarted.query(SwarmTask)
            .filter_by(run_id=run_id, status="completed")
            .count()
            == 4
        )
        assert restarted.get(Document, run_id).value()["status"] == "completed"
        assert restarted.query(Document).filter_by(kind="finding").count() == 0
