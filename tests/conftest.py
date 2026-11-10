import os
import pytest
from atlas import db as store
from atlas.config import settings


@pytest.fixture
def db(tmp_path, monkeypatch):
    # Unit tests must not inherit a running cloud/production origin or key file.
    monkeypatch.setenv("ATLAS_ENV", "development")
    monkeypatch.setenv("ATLAS_EXTERNAL_URL", "http://localhost:8000")
    monkeypatch.delenv("ATLAS_CONFIG_FILE", raising=False)
    monkeypatch.delenv("ATLAS_PROVIDER_KEY_FILE", raising=False)
    monkeypatch.setenv("ATLAS_DATABASE_URL", "sqlite:///" + str(tmp_path / "test.db"))
    monkeypatch.setenv("ATLAS_DATA_DIR", str(tmp_path / "data"))
    p = tmp_path / "master"
    p.write_bytes(os.urandom(32))
    p.chmod(0o600)
    monkeypatch.setenv("ATLAS_MASTER_KEY_FILE", str(p))
    monkeypatch.setenv("ATLAS_EMBEDDING_MODEL", "hash")
    settings.cache_clear()
    if store._engine:
        store._engine.dispose()
    store._engine = None
    store._factory = None
    store.Base.metadata.create_all(store.engine())
    with store.session() as s:
        yield s
    store._engine.dispose()
    store._engine = None
    store._factory = None
    settings.cache_clear()
