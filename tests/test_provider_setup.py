"""Credential-file tests use dummy local keys; no real credentials or HTTP."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from atlas import gateway, provider_setup
from atlas.config import settings
from atlas.db import Document


def test_raw_key_newlines_permissions_and_no_file_reformatting(db, tmp_path):
    key = tmp_path / ".env"
    original = b"synthetic-key-for-test-only\r\n\n"
    key.write_bytes(original)
    key.chmod(0o600)
    assert provider_setup.read_key_file(key) == "synthetic-key-for-test-only"
    assert key.read_bytes() == original
    key.chmod(0o644)
    with pytest.raises(ValueError, match="restrictive permissions"):
        provider_setup.read_key_file(key)
    link = tmp_path / "linked-key"
    link.symlink_to(key)
    with pytest.raises(ValueError, match="symbolic link"):
        provider_setup.read_key_file(link)


def test_raw_dotenv_key_is_not_implicitly_parsed_as_settings(
    db, tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    raw = "synthetic-raw-key-for-test-only"
    (tmp_path / ".env").write_text(raw)
    settings.cache_clear()
    assert settings().global_token_cap == 50000000
    assert raw not in capsys.readouterr().out
    assert (tmp_path / ".env").read_text() == raw


def test_provider_setup_encrypts_key_and_does_not_substitute_models(
    db, tmp_path, monkeypatch
):
    path = tmp_path / "raw-key"
    key = "synthetic-provider-key-not-real"
    path.write_text(key + "\n")
    path.chmod(0o600)
    monkeypatch.setattr(gateway, "provider_scope", lambda *_: None)
    monkeypatch.setattr(
        provider_setup,
        "construct_adapter",
        lambda _: SimpleNamespace(
            list_models=lambda: [{"id": "primary-fixture"}, {"id": "validator-fixture"}]
        ),
    )
    result = provider_setup.configure_provider(
        db,
        path,
        "https://provider.example.invalid/v1",
        "primary-fixture",
        "validator-fixture",
        bootstrap=True,
    )
    assert result["requested_models_available"] and not result["substituted_models"]
    assert result["aliases"]["verifier"] == "validator-fixture"
    assert key not in db.query(Document).filter_by(kind="provider").one().data
    assert key not in str(result)
    assert (
        Path(settings().data_dir) / "operator-access.json"
    ).stat().st_mode & 0o077 == 0
    again = provider_setup.configure_provider(
        db,
        path,
        "https://provider.example.invalid/v1",
        "primary-fixture",
        "validator-fixture",
    )
    assert again["provider_id"] == result["provider_id"]
    assert db.query(Document).filter_by(kind="provider").count() == 1


def test_missing_requested_models_create_no_alias_fallback(db, tmp_path, monkeypatch):
    path = tmp_path / "raw-key"
    path.write_text("synthetic-key-not-real")
    path.chmod(0o600)
    monkeypatch.setattr(gateway, "provider_scope", lambda *_: None)
    monkeypatch.setattr(
        provider_setup,
        "construct_adapter",
        lambda _: SimpleNamespace(list_models=lambda: [{"id": "unrequested-model"}]),
    )
    result = provider_setup.configure_provider(
        db,
        path,
        "https://provider.example.invalid/v1",
        "requested-primary",
        "requested-validator",
        bootstrap=True,
    )
    assert result["status"] == "requested_models_unavailable"
    assert result["missing_models"] == ["requested-primary", "requested-validator"]
    assert not result["substituted_models"]
    assert db.query(Document).filter_by(kind="alias").count() == 0
