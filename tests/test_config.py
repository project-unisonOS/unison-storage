from __future__ import annotations

from pathlib import Path

from src.settings import StorageServiceSettings


def test_storage_settings_defaults(monkeypatch):
    monkeypatch.delenv("UNISON_STORAGE_DB", raising=False)

    settings = StorageServiceSettings.from_env()

    assert settings.db_path == Path("/data/store.db")


def test_storage_settings_env_override(monkeypatch):
    monkeypatch.setenv("UNISON_STORAGE_DB", "/tmp/custom.db")

    settings = StorageServiceSettings.from_env()

    assert settings.db_path == Path("/tmp/custom.db")
