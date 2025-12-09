"""Typed configuration for the unison-storage service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StorageServiceSettings:
    """Top-level configuration surface."""

    db_path: Path = Path("/data/store.db")
    database_url: str = ""
    service_token: str = ""
    object_enc_key: str = ""

    @classmethod
    def from_env(cls) -> "StorageServiceSettings":
        return cls(
            db_path=Path(os.getenv("UNISON_STORAGE_DB", "/data/store.db")),
            database_url=os.getenv("STORAGE_DATABASE_URL", ""),
            service_token=os.getenv("STORAGE_SERVICE_TOKEN", ""),
            object_enc_key=os.getenv("STORAGE_OBJECT_ENC_KEY", ""),
        )


__all__ = ["StorageServiceSettings"]
