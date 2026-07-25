"""Typed configuration for the unison-storage service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from unison_common.trust import read_secret_setting


@dataclass(frozen=True)
class StorageServiceSettings:
    """Top-level configuration surface."""

    db_path: Path = Path("/data/store.db")
    database_url: str = ""
    service_token: str = ""
    object_enc_key: str = ""
    life_operations_root: Path = Path("/data/life-operations")
    life_domains_root: Path = Path("/data/life-domains")

    @classmethod
    def from_env(cls) -> "StorageServiceSettings":
        return cls(
            db_path=Path(os.getenv("UNISON_STORAGE_DB", "/data/store.db")),
            database_url=os.getenv("STORAGE_DATABASE_URL", ""),
            service_token=os.getenv("STORAGE_SERVICE_TOKEN", ""),
            object_enc_key=read_secret_setting("STORAGE_OBJECT_ENC_KEY"),
            life_operations_root=Path(os.getenv("UNISON_LIFE_OPERATIONS_ROOT", "/data/life-operations")),
            life_domains_root=Path(os.getenv("UNISON_LIFE_DOMAINS_ROOT", "/data/life-domains")),
        )


__all__ = ["StorageServiceSettings"]
