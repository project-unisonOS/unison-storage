"""Typed configuration for the unison-storage service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StorageServiceSettings:
    """Top-level configuration surface."""

    db_path: Path = Path("/data/store.db")

    @classmethod
    def from_env(cls) -> "StorageServiceSettings":
        return cls(
            db_path=Path(os.getenv("UNISON_STORAGE_DB", "/data/store.db")),
        )


__all__ = ["StorageServiceSettings"]
