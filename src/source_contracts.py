"""Shared synthetic-source errors and canonical evidence hashing/decoding."""
import hashlib
import json

class PilotDenied(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def decode_unique(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)



from typing import Protocol

class SourceAdapter(Protocol):
    identifier: str
    purpose: str
    def extract(self, raw: bytes, person: str, source_id: str, ingested_at: str,
                source_sha256: str) -> tuple[list[dict], int]: ...
    def present(self, records: list[dict]) -> tuple[list[dict], str]: ...
