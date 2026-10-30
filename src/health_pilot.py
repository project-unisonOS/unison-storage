"""Bounded synthetic export pilot. No model, connector or caller facts confer authority.

The policy evaluator is independent of bearer scopes and extraction: a durable
owner grant must match the fixed purpose/version at every operation. It shares
the source transaction so revocation, extraction and deletion serialize. This is
an in-process reference monitor, not protection from a compromised storage host.
"""
import hashlib
import json
import secrets
import time
from datetime import date, datetime, timezone
from typing import Literal
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, model_validator

POLICY_VERSION = "synthetic-health-policy.v1"
PARSER_VERSION = "synthetic-export.v1"
PURPOSE = "wellness.summary"


class PilotDenied(ValueError):
    pass


class ExportRow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    upstream_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    device: str = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=128)
    metric: Literal["sleep_duration", "steps"]
    kind: Literal["measurement", "vendor_score", "statement", "inference"]
    value: float | None
    unit: Literal["minutes", "count"]
    source_day: str
    original_timezone: str
    measured_start: str
    measured_end: str
    quality: Literal["valid", "missing", "invalid"]
    missing_reason: str | None = None
    revision: int = Field(ge=1)

    @model_validator(mode="after")
    def coherent(self):
        day = date.fromisoformat(self.source_day)
        zone = ZoneInfo(self.original_timezone)
        start, end = datetime.fromisoformat(self.measured_start), datetime.fromisoformat(self.measured_end)
        if start.utcoffset() is None or end.utcoffset() is None or end < start:
            raise ValueError("aware ordered interval required")
        if end.astimezone(zone).date() != day:
            raise ValueError("source day must match interval end in original timezone")
        if self.unit != {"sleep_duration": "minutes", "steps": "count"}[self.metric]:
            raise ValueError("metric unit mismatch")
        if self.value is not None and self.value < 0:
            raise ValueError("negative value")
        if self.quality == "valid" and self.value is None:
            raise ValueError("valid value required")
        if self.quality != "valid" and (self.value is not None or not self.missing_reason):
            raise ValueError("missing is unknown, never zero")
        return self


class Export(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["synthetic-health-export.v1"]
    synthetic: Literal[True]
    observations: list[ExportRow] = Field(min_length=1, max_length=500)

    @model_validator(mode="before")
    @classmethod
    def synthetic_only(cls, value):
        if not isinstance(value, dict) or value.get("synthetic") is not True:
            raise ValueError("explicit synthetic export required")
        return value


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


class HealthPilot:
    def __init__(self, library, enabled=False):
        self.library = library
        self.enabled = enabled

    def _enabled(self):
        if not self.enabled:
            raise PilotDenied("synthetic pilot is disabled")

    def grant(self, person, sources, expires_at, purpose, confirmed):
        self._enabled()
        now = time.time()
        if (confirmed is not True or purpose != PURPOSE or type(expires_at) not in (int, float)
                or not now < expires_at <= now + 14 * 86400 or not isinstance(sources, list)
                or not 1 <= len(sources) <= 2):
            raise PilotDenied("explicit bounded wellness consent required")
        with self.library.admitted_references(person, sources):
            state = self.library._read_index()
            grant_id = "grant_" + secrets.token_urlsafe(18)
            grant = dict(grant_id=grant_id, person_id=person, source_ids=sorted(sources),
                         purpose=PURPOSE, policy_version=POLICY_VERSION, expires_at=expires_at,
                         state="active", created_at=now)
            state.setdefault("pilot_grants", {})[grant_id] = grant
            self.library._write_index(state)
            return grant

    def _authorize(self, state, person, grant_id, action):
        self._enabled()
        grant = state.get("pilot_grants", {}).get(grant_id)
        if (not grant or grant["person_id"] != person or grant["state"] != "active"
                or grant["expires_at"] <= time.time() or grant["policy_version"] != POLICY_VERSION
                or grant["purpose"] != PURPOSE or action not in {"extract", "read", "present"}):
            raise PilotDenied("current owner consent and policy required")
        return grant

    def authorize(self, person, grant_id, action):
        with self.library._state.transaction():
            state = self.library._read_index()
            grant = self._authorize(state, person, grant_id, action)
            with self.library.admitted_references(person, grant["source_ids"]):
                return {"allowed": True, "policy_version": POLICY_VERSION, "grant_id": grant_id}

    def revoke(self, person, grant_id):
        self._enabled()
        with self.library._state.transaction():
            state = self.library._read_index()
            grant = state.get("pilot_grants", {}).get(grant_id)
            if not grant or grant["person_id"] != person:
                raise PilotDenied("owner consent not found")
            grant.update(state="revoked", revoked_at=time.time())
            self.library._write_index(state)
            return {"grant_id": grant_id, "state": "revoked"}

    def _records(self, state, person, source_id, grant_id, ingested_at):
        source = state["sources"][source_id]
        if source["media_type"] != "application/json" or source["size_bytes"] > 1024 * 1024:
            raise PilotDenied("bounded JSON export required")
        raw = self.library._state.get_blob(source_id)
        export = Export.model_validate(decode_unique(raw))
        records, seen = [], {}
        for position, row in enumerate(export.observations):
            original = row.model_dump()
            key = (row.source, row.upstream_id, row.metric, row.revision)
            if key in seen and seen[key] != original:
                raise PilotDenied("conflicting export revision")
            if key in seen:
                continue
            seen[key] = original
            fact = dict(original, synthetic=True, person_id=person,
                        observation_id=f"{source_id}:{position}", source_record_id=source_id,
                        ingestion_source="synthetic-export", ingested_at=ingested_at,
                        consent_id=grant_id, transformation_version="synthetic-observation.v1",
                        original_payload=original)
            provenance = dict(parser_version=PARSER_VERSION, source_sha256=source["checksum_sha256"],
                              row_pointer=f"/observations/{position}", fact_sha256=digest(fact))
            records.append(dict(record_id=f"{source_id}:{position}", person_id=person, domain="health",
                                record_type="wearable-observation", shared=False, evidence_status="observed",
                                facts=fact, source_ids=[source_id], provenance=provenance))
        return records

    def extract(self, person, source_id, grant_id):
        with self.library._state.transaction():
            state = self.library._read_index()
            grant = self._authorize(state, person, grant_id, "extract")
            if source_id not in grant["source_ids"]:
                raise PilotDenied("source is outside consent")
            with self.library.admitted_references(person, [source_id]):
                receipts = state.setdefault("pilot_extractions", {})
                previous = receipts.get(source_id)
                stamp = (previous["ingested_at"] if previous and previous["grant_id"] == grant_id
                         else datetime.now(timezone.utc).isoformat())
                records = self._records(state, person, source_id, grant_id, stamp)
                receipts[source_id] = dict(grant_id=grant_id, ingested_at=stamp,
                                           records_sha256=digest(records), parser_version=PARSER_VERSION)
                self.library._write_index(state)
                return {"source_id": source_id, "count": len(records), "records_sha256": digest(records),
                        "parser_version": PARSER_VERSION}

    def read(self, person, grant_id):
        with self.library._state.transaction():
            state = self.library._read_index()
            grant = self._authorize(state, person, grant_id, "read")
            with self.library.admitted_references(person, grant["source_ids"]):
                records = []
                for source_id in grant["source_ids"]:
                    receipt = state.get("pilot_extractions", {}).get(source_id)
                    if not receipt or receipt["grant_id"] != grant_id or receipt["parser_version"] != PARSER_VERSION:
                        raise PilotDenied("verified extraction required")
                    extracted = self._records(state, person, source_id, grant_id, receipt["ingested_at"])
                    if digest(extracted) != receipt["records_sha256"]:
                        raise PilotDenied("extraction integrity failed")
                    records.extend(extracted)
                return {"records": records, "policy_version": POLICY_VERSION}
