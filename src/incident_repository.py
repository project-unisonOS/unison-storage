"""Encrypted, principal-bound persistence for shared household incidents."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.fernet import Fernet, InvalidToken
from unison_common.contracts.v1.shared_incident import (
    HouseholdIncident,
    IncidentAssignment,
    IncidentState,
    SensorObservation,
)


class IncidentRejected(ValueError):
    """A request crossed an authority, integrity, or lifecycle boundary."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


class IncidentRepository:
    """Restart-safe incident state with one governed access path.

    Callers must supply the shared spaces and household members authorized by
    the current principal.  Denials intentionally use the same error so this
    repository does not become an incident or membership oracle.
    """

    def __init__(self, root: Path, encryption_key: bytes):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = root / "incident-state.enc"
        self.pending_path = root / "incident-state.pending"
        self.fernet = Fernet(encryption_key)
        if not self.state_path.exists():
            self._write({"incidents": {}, "observations": {}, "media": {}})

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.fernet.decrypt(self.state_path.read_bytes()).decode())
        except (InvalidToken, OSError, json.JSONDecodeError) as exc:
            raise IncidentRejected("incident state is unavailable") from exc

    def _write(self, state: dict[str, Any]) -> None:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        self.pending_path.write_bytes(self.fernet.encrypt(payload))
        self.pending_path.chmod(0o600)
        self.pending_path.replace(self.state_path)

    @staticmethod
    def _authorize(space_id: str, authorized_space_ids: Iterable[str]) -> None:
        if not space_id.startswith("shared:") or space_id not in set(authorized_space_ids):
            raise IncidentRejected("incident unavailable")

    def create(self, person_id: str, incident: HouseholdIncident,
               authorized_space_ids: Iterable[str]) -> HouseholdIncident:
        self._authorize(incident.space_id, authorized_space_ids)
        state = self._read()
        existing = state["incidents"].get(incident.incident_id)
        if existing:
            if existing["incident"] == incident.model_dump(mode="json"):
                return HouseholdIncident.model_validate(existing["incident"])
            raise IncidentRejected("incident identifier is already in use")
        state["incidents"][incident.incident_id] = {
            "created_by": person_id,
            "incident": incident.model_dump(mode="json"),
        }
        self._write(state)
        return incident

    def get(self, person_id: str, space_id: str, incident_id: str,
            authorized_space_ids: Iterable[str]) -> HouseholdIncident:
        del person_id  # authorization is expressed through the principal's spaces
        self._authorize(space_id, authorized_space_ids)
        record = self._read()["incidents"].get(incident_id)
        if not record or record["incident"]["space_id"] != space_id:
            raise IncidentRejected("incident unavailable")
        return HouseholdIncident.model_validate(record["incident"])

    def admit_observation(self, person_id: str, space_id: str, incident_id: str,
                          observation: SensorObservation,
                          authorized_space_ids: Iterable[str],
                          at: datetime | None = None) -> dict[str, Any]:
        self.get(person_id, space_id, incident_id, authorized_space_ids)
        if observation.integrity_state not in {"verified", "fixture"}:
            raise IncidentRejected("observation integrity is insufficient")
        if observation.fresh_until < (at or _now()):
            raise IncidentRejected("observation is stale")
        state = self._read()
        key = f"{observation.sensor_id}:{observation.source_sequence}"
        payload = observation.model_dump(mode="json")
        existing = state["observations"].get(key)
        if existing:
            if existing["observation"] == payload and existing["incident_id"] == incident_id:
                return {"status": "replayed", "observation": observation}
            raise IncidentRejected("sensor sequence conflicts with admitted evidence")
        if any(item["observation"]["observation_id"] == observation.observation_id
               for item in state["observations"].values()):
            raise IncidentRejected("observation identifier is already in use")
        state["observations"][key] = {
            "incident_id": incident_id,
            "space_id": space_id,
            "observation": payload,
        }
        self._write(state)
        return {"status": "accepted", "observation": observation}

    def replace(self, person_id: str, incident: HouseholdIncident,
                authorized_space_ids: Iterable[str]) -> HouseholdIncident:
        current = self.get(person_id, incident.space_id, incident.incident_id, authorized_space_ids)
        old = [event.model_dump(mode="json") for event in current.timeline]
        new = [event.model_dump(mode="json") for event in incident.timeline]
        if len(new) < len(old) or new[:len(old)] != old:
            raise IncidentRejected("incident history is append-only")
        if current.state == IncidentState.CLOSED and incident != current:
            raise IncidentRejected("closed incidents are immutable")
        state = self._read()
        state["incidents"][incident.incident_id]["incident"] = incident.model_dump(mode="json")
        if incident.state == IncidentState.CLOSED:
            state["media"] = {
                key: value for key, value in state["media"].items()
                if value["incident_id"] != incident.incident_id or value["retention"] != "delete-at-close"
            }
        self._write(state)
        return incident

    def assign(self, person_id: str, space_id: str, assignment: IncidentAssignment,
               authorized_space_ids: Iterable[str], household_member_ids: Iterable[str]) -> HouseholdIncident:
        incident = self.get(person_id, space_id, assignment.incident_id, authorized_space_ids)
        if assignment.assignee_person_id not in set(household_member_ids):
            raise IncidentRejected("incident unavailable")
        matches = [item for item in incident.assignments if item.assignment_id == assignment.assignment_id]
        if matches:
            if matches[0] == assignment:
                return incident
            raise IncidentRejected("assignment identifier is already in use")
        updated = incident.model_copy(update={"assignments": [*incident.assignments, assignment]})
        return self.replace(person_id, updated, authorized_space_ids)

    def retain_media_handle(self, person_id: str, space_id: str, incident_id: str,
                            handle_id: str, source_id: str, authorized_space_ids: Iterable[str],
                            retention: str = "delete-at-close") -> dict[str, str]:
        self.get(person_id, space_id, incident_id, authorized_space_ids)
        if retention not in {"delete-at-close", "incident", "person-controlled"}:
            raise IncidentRejected("media retention class is invalid")
        if not handle_id or not source_id or any(token in handle_id for token in ("/", "\\", "..")):
            raise IncidentRejected("only opaque selected-media handles may be retained")
        state = self._read()
        record = {"incident_id": incident_id, "space_id": space_id, "source_id": source_id,
                  "retention": retention}
        existing = state["media"].get(handle_id)
        if existing and existing != record:
            raise IncidentRejected("media handle is already in use")
        state["media"][handle_id] = record
        self._write(state)
        return {"handle_id": handle_id, **record}

    def media_handles(self, person_id: str, space_id: str, incident_id: str,
                      authorized_space_ids: Iterable[str]) -> list[dict[str, str]]:
        self.get(person_id, space_id, incident_id, authorized_space_ids)
        return [{"handle_id": key, **value} for key, value in self._read()["media"].items()
                if value["incident_id"] == incident_id]
