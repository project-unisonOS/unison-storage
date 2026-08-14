from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from unison_common.contracts.v1.shared_incident import (
    HouseholdIncident,
    IncidentAssignment,
    IncidentState,
    IncidentTimelineEvent,
    SensorObservation,
)

from src.incident_repository import IncidentRejected, IncidentRepository


NOW = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)
SPACE = "shared:household-1"


def event(event_id: str, state: IncidentState, minute: int = 0,
          source_ids: list[str] | None = None) -> IncidentTimelineEvent:
    return IncidentTimelineEvent(event_id=event_id, state=state, occurred_at=NOW + timedelta(minutes=minute),
                                 actor_id="unison", reason=state.value, source_ids=source_ids or ["sensor-1"],
                                 deterministic_rule="water:hazard" if state == IncidentState.ESCALATED else None)


def incident(state=IncidentState.OBSERVED, timeline=None):
    return HouseholdIncident(incident_id="inc-1", space_id=SPACE, kind="water-leak", state=state,
                             severity="urgent", source_ids=["sensor-1"], timeline=timeline or [event("e1", state)])


def observation(sequence=1, value=True, integrity="verified", fresh_until=None):
    return SensorObservation(observation_id=f"obs-{sequence}", sensor_id="sensor-1", source_sequence=sequence,
                             observed_at=NOW, received_at=NOW, state="wet", value=value, unit="boolean",
                             confidence=0.99, fresh_until=fresh_until or NOW + timedelta(minutes=5),
                             integrity_state=integrity, device_health="healthy")


def repository(tmp_path, key=None):
    return IncidentRepository(tmp_path, key or Fernet.generate_key())


def test_create_read_and_restart_are_principal_space_bound(tmp_path):
    key = Fernet.generate_key()
    store = repository(tmp_path, key)
    store.create("alice", incident(), [SPACE])
    assert store.get("alice", SPACE, "inc-1", [SPACE]).kind == "water-leak"
    assert repository(tmp_path, key).get("bob", SPACE, "inc-1", [SPACE]).incident_id == "inc-1"
    with pytest.raises(IncidentRejected, match="incident unavailable"):
        store.get("mallory", SPACE, "inc-1", ["shared:other"])


def test_observation_admission_is_fresh_integrity_gated_and_idempotent(tmp_path):
    store = repository(tmp_path)
    store.create("alice", incident(), [SPACE])
    assert store.admit_observation("alice", SPACE, "inc-1", observation(), [SPACE], NOW)["status"] == "accepted"
    assert store.admit_observation("alice", SPACE, "inc-1", observation(), [SPACE], NOW)["status"] == "replayed"
    with pytest.raises(IncidentRejected, match="conflicts"):
        store.admit_observation("alice", SPACE, "inc-1", observation(value=False), [SPACE], NOW)
    with pytest.raises(IncidentRejected, match="integrity"):
        store.admit_observation("alice", SPACE, "inc-1", observation(2, integrity="unverified"), [SPACE], NOW)
    with pytest.raises(IncidentRejected, match="stale"):
        store.admit_observation("alice", SPACE, "inc-1", observation(3), [SPACE], NOW + timedelta(hours=1))


def test_history_is_append_only_and_contract_rejects_illegal_transition(tmp_path):
    store = repository(tmp_path)
    store.create("alice", incident(), [SPACE])
    assessing = incident(IncidentState.ASSESSING, [event("e1", IncidentState.OBSERVED),
                                                   event("e2", IncidentState.ASSESSING, 1)])
    assert store.replace("alice", assessing, [SPACE]).state == IncidentState.ASSESSING
    with pytest.raises(IncidentRejected, match="append-only"):
        store.replace("alice", incident(), [SPACE])
    with pytest.raises(ValidationError, match="illegal incident transition"):
        incident(IncidentState.RECOVERED, [event("e1", IncidentState.OBSERVED),
                                           event("e2", IncidentState.RECOVERED, 1)])


def test_assignments_require_current_household_members_and_never_actuate(tmp_path):
    store = repository(tmp_path)
    store.create("alice", incident(), [SPACE])
    assignment = IncidentAssignment(assignment_id="a1", incident_id="inc-1", workflow_step_id="shutoff-check",
                                    assignee_person_id="bob", action="Inspect the labeled manual shutoff",
                                    created_at=NOW, source_ids=["procedure-1"])
    updated = store.assign("alice", SPACE, assignment, [SPACE], ["alice", "bob"])
    assert updated.assignments[0].physical_actuation is False
    with pytest.raises(IncidentRejected, match="incident unavailable"):
        store.assign("alice", SPACE, assignment.model_copy(update={"assignment_id": "a2",
                                                                    "assignee_person_id": "mallory"}),
                     [SPACE], ["alice", "bob"])


def test_only_selected_opaque_media_handles_are_retained_and_ephemeral_media_is_cleaned(tmp_path):
    store = repository(tmp_path)
    store.create("alice", incident(), [SPACE])
    store.retain_media_handle("alice", SPACE, "inc-1", "media-1", "camera-1:frame-44", [SPACE])
    with pytest.raises(IncidentRejected, match="opaque"):
        store.retain_media_handle("alice", SPACE, "inc-1", "C:\\raw\\frame.jpg", "camera-1", [SPACE])
    closed = incident(IncidentState.CLOSED, [event("e1", IncidentState.OBSERVED),
                                             event("e2", IncidentState.CLOSED, 1)])
    store.replace("alice", closed, [SPACE])
    assert store.media_handles("alice", SPACE, "inc-1", [SPACE]) == []


def test_assignment_acknowledgement_and_cancellation_are_restart_safe(tmp_path):
    key = Fernet.generate_key()
    store = repository(tmp_path, key)
    store.create("alice", incident(), [SPACE])
    assignment = IncidentAssignment(assignment_id="a1", incident_id="inc-1", workflow_step_id="inspect",
                                    assignee_person_id="bob", action="Inspect", created_at=NOW,
                                    source_ids=["procedure-1"])
    store.assign("alice", SPACE, assignment, [SPACE], ["alice", "bob"])
    acknowledged = store.update_assignment("bob", SPACE, "inc-1", "a1", "acknowledged",
                                           NOW + timedelta(minutes=1), [SPACE], ["alice", "bob"])
    assert acknowledged.assignments[0].acknowledged_at is not None
    cancelled = repository(tmp_path, key).update_assignment(
        "bob", SPACE, "inc-1", "a1", "cancelled", NOW + timedelta(minutes=2), [SPACE], ["alice", "bob"])
    assert cancelled.assignments[0].state == "cancelled"
