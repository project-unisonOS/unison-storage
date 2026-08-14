import os
import pathlib
import sys
from datetime import timedelta

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

os.environ["UNISON_PRINCIPAL_BINDING_TEST_BYPASS"] = "true"
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "src"))

import server
from incident_repository import IncidentRepository
from test_incident_repository import NOW, SPACE, incident, observation
from unison_common.contracts.v1.shared_incident import IncidentAssignment


def test_versioned_incident_api_is_restart_safe_and_space_bound(monkeypatch, tmp_path):
    store = IncidentRepository(tmp_path, Fernet.generate_key())
    monkeypatch.setattr(server, "_INCIDENT_REPOSITORY", store)
    item = incident().model_copy(update={"assignments": [IncidentAssignment(
        assignment_id="a1", incident_id="inc-1", workflow_step_id="inspect",
        assignee_person_id="alice", action="Inspect", created_at=NOW, source_ids=["procedure-1"])]})
    client = TestClient(server.app)
    authority = {"person_id": "alice", "authorized_space_ids": [SPACE], "household_member_ids": ["alice"]}
    created = client.post("/v1/incidents", json={**authority, "incident": item.model_dump(mode="json"),
                                                  "observation": observation().model_dump(mode="json")})
    assert created.status_code == 201
    acknowledged = client.post("/v1/incidents/inc-1/assignments/a1/state", json={
        **authority, "space_id": SPACE, "state": "acknowledged", "at": (NOW + timedelta(minutes=1)).isoformat()})
    assert acknowledged.status_code == 200
    read = client.post("/v1/incidents/inc-1/read", json={**authority, "space_id": SPACE})
    assert read.status_code == 200
    assert read.json()["incident"]["assignments"][0]["state"] == "acknowledged"
    denied = client.post("/v1/incidents/inc-1/read", json={
        "person_id": "mallory", "authorized_space_ids": ["shared:other"], "space_id": SPACE})
    assert denied.status_code == 404
