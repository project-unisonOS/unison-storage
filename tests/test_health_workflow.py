import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from test_storage_authority import boundary  # noqa: F401
from test_health_pilot import export
from health_workflow import HealthWorkflow, initialize_authority

SCOPES = ["storage.health.workflow."+s for s in ("consent", "import", "read", "delete", "backup", "restore")]


@pytest.fixture
def workflow(boundary, monkeypatch, tmp_path):
    module, client, headers, revoked = boundary
    root, ledger = tmp_path/"workflow", tmp_path/"authority"/"ledger.sqlite3"
    initialize_authority(ledger, os.environ["STORAGE_OBJECT_ENC_KEY"].encode())
    monkeypatch.setenv("UNISON_SYNTHETIC_HEALTH_WORKFLOW", "true")
    monkeypatch.setenv("UNISON_HEALTH_WORKFLOW_ROOT", str(root))
    monkeypatch.setenv("UNISON_HEALTH_AUTHORITY_PATH", str(ledger))
    return client, headers, root, ledger


def prepare(workflow, payload=None):
    client, headers, root, ledger = workflow
    raw = json.dumps(export() if payload is None else payload).encode()
    auth = headers(scopes=SCOPES)
    metadata = dict(filename="synthetic.json", sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw), confirmed=True)
    response = client.post("/v1/health-workflows", headers=auth, json=metadata)
    assert response.status_code == 200, response.text
    wid = response.json()["workflow_id"]
    return wid, raw, auth


def upload(client, wid, raw, auth):
    return client.post(f"/v1/health-workflows/{wid}/upload", headers=auth,
                       json={"content_b64": base64.b64encode(raw).decode()})


@pytest.mark.parametrize("mode", ["revoke", "delete"])
def test_consent_review_summary_terminate_restore_old_data(workflow, mode):
    client, headers, root, ledger = workflow
    wid, raw, auth = prepare(workflow)
    assert upload(client, wid, raw, auth).status_code == 200
    view = client.get(f"/v1/health-workflows/{wid}", headers=auth).json()
    assert "420 minutes" in view["summary"][0]["text"]
    assert "unknown" in view["summary"][1]["text"]
    assert view["summary"][0]["record_ids"] == [view["records"][0]["record_id"]]
    assert view["records"][0]["provenance"]["source_sha256"] == hashlib.sha256(raw).hexdigest()
    bid = client.post(f"/v1/health-workflows/{wid}/backup", headers=auth).json()["snapshot_id"]
    old_data = (root/"workflow.sqlite3").read_bytes()
    if mode == "revoke": response = client.post(f"/v1/health-workflows/{wid}/revoke", headers=auth)
    else: response = client.delete(f"/v1/health-workflows/{wid}", headers=auth)
    assert response.status_code == 200
    # Real old encrypted SQLite bytes replace the data store; authority is retained.
    (root/"workflow.sqlite3").write_bytes(old_data)
    assert client.get(f"/v1/health-workflows/{wid}", headers=auth).status_code == 403
    assert upload(client, wid, raw, auth).status_code == 403
    restored = client.post(f"/v1/health-workflows/{wid}/restore", headers=auth, json={"snapshot_id": bid})
    assert restored.json()["unavailable"] is True and restored.json()["restored"] is False
    state = HealthWorkflow(root, ledger, os.environ["STORAGE_OBJECT_ENC_KEY"].encode()).data.read()
    assert state == {"imports": {}, "snapshots": {}}


def test_upload_cannot_precede_or_change_consent(workflow):
    client, _, root, ledger = workflow
    wid, raw, auth = prepare(workflow)
    assert upload(client, "unconsented", raw, auth).status_code == 403
    assert upload(client, wid, raw+b" ", auth).status_code == 403
    assert client.get(f"/v1/health-workflows/{wid}", headers=auth).json()["records"] == []
    assert upload(client, wid, raw, auth).status_code == 200
    assert upload(client, wid, raw, auth).status_code == 200


@pytest.mark.parametrize("case", ["units", "date", "conflict", "nonsynthetic"])
def test_invalid_exports_leave_no_content(workflow, case):
    client, _, _, _ = workflow
    payload = export()
    if case == "units": payload["observations"][0]["unit"] = "count"
    if case == "date": payload["observations"][0]["source_day"] = "yesterday"
    if case == "conflict": payload["observations"].append({**payload["observations"][0], "value": 99})
    if case == "nonsynthetic": payload["synthetic"] = False
    wid, raw, auth = prepare(workflow, payload)
    assert upload(client, wid, raw, auth).status_code == 403
    assert client.get(f"/v1/health-workflows/{wid}", headers=auth).json()["records"] == []


def test_duplicates_missing_and_valid_restore(workflow):
    client, _, _, _ = workflow
    payload = export()
    payload["observations"][0].update(value=None, quality="missing", missing_reason="Device not worn")
    payload["observations"].append(dict(payload["observations"][0]))
    wid, raw, auth = prepare(workflow, payload)
    assert upload(client, wid, raw, auth).json()["duplicates_removed"] == 1
    view = client.get(f"/v1/health-workflows/{wid}", headers=auth).json()
    assert "Device not worn" in view["summary"][0]["text"] and view["records"][0]["facts"]["value"] is None
    bid = client.post(f"/v1/health-workflows/{wid}/backup", headers=auth).json()["snapshot_id"]
    assert client.post(f"/v1/health-workflows/{wid}/restore", headers=auth, json={"snapshot_id": bid}).json()["restored"] is True


@pytest.mark.parametrize("case", ["foreign", "scope", "missing_ledger", "expired", "wrong_policy"])
def test_authority_unavailable_fails_closed(workflow, case):
    client, headers, root, ledger = workflow
    wid, raw, auth = prepare(workflow)
    assert upload(client, wid, raw, auth).status_code == 200
    if case == "foreign": auth = headers("bob", scopes=SCOPES)
    if case == "scope": auth = headers(scopes=["storage.health.workflow.import"])
    if case == "missing_ledger": ledger.unlink()
    if case in {"expired", "wrong_policy"}:
        service = HealthWorkflow(root, ledger, os.environ["STORAGE_OBJECT_ENC_KEY"].encode())
        state = service.authority.read()
        state["grants"][wid]["expires_at" if case == "expired" else "policy_version"] = 0 if case == "expired" else "old"
        service.authority.write(state)
    assert client.get(f"/v1/health-workflows/{wid}", headers=auth).status_code == 403
    if case == "missing_ledger": assert not ledger.exists()


def test_crash_between_terminal_authority_and_purge(workflow, monkeypatch):
    client, _, _, _ = workflow
    wid, raw, auth = prepare(workflow)
    assert upload(client, wid, raw, auth).status_code == 200
    original = HealthWorkflow._purge
    def crash(*args): raise RuntimeError("synthetic crash")
    monkeypatch.setattr(HealthWorkflow, "_purge", crash)
    assert client.delete(f"/v1/health-workflows/{wid}", headers=auth).status_code == 403
    assert client.get(f"/v1/health-workflows/{wid}", headers=auth).status_code == 403
    monkeypatch.setattr(HealthWorkflow, "_purge", original)
    assert client.delete(f"/v1/health-workflows/{wid}", headers=auth).json()["content_removed"] is True

def test_restore_and_revoke_serialize(workflow):
    from concurrent.futures import ThreadPoolExecutor
    client, _, _, _ = workflow
    wid, raw, auth = prepare(workflow)
    assert upload(client, wid, raw, auth).status_code == 200
    bid = client.post(f"/v1/health-workflows/{wid}/backup", headers=auth).json()["snapshot_id"]
    with ThreadPoolExecutor(2) as pool:
        restored = pool.submit(client.post, f"/v1/health-workflows/{wid}/restore", headers=auth, json={"snapshot_id": bid})
        revoked = pool.submit(client.post, f"/v1/health-workflows/{wid}/revoke", headers=auth)
        assert restored.result().status_code == 200
        assert revoked.result().status_code == 200
    response = client.get(f"/v1/health-workflows/{wid}", headers=auth)
    assert response.status_code == 403 and response.headers["Cache-Control"] == "no-store"


def test_corrupt_authority_never_reprovisions(workflow):
    client, _, _, ledger = workflow
    wid, raw, auth = prepare(workflow)
    assert upload(client, wid, raw, auth).status_code == 200
    ledger.write_bytes(b"broken authority")
    assert client.get(f"/v1/health-workflows/{wid}", headers=auth).status_code == 403
    assert ledger.read_bytes() == b"broken authority"
