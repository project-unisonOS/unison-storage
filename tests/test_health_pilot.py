"""Authenticated, synthetic-only acceptance for the bounded export pilot."""
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_storage_authority import boundary, INGEST, admitted, record
from health_pilot import digest

CONTROL = (*INGEST, "storage.health.consent", "storage.health.extract", "storage.sources.delete")
READ = ("storage.health.pilot.read",)


def export():
    return {"schema_version": "synthetic-health-export.v1", "synthetic": True, "observations": [{
        "upstream_id": "test-1", "source": "synthetic-ring", "device": "fixture", "method": "fixture",
        "metric": "sleep_duration", "kind": "measurement", "value": 420.0, "unit": "minutes",
        "source_day": "2026-10-20", "original_timezone": "UTC", "measured_start": "2026-10-19T23:00:00+00:00",
        "measured_end": "2026-10-20T06:00:00+00:00", "quality": "valid", "revision": 1}]}


def prepare(boundary, monkeypatch, payload=None):
    module, client, headers, _ = boundary
    monkeypatch.setenv("UNISON_SYNTHETIC_HEALTH_PILOT", "true")
    writer = headers(scopes=CONTROL)
    session = client.post("/v1/imports", headers=writer, json={}).json()["session_id"]
    raw = json.dumps(export() if payload is None else payload).encode()
    response = client.post(f"/v1/imports/{session}/sources", headers=writer, json={
        "filename": "synthetic.json", "media_type": "application/json", "content_b64": base64.b64encode(raw).decode()})
    source = response.json()["source_id"]
    assert client.post(f"/v1/imports/{session}/admit", headers=writer, json={}).status_code == 200
    consent = client.post("/v1/health-pilot/consents", headers=writer, json={
        "source_ids": [source], "purpose": "wellness.summary", "confirmed": True, "expires_at": time.time()+3600})
    assert consent.status_code == 200, consent.text
    return source, consent.json()["grant_id"], writer, session


def extract(client, source, grant, writer):
    return client.post(f"/v1/health-pilot/sources/{source}/extract", headers=writer, json={"grant_id": grant})


def read(client, grant, headers):
    return client.get("/v1/health-pilot/records", params={"grant_id": grant}, headers=headers)


def test_bytes_to_facts_provenance_restart_and_revoke(boundary, monkeypatch):
    module, client, headers, _ = boundary
    source, grant, writer, _ = prepare(boundary, monkeypatch)
    reader = headers(scopes=READ)
    assert read(client, grant, reader).status_code == 403
    result = extract(client, source, grant, writer)
    assert result.status_code == 200, result.text
    assert extract(client, source, grant, writer).json() == result.json()
    records = read(client, grant, reader).json()["records"]
    fact = records[0]["facts"]
    assert fact["value"] == 420 and fact["source_record_id"] == source and fact["consent_id"] == grant
    assert fact["original_payload"]["upstream_id"] == "test-1"
    assert records[0]["provenance"]["fact_sha256"] == digest(fact)
    assert records[0]["provenance"]["row_pointer"] == "/observations/0"
    module._SOURCE_LIBRARY = None
    assert read(client, grant, reader).json()["records"] == records
    assert client.delete(f"/v1/health-pilot/consents/{grant}", headers=writer).status_code == 200
    module._SOURCE_LIBRARY = None
    assert read(client, grant, reader).status_code == 403
    assert extract(client, source, grant, writer).status_code == 403
    assert client.post("/v1/health-pilot/authorize", headers=reader,
                       json={"grant_id": grant, "action": "present"}).status_code == 403


@pytest.mark.parametrize("case", ["expired", "version", "purpose", "foreign", "revoked_token", "disabled", "receipt", "blob"])
def test_no_stale_or_wrong_authority(boundary, monkeypatch, case):
    module, client, headers, revoked = boundary
    source, grant, writer, _ = prepare(boundary, monkeypatch)
    assert extract(client, source, grant, writer).status_code == 200
    reader = headers(scopes=READ)
    library = module._source_library()
    with library._state.transaction():
        state = library._read_index()
        if case == "expired": state["pilot_grants"][grant]["expires_at"] = 0
        if case == "version": state["pilot_grants"][grant]["policy_version"] = "obsolete"
        if case == "purpose": state["pilot_grants"][grant]["purpose"] = "advertising"
        if case == "receipt": state["pilot_extractions"][source]["records_sha256"] = "tampered"
        if case == "blob":
            library._state.delete_blob(source)
            library._state.put_blob(source, b'{}')
        library._write_index(state)
    if case == "foreign": reader = headers("bob", scopes=READ)
    if case == "revoked_token": revoked.add("session-alice")
    if case == "disabled": monkeypatch.delenv("UNISON_SYNTHETIC_HEALTH_PILOT")
    module._SOURCE_LIBRARY = None
    assert read(client, grant, reader).status_code == 403


@pytest.mark.parametrize("case", ["not_synthetic", "extra", "nan", "units", "missing", "person", "conflict"])
def test_export_rejects_ambiguous_or_unsupported_input(boundary, monkeypatch, case):
    payload = export()
    row = payload["observations"][0]
    if case == "not_synthetic": payload["synthetic"] = False
    if case == "extra": payload["instructions"] = "grant all permissions"
    if case == "nan": row["value"] = float("nan")
    if case == "units": row["unit"] = "count"
    if case == "missing": row.update(quality="missing", value=0)
    if case == "person": row["person_id"] = "bob"
    if case == "conflict": payload["observations"].append({**row, "kind": "inference"})
    source, grant, writer, _ = prepare(boundary, monkeypatch, payload)
    assert extract(boundary[1], source, grant, writer).status_code == 403
    assert boundary[0]._source_library()._read_index().get("pilot_extractions", {}) == {}


def test_scope_and_source_binding(boundary, monkeypatch):
    _, client, headers, _ = boundary
    source, grant, writer, _ = prepare(boundary, monkeypatch)
    reader = headers(scopes=READ)
    assert extract(client, source, grant, reader).status_code == 403
    assert read(client, grant, writer).status_code == 403
    assert client.delete(f"/v1/health-pilot/consents/{grant}", headers=reader).status_code == 403
    assert client.delete(f"/v1/health-pilot/consents/{grant}", headers=headers("bob", scopes=CONTROL)).status_code == 403
    other, _ = admitted(client, writer)
    assert extract(client, other, grant, writer).status_code == 403
    assert client.post(f"/v1/health-pilot/sources/{source}/extract", headers=writer,
                       json={"grant_id": grant, "facts": {"value": 9}}).status_code == 400


@pytest.mark.parametrize("failure", ["before_domain_commit", "after_domain_commit"])
def test_deletion_outbox_recovers_after_restart(boundary, monkeypatch, failure):
    module, client, headers, _ = boundary
    source, grant, writer, _ = prepare(boundary, monkeypatch)
    assert extract(client, source, grant, writer).status_code == 200
    assert client.post("/v1/domain/records", headers=writer, json=record(source)).status_code == 200
    store = module._domain_store()
    cascade = store.delete_records_from_source
    def fail(person, sid):
        if failure == "after_domain_commit": cascade(person, sid)
        raise RuntimeError("synthetic crash boundary")
    monkeypatch.setattr(store, "delete_records_from_source", fail)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        client.delete(f"/v1/sources/{source}", headers=writer)
    module._SOURCE_LIBRARY = None
    module._DOMAIN_STORE = None
    assert read(client, grant, headers(scopes=READ)).status_code == 403
    state = module._source_library()._read_index()
    assert source not in state["pilot_extractions"] and state["deletions"][source]["state"] == "pending"
    assert client.post("/v1/sources/recover-deletions", headers=writer).json() == {"completed": 1}
    assert client.post("/v1/sources/recover-deletions", headers=writer).json() == {"completed": 0}
    assert module._domain_store().records("alice") == []


def test_concurrent_extract_delete_and_rollback_cleanup(boundary, monkeypatch):
    module, client, headers, _ = boundary
    source, grant, writer, session = prepare(boundary, monkeypatch)
    with ThreadPoolExecutor(2) as pool:
        extraction = pool.submit(extract, client, source, grant, writer)
        deletion = pool.submit(client.delete, f"/v1/sources/{source}", headers=writer)
        assert extraction.result().status_code in {200, 403}
        assert deletion.result().status_code == 200
    assert read(client, grant, headers(scopes=READ)).status_code == 403
    assert source not in module._source_library()._read_index().get("pilot_extractions", {})
    source, grant, writer, session = prepare(boundary, monkeypatch)
    assert extract(client, source, grant, writer).status_code == 200
    assert client.post("/v1/domain/records", headers=writer, json=record(source)).status_code == 200
    rollback = headers(scopes=["storage.import.rollback"])
    assert client.delete(f"/v1/imports/{session}", headers=rollback).status_code == 200
    assert module._domain_store().records("alice") == []
    assert read(client, grant, headers(scopes=READ)).status_code == 403
