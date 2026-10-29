"""Real signed identities and loopback introspection; synthetic data only."""
import base64
import importlib.util
import json
from pathlib import Path
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from fastapi.routing import APIRoute
from unison_common import auth


@pytest.fixture
def boundary(monkeypatch, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="storage-synthetic", alg="RS256", use="sig")
    revoked = set()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def reply(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())
        def do_GET(self): self.reply(200, {"keys": [jwk]})
        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                claims = jwt.decode(body["token"], key.public_key(), algorithms=["RS256"], options={"verify_aud": False})
                assert claims["jti"] not in revoked
                self.reply(200, {"valid": True, "claims": claims})
            except Exception:
                self.reply(401, {"valid": False})
    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=service.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{service.server_port}"
    monkeypatch.setattr(auth, "AUTH_SERVICE_URL", url)
    monkeypatch.setattr(auth, "JWKS_URL", url + "/jwks")
    monkeypatch.setattr(auth, "_jwks_cache", {"keys": None, "expires": 0, "etag": None})
    monkeypatch.delenv("UNISON_PRINCIPAL_BINDING_TEST_BYPASS", raising=False)
    monkeypatch.setenv("STORAGE_OBJECT_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("UNISON_LIFE_OPERATIONS_ROOT", str(tmp_path / "sources"))
    monkeypatch.setenv("UNISON_LIFE_DOMAINS_ROOT", str(tmp_path / "domains"))
    monkeypatch.setenv("UNISON_STORAGE_DB", str(tmp_path / "ordinary.db"))
    def headers(person="alice", scopes=(), **changes):
        now = int(time.time())
        claims = dict(sub=person, principal_id=person, principal_kind="person", person_id=person,
                      assistant_instance_id=f"assistant-{person}", household_id="household", membership_id=f"member-{person}",
                      key_handle=f"key-{person}", credential_namespace=person, data_namespace=person,
                      cache_namespace=person, index_namespace=person, aud=["storage"], iat=now, exp=now+300,
                      jti=f"session-{person}", auth_method="test-key", assurance="high", scopes=list(scopes))
        claims.update(changes)
        return {"Authorization": "Bearer " + jwt.encode(claims, key, algorithm="RS256", headers={"kid": jwk["kid"]})}
    spec = importlib.util.spec_from_file_location("storage_authority_server", Path(__file__).parents[1] / "src/server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        with TestClient(module.app) as client:
            yield module, client, headers, revoked
    finally:
        service.shutdown()
        service.server_close()
        worker.join(timeout=2)


INGEST = ("storage.import.start", "storage.import.upload", "storage.import.admit", "storage.domain.create")


def admitted(client, headers, *, admit=True, content=b"synthetic source"):
    session = client.post("/v1/imports", headers=headers, json={})
    assert session.status_code == 200, session.text
    sid = session.json()["session_id"]
    source = client.post(f"/v1/imports/{sid}/sources", headers=headers, json={
        "filename": "fixture.txt", "media_type": "text/plain", "content_b64": base64.b64encode(content).decode()})
    assert source.status_code == 200, source.text
    if admit:
        assert client.post(f"/v1/imports/{sid}/admit", headers=headers, json={}).status_code == 200
    return source.json()["source_id"], sid


def record(source):
    return {"domain": "health", "record_type": "observation", "facts": {"synthetic": True}, "source_ids": [source]}


def test_reader_cannot_mutate_any_storage_route(boundary):
    module, client, headers, _ = boundary
    reader = headers(scopes=["storage.health.read"])
    for route in module.app.routes:
        if not isinstance(route, APIRoute): continue
        path = route.path
        for name in route.param_convertors:
            path = path.replace("{" + name + "}", "synthetic-id")
        for method in route.methods & {"POST", "PUT", "PATCH", "DELETE"}:
            response = client.request(method, path, headers=reader, json={})
            assert response.status_code == 403, (method, route.path, response.status_code, response.text)


def test_distinct_import_admission_and_read_scopes(boundary):
    _, client, headers, revoked = boundary
    reader = headers(scopes=["storage.health.read"])
    writer = headers(scopes=INGEST)
    source, session = admitted(client, writer, admit=False)
    assert client.post(f"/v1/imports/{session}/admit", json={}, headers=headers(scopes=["storage.import.upload"])).status_code == 403
    assert client.post(f"/v1/imports/{session}/admit", json={}, headers=writer).status_code == 200
    assert client.post("/v1/domain/records", json=record(source), headers=writer).status_code == 200
    assert client.get("/v1/domain/records?domain=health", headers=reader).status_code == 200
    for query in ("", "?domain=finance", "?domain=health&domain=finance"):
        assert client.get("/v1/domain/records" + query, headers=reader).status_code == 403
    assert client.get("/v1/domain/records?domain=health", headers=writer).status_code == 403
    assert client.get("/v1/domain/records?domain=health", headers=headers()).status_code == 403
    revoked.add("session-alice")
    assert client.get("/v1/domain/records?domain=health", headers=reader).status_code == 403


@pytest.mark.parametrize("state", ["missing", "foreign", "preview", "deleted", "rejected"])
def test_domain_rejects_unowned_or_unadmitted_source(boundary, state):
    module, client, headers, _ = boundary
    writer = headers(scopes=INGEST)
    if state == "missing": source = "missing"
    else:
        source, session = admitted(client, headers("bob", scopes=INGEST) if state == "foreign" else writer,
                                   admit=state not in {"preview", "rejected"},
                                   content=b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" if state == "rejected" else b"synthetic")
        if state == "rejected":
            assert client.post(f"/v1/imports/{session}/admit", headers=writer, json={}).status_code == 400
        if state == "deleted": module._source_library().delete_source("alice", source)
    response = client.post("/v1/domain/records", headers=writer, json=record(source))
    assert response.status_code == 400
    assert module._domain_store().records("alice") == []


def test_deleted_source_cannot_return_orphaned_domain_record(boundary):
    module, client, headers, _ = boundary
    writer = headers(scopes=INGEST)
    source, _ = admitted(client, writer)
    assert client.post("/v1/domain/records", headers=writer, json=record(source)).status_code == 200
    # Simulate failure after source commit but before domain cascade.
    module._source_library().delete_source("alice", source)
    module._SOURCE_LIBRARY = None
    module._DOMAIN_STORE = None
    reader = headers(scopes=["storage.health.read"])
    response = client.get("/v1/domain/records?domain=health", headers=reader)
    assert response.status_code == 409 and "records" not in response.json()


@pytest.mark.parametrize("references", [None, [], "source", [""], [1], ["duplicate", "duplicate"]])
def test_malformed_references_denied_before_domain_write(boundary, references):
    module, client, headers, _ = boundary
    response = client.post("/v1/domain/records", headers=headers(scopes=INGEST),
                           json={**record("unused"), "source_ids": references})
    assert response.status_code == 400
    assert module._domain_store().records("alice") == []


@pytest.mark.parametrize("mutation", ["missing", "expired", "audience", "workload", "wildcard"])
def test_invalid_authority_cannot_start_import(boundary, mutation):
    _, client, headers, _ = boundary
    options = {"scopes": ["storage.import.start"]}
    if mutation == "expired": options["exp"] = int(time.time()) - 1
    if mutation == "audience": options["aud"] = ["orchestrator"]
    if mutation == "workload": options.update(principal_kind="workload", person_id=None)
    if mutation == "wildcard": options["scopes"] = ["storage.*"]
    response = client.post("/v1/imports", json={}, headers={} if mutation == "missing" else headers(**options))
    assert response.status_code in {401, 403}


def test_source_guard_serializes_creation_against_delete(boundary):
    from concurrent.futures import ThreadPoolExecutor
    module, client, headers, _ = boundary
    source, _ = admitted(client, headers(scopes=INGEST))
    library, domains = module._source_library(), module._domain_store()
    attempted = threading.Event()
    def delete():
        attempted.set()
        library.delete_source("alice", source)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with library.admitted_references("alice", [source]):
            future = executor.submit(delete)
            assert attempted.wait(timeout=2)
            created = domains.create_record("alice", "health:alice", "health", "observation", {"synthetic": True}, [source])
            assert not future.done()  # Delete cannot commit while creation holds source lock.
            assert created["source_ids"] == [source]
        future.result(timeout=5)
    assert client.get("/v1/domain/records?domain=health", headers=headers(scopes=["storage.health.read"])).status_code == 409


def test_vendor_json_nested_identity_denied(boundary):
    _, client, headers, _ = boundary
    response = client.post("/v1/domain/records", content=json.dumps({**record("missing"), "facts": {"person_id": "bob"}}),
                           headers={**headers(scopes=INGEST), "Content-Type": "application/vnd.unison+json"})
    assert response.status_code == 403
