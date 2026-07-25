from __future__ import annotations

from fastapi import FastAPI, Request, Body, HTTPException, Depends
import uvicorn
import logging
import json
import time
from pathlib import Path
from typing import Any, Optional
from unison_common.logging import configure_logging, log_json
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, instrument_fastapi, instrument_httpx
from unison_common.principal_middleware import PrincipalBindingMiddleware, get_bound_principal
from unison_common.trust import LocalDevelopmentKeyBroker
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
import base64
import os
import uuid
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from life_operations import ConnectionBroker, ConnectionRejected, IntakeRejected, SourceLibrary
from domain_operations import DomainRejected, LifeDomainStore
try:
    from unison_common import BatonMiddleware
except Exception:
    BatonMiddleware = None
from collections import defaultdict

from settings import StorageServiceSettings

app = FastAPI(title="unison-storage")
app.add_middleware(TracingMiddleware, service_name="unison-storage")
if BatonMiddleware:
    app.add_middleware(BatonMiddleware)
app.add_middleware(
    PrincipalBindingMiddleware,
    service_name="storage",
    allow_test_bypass=True,
)

logger = configure_logging("unison-storage")

# P0.3: Initialize tracing and instrument FastAPI/httpx
initialize_tracing()
instrument_fastapi(app)
instrument_httpx()

# Simple in-memory metrics
_metrics = defaultdict(int)
_start_time = time.time()
SETTINGS = StorageServiceSettings.from_env()
_ENGINE: Engine | None = None
_FERNET: Optional[Fernet] = None
_OBJECT_KEY_BROKER: Optional[LocalDevelopmentKeyBroker] = None
_SOURCE_LIBRARY: SourceLibrary | None = None
_CONNECTION_BROKER = ConnectionBroker()
_DOMAIN_STORE: LifeDomainStore | None = None


@app.get("/healthz")
@app.get("/health")
def health(request: Request):
    _metrics["/health"] += 1
    event_id = request.headers.get("X-Event-ID")
    log_json(logging.INFO, "health", service="unison-storage", event_id=event_id)
    return {"status": "ok", "service": "unison-storage"}

@app.get("/metrics")
def metrics():
    """Prometheus text-format metrics."""
    uptime = time.time() - _start_time
    lines = [
        "# HELP unison_storage_requests_total Total number of requests by endpoint",
        "# TYPE unison_storage_requests_total counter",
    ]
    for k, v in _metrics.items():
        lines.append(f'unison_storage_requests_total{{endpoint="{k}"}} {v}')
    lines.extend([
        "",
        "# HELP unison_storage_uptime_seconds Service uptime in seconds",
        "# TYPE unison_storage_uptime_seconds gauge",
        f"unison_storage_uptime_seconds {uptime}",
    ])
    return "\n".join(lines)

@app.get("/readyz")
@app.get("/ready")
def ready(request: Request):
    event_id = request.headers.get("X-Event-ID")
    log_json(logging.INFO, "ready", service="unison-storage", event_id=event_id, ready=True)
    # Future: check persistence / volumes
    db_ok = True
    try:
        engine = _init_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    return {"ready": db_ok}


def _init_engine() -> Engine:
    global _ENGINE
    if _ENGINE:
        return _ENGINE
    db_url = SETTINGS.database_url or f"sqlite:///{SETTINGS.db_path}"
    if os.getenv("ENVIRONMENT") == "prod" and db_url.startswith("sqlite"):
        raise RuntimeError("SQLite is not allowed in production; set STORAGE_DATABASE_URL to Postgres")
    if db_url.startswith("sqlite:///"):
        Path(db_url.replace("sqlite:///", "")).parent.mkdir(parents=True, exist_ok=True)
    _ENGINE = create_engine(db_url, future=True)
    with _ENGINE.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS kv (ns TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (ns, key))"
            )
        )
        # Core tables for future memory/vault/audit/object storage
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS memory_entries (
                    id SERIAL PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    person_id TEXT,
                    payload JSONB,
                    ttl_seconds INTEGER,
                    expires_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS vault_entries (
                    key_id TEXT PRIMARY KEY,
                    cipher_text TEXT NOT NULL,
                    metadata JSONB,
                    version INTEGER DEFAULT 1,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    person_id TEXT,
                    actor TEXT,
                    action TEXT,
                    target TEXT,
                    decision_id TEXT,
                    status TEXT,
                    payload_json JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    id TEXT PRIMARY KEY,
                    person_id TEXT,
                    content_type TEXT,
                    size_bytes BIGINT,
                    storage_backend TEXT,
                    path TEXT,
                    checksum TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                """
            )
        )
    return _ENGINE


def _get_fernet() -> Optional[Fernet]:
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    if SETTINGS.object_enc_key:
        try:
            _FERNET = Fernet(SETTINGS.object_enc_key.encode())
        except Exception:
            _FERNET = None
    return _FERNET


def _get_object_key_broker() -> Optional[LocalDevelopmentKeyBroker]:
    global _OBJECT_KEY_BROKER
    if _OBJECT_KEY_BROKER is not None:
        return _OBJECT_KEY_BROKER
    if SETTINGS.object_enc_key:
        try:
            root = base64.urlsafe_b64decode(SETTINGS.object_enc_key.encode())
            _OBJECT_KEY_BROKER = LocalDevelopmentKeyBroker(root)
        except Exception:
            _OBJECT_KEY_BROKER = None
    return _OBJECT_KEY_BROKER


def _source_library() -> SourceLibrary:
    global _SOURCE_LIBRARY
    if _SOURCE_LIBRARY is None:
        key_value = SETTINGS.object_enc_key
        if not key_value:
            if os.getenv("ENVIRONMENT") == "prod":
                raise HTTPException(status_code=503, detail="life operations encryption key unavailable")
            key_path = SETTINGS.life_operations_root / ".development-key"
            key_path.parent.mkdir(parents=True, exist_ok=True)
            if not key_path.exists():
                key_path.write_bytes(Fernet.generate_key())
                key_path.chmod(0o600)
            key_value = key_path.read_text(encoding="ascii").strip()
        _SOURCE_LIBRARY = SourceLibrary(SETTINGS.life_operations_root, key_value.encode())
    return _SOURCE_LIBRARY


def _life_key() -> bytes:
    key_value = SETTINGS.object_enc_key
    if key_value:
        return key_value.encode()
    if os.getenv("ENVIRONMENT") == "prod":
        raise HTTPException(status_code=503, detail="life operations encryption key unavailable")
    key_path = SETTINGS.life_operations_root / ".development-key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
        key_path.chmod(0o600)
    return key_path.read_text(encoding="ascii").strip().encode()


def _domain_store() -> LifeDomainStore:
    global _DOMAIN_STORE
    if _DOMAIN_STORE is None:
        _DOMAIN_STORE = LifeDomainStore(SETTINGS.life_domains_root, _life_key())
    return _DOMAIN_STORE


def _life_person(request: Request, principal: Any, supplied: str | None = None) -> str:
    person_id = principal.person_id if principal else supplied
    if not person_id:
        raise HTTPException(status_code=400, detail="person_id required")
    return person_id


def _check_auth(request: Request):
    try:
        return get_bound_principal(request)
    except RuntimeError:
        if os.getenv("UNISON_PRINCIPAL_BINDING_TEST_BYPASS", "false").lower() == "true":
            return None
        raise HTTPException(status_code=401, detail="trusted principal required")


@app.put("/kv/{namespace}/{key}")
def kv_put(namespace: str, key: str, request: Request, body: dict = Body(...)):
    _metrics["/kv/{namespace}/{key}"] += 1
    event_id = request.headers.get("X-Event-ID")
    if not namespace or not key:
        return {"ok": False, "error": "invalid-path", "event_id": event_id}
    principal = get_bound_principal(request) if not os.getenv("UNISON_PRINCIPAL_BINDING_TEST_BYPASS", "false").lower() == "true" else None
    storage_namespace = f"{principal.data_namespace}:{namespace}" if principal else namespace
    val: Any = body.get("value") if isinstance(body, dict) else None
    try:
        encoded = json.dumps(val, separators=(",", ":"))
        engine = _init_engine()
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO kv(ns, key, value) VALUES(:ns, :key, :val)
                    ON CONFLICT(ns,key) DO UPDATE SET value=excluded.value
                    """
                ),
                {"ns": storage_namespace, "key": key, "val": encoded},
            )
        log_json(logging.INFO, "kv_put", service="unison-storage", event_id=event_id, ns=namespace, key=key)
        return {"ok": True, "event_id": event_id}
    except Exception as e:
        log_json(logging.ERROR, "kv_put_error", service="unison-storage", event_id=event_id, ns=namespace, key=key, error=str(e))
        return {"ok": False, "error": "db-error", "event_id": event_id}


@app.get("/kv/{namespace}/{key}")
def kv_get(namespace: str, key: str, request: Request):
    _metrics["/kv/{namespace}/{key}"] += 1
    event_id = request.headers.get("X-Event-ID")
    try:
        principal = get_bound_principal(request) if not os.getenv("UNISON_PRINCIPAL_BINDING_TEST_BYPASS", "false").lower() == "true" else None
        storage_namespace = f"{principal.data_namespace}:{namespace}" if principal else namespace
        engine = _init_engine()
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT value FROM kv WHERE ns=:ns AND key=:key"), {"ns": storage_namespace, "key": key}
            ).fetchone()
        value = json.loads(row[0]) if row and row[0] is not None else None
        log_json(logging.INFO, "kv_get", service="unison-storage", event_id=event_id, ns=namespace, key=key, hit=value is not None)
        return {"ok": True, "value": value, "event_id": event_id}
    except Exception as e:
        log_json(logging.ERROR, "kv_get_error", service="unison-storage", event_id=event_id, ns=namespace, key=key, error=str(e))
        return {"ok": False, "error": "db-error", "event_id": event_id}


# --- Memory (TTL) ---
@app.post("/memory")
def memory_put(request: Request, body: dict = Body(...), _: None = Depends(_check_auth)):
    """Store memory payload with optional TTL (seconds)."""
    _metrics["/memory"] += 1
    session_id = body.get("session_id")
    payload = body.get("data")
    principal = get_bound_principal(request) if _ is not None else None
    person_id = principal.person_id if principal else body.get("person_id")
    stored_session_id = f"{principal.data_namespace}:{session_id}" if principal else session_id
    ttl = body.get("ttl") or body.get("ttl_seconds")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    if payload is None:
        raise HTTPException(status_code=400, detail="data required")
    expires_at = None
    if isinstance(ttl, (int, float)) and ttl > 0:
        expires_at = time.time() + float(ttl)
    engine = _init_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO memory_entries (session_id, person_id, payload, ttl_seconds, expires_at, created_at, updated_at)
                VALUES (:sid, :pid, :payload, :ttl, :expires_at, NOW(), NOW())
                ON CONFLICT (id) DO NOTHING
                """
            ),
            {
                "sid": stored_session_id,
                "pid": person_id,
                "payload": json.dumps(payload),
                "ttl": ttl,
                "expires_at": None if expires_at is None else text("to_timestamp(:ts)").bindparams(ts=expires_at),
            },
        )
    return {"ok": True, "session_id": session_id}


@app.get("/memory/{session_id}")
def memory_get(session_id: str, request: Request, principal=Depends(_check_auth)):
    stored_session_id = f"{principal.data_namespace}:{session_id}" if principal else session_id
    engine = _init_engine()
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT payload, expires_at FROM memory_entries
                WHERE session_id=:sid
                """
            ),
            {"sid": stored_session_id},
        ).fetchone()
    if not row:
        return {"ok": False, "error": "not-found"}
    payload_json, expires_at = row
    if expires_at:
        ts = expires_at.timestamp() if hasattr(expires_at, "timestamp") else expires_at
        if ts < time.time():
            return {"ok": False, "error": "expired"}
    return {"ok": True, "data": json.loads(payload_json) if payload_json else None}


@app.delete("/memory/{session_id}")
def memory_delete(session_id: str, request: Request, principal=Depends(_check_auth)):
    stored_session_id = f"{principal.data_namespace}:{session_id}" if principal else session_id
    engine = _init_engine()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM memory_entries WHERE session_id=:sid"), {"sid": stored_session_id})
    return {"ok": True}


# --- Vault ---
@app.post("/vault")
def vault_put(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    key_id = body.get("key_id") or body.get("id") or str(uuid.uuid4())
    stored_key_id = f"{principal.credential_namespace}:{key_id}" if principal else key_id
    cipher_text = body.get("cipher_text") or body.get("data")
    metadata = body.get("metadata") or {}
    if not cipher_text or not isinstance(cipher_text, str):
        raise HTTPException(status_code=400, detail="cipher_text required")
    engine = _init_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO vault_entries (key_id, cipher_text, metadata, created_at, updated_at)
                VALUES (:key_id, :cipher_text, :metadata, NOW(), NOW())
                ON CONFLICT (key_id) DO UPDATE SET
                    cipher_text=excluded.cipher_text,
                    metadata=excluded.metadata,
                    updated_at=NOW(),
                    version=vault_entries.version + 1
                """
            ),
            {"key_id": stored_key_id, "cipher_text": cipher_text, "metadata": json.dumps(metadata)},
        )
    return {"ok": True, "key_id": key_id}


@app.get("/vault/{key_id}")
def vault_get(key_id: str, request: Request, principal=Depends(_check_auth)):
    stored_key_id = f"{principal.credential_namespace}:{key_id}" if principal else key_id
    engine = _init_engine()
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT cipher_text, metadata, version, updated_at FROM vault_entries WHERE key_id=:key_id"),
            {"key_id": stored_key_id},
        ).fetchone()
    if not row:
        return {"ok": False, "error": "not-found"}
    cipher_text, metadata, version, updated_at = row
    return {
        "ok": True,
        "key_id": key_id,
        "cipher_text": cipher_text,
        "metadata": json.loads(metadata) if metadata else {},
        "version": version,
        "updated_at": updated_at,
    }


# --- Audit ---
@app.post("/audit")
def audit_log(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    event_id = body.get("id") or str(uuid.uuid4())
    actor = body.get("actor")
    action = body.get("action")
    if not action:
        raise HTTPException(status_code=400, detail="action required")
    engine = _init_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO audit_events (id, person_id, actor, action, target, decision_id, status, payload_json, created_at)
                VALUES (:id, :person_id, :actor, :action, :target, :decision_id, :status, :payload, NOW())
                ON CONFLICT (id) DO NOTHING
                """
            ),
            {
                "id": event_id,
                "person_id": principal.person_id if principal else body.get("person_id"),
                "actor": principal.principal_id if principal else actor,
                "action": action,
                "target": body.get("target"),
                "decision_id": body.get("decision_id"),
                "status": body.get("status"),
                "payload": json.dumps(body),
            },
        )
    return {"ok": True, "id": event_id}


# --- Objects ---
def _objects_dir() -> Path:
    base = SETTINGS.db_path.parent if SETTINGS.db_path else Path("/data")
    path = base / "objects"
    path.mkdir(parents=True, exist_ok=True)
    return path


@app.post("/objects")
def object_put(body: dict = Body(...), request: Request = None, _: None = Depends(_check_auth)):
    obj_id = body.get("id") or str(uuid.uuid4())
    content_b64 = body.get("content_b64")
    content_type = body.get("content_type") or "application/octet-stream"
    principal = get_bound_principal(request) if _ is not None else None
    person_id = principal.person_id if principal else body.get("person_id")
    stored_obj_id = f"{principal.data_namespace}:{obj_id}" if principal else obj_id
    backend = "filesystem"
    checksum = None
    size_bytes: Optional[int] = None
    path: Optional[str] = None
    if content_b64:
        try:
            data = base64.b64decode(content_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid base64 content")
        checksum = hashlib.sha256(data).hexdigest()
        broker = _get_object_key_broker()
        if principal and broker and principal.key_handle:
            data = broker.encrypt(
                key_handle=principal.key_handle,
                plaintext=data,
                associated_data=f"unison-storage:object:{obj_id}".encode(),
            )
        elif principal and os.getenv("ENVIRONMENT") == "prod":
            raise HTTPException(status_code=503, detail="principal key broker unavailable")
        else:
            fernet = _get_fernet()
            if fernet:
                data = fernet.encrypt(data)
        target = _objects_dir() / hashlib.sha256(stored_obj_id.encode()).hexdigest()
        target.write_bytes(data)
        path = str(target)
        size_bytes = len(data)
    else:
        raise HTTPException(status_code=400, detail="content_b64 required")
    engine = _init_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO objects (id, person_id, content_type, size_bytes, storage_backend, path, checksum, created_at)
                VALUES (:id, :person_id, :content_type, :size_bytes, :backend, :path, :checksum, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    content_type=excluded.content_type,
                    size_bytes=excluded.size_bytes,
                    storage_backend=excluded.storage_backend,
                    path=excluded.path,
                    checksum=excluded.checksum
                """
            ),
            {
                "id": stored_obj_id,
                "person_id": person_id,
                "content_type": content_type,
                "size_bytes": size_bytes,
                "backend": backend,
                "path": path,
                "checksum": checksum,
            },
        )
    return {"ok": True, "id": obj_id, "path": path, "size_bytes": size_bytes}


@app.get("/objects/{obj_id}")
def object_get(obj_id: str, request: Request, principal=Depends(_check_auth)):
    stored_obj_id = f"{principal.data_namespace}:{obj_id}" if principal else obj_id
    engine = _init_engine()
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT person_id, content_type, size_bytes, storage_backend, path, checksum
                FROM objects WHERE id=:id
                """
            ),
            {"id": stored_obj_id},
        ).fetchone()
    if not row:
        return {"ok": False, "error": "not-found"}
    person_id, content_type, size_bytes, backend, path, checksum = row
    content_b64 = None
    if path and Path(path).exists():
        data = Path(path).read_bytes()
        broker = _get_object_key_broker()
        if principal and broker and principal.key_handle:
            try:
                data = broker.decrypt(
                    key_handle=principal.key_handle,
                    ciphertext=data,
                    associated_data=f"unison-storage:object:{obj_id}".encode(),
                )
            except Exception:
                raise HTTPException(status_code=404, detail="object not found")
        else:
            fernet = _get_fernet()
        if not principal and fernet:
            try:
                data = fernet.decrypt(data)
            except InvalidToken:
                pass
        content_b64 = base64.b64encode(data).decode()
    return {
        "ok": True,
        "id": obj_id,
        "person_id": person_id,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "storage_backend": backend,
        "checksum": checksum,
        "content_b64": content_b64,
    }

# --- Private life operations intake and connection broker ---
@app.post("/v1/imports")
def import_start(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    person_id = _life_person(request, principal, body.get("person_id"))
    try:
        return _source_library().start(person_id, body.get("space_id") or f"private:{person_id}", body.get("channel", "file"))
    except IntakeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/imports/{session_id}/sources")
def import_source(session_id: str, request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    person_id = _life_person(request, principal, body.get("person_id"))
    try:
        content = base64.b64decode(body.get("content_b64", ""), validate=True)
        return _source_library().ingest(
            session_id, body.get("filename", ""), body.get("media_type", ""), content, person_id
        )
    except (IntakeRejected, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/imports/{session_id}/admit")
def import_admit(session_id: str, request: Request, body: dict = Body(default={}), principal=Depends(_check_auth)):
    try:
        return _source_library().admit(_life_person(request, principal, body.get("person_id")), session_id)
    except IntakeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/v1/imports/{session_id}")
def import_rollback(session_id: str, request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    try:
        _source_library().rollback(_life_person(request, principal, person_id), session_id)
        return {"ok": True}
    except IntakeRejected as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/v1/sources")
def sources_list(request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    return {"sources": _source_library().list_sources(_life_person(request, principal, person_id))}


@app.patch("/v1/sources/{source_id}/fields/{field_id}")
def source_correct(source_id: str, field_id: str, request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _source_library().correct_field(
            _life_person(request, principal, body.get("person_id")), source_id, field_id, body.get("value")
        )
    except IntakeRejected as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.delete("/v1/sources/{source_id}")
def source_delete(source_id: str, request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    try:
        bound_person = _life_person(request, principal, person_id)
        _source_library().delete_source(bound_person, source_id)
        cascade = _domain_store().delete_records_from_source(bound_person, source_id)
        return {"ok": True, "deleted": source_id, "derived_cascade": cascade}
    except IntakeRejected as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/v1/connections/catalog")
def connection_catalog(request: Request, principal=Depends(_check_auth)):
    return {"providers": _CONNECTION_BROKER.catalog()}


@app.post("/v1/connections/oauth/start")
def connection_oauth_start(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _CONNECTION_BROKER.begin_oauth(
            _life_person(request, principal, body.get("person_id")), body.get("provider_id", ""), body.get("redirect_uri", "")
        )
    except ConnectionRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/connections/oauth/complete")
def connection_oauth_complete(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _CONNECTION_BROKER.complete_oauth(
            _life_person(request, principal, body.get("person_id")), body.get("state", ""), body.get("authorization_code", "")
        )
    except ConnectionRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/connections/local")
def connection_local(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _CONNECTION_BROKER.register_local(
            _life_person(request, principal, body.get("person_id")), body.get("provider_id", ""),
            body.get("grant_handle", ""), body.get("watch", False)
        )
    except ConnectionRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/connections")
def connections_list(request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    return {"connections": _CONNECTION_BROKER.list_connections(_life_person(request, principal, person_id))}


@app.post("/v1/connections/{connection_id}/sync")
def connection_sync(connection_id: str, request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _CONNECTION_BROKER.sync(
            _life_person(request, principal, body.get("person_id")), connection_id,
            body.get("item_ids", []), body.get("next_cursor")
        )
    except ConnectionRejected as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.delete("/v1/connections/{connection_id}")
def connection_disconnect(connection_id: str, request: Request, person_id: str | None = None,
                          delete_imported: bool = False, principal=Depends(_check_auth)):
    try:
        return _CONNECTION_BROKER.disconnect(
            _life_person(request, principal, person_id), connection_id, delete_imported
        )
    except ConnectionRejected as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --- Household, health, finance, and cross-domain packages ---
@app.post("/v1/domain/records")
def domain_record_create(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        person_id = _life_person(request, principal, body.get("person_id"))
        domain = body.get("domain", "")
        default_space = f"{domain}:{person_id}" if domain in {"health", "finance"} else f"private:{person_id}"
        return _domain_store().create_record(
            person_id, body.get("space_id") or default_space, domain, body.get("record_type", ""),
            body.get("facts", {}), body.get("source_ids", []), body.get("evidence_status", "observed"),
            float(body.get("confidence", 1.0)),
        )
    except (DomainRejected, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/domain/records")
def domain_records(request: Request, domain: str | None = None, person_id: str | None = None,
                   principal=Depends(_check_auth)):
    return {"records": _domain_store().records(_life_person(request, principal, person_id), domain)}


@app.post("/v1/domain/records/{record_id}/share")
def domain_record_share(record_id: str, request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().share_record(_life_person(request, principal, body.get("person_id")), record_id,
                                            body.get("target_space", ""), body.get("confirmed") is True)
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/household/reconcile-product")
def household_reconcile(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().reconcile_product(_life_person(request, principal, body.get("person_id")),
                                                 body.get("label_record_id", ""), body.get("receipt_record_id", ""))
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/household/attention")
def household_attention(request: Request, body: dict = Body(default={}), principal=Depends(_check_auth)):
    return {"items": _domain_store().household_attention(
        _life_person(request, principal, body.get("person_id")), body.get("recall_feed", []))}


@app.post("/v1/domain/household/repair-brief")
def household_repair_brief(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().repair_brief(_life_person(request, principal, body.get("person_id")),
                                            body.get("record_ids", []))
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/household/procedure-brief")
def household_procedure_brief(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().procedure_brief(_life_person(request, principal, body.get("person_id")),
                                               body.get("record_id", ""))
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/health/fhir")
def health_fhir(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    return {"records": _domain_store().normalize_fhir(
        _life_person(request, principal, body.get("person_id")), body.get("source_id", ""), body.get("resources", []))}


@app.post("/v1/domain/health/safety")
def health_safety(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    return {"outcome": _domain_store().health_safety(
        _life_person(request, principal, body.get("person_id")), body.get("text", ""), body.get("source_ids", []))}


@app.get("/v1/domain/health/timeline")
def health_timeline(request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    return {"records": _domain_store().health_timeline(_life_person(request, principal, person_id))}


@app.get("/v1/domain/health/contradictions")
def health_contradictions(request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    return {"contradictions": _domain_store().reconcile_health(_life_person(request, principal, person_id))}


@app.post("/v1/domain/health/visit-brief")
def health_visit_brief(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().visit_brief(_life_person(request, principal, body.get("person_id")),
                                           body.get("record_ids", []))
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/health/trend")
def health_trend(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().health_trend(_life_person(request, principal, body.get("person_id")),
                                            body.get("record_ids", []), body.get("value_field", "value"),
                                            body.get("threshold"))
    except (DomainRejected, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/health/emergency-summary")
def health_emergency_summary(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().emergency_card(_life_person(request, principal, body.get("person_id")),
                                              body.get("record_ids", []), body.get("confirmed") is True)
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/finance/reconcile")
def finance_reconcile(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().finance_reconcile(
            _life_person(request, principal, body.get("person_id")), float(body.get("statement_total", 0)),
            body.get("transaction_record_ids", []), float(body.get("tolerance", 0.01)))
    except (DomainRejected, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/domain/finance/attention")
def finance_attention(request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    return {"items": _domain_store().finance_attention(_life_person(request, principal, person_id))}


@app.get("/v1/domain/finance/forecast")
def finance_forecast(request: Request, horizon_days: int = 30, person_id: str | None = None,
                     principal=Depends(_check_auth)):
    return _domain_store().cash_flow_forecast(_life_person(request, principal, person_id), horizon_days)


@app.post("/v1/domain/finance/household-view")
def finance_household_view(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().household_finance_view(_life_person(request, principal, body.get("person_id")),
                                                      body.get("record_ids", []))
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/domain/finance/weekly-brief")
def finance_weekly_brief(request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    return _domain_store().weekly_finance_brief(_life_person(request, principal, person_id))


@app.post("/v1/domain/drafts")
def domain_draft(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().draft(_life_person(request, principal, body.get("person_id")),
                                     body.get("action_type", ""), body.get("record_ids", []),
                                     body.get("recipients", []), body.get("disclosed_fields", []), body.get("content", ""))
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/links")
def domain_link(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().link(_life_person(request, principal, body.get("person_id")),
                                    body.get("left_record_id", ""), body.get("right_record_id", ""),
                                    body.get("purpose", ""), body.get("allowed_fields", []),
                                    body.get("recipients", []), body.get("approved") is True)
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/v1/domain/links/{link_id}")
def domain_unlink(link_id: str, request: Request, person_id: str | None = None, principal=Depends(_check_auth)):
    try:
        _domain_store().unlink(_life_person(request, principal, person_id), link_id)
        return {"ok": True}
    except DomainRejected as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/v1/domain/transitions/{transition}")
def domain_transition(transition: str, request: Request, principal=Depends(_check_auth)):
    _life_person(request, principal)
    try:
        return _domain_store().transition_template(transition)
    except DomainRejected as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/v1/domain/packets")
def domain_packet(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    try:
        return _domain_store().cross_domain_packet(_life_person(request, principal, body.get("person_id")),
                                                   body.get("link_ids", []), body.get("packet_type", ""),
                                                   body.get("recipients", []))
    except DomainRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/domain/attention")
def domain_attention(request: Request, body: dict = Body(default={}), principal=Depends(_check_auth)):
    return {"items": _domain_store().attention_inbox(
        _life_person(request, principal, body.get("person_id")), body.get("goals", []))}


@app.post("/v1/domain/pilots")
def domain_pilot(request: Request, body: dict = Body(...), principal=Depends(_check_auth)):
    _life_person(request, principal, body.get("person_id"))
    try:
        return _domain_store().pilot_report(body.get("cohort", ""), body.get("opted_in") is True,
                                            body.get("measurements", {}), int(body.get("boundary_incidents", 0)),
                                            int(body.get("unsafe_actions", 0)))
    except (DomainRejected, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


if __name__ == "__main__":
    # The container runtime publishes this internal service port intentionally.
    uvicorn.run(app, host="0.0.0.0", port=8082)  # nosec B104
