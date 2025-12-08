from __future__ import annotations

from fastapi import FastAPI, Request, Body, HTTPException
import uvicorn
import logging
import json
import time
import sqlite3
from pathlib import Path
from typing import Any, Optional
from unison_common.logging import configure_logging, log_json
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, instrument_fastapi, instrument_httpx
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
import base64
import os
import uuid
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


@app.put("/kv/{namespace}/{key}")
def kv_put(namespace: str, key: str, request: Request, body: dict = Body(...)):
    _metrics["/kv/{namespace}/{key}"] += 1
    event_id = request.headers.get("X-Event-ID")
    if not namespace or not key:
        return {"ok": False, "error": "invalid-path", "event_id": event_id}
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
                {"ns": namespace, "key": key, "val": encoded},
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
        engine = _init_engine()
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT value FROM kv WHERE ns=:ns AND key=:key"), {"ns": namespace, "key": key}
            ).fetchone()
        value = json.loads(row[0]) if row and row[0] is not None else None
        log_json(logging.INFO, "kv_get", service="unison-storage", event_id=event_id, ns=namespace, key=key, hit=value is not None)
        return {"ok": True, "value": value, "event_id": event_id}
    except Exception as e:
        log_json(logging.ERROR, "kv_get_error", service="unison-storage", event_id=event_id, ns=namespace, key=key, error=str(e))
        return {"ok": False, "error": "db-error", "event_id": event_id}


# --- Memory (TTL) ---
@app.post("/memory")
def memory_put(request: Request, body: dict = Body(...)):
    """Store memory payload with optional TTL (seconds)."""
    _metrics["/memory"] += 1
    session_id = body.get("session_id")
    payload = body.get("data")
    person_id = body.get("person_id")
    ttl = body.get("ttl") or body.get("ttl_seconds")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
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
                "sid": session_id,
                "pid": person_id,
                "payload": json.dumps(payload),
                "ttl": ttl,
                "expires_at": None if expires_at is None else text("to_timestamp(:ts)").bindparams(ts=expires_at),
            },
        )
    return {"ok": True, "session_id": session_id}


@app.get("/memory/{session_id}")
def memory_get(session_id: str):
    engine = _init_engine()
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT payload, expires_at FROM memory_entries
                WHERE session_id=:sid
                """
            ),
            {"sid": session_id},
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
def memory_delete(session_id: str):
    engine = _init_engine()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM memory_entries WHERE session_id=:sid"), {"sid": session_id})
    return {"ok": True}


# --- Vault ---
@app.post("/vault")
def vault_put(body: dict = Body(...)):
    key_id = body.get("key_id") or body.get("id") or str(uuid.uuid4())
    cipher_text = body.get("cipher_text") or body.get("data")
    metadata = body.get("metadata") or {}
    if not cipher_text:
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
            {"key_id": key_id, "cipher_text": cipher_text, "metadata": json.dumps(metadata)},
        )
    return {"ok": True, "key_id": key_id}


@app.get("/vault/{key_id}")
def vault_get(key_id: str):
    engine = _init_engine()
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT cipher_text, metadata, version, updated_at FROM vault_entries WHERE key_id=:key_id"),
            {"key_id": key_id},
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
def audit_log(body: dict = Body(...)):
    event_id = body.get("id") or str(uuid.uuid4())
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
                "person_id": body.get("person_id"),
                "actor": body.get("actor"),
                "action": body.get("action"),
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
def object_put(body: dict = Body(...)):
    obj_id = body.get("id") or str(uuid.uuid4())
    content_b64 = body.get("content_b64")
    content_type = body.get("content_type") or "application/octet-stream"
    person_id = body.get("person_id")
    backend = "filesystem"
    checksum = None
    size_bytes: Optional[int] = None
    path: Optional[str] = None
    if content_b64:
        data = base64.b64decode(content_b64)
        target = _objects_dir() / obj_id
        target.write_bytes(data)
        path = str(target)
        size_bytes = len(data)
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
                "id": obj_id,
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
def object_get(obj_id: str):
    engine = _init_engine()
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT person_id, content_type, size_bytes, storage_backend, path, checksum
                FROM objects WHERE id=:id
                """
            ),
            {"id": obj_id},
        ).fetchone()
    if not row:
        return {"ok": False, "error": "not-found"}
    person_id, content_type, size_bytes, backend, path, checksum = row
    content_b64 = None
    if path and Path(path).exists():
        content_b64 = base64.b64encode(Path(path).read_bytes()).decode()
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8082)
