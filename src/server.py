from fastapi import FastAPI, Request, Body
import uvicorn
import logging
import json
import time
import sqlite3
from pathlib import Path
from typing import Any
from unison_common.logging import configure_logging, log_json
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, instrument_fastapi, instrument_httpx
from collections import defaultdict

from .settings import StorageServiceSettings

app = FastAPI(title="unison-storage")
app.add_middleware(TracingMiddleware, service_name="unison-storage")

logger = configure_logging("unison-storage")

# P0.3: Initialize tracing and instrument FastAPI/httpx
initialize_tracing()
instrument_fastapi(app)
instrument_httpx()

# Simple in-memory metrics
_metrics = defaultdict(int)
_start_time = time.time()
SETTINGS = StorageServiceSettings.from_env()


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
    return {"ready": True}


def _db_conn():
    db_path: Path = SETTINGS.db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS kv (ns TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (ns, key))"
    )
    return conn


@app.put("/kv/{namespace}/{key}")
def kv_put(namespace: str, key: str, request: Request, body: dict = Body(...)):
    _metrics["/kv/{namespace}/{key}"] += 1
    event_id = request.headers.get("X-Event-ID")
    if not namespace or not key:
        return {"ok": False, "error": "invalid-path", "event_id": event_id}
    val: Any = body.get("value") if isinstance(body, dict) else None
    try:
        encoded = json.dumps(val, separators=(",", ":"))
        with _db_conn() as conn:
            conn.execute(
                "INSERT INTO kv(ns, key, value) VALUES(?,?,?) ON CONFLICT(ns,key) DO UPDATE SET value=excluded.value",
                (namespace, key, encoded),
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
        with _db_conn() as conn:
            cur = conn.execute("SELECT value FROM kv WHERE ns=? AND key=?", (namespace, key))
            row = cur.fetchone()
        value = json.loads(row[0]) if row and row[0] is not None else None
        log_json(logging.INFO, "kv_get", service="unison-storage", event_id=event_id, ns=namespace, key=key, hit=value is not None)
        return {"ok": True, "value": value, "event_id": event_id}
    except Exception as e:
        log_json(logging.ERROR, "kv_get_error", service="unison-storage", event_id=event_id, ns=namespace, key=key, error=str(e))
        return {"ok": False, "error": "db-error", "event_id": event_id}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8082)
