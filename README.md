# unison-storage

## Phase 6 provider-blind backup

`src.backup_service` implements independent person/shared-space snapshots,
signed incremental lineage, trusted checkpoints, scheduled verification,
retention, encrypted export, cryptographic deletion, provider migration,
resumable dry-run-first restore, and post-restore key/device rotation.

`src.backup_backends` provides atomic filesystem, deterministic hostile, and
S3-compatible backends. Backends receive opaque identifiers and ciphertext
only. Backup is intentionally separate from synchronization and remote access;
the home node remains authoritative.

Key/value, memory, vault, object, and audit storage service for UnisonOS.

## Status
Core service (active). The current implementation is a FastAPI app in `src/server.py` with a local database path configured by `src/settings.py`.

## What is implemented
- Namespaced key/value storage.
- Session memory create/read/delete endpoints.
- Vault write/read endpoints for sensitive blobs.
- Audit event ingestion.
- Object upload/download endpoints.
- Health, readiness, and metrics endpoints.

## API surface
- `GET /health`, `GET /healthz`
- `GET /ready`, `GET /readyz`
- `GET /metrics`
- `PUT /kv/{namespace}/{key}`
- `GET /kv/{namespace}/{key}`
- `POST /memory`
- `GET /memory/{session_id}`
- `DELETE /memory/{session_id}`
- `POST /vault`
- `GET /vault/{key_id}`
- `POST /audit`
- `POST /objects`
- `GET /objects/{obj_id}`

## Run locally
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -r requirements.txt
cp .env.example .env
python src/server.py
```

## Key configuration
- `UNISON_STORAGE_DB`
- `STORAGE_DATABASE_URL`
- `STORAGE_SERVICE_TOKEN`
- `STORAGE_OBJECT_ENC_KEY`

## Tests
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -r requirements.txt
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OTEL_SDK_DISABLED=true python -m pytest
```

## Docs
- Public docs: https://project-unisonos.github.io
- Repo docs: `SETUP.md`, `SECURITY.md`
