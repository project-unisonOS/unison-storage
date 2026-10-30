"""Default-deny operation authority for the bounded storage API surface.

Scopes are supplied by the verified principal, never by request bodies. Legacy
domain/connection workflows remain unavailable until separately qualified.
"""
import os
from fastapi import HTTPException, Request
from unison_common.principal import PrincipalKind, assert_identity_hints
from unison_common.principal_middleware import get_bound_principal


PUBLIC_ROUTES = frozenset({"health", "ready", "metrics"})
OPERATION_SCOPES = {
    "kv_put": "storage.kv.write", "kv_get": "storage.kv.read",
    "memory_put": "storage.memory.write", "memory_get": "storage.memory.read",
    "memory_delete": "storage.memory.delete", "vault_put": "storage.vault.write",
    "vault_get": "storage.vault.read", "audit_log": "storage.audit.append",
    "object_put": "storage.objects.write", "object_get": "storage.objects.read",
    "import_start": "storage.import.start", "import_source": "storage.import.upload",
    "import_admit": "storage.import.admit", "import_rollback": "storage.import.rollback",
    "sources_list": "storage.sources.read", "source_correct": "storage.sources.correct",
    "source_delete": "storage.sources.delete", "domain_record_create": "storage.domain.create",
    "domain_records": "storage.domain.read",
}


def _identity_maps(value):
    if isinstance(value, dict):
        yield value
        for item in value.values(): yield from _identity_maps(item)
    elif isinstance(value, list):
        for item in value: yield from _identity_maps(item)


async def require_storage_operation(request: Request):
    route_name = request.scope["route"].name
    if route_name in PUBLIC_ROUTES:
        return
    # Existing isolated legacy fixture mode only. Authenticated regressions
    # explicitly clear it; deployments must never enable this bypass.
    if os.getenv("UNISON_PRINCIPAL_BINDING_TEST_BYPASS", "false").lower() == "true":
        return
    try:
        principal = get_bound_principal(request)
    except RuntimeError:
        raise HTTPException(401, "trusted principal required") from None
    if principal.principal_kind != PrincipalKind.PERSON or not principal.person_id:
        raise HTTPException(403, "person-bound storage authority required")
    required = OPERATION_SCOPES.get(route_name)
    # Health-reader authority cannot enumerate other domains or all records.
    health_read = (route_name == "domain_records"
                   and request.query_params.getlist("domain") == ["health"]
                   and "storage.health.read" in principal.scopes)
    if required is None or (required not in principal.scopes and not health_read):
        raise HTTPException(403, "storage operation scope required")
    try:
        raw = await request.body()
        if raw:
            assert_identity_hints(principal, *_identity_maps(await request.json()))
    except Exception:
        raise HTTPException(403, "storage identity binding failed") from None
