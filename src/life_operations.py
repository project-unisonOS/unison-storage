"""Private source intake and read-only connection brokerage.

This module deliberately treats document text and provider data as untrusted data.
It never turns document instructions into executable authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import re
import secrets
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet


ALLOWED_MEDIA_TYPES = frozenset({
    "application/pdf", "image/jpeg", "image/png", "text/plain", "text/csv",
    "application/json", "application/zip",
})
PROMPT_INJECTION_PATTERNS = (
    re.compile(rb"ignore (all|any|the) (prior|previous) instructions", re.I),
    re.compile(rb"(export|reveal|print).{0,30}(token|secret|credential|password)", re.I),
)


class IntakeRejected(ValueError):
    pass


class ConnectionRejected(ValueError):
    pass


def _safe_component(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise IntakeRejected("invalid identifier")
    return value


@dataclass(frozen=True)
class IntakeLimits:
    max_bytes: int = 25 * 1024 * 1024
    max_archive_members: int = 200
    max_archive_expanded_bytes: int = 100 * 1024 * 1024


class SourceLibrary:
    def __init__(self, root: Path, encryption_key: bytes, limits: IntakeLimits | None = None,
                 ocr: Any | None = None):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.fernet = Fernet(encryption_key)
        self.limits = limits or IntakeLimits()
        self.ocr = ocr
        self.index_path = root / "source-index.json"
        if not self.index_path.exists():
            self._write_index({"sessions": {}, "sources": {}, "fields": {}})

    def _read_index(self) -> dict[str, Any]:
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def _write_index(self, index: dict[str, Any]) -> None:
        pending = self.index_path.with_suffix(".pending")
        pending.write_text(json.dumps(index, sort_keys=True, indent=2), encoding="utf-8")
        pending.replace(self.index_path)

    def start(self, person_id: str, space_id: str, channel: str = "file") -> dict[str, Any]:
        if channel not in {"file", "camera", "folder", "share", "provider"}:
            raise IntakeRejected("unsupported intake channel")
        session_id = f"imp_{secrets.token_urlsafe(12)}"
        session = {
            "schema_version": "import-session.v1", "session_id": session_id,
            "person_id": person_id, "space_id": space_id, "channel": channel,
            "state": "receiving", "source_ids": [], "checkpoint": "created",
            "created_at": time.time(), "updated_at": time.time(),
        }
        index = self._read_index()
        index["sessions"][session_id] = session
        self._write_index(index)
        return session

    def ingest(self, session_id: str, filename: str, media_type: str, content: bytes,
               actor_person_id: str | None = None) -> dict[str, Any]:
        filename = Path(filename).name
        if not filename or len(content) > self.limits.max_bytes:
            raise IntakeRejected("file is empty or exceeds the configured limit")
        if media_type not in ALLOWED_MEDIA_TYPES:
            raise IntakeRejected("unsupported media type")
        self._verify_signature(media_type, content)
        guessed = mimetypes.guess_type(filename)[0]
        if guessed and media_type not in {guessed, "application/octet-stream"}:
            raise IntakeRejected("declared media type does not match filename")
        self._inspect_archive(media_type, content)
        index = self._read_index()
        session = index["sessions"].get(session_id)
        if not session or session["state"] in {"admitted", "rejected", "rolled_back"}:
            raise IntakeRejected("import session is not resumable")
        if actor_person_id and session["person_id"] != actor_person_id:
            raise IntakeRejected("import session not found")
        checksum = hashlib.sha256(content).hexdigest()
        duplicate = next((v for v in index["sources"].values()
                          if v["person_id"] == session["person_id"] and v["checksum_sha256"] == checksum
                          and v["state"] != "deleted"), None)
        source_id = f"src_{secrets.token_urlsafe(12)}"
        prior = self._find_prior(index, session["person_id"], filename)
        source = {
            "schema_version": "source-object.v1", "source_id": source_id,
            "person_id": session["person_id"], "space_id": session["space_id"],
            "import_session_id": session_id, "media_type": media_type, "filename": filename,
            "checksum_sha256": checksum, "size_bytes": len(content), "state": "quarantined",
            "visibility": "private", "version": (prior or {}).get("version", 0) + 1,
            "prior_version_id": (prior or {}).get("source_id"),
            "duplicate_of": (duplicate or {}).get("source_id"),
            "security_flags": self._security_flags(content), "created_at": time.time(),
        }
        person_dir = self.root / hashlib.sha256(session["person_id"].encode()).hexdigest()
        person_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        (person_dir / f"{source_id}.enc").write_bytes(self.fernet.encrypt(content))
        index["sources"][source_id] = source
        session["source_ids"].append(source_id)
        session.update(state="preview", checkpoint=f"source:{source_id}", updated_at=time.time())
        index["fields"][source_id] = self._extract(source_id, filename, media_type, content)
        self._write_index(index)
        return {**source, "fields": index["fields"][source_id]}

    def _inspect_archive(self, media_type: str, content: bytes) -> None:
        if media_type != "application/zip":
            return
        try:
            from io import BytesIO
            with zipfile.ZipFile(BytesIO(content)) as archive:
                members = archive.infolist()
                if len(members) > self.limits.max_archive_members:
                    raise IntakeRejected("archive has too many members")
                total = 0
                for member in members:
                    path = Path(member.filename)
                    if path.is_absolute() or ".." in path.parts:
                        raise IntakeRejected("archive path traversal detected")
                    total += member.file_size
                if total > self.limits.max_archive_expanded_bytes:
                    raise IntakeRejected("archive expansion limit exceeded")
        except zipfile.BadZipFile as exc:
            raise IntakeRejected("invalid archive") from exc

    @staticmethod
    def _verify_signature(media_type: str, content: bytes) -> None:
        signatures = {
            "application/pdf": (b"%PDF-",),
            "image/jpeg": (b"\xff\xd8\xff",),
            "image/png": (b"\x89PNG\r\n\x1a\n",),
            "application/zip": (b"PK\x03\x04", b"PK\x05\x06"),
        }
        expected = signatures.get(media_type)
        if expected and not any(content.startswith(value) for value in expected):
            raise IntakeRejected("file signature does not match declared media type")

    @staticmethod
    def _security_flags(content: bytes) -> list[str]:
        flags = ["untrusted-content"]
        if any(pattern.search(content[:2_000_000]) for pattern in PROMPT_INJECTION_PATTERNS):
            flags.append("document-prompt-injection")
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
            flags.append("malware-signature")
        return flags

    def _extract(self, source_id: str, filename: str, media_type: str, content: bytes) -> list[dict[str, Any]]:
        text = ""
        processor = "binary-metadata.v1"
        if media_type.startswith("text/") or media_type == "application/json":
            text = content.decode("utf-8", errors="replace")[:100_000]
            processor = "local-structured-text.v1"
        elif media_type.startswith("image/") and self.ocr:
            text = str(self.ocr(content, media_type))[:100_000]
            processor = "local-ocr.v1"
        fields: list[dict[str, Any]] = [{
            "schema_version": "extracted-field.v1", "field_id": f"fld_{source_id}_metadata",
            "source_id": source_id, "name": "source_metadata",
            "value": {"filename": filename, "media_type": media_type, "byte_length": len(content),
                      "processor": processor},
            "region": {"label": "source metadata"}, "confidence": 1.0,
            "corrected_value": None, "correction_actor": None,
        }]
        if not text:
            return fields
        fields.append({
            "schema_version": "extracted-field.v1", "field_id": f"fld_{source_id}_text",
            "source_id": source_id, "name": "document_text", "value": text,
            "region": {"character_range": [0, len(text)], "label": "document body"},
            "confidence": 1.0, "corrected_value": None, "correction_actor": None,
        })
        if media_type == "text/csv":
            rows = [line.split(",") for line in text.splitlines()]
            fields.append({"schema_version": "extracted-field.v1", "field_id": f"fld_{source_id}_table",
                           "source_id": source_id, "name": "table", "value": rows,
                           "region": {"character_range": [0, len(text)], "label": "CSV table"},
                           "confidence": 1.0, "corrected_value": None, "correction_actor": None})
        for match in re.finditer(r"\b(?:UPC|EAN|QR)[: ]+([A-Z0-9-]{6,64})\b", text, re.I):
            fields.append({"schema_version": "extracted-field.v1",
                           "field_id": f"fld_{source_id}_barcode_{match.start()}", "source_id": source_id,
                           "name": "barcode", "value": match.group(1),
                           "region": {"character_range": [match.start(1), match.end(1)], "label": "barcode text"},
                           "confidence": 0.95, "corrected_value": None, "correction_actor": None})
        return fields

    @staticmethod
    def _find_prior(index: dict[str, Any], person_id: str, filename: str) -> dict[str, Any] | None:
        matches = [v for v in index["sources"].values()
                   if v["person_id"] == person_id and v["filename"] == filename and v["state"] != "deleted"]
        return max(matches, key=lambda item: item["version"], default=None)

    def correct_field(self, person_id: str, source_id: str, field_id: str, value: Any) -> dict[str, Any]:
        index = self._read_index()
        source = index["sources"].get(source_id)
        if not source or source["person_id"] != person_id:
            raise IntakeRejected("source not found")
        field = next((f for f in index["fields"].get(source_id, []) if f["field_id"] == field_id), None)
        if not field:
            raise IntakeRejected("field not found")
        field.update(corrected_value=value, correction_actor="person")
        self._write_index(index)
        return field

    def admit(self, person_id: str, session_id: str) -> dict[str, Any]:
        index = self._read_index()
        session = index["sessions"].get(session_id)
        if not session or session["person_id"] != person_id:
            raise IntakeRejected("session not found")
        blocked = []
        for source_id in session["source_ids"]:
            source = index["sources"][source_id]
            if "malware-signature" in source["security_flags"]:
                blocked.append(source_id)
            else:
                source["state"] = "admitted"
        session["state"] = "rejected" if blocked else "admitted"
        session["checkpoint"] = session["state"]
        session["updated_at"] = time.time()
        self._write_index(index)
        if blocked:
            raise IntakeRejected("malware policy rejected the import")
        return session

    def list_sources(self, person_id: str) -> list[dict[str, Any]]:
        return [v for v in self._read_index()["sources"].values()
                if v["person_id"] == person_id and v["state"] != "deleted"]

    def reclassify(self, person_id: str, source_id: str, space_id: str, classification: str) -> dict[str, Any]:
        index = self._read_index()
        source = index["sources"].get(source_id)
        if not source or source["person_id"] != person_id or source["state"] == "deleted":
            raise IntakeRejected("source not found")
        source["space_id"] = space_id
        source["classification"] = classification
        source["version"] += 1
        self._write_index(index)
        return source

    def export_source(self, person_id: str, source_id: str) -> bytes:
        index = self._read_index()
        source = index["sources"].get(source_id)
        if not source or source["person_id"] != person_id or source["state"] == "deleted":
            raise IntakeRejected("source not found")
        person_dir = self.root / hashlib.sha256(person_id.encode()).hexdigest()
        return self.fernet.decrypt((person_dir / f"{source_id}.enc").read_bytes())

    def delete_source(self, person_id: str, source_id: str) -> None:
        index = self._read_index()
        source = index["sources"].get(source_id)
        if not source or source["person_id"] != person_id:
            raise IntakeRejected("source not found")
        person_dir = self.root / hashlib.sha256(person_id.encode()).hexdigest()
        (person_dir / f"{source_id}.enc").unlink(missing_ok=True)
        index["fields"].pop(source_id, None)
        source.update(state="deleted", checksum_sha256="", size_bytes=0)
        self._write_index(index)

    def rollback(self, person_id: str, session_id: str) -> None:
        index = self._read_index()
        session = index["sessions"].get(session_id)
        if not session or session["person_id"] != person_id:
            raise IntakeRejected("session not found")
        for source_id in list(session["source_ids"]):
            source = index["sources"].get(source_id)
            if source:
                person_dir = self.root / hashlib.sha256(person_id.encode()).hexdigest()
                (person_dir / f"{source_id}.enc").unlink(missing_ok=True)
                index["fields"].pop(source_id, None)
                index["sources"].pop(source_id, None)
        session.update(state="rolled_back", checkpoint="rolled_back", updated_at=time.time())
        self._write_index(index)


PROVIDER_CATALOG: dict[str, dict[str, Any]] = {
    "oauth-fixture": {"profile": "oauth-pkce", "scopes": ["records.read"], "sandbox": True,
                      "guide": "Authorize read-only access on the provider page."},
    "smart-health-sandbox": {"profile": "smart-fhir", "scopes": ["openid", "fhirUser", "patient/*.read"], "sandbox": True,
                             "guide": "Choose your test health system and approve patient record reading only."},
    "finance-test-provider": {"profile": "financial-sandbox", "scopes": ["accounts.read", "transactions.read"], "sandbox": True,
                              "guide": "Approve balances and transaction history only. Money movement is unavailable."},
    "local-folder": {"profile": "local-folder", "scopes": ["selected-folder.read"], "sandbox": True,
                     "guide": "Choose one folder for a one-time import. Watching it later requires a separate grant."},
    "bounded-mcp": {"profile": "bounded-mcp", "scopes": ["resources.read"], "sandbox": True,
                    "guide": "Select exact MCP resources. Server-wide registration is rejected."},
}


class ConnectionBroker:
    def __init__(self):
        self.connections: dict[str, dict[str, Any]] = {}
        self.pending: dict[str, dict[str, Any]] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self._credentials: dict[str, str] = {}

    def catalog(self) -> dict[str, dict[str, Any]]:
        return PROVIDER_CATALOG

    def begin_oauth(self, person_id: str, provider_id: str, redirect_uri: str) -> dict[str, str]:
        manifest = PROVIDER_CATALOG.get(provider_id)
        if not manifest or manifest["profile"] not in {"oauth-pkce", "smart-fhir", "financial-sandbox"}:
            raise ConnectionRejected("provider does not support OAuth setup")
        state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        self.pending[state] = {"person_id": person_id, "provider_id": provider_id,
                               "redirect_uri": redirect_uri, "verifier": verifier, "created_at": time.time()}
        return {"state": state, "code_challenge": challenge, "code_challenge_method": "S256"}

    def complete_oauth(self, person_id: str, state: str, authorization_code: str) -> dict[str, Any]:
        pending = self.pending.pop(state, None)
        if not pending or pending["person_id"] != person_id or time.time() - pending["created_at"] > 600:
            raise ConnectionRejected("OAuth state is invalid or expired")
        connection_id = f"con_{secrets.token_urlsafe(12)}"
        token_handle = f"vault://life-operations/{person_id}/{connection_id}"
        self._credentials[token_handle] = authorization_code
        manifest = PROVIDER_CATALOG[pending["provider_id"]]
        connection = {
            "schema_version": "connection.v1", "connection_id": connection_id,
            "person_id": person_id, "provider_id": pending["provider_id"],
            "profile": manifest["profile"], "scopes": manifest["scopes"],
            "token_handle": token_handle, "cursor_handle": None, "status": "active", "read_only": True,
        }
        self.connections[connection_id] = connection
        return connection

    def register_local(self, person_id: str, provider_id: str, grant_handle: str,
                       watch: bool = False) -> dict[str, Any]:
        manifest = PROVIDER_CATALOG.get(provider_id)
        if not manifest or manifest["profile"] not in {"local-folder", "bounded-mcp"}:
            raise ConnectionRejected("unsupported local connection")
        if provider_id == "bounded-mcp" and not grant_handle.startswith("mcp-resource://"):
            raise ConnectionRejected("MCP registration requires a bounded resource grant")
        if provider_id == "local-folder" and not grant_handle.startswith("folder-grant://"):
            raise ConnectionRejected("folder registration requires a trusted picker grant")
        connection_id = f"con_{secrets.token_urlsafe(12)}"
        connection = {"schema_version": "connection.v1", "connection_id": connection_id,
                      "person_id": person_id, "provider_id": provider_id, "profile": manifest["profile"],
                      "scopes": manifest["scopes"], "token_handle": grant_handle,
                      "cursor_handle": None, "status": "active", "read_only": True,
                      "watch_enabled": bool(watch), "watch_granted_at": time.time() if watch else None}
        self.connections[connection_id] = connection
        return connection

    def sync(self, person_id: str, connection_id: str, item_ids: list[str], next_cursor: str | None) -> dict[str, Any]:
        connection = self.connections.get(connection_id)
        if not connection or connection["person_id"] != person_id or connection["status"] != "active":
            raise ConnectionRejected("active connection not found")
        seen_key = f"seen:{connection_id}"
        seen = set(self._credentials.get(seen_key, "").split(",")) - {""}
        unique = [item for item in item_ids if item not in seen]
        seen.update(unique)
        self._credentials[seen_key] = ",".join(sorted(seen))
        receipt_id = f"syn_{secrets.token_urlsafe(12)}"
        receipt = {"schema_version": "sync-receipt.v1", "receipt_id": receipt_id,
                   "connection_id": connection_id, "person_id": person_id, "started_at": time.time(),
                   "completed_at": time.time(), "cursor_before": connection.get("cursor_handle"),
                   "cursor_after": next_cursor, "observed": len(item_ids), "imported": len(unique),
                   "duplicates": len(item_ids) - len(unique), "status": "complete"}
        connection["cursor_handle"] = next_cursor
        self.receipts[receipt_id] = receipt
        return receipt

    def list_connections(self, person_id: str) -> list[dict[str, Any]]:
        return [c for c in self.connections.values() if c["person_id"] == person_id]

    def refresh(self, person_id: str, connection_id: str, refreshed_token: str) -> dict[str, Any]:
        connection = self.connections.get(connection_id)
        if not connection or connection["person_id"] != person_id or connection["status"] != "active":
            raise ConnectionRejected("active connection not found")
        handle = connection.get("token_handle")
        if not handle or not handle.startswith("vault://"):
            raise ConnectionRejected("connection does not use a refreshable credential")
        self._credentials[handle] = refreshed_token
        return {"connection_id": connection_id, "status": "active", "token_handle": handle}

    def disconnect(self, person_id: str, connection_id: str, delete_imported: bool = False) -> dict[str, Any]:
        connection = self.connections.get(connection_id)
        if not connection or connection["person_id"] != person_id:
            raise ConnectionRejected("connection not found")
        handle = connection.get("token_handle")
        if handle:
            self._credentials.pop(handle, None)
        self._credentials.pop(f"seen:{connection_id}", None)
        connection.update(status="revoked", token_handle=None, cursor_handle=None)
        return {"connection": connection, "delete_imported_requested": delete_imported}
