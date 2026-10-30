"""Synthetic source workflow: prospective consent and a non-restored authority ledger.

Only the data snapshot is restorable. Every operation locks the separate authority
ledger first. Missing/corrupt authority fails closed; no automatic reprovisioning.
This does not resist rollback of the authority ledger itself or key/host compromise.
"""
import hashlib
import json
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from encrypted_state import EncryptedState
from source_contracts import PilotDenied, digest
from source_adapters import ADAPTERS

VERSION = "synthetic-source-workflow.v1"


def initialize_authority(path: Path, key: bytes, schema=VERSION):
    """Explicit disposable-fixture provisioning only, never called by HTTP routes."""
    if path.exists():
        raise ValueError("authority already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    return EncryptedState(path, key, {"schema": schema, "grants": {}})


class SourceWorkflow:
    policy_version = VERSION
    id_prefix = "source_"
    legacy_adapter_id = None
    def __init__(self, root: Path, authority_path: Path, key: bytes, adapter_id: str):
        if adapter_id not in ADAPTERS:
            raise PilotDenied("source adapter not qualified")
        self.adapter = ADAPTERS[adapter_id]
        root, authority_path = root.resolve(), authority_path.resolve()
        if authority_path.is_relative_to(root) or not authority_path.is_file():
            raise PilotDenied("separate existing authority ledger required")
        self.authority = EncryptedState(authority_path, key, {})
        if self.authority.read().get("schema") != self.policy_version:
            raise PilotDenied("authority schema unavailable")
        root.mkdir(parents=True, exist_ok=True)
        self.data = EncryptedState(root / "workflow.sqlite3", key, {"imports": {}, "snapshots": {}})
        self.cipher = Fernet(key)

    def _grant(self, state, person, wid, *, active=True):
        grant = state["grants"].get(wid)
        if (not grant or grant["person_id"] != person
                or grant.get("adapter_id", self.legacy_adapter_id) != self.adapter.identifier):
            raise PilotDenied("workflow unavailable")
        if active and (grant["state"] != "active" or grant["expires_at"] <= time.time()
                       or grant["policy_version"] != self.policy_version):
            raise PilotDenied("workflow consent unavailable")
        return grant

    def consent(self, person, metadata):
        if (set(metadata) != {"filename", "sha256", "size_bytes", "confirmed"}
                or metadata["confirmed"] is not True
                or not isinstance(metadata["filename"], str) or not 1 <= len(metadata["filename"]) <= 120
                or not isinstance(metadata["sha256"], str) or not re.fullmatch('[a-f0-9]{64}', metadata["sha256"])
                or type(metadata["size_bytes"]) is not int or not 0 < metadata["size_bytes"] <= 1024*1024):
            raise PilotDenied("explicit bounded export consent required")
        with self.authority.transaction():
            state = self.authority.read()
            wid = self.id_prefix + secrets.token_urlsafe(18)
            grant = dict(person_id=person, state="active", policy_version=self.policy_version, purpose=self.adapter.purpose, adapter_id=self.adapter.identifier,
                         expires_at=time.time()+86400, created_at=time.time(), **metadata)
            state["grants"][wid] = grant
            self.authority.write(state)
            return {"workflow_id": wid, "state": "consented", "expires_at": grant["expires_at"]}

    def upload(self, person, wid, raw):
        with self.authority.transaction():
            grant = self._grant(self.authority.read(), person, wid)
            if len(raw) != grant["size_bytes"] or hashlib.sha256(raw).hexdigest() != grant["sha256"]:
                raise PilotDenied("file differs from consented selection")
            # Validate before retaining any content; only the named synthetic schema is supported.
            stamp = datetime.now(timezone.utc).isoformat()
            with self.data.transaction():
                state = self.data.read()
                prior = state["imports"].get(wid)
                if prior: stamp = prior["ingested_at"]
                records, original_rows = self.adapter.extract(raw, person, wid, stamp, grant["sha256"])
                self.data.delete_blob(wid)
                self.data.put_blob(wid, raw)
                state["imports"][wid] = {"ingested_at": stamp, "records_hash": digest(records),
                                          "original_rows": original_rows}
                self.data.write(state)
            return {"state": "review", "facts": len(records), "duplicates_removed": original_rows-len(records)}

    def _view(self, person, wid, grant):
        state = self.data.read()
        saved = state["imports"].get(wid)
        if not saved: return {"state": "consented", "records": [], "summary": []}
        raw = self.data.get_blob(wid)
        if hashlib.sha256(raw).hexdigest() != grant["sha256"]:
            raise PilotDenied("source integrity unavailable")
        records, _ = self.adapter.extract(raw, person, wid, saved["ingested_at"], grant["sha256"])
        if digest(records) != saved["records_hash"]:
            raise PilotDenied("derived integrity unavailable")
        summary, interpretation = self.adapter.present(records)
        return {"state": "review", "workflow_id": wid, "filename": grant["filename"], "records": records,
                "summary": summary, "duplicates_removed": saved["original_rows"]-len(records),
                "interpretation": interpretation, "adapter_id": self.adapter.identifier}

    def view(self, person, wid):
        with self.authority.transaction():
            grant = self._grant(self.authority.read(), person, wid)
            with self.data.transaction(): return self._view(person, wid, grant)

    def _purge(self, wid):
        with self.data.transaction():
            state = self.data.read()
            state["imports"].pop(wid, None)
            self.data.delete_blob(wid)
            for bid, snapshot in list(state["snapshots"].items()):
                if snapshot["workflow_id"] == wid:
                    self.data.delete_blob(bid)
                    del state["snapshots"][bid]
            self.data.write(state)

    def terminate(self, person, wid, mode):
        if mode not in {"revoked", "deleted"}: raise PilotDenied("invalid terminal state")
        # Commit authority first. Any failure purging derivatives must leave reads denied.
        with self.authority.transaction():
            state = self.authority.read()
            grant = self._grant(state, person, wid, active=False)
            if grant["state"] == "active" or mode == "deleted":
                grant.update(state=mode, terminated_at=time.time())
            for field in ("filename", "sha256", "size_bytes", "confirmed"):
                grant.pop(field, None)
            self.authority.write(state)
        with self.authority.transaction():
            self._grant(self.authority.read(), person, wid, active=False)
            self._purge(wid)
        return {"state": grant["state"], "content_removed": True}

    def backup(self, person, wid):
        with self.authority.transaction():
            grant = self._grant(self.authority.read(), person, wid)
            with self.data.transaction():
                self._view(person, wid, grant)
                state = self.data.read()
                if wid not in state["imports"]: raise PilotDenied("nothing to back up")
                raw = self.data.get_blob(wid)
                payload = json.dumps({"workflow_id": wid, "person_id": person,
                                      "saved": state["imports"][wid], "raw": raw.decode()}).encode()
                # An opaque encrypted snapshot; the authority ledger is never included.
                bid = "snapshot_" + secrets.token_urlsafe(18)
                self.data.put_blob(bid, self.cipher.encrypt(payload))
                state["snapshots"][bid] = {"workflow_id": wid}
                self.data.write(state)
                return {"snapshot_id": bid}

    def restore(self, person, wid, bid):
        with self.authority.transaction():
            state = self.authority.read()
            grant = self._grant(state, person, wid, active=False)
            if grant["state"] != "active" or grant["expires_at"] <= time.time() or grant["policy_version"] != self.policy_version:
                self._purge(wid)
                return {"restored": False, "state": grant["state"], "unavailable": True}
            with self.data.transaction():
                data = self.data.read()
                if data["snapshots"].get(bid, {}).get("workflow_id") != wid:
                    raise PilotDenied("snapshot unavailable")
                snapshot = json.loads(self.cipher.decrypt(self.data.get_blob(bid)))
                if snapshot["person_id"] != person or snapshot["workflow_id"] != wid:
                    raise PilotDenied("snapshot authority mismatch")
                raw = snapshot["raw"].encode()
                if hashlib.sha256(raw).hexdigest() != grant["sha256"]:
                    raise PilotDenied("snapshot source mismatch")
                self.data.delete_blob(wid)
                self.data.put_blob(wid, raw)
                data["imports"][wid] = snapshot["saved"]
                self.data.write(data)
                self._view(person, wid, grant)
                return {"restored": True, "state": "review"}
