"""Synthetic browser workflow: prospective consent and a non-restored authority ledger.

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
from health_pilot import Export, PilotDenied, decode_unique, digest, records_from_export

VERSION = "synthetic-health-workflow.v1"


def initialize_authority(path: Path, key: bytes):
    """Explicit disposable-fixture provisioning only, never called by HTTP routes."""
    if path.exists():
        raise ValueError("authority already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    return EncryptedState(path, key, {"schema": VERSION, "grants": {}})


class HealthWorkflow:
    def __init__(self, root: Path, authority_path: Path, key: bytes):
        root, authority_path = root.resolve(), authority_path.resolve()
        if authority_path.is_relative_to(root) or not authority_path.is_file():
            raise PilotDenied("separate existing authority ledger required")
        self.authority = EncryptedState(authority_path, key, {})
        if self.authority.read().get("schema") != VERSION:
            raise PilotDenied("authority schema unavailable")
        root.mkdir(parents=True, exist_ok=True)
        self.data = EncryptedState(root / "workflow.sqlite3", key, {"imports": {}, "snapshots": {}})
        self.cipher = Fernet(key)

    def _grant(self, state, person, wid, *, active=True):
        grant = state["grants"].get(wid)
        if not grant or grant["person_id"] != person:
            raise PilotDenied("workflow unavailable")
        if active and (grant["state"] != "active" or grant["expires_at"] <= time.time()
                       or grant["policy_version"] != VERSION):
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
            wid = "health_" + secrets.token_urlsafe(18)
            grant = dict(person_id=person, state="active", policy_version=VERSION, purpose="wellness.summary",
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
            export = Export.model_validate(decode_unique(raw))
            stamp = datetime.now(timezone.utc).isoformat()
            with self.data.transaction():
                state = self.data.read()
                prior = state["imports"].get(wid)
                if prior: stamp = prior["ingested_at"]
                records = records_from_export(raw, person, wid, wid, stamp, grant["sha256"])
                self.data.delete_blob(wid)
                self.data.put_blob(wid, raw)
                state["imports"][wid] = {"ingested_at": stamp, "records_hash": digest(records),
                                          "original_rows": len(export.observations)}
                self.data.write(state)
            return {"state": "review", "facts": len(records), "duplicates_removed": len(export.observations)-len(records)}

    def _view(self, person, wid, grant):
        state = self.data.read()
        saved = state["imports"].get(wid)
        if not saved: return {"state": "consented", "records": [], "summary": []}
        raw = self.data.get_blob(wid)
        if hashlib.sha256(raw).hexdigest() != grant["sha256"]:
            raise PilotDenied("source integrity unavailable")
        records = records_from_export(raw, person, wid, wid, saved["ingested_at"], grant["sha256"])
        if digest(records) != saved["records_hash"]:
            raise PilotDenied("derived integrity unavailable")
        summary = []
        for metric, label in (("sleep_duration", "Sleep duration"), ("steps", "Steps")):
            values = [r for r in records if r["facts"]["metric"] == metric and r["facts"]["kind"] == "measurement"]
            if not values:
                summary.append({"metric": metric, "text": f"{label}: unknown; no measurement supplied.", "record_ids": []})
                continue
            day = max(r["facts"]["source_day"] for r in values)
            current = [r for r in values if r["facts"]["source_day"] == day]
            latest = {}
            for r in current:
                key = (r["facts"]["source"], r["facts"]["upstream_id"])
                if key not in latest or r["facts"]["revision"] > latest[key]["facts"]["revision"]: latest[key] = r
            current = list(latest.values())
            if len(current) != 1:
                text = f"{label} on {day}: unknown; multiple measurements need review."
            else:
                fact = current[0]["facts"]
                text = (f"{label} on {day}: {fact['value']:g} {fact['unit']}." if fact["quality"] == "valid"
                        else f"{label} on {day}: unknown; {fact['missing_reason']}.")
            summary.append({"metric": metric, "text": text, "record_ids": [r["record_id"] for r in current]})
        return {"state": "review", "workflow_id": wid, "filename": grant["filename"], "records": records,
                "summary": summary, "duplicates_removed": saved["original_rows"]-len(records),
                "interpretation": "Descriptive synthetic measurements only. No diagnosis or health recommendation."}

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
            if grant["state"] != "active" or grant["expires_at"] <= time.time() or grant["policy_version"] != VERSION:
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
