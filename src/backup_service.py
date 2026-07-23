"""Incremental, provider-blind backup and replacement-device restore."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from unison_common.backup import (
    BackupCrypto,
    BackupManifest,
    ChunkReference,
    EncryptedChunk,
    ManifestCheckpoint,
    RestorePlan,
    RestoreStatus,
    ScopeKind,
    SignedManifestEnvelope,
    SnapshotLineage,
    Tombstone,
    VerificationRecord,
    VerificationStatus,
)

from .backup_backends import BackupBackend, ConditionalWriteError, ObjectNotFoundError


class BackupIntegrityError(RuntimeError):
    pass


class RestoreCancelled(RuntimeError):
    pass


@dataclass
class ScopeSecrets:
    scope_kind: ScopeKind
    scope_id: str
    key_epoch: int
    scope_keys: dict[int, bytes]
    scope_handle_key: bytes
    signing_key: Ed25519PrivateKey
    revoked_device_ids: set[str] = field(default_factory=set)

    @classmethod
    def create(cls, scope_kind: ScopeKind, scope_id: str) -> "ScopeSecrets":
        return cls(
            scope_kind=scope_kind,
            scope_id=scope_id,
            key_epoch=1,
            scope_keys={1: BackupCrypto.generate_scope_key()},
            scope_handle_key=BackupCrypto.generate_scope_key(),
            signing_key=BackupCrypto.generate_signing_key(),
        )

    @property
    def current_key(self) -> bytes:
        return self.scope_keys[self.key_epoch]

    @property
    def opaque_scope_id(self) -> str:
        return BackupCrypto.opaque_scope_id(self.scope_handle_key, self.scope_id)

    @property
    def trusted_public_key(self) -> bytes:
        return BackupCrypto.public_key_bytes(self.signing_key.public_key())

    def rotate(self, *, revoked_device_id: str | None = None) -> int:
        self.key_epoch += 1
        self.scope_keys[self.key_epoch] = BackupCrypto.generate_scope_key()
        if revoked_device_id:
            self.revoked_device_ids.add(revoked_device_id)
        return self.key_epoch

    def wrap_shared_space_key(
        self,
        member_wrapping_keys: dict[str, bytes],
    ) -> dict[str, dict[str, str | int]]:
        if self.scope_kind is not ScopeKind.SHARED_SPACE:
            raise ValueError("member key wrapping applies only to shared spaces")
        wrapped: dict[str, dict[str, str | int]] = {}
        for person_id, wrapping_key in sorted(member_wrapping_keys.items()):
            if len(wrapping_key) != 32:
                raise ValueError("member wrapping keys must be 256 bits")
            nonce = os.urandom(12)
            aad = (
                f"unison-backup-v1:shared-wrap:{self.scope_id}:"
                f"{self.key_epoch}:{person_id}"
            ).encode()
            ciphertext = AESGCM(wrapping_key).encrypt(
                nonce,
                self.current_key,
                aad,
            )
            wrapped[person_id] = {
                "key_epoch": self.key_epoch,
                "nonce": _urlsafe(nonce),
                "ciphertext": _urlsafe(ciphertext),
            }
        return wrapped


class FileCheckpointWitness:
    """Independent trusted checkpoint store, separate from the blob provider."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, opaque_scope_id: str) -> Path:
        safe = hashlib.sha256(opaque_scope_id.encode()).hexdigest()
        return self.root / f"{safe}.checkpoint.json"

    def read(self, opaque_scope_id: str) -> ManifestCheckpoint | None:
        path = self._path(opaque_scope_id)
        if not path.exists():
            return None
        return ManifestCheckpoint.model_validate_json(path.read_bytes())

    def write(self, checkpoint: ManifestCheckpoint) -> None:
        target = self._path(checkpoint.opaque_scope_id)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{target.name}.",
            dir=target.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(checkpoint.model_dump_json().encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class BackupCoordinator:
    def __init__(
        self,
        backend: BackupBackend,
        witness: FileCheckpointWitness,
        *,
        journal_root: str | Path,
        chunk_size: int = 4 * 1024 * 1024,
    ):
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        self.backend = backend
        self.witness = witness
        self.journal_root = Path(journal_root)
        self.journal_root.mkdir(parents=True, exist_ok=True)
        self.chunk_size = chunk_size

    @staticmethod
    def _head_key(opaque_scope_id: str) -> str:
        return f"heads/{opaque_scope_id}.json"

    @staticmethod
    def _manifest_key(opaque_scope_id: str, sequence: int) -> str:
        return f"manifests/{opaque_scope_id}/{sequence:020d}.json"

    @staticmethod
    def _chunk_key(opaque_scope_id: str, object_id: str) -> str:
        return f"objects/{opaque_scope_id}/{object_id}.json"

    def _journal_path(self, plan_id: str) -> Path:
        return self.journal_root / f"{plan_id}.json"

    def _read_head(
        self,
        opaque_scope_id: str,
    ) -> SignedManifestEnvelope | None:
        try:
            value = self.backend.get(self._head_key(opaque_scope_id))
        except ObjectNotFoundError:
            return None
        return SignedManifestEnvelope.model_validate_json(value)

    def create_snapshot(
        self,
        secrets: ScopeSecrets,
        payload: bytes,
        *,
        provenance: tuple[str, ...] = (),
        tombstones: tuple[Tombstone, ...] = (),
        retention_until: datetime | None = None,
        interrupt_after_objects: int | None = None,
    ) -> SignedManifestEnvelope:
        opaque = secrets.opaque_scope_id
        previous = self._read_head(opaque)
        checkpoint = self.witness.read(opaque)
        if previous and checkpoint:
            BackupCrypto.verify_checkpoint(previous, checkpoint)
        sequence = 1 if previous is None else previous.sequence + 1
        parent = None if previous is None else previous.manifest_digest
        references: list[ChunkReference] = []
        uploaded = 0
        chunks = [
            payload[offset : offset + self.chunk_size]
            for offset in range(0, len(payload), self.chunk_size)
        ] or [b""]
        for ordinal, plaintext in enumerate(chunks):
            encrypted = BackupCrypto.encrypt_chunk(
                plaintext,
                scope_key=secrets.current_key,
                opaque_scope_id=opaque,
                key_epoch=secrets.key_epoch,
            )
            stored = encrypted.model_dump_json().encode()
            key = self._chunk_key(opaque, encrypted.object_id)
            if not self.backend.exists(key):
                try:
                    self.backend.put(key, stored, if_absent=True)
                except ConditionalWriteError:
                    pass
                uploaded += 1
                if (
                    interrupt_after_objects is not None
                    and uploaded >= interrupt_after_objects
                ):
                    raise InterruptedError("simulated interrupted backup")
            references.append(
                ChunkReference(
                    object_id=encrypted.object_id,
                    plaintext_sha256=hashlib.sha256(plaintext).hexdigest(),
                    plaintext_size=len(plaintext),
                    stored_size=len(stored),
                    ordinal=ordinal,
                )
            )
        manifest = BackupManifest(
            snapshot_id=str(uuid.uuid4()),
            opaque_scope_id=opaque,
            scope_kind=secrets.scope_kind,
            scope_id=secrets.scope_id,
            key_epoch=secrets.key_epoch,
            lineage=SnapshotLineage(
                sequence=sequence,
                parent_manifest_digest=parent,
            ),
            chunks=tuple(references),
            tombstones=tombstones,
            provenance=provenance,
            retention_until=retention_until,
        )
        envelope = BackupCrypto.encrypt_and_sign_manifest(
            manifest,
            scope_key=secrets.current_key,
            signing_key=secrets.signing_key,
        )
        manifest_key = self._manifest_key(opaque, sequence)
        self.backend.put(manifest_key, envelope.model_dump_json().encode())
        self.backend.put(
            self._head_key(opaque),
            envelope.model_dump_json().encode(),
        )
        next_checkpoint = BackupCrypto.checkpoint(envelope)
        if checkpoint is not None:
            next_checkpoint = next_checkpoint.model_copy(
                update={
                    "lineage_floor_sequence": checkpoint.lineage_floor_sequence,
                    "lineage_floor_parent_digest": (
                        checkpoint.lineage_floor_parent_digest
                    ),
                }
            )
        self.witness.write(next_checkpoint)
        return envelope

    def verify(
        self,
        secrets: ScopeSecrets,
        *,
        require_anchor: bool = True,
    ) -> VerificationRecord:
        opaque = secrets.opaque_scope_id
        head = self._read_head(opaque)
        if head is None:
            return VerificationRecord(
                verification_id=str(uuid.uuid4()),
                opaque_scope_id=opaque,
                snapshot_id=None,
                status=VerificationStatus.INCOMPLETE,
                checked_objects=0,
                detail="No snapshot is available.",
            )
        checkpoint = self.witness.read(opaque)
        if checkpoint is None and require_anchor:
            return VerificationRecord(
                verification_id=str(uuid.uuid4()),
                opaque_scope_id=opaque,
                snapshot_id=None,
                status=VerificationStatus.UNANCHORED,
                checked_objects=0,
                detail="The latest signed checkpoint is unavailable.",
            )
        try:
            if checkpoint:
                BackupCrypto.verify_checkpoint(head, checkpoint)
            manifests = self._verify_lineage(secrets, head)
            manifest = manifests[0]
            checked = 0
            checked_ids: set[str] = set()
            for retained_manifest in manifests:
                for reference in sorted(
                    retained_manifest.chunks,
                    key=lambda item: item.ordinal,
                ):
                    stored = self.backend.get(
                        self._chunk_key(opaque, reference.object_id)
                    )
                    chunk = EncryptedChunk.model_validate_json(stored)
                    plaintext = BackupCrypto.decrypt_chunk(
                        chunk,
                        scope_key=secrets.scope_keys[
                            chunk.wrapped_data_key.key_epoch
                        ],
                        opaque_scope_id=opaque,
                    )
                    if not hmac_compare(
                        hashlib.sha256(plaintext).hexdigest(),
                        reference.plaintext_sha256,
                    ):
                        raise BackupIntegrityError("chunk plaintext digest mismatch")
                    if reference.object_id not in checked_ids:
                        checked_ids.add(reference.object_id)
                        checked += 1
        except (
            InvalidTag,
            KeyError,
            ValueError,
            ObjectNotFoundError,
            BackupIntegrityError,
        ) as exc:
            detail = str(exc)
            status = (
                VerificationStatus.ROLLED_BACK
                if "rollback" in detail or "forked" in detail
                else VerificationStatus.CORRUPT
            )
            return VerificationRecord(
                verification_id=str(uuid.uuid4()),
                opaque_scope_id=opaque,
                snapshot_id=None,
                status=status,
                checked_objects=0,
                detail=detail,
            )
        return VerificationRecord(
            verification_id=str(uuid.uuid4()),
            opaque_scope_id=opaque,
            snapshot_id=manifest.snapshot_id,
            status=VerificationStatus.VERIFIED,
            checked_objects=checked,
            detail="Signed manifest, anchor, lineage, and every chunk verified.",
        )

    def _verify_lineage(
        self,
        secrets: ScopeSecrets,
        head: SignedManifestEnvelope,
    ) -> list[BackupManifest]:
        """Verify every retained link to detect truncation, reordering, or replay."""

        checkpoint = self.witness.read(head.opaque_scope_id)
        floor = checkpoint.lineage_floor_sequence if checkpoint else 1
        floor_parent = checkpoint.lineage_floor_parent_digest if checkpoint else None
        if floor > head.sequence:
            raise BackupIntegrityError("lineage floor exceeds manifest head")
        child_manifest: BackupManifest | None = None
        head_manifest: BackupManifest | None = None
        manifests: list[BackupManifest] = []
        for sequence in range(head.sequence, floor - 1, -1):
            envelope = (
                head
                if sequence == head.sequence
                else SignedManifestEnvelope.model_validate_json(
                    self.backend.get(
                        self._manifest_key(head.opaque_scope_id, sequence)
                    )
                )
            )
            if envelope.sequence != sequence:
                raise BackupIntegrityError("manifest sequence was reordered")
            manifest = BackupCrypto.verify_and_decrypt_manifest(
                envelope,
                scope_key=secrets.scope_keys[envelope.key_epoch],
                trusted_public_key=secrets.trusted_public_key,
            )
            if head_manifest is None:
                head_manifest = manifest
            manifests.append(manifest)
            if child_manifest is not None and not hmac_compare(
                child_manifest.lineage.parent_manifest_digest or "",
                envelope.manifest_digest,
            ):
                raise BackupIntegrityError("manifest lineage was truncated or reordered")
            child_manifest = manifest
        assert head_manifest is not None
        if child_manifest:
            if floor == 1 and child_manifest.lineage.parent_manifest_digest is not None:
                raise BackupIntegrityError("first manifest has an unexpected parent")
            if floor > 1 and not hmac_compare(
                child_manifest.lineage.parent_manifest_digest or "",
                floor_parent or "",
            ):
                raise BackupIntegrityError("retention lineage floor does not match")
        return manifests

    def verify_and_record(
        self,
        secrets: ScopeSecrets,
        *,
        minimum_interval: timedelta = timedelta(hours=24),
        force: bool = False,
    ) -> VerificationRecord:
        path = self.journal_root / (
            hashlib.sha256(secrets.opaque_scope_id.encode()).hexdigest()
            + ".verification.json"
        )
        if path.exists() and not force:
            previous = VerificationRecord.model_validate_json(path.read_bytes())
            if datetime.now(timezone.utc) - previous.checked_at < minimum_interval:
                return previous
        record = self.verify(secrets)
        path.write_text(record.model_dump_json(), encoding="utf-8")
        return record

    def plan_restore(
        self,
        secrets: ScopeSecrets,
        *,
        target_device_id: str,
    ) -> RestorePlan:
        verification = self.verify(secrets, require_anchor=True)
        if verification.status is not VerificationStatus.VERIFIED:
            raise BackupIntegrityError(verification.detail)
        head = self._read_head(secrets.opaque_scope_id)
        assert head is not None
        manifest = BackupCrypto.verify_and_decrypt_manifest(
            head,
            scope_key=secrets.scope_keys[head.key_epoch],
            trusted_public_key=secrets.trusted_public_key,
        )
        return RestorePlan(
            plan_id=str(uuid.uuid4()),
            opaque_scope_id=secrets.opaque_scope_id,
            snapshot_id=manifest.snapshot_id,
            manifest_digest=head.manifest_digest,
            target_device_id=target_device_id,
            total_objects=len(manifest.chunks),
            dry_run=True,
            anchor_verified=True,
        )

    def restore(
        self,
        secrets: ScopeSecrets,
        plan: RestorePlan,
        *,
        target: str | Path,
        cancel_after_objects: int | None = None,
        interrupt_after_objects: int | None = None,
        replaced_device_id: str | None = None,
        rotate_after_activate: bool = False,
    ) -> RestorePlan:
        if plan.target_device_id in secrets.revoked_device_ids:
            raise BackupIntegrityError("the target device is revoked")
        verification = self.verify(secrets, require_anchor=True)
        if verification.status is not VerificationStatus.VERIFIED:
            raise BackupIntegrityError(verification.detail)
        current = self._read_head(plan.opaque_scope_id)
        if current is None or not hmac_compare(
            current.manifest_digest,
            plan.manifest_digest,
        ):
            raise BackupIntegrityError("restore plan no longer matches anchored head")
        manifest = BackupCrypto.verify_and_decrypt_manifest(
            current,
            scope_key=secrets.scope_keys[current.key_epoch],
            trusted_public_key=secrets.trusted_public_key,
        )
        journal_path = self._journal_path(plan.plan_id)
        journal = {"completed": 0, "parts": []}
        resumed = False
        if journal_path.exists():
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            resumed = journal["completed"] > 0
        stage_dir = self.journal_root / f"{plan.plan_id}.stage"
        stage_dir.mkdir(parents=True, exist_ok=True)
        references = sorted(manifest.chunks, key=lambda item: item.ordinal)
        for index in range(journal["completed"], len(references)):
            reference = references[index]
            chunk = EncryptedChunk.model_validate_json(
                self.backend.get(
                    self._chunk_key(plan.opaque_scope_id, reference.object_id)
                )
            )
            plaintext = BackupCrypto.decrypt_chunk(
                chunk,
                scope_key=secrets.scope_keys[chunk.wrapped_data_key.key_epoch],
                opaque_scope_id=plan.opaque_scope_id,
            )
            if hashlib.sha256(plaintext).hexdigest() != reference.plaintext_sha256:
                raise BackupIntegrityError("restore chunk digest mismatch")
            part = stage_dir / f"{index:020d}.part"
            part.write_bytes(plaintext)
            journal = {
                "completed": index + 1,
                "parts": [f"{position:020d}.part" for position in range(index + 1)],
                "resumed": resumed,
            }
            journal_path.write_text(
                json.dumps(journal, sort_keys=True),
                encoding="utf-8",
            )
            if cancel_after_objects is not None and index + 1 >= cancel_after_objects:
                return plan.model_copy(
                    update={
                        "status": RestoreStatus.CANCELLED,
                        "completed_objects": index + 1,
                        "dry_run": False,
                    }
                )
            if (
                interrupt_after_objects is not None
                and index + 1 >= interrupt_after_objects
            ):
                raise InterruptedError("simulated interrupted restore")
        target_path = Path(target)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = target_path.with_suffix(target_path.suffix + ".restore")
        with temporary.open("wb") as stream:
            for index in range(len(references)):
                stream.write((stage_dir / f"{index:020d}.part").read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target_path)
        shutil.rmtree(stage_dir)
        journal_path.unlink(missing_ok=True)
        if rotate_after_activate:
            secrets.rotate(revoked_device_id=replaced_device_id)
        return plan.model_copy(
            update={
                "status": RestoreStatus.ACTIVATED,
                "completed_objects": len(references),
                "dry_run": False,
            }
        )

    def prune_retention(
        self,
        secrets: ScopeSecrets,
        *,
        keep_latest: int = 30,
        now: datetime | None = None,
    ) -> dict[str, int]:
        if keep_latest < 1:
            raise ValueError("at least one snapshot must be retained")
        opaque = secrets.opaque_scope_id
        now = now or datetime.now(timezone.utc)
        manifest_keys = self.backend.list(f"manifests/{opaque}")
        envelopes = [
            SignedManifestEnvelope.model_validate_json(self.backend.get(key))
            for key in manifest_keys
        ]
        envelopes.sort(key=lambda item: item.sequence, reverse=True)
        retain: list[SignedManifestEnvelope] = []
        expire: list[SignedManifestEnvelope] = []
        for index, envelope in enumerate(envelopes):
            manifest = BackupCrypto.verify_and_decrypt_manifest(
                envelope,
                scope_key=secrets.scope_keys[envelope.key_epoch],
                trusted_public_key=secrets.trusted_public_key,
            )
            if index < keep_latest or (
                manifest.retention_until is not None
                and manifest.retention_until > now
            ):
                retain.append(envelope)
            else:
                expire.append(envelope)
        if retain:
            floor_sequence = min(item.sequence for item in retain)
            retain = [
                item for item in envelopes if item.sequence >= floor_sequence
            ]
            expire = [
                item for item in envelopes if item.sequence < floor_sequence
            ]
        retained_objects: set[str] = set()
        for envelope in retain:
            manifest = BackupCrypto.verify_and_decrypt_manifest(
                envelope,
                scope_key=secrets.scope_keys[envelope.key_epoch],
                trusted_public_key=secrets.trusted_public_key,
            )
            retained_objects.update(item.object_id for item in manifest.chunks)
        deleted_manifests = 0
        for envelope in expire:
            if self.backend.delete(
                self._manifest_key(opaque, envelope.sequence)
            ):
                deleted_manifests += 1
        deleted_chunks = 0
        for key in self.backend.list(f"objects/{opaque}"):
            object_id = Path(key).stem
            if object_id not in retained_objects and self.backend.delete(key):
                deleted_chunks += 1
        if retain:
            oldest = min(retain, key=lambda item: item.sequence)
            oldest_manifest = BackupCrypto.verify_and_decrypt_manifest(
                oldest,
                scope_key=secrets.scope_keys[oldest.key_epoch],
                trusted_public_key=secrets.trusted_public_key,
            )
            checkpoint = self.witness.read(opaque)
            if checkpoint is None:
                raise BackupIntegrityError("cannot prune without a trusted checkpoint")
            self.witness.write(
                checkpoint.model_copy(
                    update={
                        "lineage_floor_sequence": oldest.sequence,
                        "lineage_floor_parent_digest": (
                            oldest_manifest.lineage.parent_manifest_digest
                        ),
                    }
                )
            )
        return {
            "deleted_manifests": deleted_manifests,
            "deleted_chunks": deleted_chunks,
            "retained_manifests": len(retain),
        }

    def migrate_provider(
        self,
        secrets: ScopeSecrets,
        target: BackupBackend,
    ) -> VerificationRecord:
        opaque = secrets.opaque_scope_id
        keys = sorted(
            self.backend.list(f"objects/{opaque}")
            + self.backend.list(f"manifests/{opaque}")
            + [self._head_key(opaque)]
        )
        for key in keys:
            target.put(key, self.backend.get(key))
        migrated = BackupCoordinator(
            target,
            self.witness,
            journal_root=self.journal_root / "provider-migration",
            chunk_size=self.chunk_size,
        )
        return migrated.verify(secrets)

    def delete_scope(self, secrets: ScopeSecrets) -> dict[str, int | bool]:
        opaque = secrets.opaque_scope_id
        keys = (
            self.backend.list(f"objects/{opaque}")
            + self.backend.list(f"manifests/{opaque}")
            + [self._head_key(opaque)]
        )
        deleted = sum(1 for key in keys if self.backend.delete(key))
        checkpoint = self.witness._path(opaque)
        checkpoint.unlink(missing_ok=True)
        secrets.scope_keys.clear()
        return {
            "deleted_objects": deleted,
            "cryptographic_erasure": True,
            "provider_physical_erasure_guaranteed": False,
        }

    def export_encrypted_scope(self, secrets: ScopeSecrets) -> dict[str, bytes]:
        opaque = secrets.opaque_scope_id
        keys = sorted(
            self.backend.list(f"objects/{opaque}")
            + self.backend.list(f"manifests/{opaque}")
            + [self._head_key(opaque)]
        )
        return {key: self.backend.get(key) for key in keys}


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _urlsafe(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).decode().rstrip("=")


__all__ = [
    "BackupCoordinator",
    "BackupIntegrityError",
    "FileCheckpointWitness",
    "RestoreCancelled",
    "ScopeSecrets",
]
