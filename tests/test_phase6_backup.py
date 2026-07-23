from __future__ import annotations

import json

import pytest

from src.backup_backends import FileSystemBackend, HostileMemoryBackend
from src.backup_service import (
    BackupCoordinator,
    BackupIntegrityError,
    FileCheckpointWitness,
    ScopeSecrets,
)
from unison_common.backup import RestoreStatus, ScopeKind, VerificationStatus


def _coordinator(tmp_path, backend=None, chunk_size=8):
    return BackupCoordinator(
        backend or HostileMemoryBackend(),
        FileCheckpointWitness(tmp_path / "witness"),
        journal_root=tmp_path / "journals",
        chunk_size=chunk_size,
    )


def test_provider_sees_ciphertext_and_opaque_scope_only(tmp_path):
    backend = HostileMemoryBackend()
    coordinator = _coordinator(tmp_path, backend)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice-private")
    coordinator.create_snapshot(alice, b"Alice secret medical reminder")

    provider_view = b"\n".join(
        key.encode() + b":" + value for key, value in backend.objects.items()
    )
    assert b"Alice secret" not in provider_view
    assert b"alice-private" not in provider_view
    assert coordinator.verify(alice).status is VerificationStatus.VERIFIED


def test_wrong_person_and_household_admin_cannot_decrypt(tmp_path):
    backend = HostileMemoryBackend()
    coordinator = _coordinator(tmp_path, backend)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    bob = ScopeSecrets.create(ScopeKind.PERSON, "bob")
    coordinator.create_snapshot(alice, b"alice-private")

    bob.scope_keys = {1: bob.current_key}
    bob.scope_id = alice.scope_id
    with pytest.raises((BackupIntegrityError, KeyError, ValueError)):
        coordinator.plan_restore(bob, target_device_id="replacement")


def test_manifest_and_chunk_tampering_missing_data_and_rollback_detected(tmp_path):
    backend = HostileMemoryBackend()
    coordinator = _coordinator(tmp_path, backend)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    coordinator.create_snapshot(alice, b"first snapshot")
    old_head = backend.get(f"heads/{alice.opaque_scope_id}.json")
    coordinator.create_snapshot(alice, b"second snapshot")
    backend.put(f"heads/{alice.opaque_scope_id}.json", old_head)
    assert coordinator.verify(alice).status is VerificationStatus.ROLLED_BACK

    backend.put(
        f"heads/{alice.opaque_scope_id}.json",
        backend.get(f"manifests/{alice.opaque_scope_id}/00000000000000000002.json"),
    )
    chunk_key = backend.list(f"objects/{alice.opaque_scope_id}")[0]
    backend.corrupt(chunk_key)
    assert coordinator.verify(alice).status is VerificationStatus.CORRUPT


def test_interrupted_backup_and_restore_resume_safely(tmp_path):
    backend = HostileMemoryBackend()
    coordinator = _coordinator(tmp_path, backend, chunk_size=4)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    with pytest.raises(InterruptedError):
        coordinator.create_snapshot(
            alice,
            b"0123456789abcdef",
            interrupt_after_objects=2,
        )
    envelope = coordinator.create_snapshot(alice, b"0123456789abcdef")
    assert envelope.sequence == 1
    plan = coordinator.plan_restore(alice, target_device_id="replacement")
    target = tmp_path / "restored.bin"
    with pytest.raises(InterruptedError):
        coordinator.restore(
            alice,
            plan,
            target=target,
            interrupt_after_objects=2,
        )
    completed = coordinator.restore(
        alice,
        plan,
        target=target,
        replaced_device_id="old-device",
        rotate_after_activate=True,
    )
    assert completed.status is RestoreStatus.ACTIVATED
    assert target.read_bytes() == b"0123456789abcdef"
    assert "old-device" in alice.revoked_device_ids
    assert alice.key_epoch == 2


def test_restore_cancellation_is_non_destructive_and_resumable(tmp_path):
    coordinator = _coordinator(tmp_path, chunk_size=4)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    coordinator.create_snapshot(alice, b"0123456789")
    plan = coordinator.plan_restore(alice, target_device_id="replacement")
    target = tmp_path / "restored.bin"
    cancelled = coordinator.restore(
        alice,
        plan,
        target=target,
        cancel_after_objects=1,
    )
    assert cancelled.status is RestoreStatus.CANCELLED
    assert not target.exists()
    assert coordinator.restore(alice, plan, target=target).status is RestoreStatus.ACTIVATED


def test_person_and_shared_space_are_independent_and_rotation_revokes_future(tmp_path):
    coordinator = _coordinator(tmp_path)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    household = ScopeSecrets.create(ScopeKind.SHARED_SPACE, "household")
    wraps_v1 = household.wrap_shared_space_key(
        {"alice": b"a" * 32, "bob": b"b" * 32}
    )
    coordinator.create_snapshot(alice, b"private")
    first = coordinator.create_snapshot(household, b"shared-v1")
    previous_opaque = household.opaque_scope_id
    old_key = household.current_key
    household.rotate(revoked_device_id="removed-member-device")
    wraps_v2 = household.wrap_shared_space_key({"alice": b"a" * 32})
    second = coordinator.create_snapshot(household, b"shared-v2")

    assert first.opaque_scope_id == previous_opaque
    assert second.opaque_scope_id == previous_opaque
    assert household.current_key != old_key
    assert set(wraps_v1) == {"alice", "bob"}
    assert set(wraps_v2) == {"alice"}
    plan = coordinator.plan_restore(household, target_device_id="remaining-device")
    with pytest.raises(BackupIntegrityError, match="revoked"):
        coordinator.restore(
            household,
            plan.model_copy(update={"target_device_id": "removed-member-device"}),
            target=tmp_path / "forbidden.bin",
        )
    assert coordinator.verify(alice).status is VerificationStatus.VERIFIED


def test_independent_export_and_cryptographic_deletion(tmp_path):
    coordinator = _coordinator(tmp_path)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    bob = ScopeSecrets.create(ScopeKind.PERSON, "bob")
    coordinator.create_snapshot(alice, b"alice")
    coordinator.create_snapshot(bob, b"bob")
    exported = coordinator.export_encrypted_scope(alice)
    assert exported
    assert all(b"alice" not in value for value in exported.values())
    result = coordinator.delete_scope(alice)
    assert result["cryptographic_erasure"] is True
    assert result["provider_physical_erasure_guaranteed"] is False
    assert coordinator.verify(bob).status is VerificationStatus.VERIFIED


def test_filesystem_backend_portability(tmp_path):
    source = FileSystemBackend(tmp_path / "provider-a")
    target = FileSystemBackend(tmp_path / "provider-b")
    coordinator = _coordinator(tmp_path, source)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    coordinator.create_snapshot(alice, b"portable")
    for key in source.list("objects") + source.list("manifests") + source.list("heads"):
        target.put(key, source.get(key))
    migrated = BackupCoordinator(
        target,
        coordinator.witness,
        journal_root=tmp_path / "migrated-journals",
        chunk_size=8,
    )
    assert migrated.verify(alice).status is VerificationStatus.VERIFIED
    plan = migrated.plan_restore(alice, target_device_id="replacement")
    restored = tmp_path / "portable.bin"
    migrated.restore(alice, plan, target=restored)
    assert restored.read_bytes() == b"portable"


def test_scheduled_verification_retention_and_provider_migration(tmp_path):
    source = HostileMemoryBackend()
    target = HostileMemoryBackend()
    coordinator = _coordinator(tmp_path, source, chunk_size=4)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    coordinator.create_snapshot(alice, b"snapshot-one")
    coordinator.create_snapshot(alice, b"snapshot-two")
    first = coordinator.verify_and_record(alice, force=True)
    second = coordinator.verify_and_record(alice)
    assert first.verification_id == second.verification_id
    result = coordinator.prune_retention(alice, keep_latest=1)
    assert result["deleted_manifests"] == 1
    migrated = coordinator.migrate_provider(alice, target)
    assert migrated.status is VerificationStatus.VERIFIED


def test_backend_contains_no_plaintext_manifest(tmp_path):
    backend = HostileMemoryBackend()
    coordinator = _coordinator(tmp_path, backend)
    alice = ScopeSecrets.create(ScopeKind.PERSON, "alice")
    coordinator.create_snapshot(alice, json.dumps({"private": "value"}).encode())
    manifest_key = backend.list("manifests")[0]
    stored = backend.get(manifest_key)
    assert b'"scope_id":' not in stored
    assert b"private" not in stored
