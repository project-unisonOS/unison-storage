"""Synthetic source-state privacy and concurrent-update regression tests."""
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from pathlib import Path
import time

import pytest
from cryptography.fernet import Fernet
from src.life_operations import SourceLibrary


def _start_in_process(arguments):
    path, key = arguments
    return SourceLibrary(Path(path), key).start("synthetic-alice", "private:synthetic-alice")["session_id"]


def test_derivatives_are_encrypted_at_rest(tmp_path):
    library = SourceLibrary(tmp_path, Fernet.generate_key())
    session = library.start("synthetic-alice", "private:synthetic-alice")
    library.ingest(session["session_id"], "synthetic-private-title.txt", "text/plain",
                   b"SYNTHETIC_PRIVATE_OBSERVATION", actor_person_id="synthetic-alice")
    for path in tmp_path.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert b"SYNTHETIC_PRIVATE_OBSERVATION" not in data
            assert b"synthetic-private-title" not in data


def test_separate_instances_do_not_lose_concurrent_sessions(tmp_path, monkeypatch):
    key = Fernet.generate_key()
    libraries = [SourceLibrary(tmp_path, key) for _ in range(8)]
    original = SourceLibrary._read_index
    def delayed_read(self):
        result = original(self)
        time.sleep(0.01)
        return result
    monkeypatch.setattr(SourceLibrary, "_read_index", delayed_read)
    with ThreadPoolExecutor(max_workers=8) as pool:
        sessions = list(pool.map(lambda i: libraries[i % 8].start("synthetic-alice", "private:synthetic-alice"), range(24)))
    restored = SourceLibrary(tmp_path, key)
    assert set(restored._read_index()["sessions"]) == {s["session_id"] for s in sessions}


def test_wrong_key_cannot_read_existing_state(tmp_path):
    key = Fernet.generate_key()
    SourceLibrary(tmp_path, key).start("synthetic-alice", "private:synthetic-alice")
    with pytest.raises(Exception):
        SourceLibrary(tmp_path, Fernet.generate_key())._read_index()


def test_failed_extraction_rolls_back_blob_and_metadata(tmp_path, monkeypatch):
    import sqlite3
    key = Fernet.generate_key()
    library = SourceLibrary(tmp_path, key)
    session = library.start("synthetic-alice", "private:synthetic-alice")
    def failure(*args):
        raise RuntimeError("synthetic extraction failure")
    monkeypatch.setattr(library, "_extract", failure)
    with pytest.raises(RuntimeError, match="synthetic extraction"):
        library.ingest(session["session_id"], "fixture.txt", "text/plain", b"synthetic")
    restored = SourceLibrary(tmp_path, key)
    assert restored.list_sources("synthetic-alice") == []
    assert restored._read_index()["sessions"][session["session_id"]]["source_ids"] == []
    with sqlite3.connect(restored.index_path) as db:
        assert db.execute("SELECT COUNT(*) FROM blobs").fetchone()[0] == 0


def test_legacy_plaintext_is_never_silently_overwritten(tmp_path):
    path = tmp_path / "source-index.json"
    path.write_text('{"synthetic": "legacy"}')
    with pytest.raises(ValueError, match="explicit offline migration"):
        SourceLibrary(tmp_path, Fernet.generate_key())
    assert path.read_text() == '{"synthetic": "legacy"}'


def test_delete_removes_blob_and_derivatives_atomically(tmp_path):
    key = Fernet.generate_key()
    library = SourceLibrary(tmp_path, key)
    session = library.start("synthetic-alice", "private:synthetic-alice")
    source = library.ingest(session["session_id"], "fixture.txt", "text/plain", b"synthetic")
    library.delete_source("synthetic-alice", source["source_id"])
    restored = SourceLibrary(tmp_path, key)
    assert restored.list_sources("synthetic-alice") == []
    assert source["source_id"] not in restored._read_index()["fields"]
    with pytest.raises(ValueError):
        restored.export_source("synthetic-alice", source["source_id"])


def test_processes_share_one_transactional_state(tmp_path):
    key = Fernet.generate_key()
    SourceLibrary(tmp_path, key)
    with ProcessPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(_start_in_process, [(str(tmp_path), key)] * 12))
    assert set(SourceLibrary(tmp_path, key)._read_index()["sessions"]) == set(ids)
