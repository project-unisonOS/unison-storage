"""Transactional local state: SQLite sees ciphertext, never private JSON/blobs.

The caller owns key custody and authorization. This is not protection against
compromise of the unlocked process/host, nor a backup key-revocation mechanism.
"""
from contextlib import contextmanager
from functools import wraps
import json
from pathlib import Path
import sqlite3
import threading

from cryptography.fernet import Fernet


def transactional(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._state.transaction():
            return method(self, *args, **kwargs)
    return wrapped


class EncryptedState:
    def __init__(self, path: Path, key: bytes, initial: dict):
        self.path = path
        self.cipher = Fernet(key)
        self.local = threading.local()
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id=1), value BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, value BLOB NOT NULL)")
            if db.execute("SELECT 1 FROM state WHERE id=1").fetchone() is None:
                self.write(initial)
            else:
                self.read()  # Verify key/integrity before accepting any mutation.
        self.path.chmod(0o600)

    @contextmanager
    def transaction(self):
        current = getattr(self.local, "connection", None)
        if current is not None:
            yield current
            return
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA secure_delete=ON")
            db.execute("BEGIN IMMEDIATE")
            self.local.connection = db
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            self.local.connection = None
            db.close()

    def read(self):
        with self.transaction() as db:
            row = db.execute("SELECT value FROM state WHERE id=1").fetchone()
            return json.loads(self.cipher.decrypt(row[0]))

    def write(self, state):
        value = self.cipher.encrypt(json.dumps(state, sort_keys=True).encode())
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO state (id,value) VALUES (1,?)", (value,))

    def put_blob(self, identifier, value):
        ciphertext = self.cipher.encrypt(value)
        with self.transaction() as db:
            db.execute("INSERT INTO blobs (id,value) VALUES (?,?)", (identifier, ciphertext))

    def get_blob(self, identifier):
        with self.transaction() as db:
            row = db.execute("SELECT value FROM blobs WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise ValueError("source unavailable")
            return self.cipher.decrypt(row[0])

    def delete_blob(self, identifier):
        with self.transaction() as db:
            db.execute("DELETE FROM blobs WHERE id=?", (identifier,))
