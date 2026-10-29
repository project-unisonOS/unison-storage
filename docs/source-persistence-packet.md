# Source persistence packet, October 2026

Status: draft software change for review; no operational migration or deployment.

Source-library metadata, extracted derivatives and original source bytes now
share one SQLite transaction. JSON and blob values are encrypted before entering
SQLite, including its journal. The existing key owner supplies the encryption
key; the database does not contain it. Transactions serialize competing writers
across instances and processes and roll back incomplete intake or deletion.

This change deliberately refuses a legacy `source-index.json` or pending index.
It does not overwrite or silently migrate existing data. An explicit, reviewed
offline migration/export procedure and backup integration are release blockers
for an existing installation. No such installation was changed in this packet.

## Validation

Synthetic unit/component tests cover encrypted original and derived content,
wrong keys, restart, concurrent sessions across threads and processes,
extraction failure after blob insertion, deletion, and preservation of legacy
files. Initial baseline tests reproduced three failures. The expanded suite plus
existing intake tests passes 15 cases locally on Windows/Python 3.12.

Supported filename extensions use the documented MIME contract so host-specific
Windows application registrations do not reinterpret CSV as an Excel format.
Content signature and declared-type checks remain in place.

## Limits and next packet

This is not whole-system encryption or private-data release approval. Other
domain/incident/resolution persistence, key custody, backup retention and
revocation, authenticated integration, power-loss qualification, disk-full
behavior and independent security review require their own evidence. SQLite
serialization is suitable for this small initial store; larger-scale indexing
and per-person cryptographic key separation remain design work.

Deleted ciphertext may remain in backups or storage-device history. This packet
does not claim secure erasure or revoke previously exported copies. The current
parser and malware fixtures remain insufficient for arbitrary real documents.
