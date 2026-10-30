# Bounded storage operation authority

Status: synthetic-development candidate. Not a production or real-data release.

Every FastAPI application route has a global operation dependency. Health,
readiness and metrics are public; private operations require an authenticated,
active person with storage audience and the exact scope in
`src/storage_authority.py`. There are no wildcard, household-admin or implicit
write grants. JSON identity hints are checked independent of content type.

The synthetic brief token carries `storage.health.read`, plus the orchestrator's
`wellness.read` and `wellness.present` scopes. Storage accepts that read scope
only for GET `/v1/domain/records?domain=health`, with exactly one domain parameter.
It cannot import, admit, create, correct, delete or enumerate other domains.

Ingestion is separate: `storage.import.start`, `storage.import.upload`,
`storage.import.admit`, and `storage.domain.create`. Source listing and deletion
require `storage.sources.read` and `storage.sources.delete` respectively.
Rollback and correction have separate scopes. Namespaced KV, memory, objects,
vault and audit operations also require distinct explicit scopes.

Unmapped routes deny by default. In particular, legacy domain packages,
connection/OAuth fixtures and incident workflows are unavailable to authenticated
callers until their operation/reference contracts are separately qualified. This
is a deliberate compatibility restriction, not a claim those workflows shipped.
Existing legacy tests using the explicit principal test bypass remain isolated
fixture evidence. That bypass must never be enabled in a deployment.

## References and transaction boundary

Canonical domain creation requires nonempty, unique source IDs owned by the bound
person and in admitted state. The source SQLite transaction stays locked through
the domain commit, preventing concurrent deletion between validation and write.
The lock order is source then domain; readers release their domain read transaction
before validating references under the source lock.

Admission checks source/session lifecycle, ownership, session association,
decryption integrity, byte length and SHA-256 before changing any source state.
Rejected and rolled-back sessions are terminal; deleted source IDs cannot regain
admission. Valid intact admission replay remains idempotent. A new import is
required after rejection, even if bytes are later repaired. Reference checks also
verify source bytes, so an admitted metadata flag alone cannot authorize a record.

Canonical domain reads validate all referenced sources. If source deletion commits
but the separate domain cascade fails, subsequent reads fail closed (409), including
after restart. This prevents that canonical API from returning orphaned records.
It does not make the two databases atomic, physically erase orphaned ciphertext,
or validate backup/recovery across both databases. Those remain release gates.
Other domain workflows are denied rather than offering an alternate derivative
read path. Domain-store unit methods are not themselves an authenticated API.

Reference validation does not prove supplied facts were extracted from source
bytes. The synthetic harness still posts facts manually. Verified extraction,
consent, independent policy, all derivative stores and model qualification remain
separate work. No new grants are issued by this change; callers must obtain the
appropriate existing issuer-approved scopes.

## Evidence

`tests/test_storage_authority.py` uses real signed synthetic identities and a
loopback JWKS/introspection service, with no principal bypass. It covers every
mutation route with a health-reader token, distinct admission/read grants,
missing/expired/wrong-audience/workload/wildcard authority, direct revocation,
invalid source states, malformed references, alternate JSON identity hints,
restart after an interrupted cascade, and simultaneous create/delete locking.
Component and workspace CI are recorded in the implementation checkpoint.

## Synthetic export pilot candidate

See [synthetic export prerequisite contract](synthetic-export-pilot.md) for the
separate default-disabled consent/extraction API and deletion outbox. These do
not upgrade legacy manually posted records to verified pilot evidence.
