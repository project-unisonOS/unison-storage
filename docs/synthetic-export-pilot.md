# Synthetic export-first health prerequisite contract

Status: implementation candidate; synthetic fixtures only. This is not enrollment
or permission to supply personal records. `UNISON_SYNTHETIC_HEALTH_PILOT=true`
explicitly enables the separate API; it is disabled by default.

## Authority and scope

The bounded pilot accepts one or two owned admitted JSON sources, at most 1 MiB
and 500 rows per source. It supports only sleep duration (minutes) and steps
(count), retaining measurement, score, statement and inference distinctions.
No wearable/clinical export compatibility, OAuth, inference or treatment is implied.
The synthetic marker is a contract assertion, not a detector of real personal data.

Signed person scopes are necessary but insufficient. The storage reference
monitor independently checks durable owner consent, fixed `wellness.summary`
purpose, `synthetic-health-policy.v1`, expiration and source integrity at extraction,
read and presentation checks. An explicit confirmed grant expires within 14 days;
revocation persists across process restart and cannot be reversed on that grant.
A new grant requires a fresh explicit owner operation. Household administrators
and models have no implicit authority. There is no consent decision cache.

- `storage.health.consent`: create/revoke owner consent.
- `storage.health.extract`: extract the specified admitted source under consent.
- `storage.health.pilot.read`: read and recheck presentation authority.
- Existing import scopes govern quarantine/admission; they do not confer pilot use.
- Existing manual domain records are not pilot evidence and are never a fallback.

The policy is independent of model decisions but runs inside storage's trust
boundary. It is not a separately deployed policy service or protection against
an unlocked host compromise. Network delivery after the final check is not an
atomic revocation transaction; no remote delivery channel is qualified here.

## Routes and extraction

`POST /v1/health-pilot/consents` accepts exactly `source_ids`, `purpose`,
`confirmed` and `expires_at`. `DELETE /v1/health-pilot/consents/{grant_id}` revokes.
`POST /v1/health-pilot/sources/{source_id}/extract` accepts only `grant_id`.
`GET /v1/health-pilot/records?grant_id=...` returns regenerated verified facts.
`POST /v1/health-pilot/authorize` accepts `grant_id` and `read` or `present` action.

`src/health_pilot.py` owns the strict `synthetic-health-export.v1` schema. Unknown
fields, duplicate JSON keys, conflicting revisions, non-finite values, mixed units,
missing-as-zero and unbound identities are rejected. Timezone, source day and
measurement interval remain explicit. Each fact retains the original row, upstream
identifier, source/device/method, quality, missingness, revision and ingestion time.
Provenance binds the original blob SHA-256, JSON row pointer, parser version and
canonical fact SHA-256. Extraction reads stored bytes; callers cannot post facts.
An encrypted receipt is committed in the source database. Reads reparse immutable
bytes and verify the receipt. This proves derivation from the admitted fixture,
not that a vendor measurement is true or clinically accurate.

## Deletion and recovery

Source deletion atomically removes encrypted source bytes, extracted fields and
pilot receipts and writes a durable pending cascade job in source SQLite. Existing
domain derivatives are removed separately by an idempotent cascade. Tombstones
remain terminal. Rollback of an import uses the same outbox. Lock order is source
then domain. Source invalidation prevents canonical orphan disclosure immediately.

A successful deletion response means its requested cascade completed. If interrupted,
restart and call `POST /v1/sources/recover-deletions` with the owner's
`storage.sources.delete` scope; retries are idempotent and return a completion count.
A crash after domain commit but before journal completion safely repeats cleanup.
Do not report deletion success merely because source bytes disappeared.

This is recoverable two-store deletion, not a distributed atomic transaction.
Encrypted tombstone/consent metadata remains. External exports, device caches,
backups, filesystem remnants, other derivative stores and a full state rollback
are not erased or qualified by this outbox. Backup restore must not resurrect
revoked consent or deleted records; an independent revocation/retention design is
still a live-data blocker.

## Acceptance evidence

`tests/test_health_pilot.py` uses signed identities and loopback introspection.
It exercises source extraction and restart, expiry/revocation/version/purpose,
wrong-person and wrong-scope denial, malformed exports, damaged bytes/receipts,
concurrent extraction/deletion, rollback and failure before/after domain commit.
The workspace's `test_export_health_pilot.py` checks actual ASGI intake through a
brief, with no manual fact insertion, and revokes between read and presentation.
All fixtures are synthetic. Hosted CI is not physical power-loss evidence.
