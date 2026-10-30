# Synthetic health export experience contract

Status: candidate, disabled by default, synthetic records only. Entry point is the
renderer browser experience at `/static/health-export.html`, not a command-line UI.

## Before intake

The person selects one `synthetic-health-export.v1` JSON file and explicitly permits
upload, private retention, review and descriptive summary for 24 hours. Before any
content upload, the backend records owner, exact file SHA-256/size, purpose, expiry
and policy version. Upload without that consent, after termination, or with different
bytes fails. Existing general imports and old pilot routes do not become this workflow.
The workflow has its own isolated data root and operation-specific scopes.

## Facts and derivatives

Reuse the strict parser from `health_pilot.py`. Units, original timezone/date,
missingness, row identity and conflicting revisions are checked before storage.
Identical rows are deduplicated. The original export is encrypted; facts are
regenerated from it with source hash, row pointer, parser version and fact hash.
The summary reports the latest measurement for each supported metric with source
links. It does not infer health significance, blend scores or replace unknown with zero.

Affected derivatives are the encrypted source, extraction receipt, generated facts
and summary, scoped encrypted snapshots, HTTP responses and browser display.
No graph, domain record, model memory, external service or analytics copy is written.
API responses use no-store. Browser health data is not persisted in web storage;
only opaque workflow/snapshot IDs and the existing session token are referenced.
Revoke/delete clears the display, source, receipt and retained workflow snapshots.
Minimal encrypted owner/terminal authority remains; file metadata is removed.
Already disclosed content, screenshots and external copies cannot be recalled.

## Restore boundary

`HealthWorkflow` locks a separate encrypted authority ledger before data operations.
Its configured path must be outside the workflow data root. HTTP routes never create
or replace that ledger. Fixture provisioning uses `initialize_authority` explicitly.
Missing, corrupt, expired or incompatible authority fails closed.

Workflow backups exclude the authority ledger. Revoke/delete commits terminal
authority before purging data; a crash between those commits still denies access.
Retries finish cleanup. Restoring actual old workflow SQLite bytes does not restore
permission. The restore operation checks retained authority first and purges stale
content instead of reactivating it. A valid active consent is a positive restore control.

This is single-host, authority-retaining workflow restore, not whole-appliance or
distributed rollback protection. Restoring the authority ledger itself, losing it on
replacement hardware, key compromise, filesystem remnants and arbitrary access to
an unlocked process remain unsolved. Existing BackupService device recovery is not
silently upgraded. Real data remains blocked until a trusted authority checkpoint/
revocation custody design and recovery ceremony are independently qualified.

## Experience and testing

The optional browser surface uses labelled controls, keyboard operation, live status,
source disclosures, textual uncertainty, responsive wrapping and forced-color support.
There is no model, background polling, or automatically enabled audio. It clears facts
on local termination, failed reads, visibility changes and page restoration. Cross-device
push revocation and native voice/Braille composition are not claimed; every new action
revalidates authority. Participatory accessibility testing remains open.

Storage tests include consent-before-upload, invalid exports, duplicate/missing rows,
wrong person/scope, lost authority, interrupted deletion and actual old-data restoration.
The workspace browser test exercises renderer HTTP with signed identities and real
encrypted storage, connected by an in-process upstream transport. It covers mobile/
desktop widths, forced colors, keyboard controls, 200% text, source links and both revoke
and delete followed by restoring old encrypted bytes. These are software tests, not
physical power-loss or operational deployment evidence.
