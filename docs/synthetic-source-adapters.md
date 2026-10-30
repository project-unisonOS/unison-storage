# Synthetic source adapter reference

Status: candidate library and synthetic tests; no new public API or live intake.

`SourceWorkflow` owns consent, byte binding, encrypted source/snapshot storage,
provenance integrity, owner isolation and terminal-before-purge recovery. Its
fixed adapter registry owns interpretation: existing health JSON, synthetic
statement CSV and a bounded unfamiliar JSON document. Adding a format does not
change the lifecycle. Parsers are reviewed application code, never downloaded
or selected by model-generated executable instructions.

The statement adapter accepts only the explicit synthetic version marker,
canonical dates, integer minor currency units and three qualified currencies.
Identical IDs deduplicate; conflicting IDs fail. Totals never mix currencies.
Balance remains unknown. Unfamiliar text is retained as untrusted source evidence;
claims are empty and no obligations or actions are inferred.

Each grant binds its adapter identity and purpose as well as exact file bytes.
Every source review is recomputed from retained bytes and checked against its
saved fact digest. Health-specific field validation and presentation remain in
`health_pilot.py` / `health_source_adapter.py`; `health_workflow.py` is a compatible
entry point preserving its existing API schema, ID prefix and default-disabled gate.
The source core imports only common evidence helpers and the fixed registry.

Evidence: `pytest tests/test_source_workflow.py tests/test_health_workflow.py`.
The shared unit journey admits each synthetic format with consent, reviews
source-linked facts, revokes/deletes, restores old data bytes and verifies denial
under the current retained authority ledger. Existing authenticated health API
tests exercise the refactored implementation. The new formats are library-only;
no claim of authenticated HTTP enrollment for them is made.

Remaining gates: arbitrary/vendor formats, migrations of existing installations,
independent adapter packages/sandboxing, separate secured policy process, whole-host
or authority-ledger rollback and replacement-device key custody. Expiration denies
access; it does not schedule deletion. Physical erasure and previously disclosed
copies are not solved. No real records or financial effects are authorized.
