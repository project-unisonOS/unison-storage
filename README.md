# unison-storage

The storage service manages data for Unison.

Responsibilities (future):
- Ephemeral working memory for the orchestrator.
- Long-term personal memory with encryption and delete-on-request.
- Secret vault for credentials and payment tokens.
- Audit log of high-impact actions.

Current state:
- Minimal HTTP service with `/health` and `/ready`.
- Containerized for inclusion in `unison-devstack`.
