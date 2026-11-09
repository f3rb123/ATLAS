# ATLAS V3 build state

The Section 21.0 implementation is complete for the scope supported by this workspace. Continue only if resuming delivery, incorporating owner-supplied inputs, or making a reviewed product change. Do not deploy to a real VPS or scan live targets without explicit owner approval.

## Verified locally

- Greenfield Python/FastAPI, PostgreSQL/pgvector, Redis workers, Next.js Web UI, API-backed CLI, provider gateway, strong owner authentication, encrypted secret handling, durable research FSM, independent verifier, sandbox, reports, and Ubuntu Compose/TLS/backup assets are implemented.
- Public corpus: 21,012 unique records, 39,985 aliases, 34,229 pinned MiniLM vectors; 21,011 structured advisories and one training/reference item. Full-text bounty reports and patch-only records: zero. All 491 legacy excluded GHSA items were reviewed as upstream withdrawals; there are no unresolved parser/import errors.
- Full backend suite: 86 passed, one upstream Starlette/httpx deprecation warning. The KEV connector now stores an immutable native-ID manifest and resumes safely when a later feed reorders or removes entries.
- Browser workflow and clean disposable CI E2E passed; accessibility checks recorded zero axe violations on the welcome and corpus-memory screens. Docker PostgreSQL workflow restart, real sandbox, pinned-model inference, database/vector/raw-artifact validation, staging TLS, and authenticated encrypted backup/restore were also verified.
- Latest local Docker image matches all 35 Python source modules. Health check is 200, protected campaign API is 401 without a session, and readiness remains 503 until the owner enrolls.

## Local delivery and external inputs

- See [DELIVERY.md](DELIVERY.md), [validation evidence](test-results/VALIDATION.md), [implementation ledger](IMPLEMENTATION_GAP_ANALYSIS.md), [corpus report](CORPUS_INGESTION_REPORT.md), and [security review](SECURITY_REVIEW.md).
- The public corpus archive is in ignored `.runtime/delivery/atlas-v3-public-corpus.tar.gz`. A Git bundle and SHA256SUMS are prepared at final handoff; no remote push is authorized or performed.
- The initial cloud setup draft (revision 3) was previously confirmed saved with tested install/start instructions and existing repository/network settings preserved. The cloud settings service denied access when reread in this session; its current state could not be safely verified or updated. The draft still requires review/save/publish in environment settings before those saved instructions take effect.
- The exact historical 64/67-resource list and its rights, provider credentials, and real domain/VPS details were not supplied. Advanced mobile/cloud/fuzzing/state-changing adapters remain disabled. The corpus has no full-text bounty reports. These are recorded product boundaries, not fabricated completion claims.
- The Git remote remains unchanged and may still point to an empty original `main`; local commits are recoverable from the delivery bundle. The main SQLite and Docker PostgreSQL databases contain the public corpus and no owner account or private campaign.
