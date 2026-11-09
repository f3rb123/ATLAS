# ATLAS V3

Current rebuild: [audit](ATLAS_V3_FULL_AUDIT.md), [research](ATLAS_V3_REFERENCE_RESEARCH.md), [implementation ledger](ATLAS_V3_IMPLEMENTATION_LEDGER.md), [handoff](ATLAS_HANDOFF.md).
The supplied release has been restored with a shared knowledge harness, SQL-backed concurrent specialist tasks and live persisted visibility. Default new runs use eight roles; legacy runs remain supported. Password-only private operator access is the default; enrolled factors remain enforced, and `ATLAS_REQUIRE_MFA=true` enables the stricter enrollment policy.

**The historical corpus and embedding assets were not delivered.** Counts below describe the previous release environment, not this checkout. Do not treat local synthetic/hash-mode tests as original-corpus or real-model validation. Full rebuild/deployment remains in progress.

Cloud development: run `bash scripts/cloud-install.sh`, then `bash scripts/cloud-start.sh`. The launcher creates only isolated `.runtime/cloud-dev` state, preserves existing keys and applies additive migrations. In an interactive terminal, source `scripts/cloud-dev-env.sh` before `uv run atlas host bootstrap`; never put the token or provider secrets in chat. Semantic setup remains a separate required gate once download access is available.

Private, evidence-driven vulnerability research workbench. Next.js Web UI and Python CLI share an authenticated FastAPI backend, PostgreSQL/pgvector state, durable workers, deterministic scope relay, encrypted provider gateway and independent verifier.

This repository was built from an empty checkout. Read [the specification](docs/SPECIFICATION.md), [build log](docs/BUILD_LOG.md), [requirement ledger](docs/IMPLEMENTATION_GAP_ANALYSIS.md) and [current resume point](docs/NEXT_ACTION.md) for evidence and remaining work. Historical tests and historical seed-library counts are not claimed as delivered artifacts.

## Local development

```sh
UV_CACHE_DIR=/workspace/.cache/uv uv sync --frozen
uv run atlas host init-key
uv run atlas host migrate
uv run atlas host embeddings-prepare
uv run uvicorn atlas.api:app --host 127.0.0.1 --port 8000 --no-access-log
```

In separate terminals:

```sh
uv run python -m atlas.worker research
uv run python -m atlas.worker verify
uv run python -m atlas.corpus_worker
cd apps/web
npm ci
npm run dev
```

Set `ATLAS_EXTERNAL_URL=http://localhost:3000` for the API/worker processes when using the Web UI on port 3000. The default master key path is `.runtime/master.key`; generate once, never overwrite it, and never put it in Git. `atlas host bootstrap` prints a short-lived single-use token only to an interactive terminal. Use it in the first-owner form, set a unique long passphrase, enroll passkeys, TOTP and offline recovery codes. No public signup or default account exists.

SQLite is an isolated development/test option. Production uses PostgreSQL with migrations. Redis is transient coordination; workflow state and journals survive Redis loss. Production workers receive service-specific tokens and do not receive the provider KEK. Source acquisition has a separate worker and network.

## Corpus

The acquired public corpus contains **21,012 unique normalized records**: 21,011 structured advisory/CVE records and one OWASP reference. Full-text bounty-report count is **0**. These counts are from persisted records, not chunks or aliases. See [the acquisition report](docs/CORPUS_INGESTION_REPORT.md) and [inventory](knowledge/corpus_inventory.json). The complete public corpus has34,229genuine MiniLM384 semantic chunks. NVD/OSV and the official CISA mirror were acquired successfully; source terms govern subsequent imports.

```sh
uv run atlas host corpus-sync --source ghsa --limit 21000
uv run atlas host corpus-validate
```

The API-backed `atlas corpus` commands support source/job management, import, validate, duplicate review, indexing, stats and exports. Use scoped, expiring CLI tokens generated after WebAuthn step-up; never pass keys/passwords on command lines. Provider creation and rotation use protected prompts. See [CLI/API documentation](docs/API.md).

## Validation and deployment

```sh
uv run pytest -q
npm --prefix apps/web run build
```

Sandbox tests need Linux user namespaces. The cloud command wrapper forbids nested setup; the actual outer host and configured Docker runner are tested separately. Target-facing tests use controlled local services and test-only mock model providers; semantic and corpus validation use the actual acquired public data. No live targets were scanned.

[Deployment](docs/DEPLOYMENT.md), [operations](docs/OPERATIONS.md), [authentication and secrets](docs/AUTHENTICATION_AND_SECRETS.md), and [backup/restore](docs/BACKUP_RESTORE.md) cover the Ubuntu VPS assets. No real VPS deployment, SSH/firewall change, or live assessment is authorized by this build.
