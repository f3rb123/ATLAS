# ATLAS V3

Private, evidence-driven vulnerability research workbench. Next.js Web UI and Python CLI share an authenticated FastAPI backend, PostgreSQL/pgvector state, durable workers, deterministic scope relay, encrypted provider gateway and independent verifier.

This repository was built from an empty checkout. Read [the specification](docs/SPECIFICATION.md), [build log](docs/BUILD_LOG.md), [requirement ledger](docs/IMPLEMENTATION_GAP_ANALYSIS.md) and [current resume point](docs/NEXT_ACTION.md) for evidence and remaining work. Historical tests and historical seed-library counts are not claimed as delivered artifacts.

## Local development

```sh
UV_CACHE_DIR=/workspace/.cache/uv uv sync --frozen
uv run atlas host init-key
uv run atlas host migrate
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

The acquired public corpus contains **21,002 unique normalized records**: 21,001 structured advisory/CVE records and one OWASP reference. Full-text bounty-report count is **0**. These counts are from persisted records, not chunks or aliases. See [the acquisition report](docs/CORPUS_INGESTION_REPORT.md) and [inventory](knowledge/corpus_inventory.json). NVD/OSV/CISA connections require the network-policy changes described in the report; source terms must permit storage.

```sh
uv run atlas host corpus-sync --source ghsa --limit 21000
uv run atlas host corpus-validate
```

The API-backed `atlas corpus` commands support source/job management, import, validate, duplicate review, indexing, stats and exports. Use scoped, expiring CLI tokens generated after WebAuthn step-up; never pass keys/passwords on command lines. Provider creation and rotation use protected prompts. See [CLI/API documentation](docs/API.md).

## Validation and deployment

```sh
uv run pytest -q -m 'not sandbox'
uv run pytest -q -m sandbox
npm --prefix apps/web run build
```

Sandbox tests need Linux user namespaces. The cloud command wrapper forbids nested setup; the actual outer host and configured Docker runner are tested separately. All tests use synthetic local fixtures and mock model providers, never live targets.

[Deployment](docs/DEPLOYMENT.md), [operations](docs/OPERATIONS.md), [authentication and secrets](docs/AUTHENTICATION_AND_SECRETS.md), and [backup/restore](docs/BACKUP_RESTORE.md) cover the Ubuntu VPS assets. No real VPS deployment, SSH/firewall change, or live assessment is authorized by this build.
