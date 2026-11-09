#!/usr/bin/env bash
# Disposable CI fixture databases only. Never run against an application database.
set -euo pipefail
cd "$(dirname "$0")/.."
export UV_CACHE_DIR=${UV_CACHE_DIR:-/tmp/atlas-uv-cache}
export ATLAS_EMBEDDING_MODEL=hash
export ATLAS_DATA_DIR=.runtime/ci-source-data
export ATLAS_DATABASE_URL=sqlite:///.runtime/ci-source.db
export ATLAS_MASTER_KEY_FILE=.runtime/ci-master.key
export ATLAS_EXTERNAL_URL=http://localhost:3000
export ATLAS_PROVIDER_LOCAL_ALLOWLIST='["127.0.0.1:9001"]'
export ATLAS_E2E_MIN_RECORDS=1
.venv/bin/python - <<'PY'
import socket
for port in (8000,3000,9001):
    with socket.socket() as s:
        try: s.bind(('127.0.0.1',port))
        except OSError: raise SystemExit(f'Fixture port {port} is occupied; inspect its owner before starting the test.')
PY
[ ! -f .runtime/ci-source.db ] && [ ! -f .runtime/e2e.db ] || { echo 'Disposable CI databases already exist; refusing replacement.' >&2; exit 1; }
mkdir -p .runtime
uv run python - <<'PY'
import os
from pathlib import Path
from atlas.db import Base,engine,session
from atlas.corpus import import_file
Base.metadata.create_all(engine())
p=Path('.runtime/ci-master.key');p.write_bytes(os.urandom(32));p.chmod(0o600)
p=Path('.runtime/ci-reference.md');p.write_text('# CI training fixture\nTenant authorization enforces ownership boundaries. Synthetic reference only.\n')
with session() as db:
    import_file(db,p,'MIT','atlas:ci-authored','training_reference',owner='public');db.commit()
PY
uv run python scripts/prepare-e2e.py
export ATLAS_DATABASE_URL=sqlite:///.runtime/e2e.db
export ATLAS_DATA_DIR=.runtime/e2e-data
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT
uv run uvicorn atlas.api:app --host 127.0.0.1 --port 8000 --no-access-log > .runtime/ci-api.log 2>&1 & pids+=("$!")
uv run python tests/e2e_provider.py > .runtime/ci-provider.log 2>&1 & pids+=("$!")
uv run python -m atlas.worker research > .runtime/ci-research.log 2>&1 & pids+=("$!")
uv run python -m atlas.worker verify > .runtime/ci-verify.log 2>&1 & pids+=("$!")
(cd apps/web && exec node node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port 3000) > .runtime/ci-web.log 2>&1 & pids+=("$!")
ready=0
for attempt in $(seq 1 30); do
  if curl -fsS http://localhost:8000/health/live >/dev/null 2>&1 && curl -fsS http://localhost:3000 >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] && kill -0 "${pids[@]}" || { echo 'Fixture services failed to start; inspect .runtime/ci-*.log' >&2; exit 1; }
npm run test --prefix apps/web
