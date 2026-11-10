#!/usr/bin/env bash
set -euo pipefail
umask 077
cd /workspace/ATLAS
source scripts/cloud-dev-env.sh
mkdir -p .runtime/cloud-dev/logs
chmod 700 .runtime/cloud-dev .runtime/cloud-dev/logs
for path in .runtime/cloud-dev/atlas.db .runtime/cloud-dev/atlas.db-wal .runtime/cloud-dev/atlas.db-shm; do
    [[ ! -f "$path" ]] || chmod 600 "$path"
done
exec 9>.runtime/cloud-dev/start.lock
flock -n 9 || { echo 'Cloud development services already have a launcher; inspect local health.'; exit 0; }
.venv/bin/python - <<'PY'
import socket
for port in (8000,3000):
    with socket.socket() as s:
        try: s.bind(('127.0.0.1',port))
        except OSError: raise SystemExit(f'Port {port} is occupied; inspect its owner before starting ATLAS.')
PY
if [[ ! -f "$ATLAS_MASTER_KEY_FILE" ]]; then
    .venv/bin/atlas host init-key
fi
.venv/bin/atlas host migrate
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true' EXIT
.venv/bin/python -m uvicorn atlas.api:app --host 127.0.0.1 --port 8000 --no-access-log >.runtime/cloud-dev/logs/api.log 2>&1 & pids+=("$!")
.venv/bin/python -m atlas.worker research >.runtime/cloud-dev/logs/research.log 2>&1 & pids+=("$!")
.venv/bin/python -m atlas.worker verify >.runtime/cloud-dev/logs/verify.log 2>&1 & pids+=("$!")
.venv/bin/python -m atlas.corpus_worker >.runtime/cloud-dev/logs/corpus.log 2>&1 & pids+=("$!")
(cd apps/web && exec node node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port 3000) >.runtime/cloud-dev/logs/web.log 2>&1 & pids+=("$!")
printf '%s\n' "${pids[@]}" >.runtime/cloud-dev/pids
ready=0
for attempt in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8000/health/ready >/dev/null 2>&1 && curl -fsS http://localhost:3000 | rg -q ATLAS; then
        ready=1; break
    fi
    sleep 1
done
[[ "$ready" == 1 ]] || { echo 'Startup failed; inspect .runtime/cloud-dev/logs.' >&2; exit 1; }
echo 'API database readiness and rendered web response verified. Services stay attached to this launcher.'
.venv/bin/python - <<'PY'
from atlas.db import session, Document
from atlas.knowledge import availability
with session() as db:
    state = availability(db, "public")
    providers = db.query(Document).filter_by(kind="provider").count()
    print(f"Knowledge: {state['status']}; {state['visible_records']} records / {state['active_chunks']} active chunks; {providers} configured providers.")
    print("Startup preserves existing data and keys. Provider acceptance and deployment evidence are recorded separately.")
PY
wait -n "${pids[@]}"
