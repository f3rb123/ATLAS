#!/usr/bin/env bash
set -euo pipefail
cd /workspace/ATLAS
export UV_CACHE_DIR=/workspace/.cache/uv
export XDG_CACHE_HOME=/workspace/.cache
mkdir -p "$UV_CACHE_DIR" "$XDG_CACHE_HOME"
uv sync --frozen
python3 scripts/install-research-tools.py --destination /workspace/ATLAS/.runtime/research-tools --tools httpx katana nuclei ffuf subfinder dnsx naabu gau waybackurls
npm ci --prefix apps/web --cache /workspace/.cache/npm
command -v bwrap >/dev/null || { echo 'Install bubblewrap before offline execution; do not weaken sandbox policy.' >&2; exit 1; }
npm run build --prefix apps/web
uv run python - <<'PY'
from atlas.embeddings import verify_model
try:
    verify_model()
    print('Pinned semantic assets verified.')
except ValueError:
    print('Semantic assets are not ready. After approved Hugging Face access, run: uv run atlas host embeddings-prepare')
    print('The original corpus is not included; no data was recreated or re-embedded.')
PY
# Real semantic readiness is a separate acceptance gate, never a hash-mode claim.
# Preserve any existing database, corpus, master key and local Git checkpoints.
