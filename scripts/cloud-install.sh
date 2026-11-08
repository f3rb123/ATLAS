#!/usr/bin/env bash
set -euo pipefail
cd /workspace/ATLAS
export UV_CACHE_DIR=/workspace/.cache/uv
export XDG_CACHE_HOME=/workspace/.cache
mkdir -p "$UV_CACHE_DIR" "$XDG_CACHE_HOME"
uv sync --frozen
npm ci --prefix apps/web --cache /workspace/.cache/npm
command -v bwrap >/dev/null || { echo 'Install bubblewrap before offline execution; do not weaken sandbox policy.' >&2; exit 1; }
uv run atlas host embeddings-prepare
# Secret creation, bootstrap and application migrations are explicit operator actions.
# Preserve any existing database, corpus, master key and local Git checkpoints.
