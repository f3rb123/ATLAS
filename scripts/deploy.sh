#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env.production ] || { echo 'Create .env.production from its example and review the deployment guide.' >&2; exit 1; }
python3 scripts/prepare-secrets.py
scripts/compose.sh --env-file .env.production -f compose.yaml -f compose.production.yaml config --quiet
scripts/compose.sh --env-file .env.production -f compose.yaml -f compose.production.yaml build
scripts/compose.sh --env-file .env.production -f compose.yaml -f compose.production.yaml up -d
