#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/prepare-secrets.py
docker compose run --rm init
docker compose up -d
docker compose exec api atlas host bootstrap
