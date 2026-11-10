#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/prepare-secrets.py
scripts/compose.sh run --rm init
scripts/compose.sh up -d
scripts/compose.sh exec api atlas host bootstrap
