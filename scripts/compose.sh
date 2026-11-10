#!/usr/bin/env bash
# The owner's raw .env credential file is never parsed as Compose configuration.
set -euo pipefail
exec docker compose --env-file "${ATLAS_COMPOSE_ENV_FILE:-/dev/null}" "$@"
