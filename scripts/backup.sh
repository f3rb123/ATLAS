#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
destination=${1:?Usage: scripts/backup.sh NEW_BACKUP_DIRECTORY}
mkdir -p "$(dirname "$destination")"
mkdir -m700 "$destination"
docker compose exec -T postgres pg_dump -U atlas -d atlas -Fc | python -m atlas.backup encrypt --password-file .runtime/secrets/backup_password > "$destination/database.atlasenc"
docker compose exec -T api tar -C /data -cf - . | python -m atlas.backup encrypt --password-file .runtime/secrets/backup_password > "$destination/artifacts.atlasenc"
git rev-parse HEAD > "$destination/commit.txt"
printf '%s\n' 'Encrypted backup completed. Keep backup password and KEK separately/off-host.'
