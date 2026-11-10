#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
destination=${1:?Usage: scripts/backup.sh NEW_BACKUP_DIRECTORY}
python_bin=.venv/bin/python
if [ ! -x "$python_bin" ]; then python_bin=python; fi
mkdir -p "$(dirname "$destination")"
mkdir -m700 "$destination"
scripts/compose.sh exec -T postgres pg_dump -U atlas -d atlas -Fc | "$python_bin" -m atlas.backup encrypt --password-file .runtime/secrets/backup_password > "$destination/database.atlasenc"
scripts/compose.sh exec -T api tar -C /data -cf - . | "$python_bin" -m atlas.backup encrypt --password-file .runtime/secrets/backup_password > "$destination/artifacts.atlasenc"
scripts/compose.sh exec -T api tar -C /targetkeys -cf - . | "$python_bin" -m atlas.backup encrypt --password-file .runtime/secrets/backup_password > "$destination/target-key.atlasenc"
git rev-parse HEAD > "$destination/commit.txt"
printf '%s\n' 'Encrypted backup completed. Keep backup password and KEK separately/off-host.'
