#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
backup=${1:?Usage: scripts/restore-check.sh BACKUP_DIRECTORY}
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT
python -m atlas.backup decrypt --password-file .runtime/secrets/backup_password < "$backup/database.atlasenc" > "$scratch_dir/database.dump"
python -m atlas.backup decrypt --password-file .runtime/secrets/backup_password < "$backup/artifacts.atlasenc" > "$scratch_dir/artifacts.tar"
# Restore only into an isolated temporary database, never the application database.
docker compose exec -T postgres createdb -U atlas atlas_restore_check
trap 'docker compose exec -T postgres dropdb -U atlas --if-exists atlas_restore_check; rm -rf "$scratch_dir"' EXIT
docker compose exec -T postgres pg_restore -U atlas -d atlas_restore_check --exit-on-error < "$scratch_dir/database.dump"
docker compose exec -T postgres psql -U atlas -d atlas_restore_check -c 'SELECT version_num FROM alembic_version; SELECT count(*) FROM documents;'
tar -tf "$scratch_dir/artifacts.tar" >/dev/null
printf '%s\n' 'Authenticated archives verified and PostgreSQL restore passed. KEK not included.'
