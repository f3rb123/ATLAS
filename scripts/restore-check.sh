#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
backup=${1:?Usage: scripts/restore-check.sh BACKUP_DIRECTORY}
python_bin=.venv/bin/python
if [ ! -x "$python_bin" ]; then python_bin=python; fi
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT
"$python_bin" -m atlas.backup decrypt --password-file .runtime/secrets/backup_password < "$backup/database.atlasenc" > "$scratch_dir/database.dump"
"$python_bin" -m atlas.backup decrypt --password-file .runtime/secrets/backup_password < "$backup/artifacts.atlasenc" > "$scratch_dir/artifacts.tar"
if [ -f "$backup/target-key.atlasenc" ]; then
  "$python_bin" -m atlas.backup decrypt --password-file .runtime/secrets/backup_password < "$backup/target-key.atlasenc" > "$scratch_dir/target-key.tar"
  # Validate in memory; never extract or display the encryption key.
  "$python_bin" - "$scratch_dir/target-key.tar" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    entries = [entry for entry in archive if entry.name in ("target_key", "./target_key")]
    if len(entries) != 1 or not entries[0].isfile() or entries[0].size != 32:
        raise SystemExit("Target key backup has an invalid structure")
PY
else
  printf '%s\n' 'Historical backup has no target-key archive; target identities are not covered.' >&2
fi
# Restore only into an isolated temporary database, never the application database.
scripts/compose.sh exec -T postgres createdb -U atlas atlas_restore_check
trap 'scripts/compose.sh exec -T postgres dropdb -U atlas --if-exists atlas_restore_check; rm -rf "$scratch_dir"' EXIT
scripts/compose.sh exec -T postgres pg_restore -U atlas -d atlas_restore_check --exit-on-error < "$scratch_dir/database.dump"
scripts/compose.sh exec -T postgres psql -U atlas -d atlas_restore_check -c 'SELECT version_num FROM alembic_version; SELECT count(*) FROM documents; SELECT count(*) FROM knowledge; SELECT count(*) FROM knowledge_chunks;'
tar -tf "$scratch_dir/artifacts.tar" >/dev/null
printf '%s\n' 'Authenticated archives verified and PostgreSQL restore passed. KEK not included.'
