# Backup and restore

From the activated development environment or an application management environment containing cryptography:

```sh
scripts/backup.sh .runtime/backups/manual-check
scripts/restore-check.sh .runtime/backups/manual-check
```

Backups include a PostgreSQL custom-format dump, the /data artifact volume and source commit metadata. They do not include /master, /research, /verify or database-password volumes. Each stream uses scrypt-derived keys and framed AES-GCM, including a final authenticated marker so truncation fails. Files are created under umask 077. Keep the randomly generated backup password off-host separately, and store KEKs outside backup archives in a protected password manager/offline system.

Restore-check authenticates both archives into a restricted temporary directory, restores into the isolated atlas_restore_check database, checks migration metadata and artifact archive integrity, then drops only that temporary database. It never overwrites the application database. Failed checks exit nonzero. Test wrong passwords, corruption and truncated archives; do not pipe unverified decrypted data directly into a production restore.

For disaster recovery, stop workers/API, restore the verified database to a clean PostgreSQL instance with pgvector, restore artifacts with UID10001 ownership, separately restore the matching KEK and service secrets, apply reviewed migrations and run doctor before resuming. Preserve run policy/model/skill versions. Resume only explicitly approved work; queued target traffic must remain disabled during recovery.

Define retention for public corpus, private campaign data and backups. Keep at least one verified off-host backup and test restoration regularly. Rotate provider keys after suspected compromise; rewrapping DEKs does not revoke a stolen provider key. Old backups require their old KEK. Host disk encryption is an operator prerequisite, not a property inferred from Docker volumes.
