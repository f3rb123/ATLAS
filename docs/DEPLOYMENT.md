# Ubuntu VPS controlled deployment

This guide is for an operator who has reviewed the private `f3rb123/ATLAS` repository and its release assets. No deployment to an owner VPS has been performed. Keep first access on Tailscale or WireGuard. Do not enable public ingress until owner enrollment, passkey/MFA recovery, TLS, provider policy and backups have been checked.

## Host prerequisites and hardening

Use a supported Ubuntu LTS release (22.04 or 24.04), x86-64, at least 4 vCPU, 8 GiB RAM and 80 GiB SSD. Use encrypted host storage, current security updates, accurate time, and a named non-root sudo account with SSH public-key authentication. Keep a second verified SSH session open before changing SSH or firewall rules. Do not add the operator to the `docker` group; Docker access is root-equivalent, so the commands below use `sudo`.

Install Docker Engine and the Compose plugin from Docker's official Ubuntu repository:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl ufw unattended-upgrades
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker compose version
```

Install the pinned project dependencies for the host-side backup/restore utilities. Application services themselves run in Compose:

~~~sh
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv sync --locked --no-dev
~~~

Install and enroll Tailscale using its official instructions, then restrict the tailnet with its ACL/device approval controls. For WireGuard, substitute the actual interface and private address below. Do not expose PostgreSQL, Redis, worker or gateway ports. Docker-published ports can bypass UFW forwarding rules; binding the only published HTTPS port to the VPN interface is the primary boundary.

```sh
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
sudo tailscale ip -4
sudo tailscale status
```

If SSH is available only through the VPN, configure host/cloud firewall policy to allow SSH and HTTPS on the VPN interface. Verify a second connection before enabling UFW or applying the supplied SSH drop-in. Review `infra/ubuntu/sshd-atlas.conf`, run `sudo sshd -t`, and reload SSH only after confirming that the current account and key remain allowed. Never rely on UFW alone to restrict a Docker-published service.

## Clone the private release

Authorize GitHub access with an SSH deploy key limited to read-only access to this repository, or use `gh auth login` interactively. Never place a personal access token in a clone URL, shell history, source file or log. Then clone the repository and check out the release tag:

```sh
git clone git@github.com:f3rb123/ATLAS.git atlas
cd atlas
git checkout v3.0.0-rc1
git status --short
git rev-parse --short HEAD
```

The expected short commit is recorded in the GitHub release notes. The repository includes migrations, Compose files, tests, research ingestion and the public corpus conversion scripts. The database and runtime data are not in Git.

## Private HTTPS and production environment

Choose the VPS's Tailscale IPv4 address (or WireGuard interface address) and its private DNS name. With Tailscale, use the machine's MagicDNS name. Set `ATLAS_BIND_IP` to that interface address, `ATLAS_HOST` to the matching DNS name, and `ATLAS_EXTERNAL_URL` to `https://` plus that exact hostname. Do not use a public address or public DNS name for the initial test.

```sh
cp .env.production.example .env.production
chmod 600 .env.production
sudoedit .env.production
```

Keep provider allowlists narrow and empty until you have chosen the provider. Provider API credentials are registered later through the authenticated Settings UI; never put them in `.env.production`. Generate the local service secrets without printing or overwriting existing values:

```sh
python3 scripts/prepare-secrets.py
chmod 700 .runtime/secrets
chmod 600 .runtime/secrets/*
```

The script creates a 256-bit encryption master key and separate service/database/backup credentials. Back up `.runtime/secrets/master_key` through a protected offline process and keep its recovery copy separately from encrypted database backups. Losing this key makes encrypted provider secrets unrecoverable. Do not paste it into a prompt, ticket or shell command. Keep `.env.production` and `.runtime/secrets` out of Git and preserve them across upgrades.

Validate and start the VPN-only stack. The private override binds only port 443 to `ATLAS_BIND_IP` and uses Caddy's internal CA; the public production Caddy config is replaced for this mode.

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml config --quiet
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml build
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml up -d
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml ps
```

The one-shot init service applies Alembic migrations and prepares restricted volumes. Application services use the non-superuser `atlas_app` database role; init has the separate migration credential. Confirm the proxy listens only on the selected private address:

```sh
sudo ss -lntp
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec api atlas version
```

Caddy stores its internal CA in the protected `caddy_data` Docker volume. Export only the public root certificate, verify its SHA256 fingerprint over a separate trusted channel, and import that certificate into the testing computer's OS/browser trust store. Never export the CA private key. Keep the resulting test URL on the private network: `https://$ATLAS_HOST`.

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec -T proxy cat /data/caddy/pki/authorities/local/root.crt > atlas-caddy-root.crt
chmod 644 atlas-caddy-root.crt
sha256sum atlas-caddy-root.crt
```

Transfer the public root certificate over the private VPN and compare its fingerprint before trusting it. The Caddy root certificate is public trust material; the CA private key under the Docker volume is secret. A browser warning is not a reason to bypass TLS verification.

## First owner, passkeys and recovery

Readiness stays in setup-required state until the first owner is enrolled. Generate the short-lived, single-use bootstrap token on the host only after HTTPS and private network access work:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec api atlas host bootstrap
```

Run this in a trusted interactive SSH terminal. Do not use `tee`, shell tracing, a terminal recorder, CI, or a command that stores terminal output. Use the displayed token directly in the first-owner setup page at `https://$ATLAS_HOST`; it expires after ten minutes and can be redeemed once. The bootstrap token is never a password and must not be saved in a shell history, note or log.

Set a unique long passphrase. Enroll at least two passkeys on separate devices, enroll TOTP, and store the one-time recovery codes offline in a protected place. Sign out and verify passkey login and the recovery path while access remains private. Confirm the first-owner account is the only owner, then check `/health/ready` returns success. Do not open public ingress before this recovery check succeeds.

## Import the separately delivered corpus

Download the private corpus archive and its checksum file from the GitHub release. Verify the checksum before extraction. Extract into a new owner-only staging directory; do not extract over an existing database or runtime directory:

```sh
mkdir -m 700 -p .runtime/corpus-import
sha256sum -c CORPUS_SHA256SUMS
tar --no-same-owner -xzf atlas-v3-public-corpus.tar.gz -C .runtime/corpus-import
```

Use the directory created by extraction as `ATLAS_CORPUS_DIR`. The following imports are additive/idempotent; use the exact same three Compose files as startup. The original database is not reset or dropped:

```sh
ATLAS_CORPUS_DIR="$PWD/.runtime/corpus-import"
tar -C "$ATLAS_CORPUS_DIR" -cf - corpus_raw models | \
  sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec -T api tar -C /data --skip-old-files -xf -
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec -T api atlas host corpus-load < .runtime/corpus-import/corpus.semantic.records.jsonl
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec -T api atlas host corpus-load-vectors < .runtime/corpus-import/corpus.semantic.vectors.jsonl
```

Run the read-only corpus health and search checks in the UI/CLI. Compare imported public record, chunk and vector totals with the release manifest. Do not use a database reset, volume removal or destructive cleanup command as an import remedy. The archive contains public material only; it does not contain the application database, owner accounts, sessions or master key.

## Provider registration and controlled research

In the authenticated Settings page, register only a provider you control, use a dedicated least-privilege credential, set the exact approved provider domain in the provider allowlist, and run the built-in connection probe. The secret is encrypted at rest with the host master key and is write-only after save. Do not place it in a chat, `.env` file or command argument. Assign the required model aliases, run doctor and the offline benchmark, and confirm the selected model through the UI. Keep live target access disabled; start only against an explicitly approved local fixture until the operator separately authorizes a target.

## Health and readiness checks

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml ps
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml logs --tail 50 init api worker-research worker-verify proxy
curl --fail --cacert atlas-caddy-root.crt "https://$ATLAS_HOST/health/live"
curl --fail --cacert atlas-caddy-root.crt "https://$ATLAS_HOST/health/ready"
```

After owner enrollment, verify HTTPS in the browser, passkey login, protected API denial without authentication, settings/provider write-only behavior, corpus search, queue/worker health, and a local fixture research run. Check migrations using the documented database status command and confirm the app reports the current Alembic head. Do not infer target safety from successful local fixtures.

## Optional public TLS mode

Keep the VPN-only stack for controlled testing. Public access requires a separate review of authentication/recovery, public DNS ownership, Caddy ACME reachability, host/cloud firewall policy, provider egress restrictions, rate limits and backup restoration. Do not expose the service publicly until all those checks pass. For that reviewed mode only, set the bind address to the intended public interface and start without `compose.private.yaml`; `Caddyfile.production` obtains a public certificate automatically when DNS points to the host and ports 80/443 are reachable. Verify the certificate chain from a separate client before admitting users.

## Backups, restoration, updates and rollback

Create encrypted backups to a new protected directory and move a copy off-host. Keep the backup password and master-key recovery copy separate from the backup files. The backup script reads the running Compose project; run it from the same shell context and with the same Compose configuration used for the deployment. A restore check creates and drops only the disposable `atlas_restore_check` database; run it against a separate recovery host or maintenance clone, never against a database that contains the only copy of user/corpus data.

```sh
sudo env COMPOSE_FILE='compose.yaml:compose.production.yaml:compose.private.yaml' COMPOSE_ENV_FILES='.env.production' scripts/backup.sh /secure/local/atlas-backup-$(date -u +%Y%m%dT%H%M%SZ)
sudo env COMPOSE_FILE='compose.yaml:compose.production.yaml:compose.private.yaml' COMPOSE_ENV_FILES='.env.production' scripts/restore-check.sh /secure/local/atlas-backup-REPLACE_WITH_REVIEWED_DIRECTORY
```

Before an update, verify the backup and its off-host copy, record the current commit/tag, and preserve `.runtime/secrets`, database volumes, artifact volume and Caddy data. Pull the reviewed release, inspect migrations and compose changes, then rebuild and restart with the same production/private Compose files. Never run `down -v`, volume-prune, database reset, or cleanup commands against production data.

```sh
git fetch --tags origin
git checkout v3.0.0-rc1
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml build
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml up -d
```

For rollback, check out the previously recorded release and rebuild/restart its images. Database migrations may be forward-only: if the older code cannot use the migrated schema, restore the verified encrypted database and artifact backups to an isolated recovery host first, validate it there, then perform a planned restore to the target host. Keep the failed current database intact until the restored copy is proven, and retain the master-key backup required to decrypt encrypted fields. Never test restoration by overwriting the sole live database.

## Sandbox and local TLS reference

The worker seccomp profile is a reviewed extension of Moby's default that permits nested namespace creation without `SYS_ADMIN` or privileged mode. Bubblewrap mounts only read-only runtime libraries, the authorized snapshot, a private `/dev` and `/tmp`, and omits procfs. Linux/AppArmor must permit unprivileged user namespaces. Do not weaken global host policy or expose the Docker socket to work around a failure. `compose.staging.yaml` and the staging Caddy local CA are for automated local validation only; they do not validate VPS TLS or firewall policy.
