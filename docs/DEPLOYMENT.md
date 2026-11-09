# ATLAS V3 manual Ubuntu installation

This guide installs the locally packaged source on a new Ubuntu 22.04/24.04 LTS VPS for controlled testing. No VPS deployment has been performed. Keep access on Tailscale or WireGuard until authentication, recovery, TLS and backups pass the checks below. The delivery package has no `.env`, database, owner account, provider key, encryption key, SSH material or runtime volume.

## 1. Prepare the Ubuntu host

Use an x86-64 host with at least 4 vCPU, 8 GiB RAM and 80 GiB SSD. Enable encrypted storage and unattended security updates. Create a named sudo user, install its SSH public key, and test a second SSH session before changing SSH or firewall rules. Do not use root for routine administration and do not add the user to the `docker` group because Docker access is root-equivalent.

Install base utilities and Docker Engine with the Compose plugin from Docker's official Ubuntu repository:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl ufw unattended-upgrades python3 tar unzip
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker compose version
```

Install and enroll Tailscale using its official Ubuntu instructions, or configure WireGuard through your organization's approved process. Confirm the private interface address and private DNS name from the VPS itself:

```sh
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
sudo tailscale ip -4
sudo tailscale status
```

Use MagicDNS or private WireGuard DNS for the application hostname. Keep PostgreSQL, Redis and worker ports private. Docker port publishing can bypass UFW forwarding rules, so the private Compose override's bind to the VPN interface is an important boundary.

## 2. Transfer and verify the package from Windows

Download `atlas-v3-deployment.zip`, `atlas-v3.bundle`, `SHA256SUMS` and `RELEASE-MANIFEST.md` from the Codex artifact links. The corpus archive is intentionally absent from this delivery (see [Corpus status](#corpus-status)). On Windows, verify the two shipped binary artifacts in PowerShell before transfer; compare each output with the matching line in `SHA256SUMS`:

```powershell
Get-FileHash .\atlas-v3-deployment.zip -Algorithm SHA256
Get-FileHash .\atlas-v3.bundle -Algorithm SHA256
```

In WinSCP, create a new SFTP session to the VPS's private VPN address on port 22, using the named non-root sudo account and its SSH key. Verify the SSH host-key fingerprint through a trusted channel. Upload the four files into `/home/<sudo-user>/atlas-release/`; do not upload passwords, private keys, `.env` files, databases or runtime directories. Set the remote directory to owner-only permissions in the VPS shell:

```sh
install -d -m 700 "$HOME/atlas-release"
chmod 600 "$HOME"/atlas-release/*
cd "$HOME/atlas-release"
sha256sum -c SHA256SUMS
```

The checksum command must report `OK` for the deployment ZIP and bundle. Read `RELEASE-MANIFEST.md` and confirm its commit and test results match the package you intend to install.

Extract into a fresh installation directory. Keep the uploaded bundle separately as the offline history backup:

```sh
sudo install -d -o "$USER" -g "$(id -gn)" -m 750 /opt/atlas-v3
unzip -q "$HOME/atlas-release/atlas-v3-deployment.zip" -d /opt/atlas-v3
cd /opt/atlas-v3
```

The ZIP extracts as `atlas-v3/` under `/opt/atlas-v3`. Alternatively, to recover the complete Git history from the separate bundle, use `git clone "$HOME/atlas-release/atlas-v3.bundle" /opt/atlas-v3-history`; this is an offline source-history copy, not the configured deployment directory. Compare the extracted source with the uploaded `RELEASE-MANIFEST.md` before installation.

## 3. Configure production environment and host secrets

Work from the extracted source directory:

```sh
cd /opt/atlas-v3/atlas-v3
cp .env.production.example .env.production
chmod 600 .env.production
sudoedit .env.production
```

Set `ATLAS_BIND_IP` to the VPS's Tailscale/WireGuard interface address, `ATLAS_HOST` to its private DNS name, and `ATLAS_EXTERNAL_URL` to `https://` plus that exact host. Preserve the other documented placeholders and use unique host-specific values for ordinary non-provider configuration. Do not enter provider API credentials in this file; register them later in the authenticated Settings UI. The app package contains only placeholder examples.

Generate the encryption master key separately on the VPS. The script creates secret files with restrictive permissions, does not print their contents, and refuses to replace existing values:

```sh
python3 scripts/prepare-secrets.py
chmod 700 .runtime/secrets
chmod 600 .runtime/secrets/*
stat -c 'master_key mode=%a bytes=%s' .runtime/secrets/master_key
```

Confirm mode `600` and length `32`. Back up the master key through a protected offline process, separate from encrypted database backups. Losing it makes saved provider secrets unrecoverable. Never put it in shell history, source, chat, WinSCP transfer files, or a log. Preserve `.env.production` and `.runtime/secrets` across upgrades.

## 4. Configure firewall and start VPN-only HTTPS

Restrict the cloud firewall/security group to SSH from the VPN administrator path. For host UFW, first confirm your current SSH source and that a second session works. Then allow SSH and HTTPS only on the VPN interface (replace `tailscale0` with the actual interface):

```sh
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow in on tailscale0 to any port 22 proto tcp
sudo ufw allow in on tailscale0 to any port 443 proto tcp
sudo ufw enable
sudo ufw status verbose
```

Do not expose ports 80/443 on a public interface for this initial private deployment. If SSH must remain available on a separate trusted management interface, add its narrowly scoped rule before enabling UFW. Review `infra/ubuntu/sshd-atlas.conf`; apply SSH hardening only after `sudo sshd -t` passes and a second key-authenticated session is open. Do not rely on UFW alone to restrict Docker-published ports.

Validate Compose configuration and build/start the private production stack:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml config --quiet
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml build
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml up -d
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml ps
```

The init service applies Alembic migrations and prepares restricted volumes. Confirm only the VPN address has a published HTTPS listener and that PostgreSQL, Redis and worker ports are not externally published:

```sh
sudo ss -lntp
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec api atlas version
```

Caddy uses its internal CA in this private mode. Export only the public root certificate, compare its SHA256 fingerprint over a separate trusted channel, and install it in the testing computer's trust store. Never export the CA private key:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec -T proxy cat /data/caddy/pki/authorities/local/root.crt > "$HOME/atlas-caddy-root.crt"
chmod 644 "$HOME/atlas-caddy-root.crt"
sha256sum "$HOME/atlas-caddy-root.crt"
```

Open `https://<private-hostname>` only after trusting the verified CA root. Do not bypass TLS warnings.

## 5. Database, first owner and recovery setup

The Compose init service performs schema migrations on first startup. Confirm it completed successfully before enrollment:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml ps
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml logs --tail 100 init api
```

Readiness remains setup-required until you create the first owner. Generate a short-lived, single-use bootstrap token on the VPS only after the private HTTPS site is reachable. Run this in a trusted interactive SSH terminal; do not pipe or record its output:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec api atlas host bootstrap
```

Enter the displayed token directly into the first-owner setup page. It expires after ten minutes and can be redeemed once. Choose a unique passphrase, enroll at least two passkeys on separate devices, enroll TOTP, and store the single-use recovery codes offline. Sign out and test passkey login and recovery while access is still VPN-only. Confirm only the intended owner exists and `/health/ready` becomes healthy. Never save a bootstrap token or recovery code in a log or ordinary note.

## 6. Corpus status and import procedure

**No corpus archive is included in this release package.** A fresh scan of the sanitized candidate produced 2,151 detections: 2,125 are classified as schema/model/hash false positives, while 26 content candidates remain unresolved across structured records, vectors and raw source documents. The findings may represent credentials or private-key material. The candidate was not included. Do not copy the local candidate archive to the VPS.

The application may be initialized and tested without the optional knowledge corpus. Wait for a future separately reviewed corpus package before importing corpus data. When an approved archive is provided, verify its separately supplied checksum, stage it in a new owner-only directory, and follow the importer commands supplied with that exact archive. Corpus imports are additive/idempotent; never reset the application database or remove Docker volumes to solve an import problem. The delivered source contains the acquisition, conversion, validation and import tools, but this does not make the unresolved candidate safe to distribute.

## 7. Add a custom model provider

After first-owner authentication, open Settings and register a provider that you control. Use a dedicated least-privilege API credential, narrow the provider hostname allowlist to the provider endpoint, select its protocol, and run the built-in connection probe. The credential is write-only in the UI and encrypted with the separately generated host master key. Assign and pin the model aliases required by the workflow, then run the built-in offline benchmark and doctor checks. Do not place API keys in `.env.production`, CLI arguments, URLs, or shell commands.

## 8. Health, logs and troubleshooting

Check services, logs and health from the VPS:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml ps
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml logs --tail 100 init api worker-research worker-verify proxy
curl --fail --cacert "$HOME/atlas-caddy-root.crt" "https://<private-hostname>/health/live"
curl --fail --cacert "$HOME/atlas-caddy-root.crt" "https://<private-hostname>/health/ready"
```

If Compose validation fails, inspect `.env.production` placeholder substitutions and use the same three Compose files on every command. If containers fail, inspect their logs before restarting. For TLS errors, compare the trusted root certificate fingerprint and confirm the private hostname resolves to the VPN address. For sandbox failures, check Ubuntu/AppArmor support for unprivileged user namespaces; do not add `SYS_ADMIN`, privileged mode or Docker-socket access. Keep the site private while debugging.

## 9. Backup and restoration

Create an encrypted backup in a protected directory and copy it off-host. Keep the backup password and master-key recovery copy separately from the archive. A restore check is intended for a separate recovery host or maintenance clone; it creates and drops only a disposable `atlas_restore_check` database there, never run it against the only production database:

```sh
sudo env COMPOSE_FILE='compose.yaml:compose.production.yaml:compose.private.yaml' COMPOSE_ENV_FILES='.env.production' scripts/backup.sh /secure/local/atlas-backup-$(date -u +%Y%m%dT%H%M%SZ)
sudo env COMPOSE_FILE='compose.yaml:compose.production.yaml:compose.private.yaml' COMPOSE_ENV_FILES='.env.production' scripts/restore-check.sh /secure/local/atlas-backup-REPLACE_WITH_REVIEWED_DIRECTORY
```

Before production recovery, restore to an isolated host, validate migrations, records, attachments and owner login, then schedule a controlled cutover. Keep the original database intact until the restored copy is proven. Without the master-key recovery copy, encrypted provider credentials cannot be recovered.

## 10. Updates and rollback

Keep the uploaded source ZIP and bundle as the offline deployment record. For an update, verify the new artifact checksums, make and verify an encrypted backup and off-host copy, record the running commit, inspect migration and Compose changes, then extract to a new version directory. Preserve `.env.production`, `.runtime/secrets`, Docker volumes and Caddy data. Switch to the new reviewed version only after validation; never run `down -v`, volume-prune, database reset or cleanup against production data.

Rollback code to the previously recorded source checkpoint and rebuild/restart. Database migrations may be forward-only. If older code cannot use the migrated schema, keep the current data intact and restore a verified backup to an isolated recovery host first; perform a planned restore only after validation. Do not test rollback by overwriting the only live database.

## Corpus status

The validated live build corpus contains 21,012 public record identities and 34,229 vectors, but distribution is blocked by unresolved candidate scan findings. The deployment ZIP contains the source pipeline and validation tools, not corpus database files or the candidate archive. No VPS install, public exposure or external target test has been performed by this build process.
