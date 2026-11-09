# Ubuntu VPS deployment

No deployment to the owner's VPS has been performed. These are operator-run assets. Review source, security controls, network exposure and current gate evidence before using a real server. A starting estimate is 4 vCPU, 8–16 GiB RAM and 80 GiB SSD; remote model inference needs no GPU.

## Prerequisites

Use a supported Ubuntu release, Docker Engine with Compose 2.24.4+ (for !override), Python 3, time synchronization, a named SSH-key-only sudo account, and a reviewed DNS hostname. Prefer private VPN access and keep ATLAS_BIND_IP on loopback/private interfaces. The default scripts never modify SSH or firewall settings. Enable encrypted host storage and off-host backups; master key backup is separate.

This build is committed locally; a remote Git push is not assumed. Transfer the reviewed Git bundle/source archive through your approved channel. From a bundle on the VPS:

```sh
git clone ./atlas-v3.bundle atlas
cd atlas
cp .env.production.example .env.production
python3 scripts/prepare-secrets.py
```

Edit .env.production locally: set ATLAS_HOST and ATLAS_EXTERNAL_URL to the exact HTTPS origin, choose the reviewed bind address and port, and set provider allowlists. Never put provider keys into this file. Secret files under .runtime/secrets are generated locally with restrictive permissions and never committed. Preserve them on upgrades.

```sh
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml config --quiet
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml build
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml up -d
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml ps
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml exec api atlas host bootstrap
```

The one-shot init service applies Alembic migrations and prepares restricted volumes. Application services use the non-superuser atlas_app DB role; init uses the separate migration credential. Redis requires its generated password. Only API/gateway receive the master key volume. Research/verifier tokens and volumes differ. No stateful service or worker publishes a host port.

Use the token in the owner form, set a long passphrase, enroll two passkeys, enroll TOTP and save recovery codes offline. Production /health/ready remains setup-required until enrollment is complete. Configure a provider through Settings, register and probe a model, assign reasoning/verifier aliases, run doctor and the offline benchmark before authorizing a campaign. No live traffic is enabled by merely configuring a model.

## Repository sandbox

The worker seccomp profile is a reviewed extension of Moby's default that permits nested namespace creation without SYS_ADMIN or privileged mode. Bubblewrap mounts only read-only runtime libraries, the authorized snapshot, a private /dev and /tmp, and deliberately omits procfs. Linux/AppArmor must permit unprivileged user namespaces. Run the local invariant benchmark before enabling source execution. Do not weaken global host policy or expose the Docker socket to work around a failure.

## Validation

```sh
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml logs --tail 50 init api worker-research worker-verify
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml exec api atlas version
```

Run `atlas doctor` from a client with a fresh scoped CLI token. Verify HTTPS using a trusted certificate, passkey login, protected API denial without authentication, provider write-only behavior, queue/worker health, backup restore and a local fixture run. Public TLS/DNS and the owner's firewall/SSH posture cannot be established by a local build.

## Local TLS staging

compose.staging.yaml uses a Caddy local CA for atlas.localhost:8443. It is for automated local validation, not public TLS. Verify it with the exported root CA and normal certificate checks; never use curl -k. Local staging does not claim ACME/DNS validation on the owner's domain.

## Host hardening review

Run `scripts/preflight-vps.sh` for read-only checks. The proposed `infra/ubuntu/sshd-atlas.conf` disables root/password/keyboard-interactive login and limits authentication attempts. Before installing it, establish and verify a second SSH connection using a named sudo user and public key; validate the combined SSH configuration with `sshd -t`. Apply host changes only under the owner's explicit deployment approval.

Keep the application on loopback/private VPN whenever practical. If public HTTPS is approved, review the host firewall to permit only the intended SSH/VPN and HTTPS ingress. Docker-published ports can bypass some UFW rules: inspect Docker's own forwarding rules and bind addresses rather than relying on a generic UFW status display. The supplied Compose publishes no PostgreSQL/Redis/worker port. Protect the host disk, backup password and KEK independently.

Do not include compose.test.yaml in production. It enables a synthetic internal model fixture and a test-only private endpoint allowlist solely for local restart/recovery validation. Remove that service/override after validation. No mock provider is used by production application code.
