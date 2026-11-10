# ATLAS V3 private deployment

This guide installs the autonomous web build on a fresh owner-controlled Ubuntu
22.04/24.04 x86-64 host. It is a manual procedure, not a record of a VPS operation.
The current implementation is being completed before final verification at the
owner's request. Do not transfer older test results to newer functionality.

## Preserve an existing installation

Keep the full database, artifact store, original corpus/model files, provider
master key, dedicated target key, provider configuration and token ledger.
Never initialize a second spending copy. Stop the old spending instance before
activating a restored installation. Defaults never reset an existing ledger.
Do not extract source over populated stores, drop tables or remove data volumes.

The owner's current `/workspace/ATLAS/.env` is a raw provider key, not dotenv.
Use a separate `.env.production`. Source artifacts contain no live credentials,
accounts, databases, corpus ZIP, model binaries, private screenshots or sessions.

## Fresh host and source

Use at least 4 vCPU, 8 GiB RAM and 80 GiB SSD, with encrypted storage and a private
Tailscale/WireGuard administration path. Install Docker Engine and Compose from
Docker's official Ubuntu repository. Use a named sudo account and keep Docker
administration separate from normal application access. Review the supplied
`infra/ubuntu` hardening configuration before applying it to your own host.

Transfer the release manifest, SHA256SUMS, source ZIP and complete Git bundle by
SFTP. Verify the published hashes before and after transfer. From an empty
owner-controlled installation directory, recover the exact source:

```sh
sha256sum -c SHA256SUMS
git clone --branch work atlas-v3-complete.bundle ATLAS
cd ATLAS
git rev-parse HEAD
```

Alternatively, the source ZIP extracts under `ATLAS/`. Compare the exact commit
with RELEASE-MANIFEST.md. Keep the complete bundle independently of the cloud
session: fresh-task restoration of local-only Git commits is not guaranteed.

## Configuration and keys

```sh
cp .env.production.example .env.production
chmod 600 .env.production
python3 scripts/prepare-secrets.py
```

Set `ATLAS_HOST` to the private DNS name, `ATLAS_BIND_IP` to the VPN interface
address, and `ATLAS_EXTERNAL_URL` to the matching HTTPS origin. Keep the
50,000,000-token global authority, 2,000,000 initial allocation and protected
validation capacity. Configure optional strict MFA with `ATLAS_REQUIRE_MFA`.
Provider and target credentials are entered through authenticated settings,
not `.env.production`, command arguments, Git or logs.

The init service prepares permissions and additive migrations. It also creates
a separate target-only key under `/targetkeys`; the relay cannot decrypt
provider envelopes. Research/verification workers receive neither key. Preserve
both keys and the original host secret files across upgrades.

## Build and private startup

Use the same explicit configuration and Compose files for every operation:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml config --quiet
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml build
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml up -d
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml ps
```

Only private HTTPS should be published. PostgreSQL, Redis, the model gateway,
target relay and worker ports remain private. Docker-published ports need an
explicit private bind; a host firewall alone is insufficient.

The private proxy uses its own CA. Export only its public certificate, verify
its fingerprint through your trusted administration channel and trust it on the
operator computer. Keep the CA private key in its protected volume. Preserve TLS
verification for provider, corpus, tool downloads and target connections.

The API image installs eight release-pinned executables with archive and binary
SHA256 verification. HTTPX/Katana/ffuf/Nuclei use an isolated HTTP bridge;
subfinder/gau use fixed public-index queries; an owner-managed waybackurls profile uses the same boundary; dnsx/naabu use bounded
DNS/connect bridges. Tools have no direct external network, host shell, provider
key, database credentials or Docker socket. Do not grant SYS_ADMIN, privileged
mode or host-network access to make a failed sandbox start. The worker seccomp
profile supports the intended Linux namespace operations.

## Owner and providers

Bootstrap the first owner in a trusted interactive terminal:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec api atlas host bootstrap
```

Enter the one-use token directly into setup without logging it. Configure your
password, passkeys/TOTP and recovery policy. Enrolled factors remain enforced;
strict MFA is an explicit policy choice. Save recovery material offline.

In Providers, configure HackerAI at `https://api.hackerai.sh/v1`, protocol
`custom_openai_compatible`, primary `deepseek-v4.1-flash` and verifier/deep research
`deepseek-v4-pro`. Discover/test exact model IDs and pin aliases. Do not silently
substitute models. API keys are encrypted and write-only. Actual USD prices must
be verified separately; unknown prices and billing remain flagged.

For an existing paid deployment, restore its actual ledger and matching keys.
The last pre-continuation counters were 744,368 consumed, 282,255 held and 973,377
remaining in the initial allocation. The final release manifest governs later
counters. Never release uncertain holds or reset usage without verified evidence.

## Preserve and restore the supplied corpus

The separate owner-supplied review ZIP has SHA256
`e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025`.
It contains 21,012 advisory/reference identities and 34,229 real 384-dimensional
MiniLM vectors, with original model assets and provenance. It has no full-text
bounty reports. Supplied omissions and protected-view curation remain recorded.
This input is authorized for private integration; it is not an approval to publish
raw artifacts or the corpus publicly.

Use the authenticated resumable import interface under Research Memory, or the
same host service through bounded stdin in a fresh compatible corpus store:

```sh
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec -T api atlas host corpus-inspect - --sha256 e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025 < /private/atlas-v3-public-corpus-review.zip
sudo docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml -f compose.private.yaml exec -T api atlas host corpus-restore - --sha256 e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025 < /private/atlas-v3-public-corpus-review.zip
```

The importer checks archive safety, hashes, schema, identity mapping, dimensions
and model compatibility before writes. It restores an empty compatible corpus
or verifies an identical completed fingerprint. It does not overwrite populated
or changed stores, recreate identities, re-embed or fall back to hash retrieval.

## Autonomous engagement configuration

1. Enter an authorized target, instructions, authorization reference and exact
   scope. Select the permitted check classes, rates, ports and request limits.
   Wildcards do not include the apex; redirects and additional assets need scope.
2. Configure owned test identities, either static Authorization/Cookie/X-API-Key
   bindings or explicit JSON login flows. Login POST endpoints and authentication
   must be authorized. Credentials/session values never enter model contexts.
3. Select enabled tool profiles, starting URLs, page/depth/check limits, optional
   source snapshots, specialist concurrency and model mode. Owned resource
   comparisons require two isolated accounts/resources and distinct markers.
4. Start the engagement. Bounded discovery precedes specialist reasoning; new
   scoped observations activate research, tool requests and follow-up specialists.
5. Review persisted tasks, events and web/network evidence. Typed experiments
   produce candidates. Separate verification repeats fresh proof/control requests
   and requires an evidence-bound model review before confirmation.
6. Pause/stop/resume and the emergency switch prevent new dispatch. Existing
   runs keep their scope, identity, tool, template, skill and model pins.

The minimal SBI acceptance profile is separate: at most two unauthenticated
root HEADs. It does not limit capabilities of other explicitly authorized
engagements. No SBI test is authorized until a specific verified hostname is
available. The final product still has no database/server/file administration
capability or destructive target method.

Optional external intelligence uses fixed SecurityTrails/Shodan/Censys v2/
VirusTotal/FOFA APIs and separately supplied account entitlements. MCP supports
reviewed resource URIs and narrowly reviewed read-only hostname lookup tools.
No arbitrary MCP command or server installation is model-accessible. Amass and
masscan JSON output can be imported with explicit external/unverified provenance;
their raw engines are not run by this worker. Nuclei supports bundled observation
templates and owner-reviewed fixed HTTP templates, not arbitrary executable DSL.

## Backup, recovery and operation

Use a unique new backup directory and an explicit Compose selector:

```sh
sudo env ATLAS_COMPOSE_ENV_FILE=.env.production COMPOSE_FILE=compose.yaml:compose.production.yaml:compose.private.yaml scripts/backup.sh /private/backups/atlas-REVIEWED-UTC-TIMESTAMP
```

The backup encrypts the database, artifacts and dedicated target-key archive.
Keep the backup password and provider master-key recovery copy separately and
off-host. Restore testing belongs in a separate disposable database. A real
restore must retain matching keys, the global ledger, uncertain reservations,
model/corpus files, tasks/events and file permissions, with only one spending
instance active. Never solve recovery failures with database reset or `down -v`.

Inspect `/health/live`, `/health/ready`, authenticated readiness, task failures,
budgets and correlated logs. A completed run can be partial when tools/tasks
failed. Scanner matches, reflected strings, schema availability and missing
headers are observations; they do not prove exploitability by themselves.
The release manifest distinguishes implementation, build checks, real-provider
acceptance, synthetic fixtures and outstanding external dependencies.

## Owner-managed Waybackurls profile

Upstream repository/tag metadata declares no license, so this release does not
bundle or automatically install its executable. Gau provides archive discovery
in the default autonomous pipeline. If you separately have authorization to use
a matching Waybackurls binary, supply its directory read-only through
`compose.owner-tools.yaml` and `ATLAS_OWNER_TOOLS_DIR`, record its provenance in
Recon Tools and enable it. Its hash/version and namespace/relay boundaries are
still enforced. This is distinct from claiming an unlicensed binary was shipped.

## Generated source experiments

With a pinned source snapshot and explicit offline execution enabled, agents can
use `source.experiment` to generate bounded unittest proof and functional controls
and an exact secure replacement. The original and patched copies run in the
offline namespace; original uploads are never patched. The vulnerable assertion
must pass originally and fail by assertion after the secure change, while
legitimate functionality passes both. An independent worker repeats the phases
and reviews the actual code, controls and fresh artifacts before confirmation.
The current execution profile is Python unittest with the available sandbox
runtime; missing project dependencies are reported, never simulated as success.
