# ATLAS V3 all-in-one prebuilt installation

This download includes the built Linux x86-64 API/worker/frontend images,
PostgreSQL with pgvector, Redis, the HTTPS proxy, eight pinned native tool
binaries, the original public corpus ZIP, all 34,229 vectors and the pinned
MiniLM ONNX/tokenizer assets. No ATLAS compilation, npm/pip install, Docker image
pull, embedding download or re-embedding is required on the server.

The corpus has **21,012 advisory/reference record identities**, not 20,000
full-text bounty reports. Its full-text bounty report count is zero. The
installer restores the supplied corpus and its model assets automatically into
an empty store before starting the application. An identical completed import
is idempotent; changed or unrelated populated stores are preserved and rejected.

## Host prerequisites

Use Linux x86-64 with Docker Engine, Docker Compose v2.24.4 or newer, Python 3,
GNU core utilities and `flock`. Recommended capacity is 4 vCPU, 8 GiB RAM and
80 GiB storage. Docker must support non-root nested user namespaces for the
isolated research tools. Do not disable host security or grant privileged mode
if its sandbox is unavailable; see `infra/security/README.md`.

## Install

Download the single `atlas-v3-prebuilt-20261110.zip` and its `.sha256` file from
the GitHub release, verify its SHA256, then extract it:

```sh
sha256sum -c atlas-v3-prebuilt-20261110.zip.sha256
unzip atlas-v3-prebuilt-20261110.zip
cd atlas-v3-prebuilt-20261110
sudo bash INSTALL.sh
```

The installer checks bundled file hashes and all five image identities, loads
the local images, generates fresh host-only secrets without overwriting existing
ones, runs additive migrations, preserves historical token consumption, restores
the corpus and starts Compose without building or pulling anything. It does not
configure a live provider, initiate a target request or run application tests.
Keep the extracted directory and its `.runtime` host secrets for upgrades.

The default endpoint is **https://atlas.localhost:8443**, bound only to the
server's loopback interface. It is deliberately private. Access a remote server
using your own SSH tunnel:

```sh
ssh -L 8443:127.0.0.1:8443 YOUR_USER@YOUR_SERVER
```

The proxy generates a local CA. Export its public certificate and verify/trust it
on the operator computer before use; keep its private key in the Docker volume:

```sh
sudo bash ATLAS/scripts/prebuilt-control.sh ca-cert > atlas-local-ca.crt
sudo bash ATLAS/scripts/prebuilt-control.sh bootstrap
```

The second command displays a private, one-use owner setup token in your own
terminal. Do not copy it into public logs. Complete owner setup in the browser,
enroll your authentication factors and configure your provider key securely.
The corpus and model assets are already restored at this point. The six bundled
licensed methodology references are installed for each owner by the normal UI
initialization. Tools remain constrained by each campaign's explicit scope.

For a private VPN/domain, edit `ATLAS/.env.prebuilt` with the matching bind IP,
hostname, port and external HTTPS origin, then run the control script's `start`
command. Do not expose an unverified release candidate publicly. The prebuilt
frontend uses the correct internal `api:8000` service destination.

## State, credentials and spending

API keys, passwords, SSH credentials, private accounts, original application
databases and master keys are not in the public archive. Provider/API/MCP
credentials must be configured securely after owner setup. No key is required
to load the images or import the knowledge. Preserve existing private state
separately; this public distribution is not a backup of owner accounts/tasks.

Fresh installation imports a conservative historical budget floor: 744,368
consumed tokens and 282,255 held tokens for five uncertain billing outcomes.
Input/output/cached/reasoning counters and validation reservations are retained,
leaving 973,377 under the initial 2M allocation and 48,973,377 under the 50M global
authority after holds. Public budget metadata contains no original account,
provider, request or run identifiers; old detailed billing records remain in the
private original database. Unknown billing is not automatically released.

An existing ledger is never replaced or reset. A ledger older than the packaged
consumption floor requires explicit state migration. Only one instance may use
the owner's paid provider allowance: keep the previous spending workers stopped
before configuring the new instance. Restore the actual private database and
keys when private account/task/billing history is required; do not create
independent spending clones or treat this floor as a full database migration.

## Operations and status

```sh
sudo bash ATLAS/scripts/prebuilt-control.sh status
sudo bash ATLAS/scripts/prebuilt-control.sh logs
sudo bash ATLAS/scripts/prebuilt-control.sh stop
sudo bash ATLAS/scripts/prebuilt-control.sh start
```

All project volumes remain persistent. No installer/control command drops
databases, deletes volumes, resets consumption or removes existing files.
The `stop` command preserves state. Keep backups and encryption keys off-host.

This is a prebuilt **release candidate**. The owner explicitly deferred further
application testing. Packaging/image/hash checks are not runtime acceptance.
Some external integrations need keys; owner-managed Waybackurls needs separate
licensing/provenance, and raw Amass/masscan execution remains external imports.
Prebuilt packaging does not remove those boundaries or complete the deferred
functional/deployment acceptance gates.
