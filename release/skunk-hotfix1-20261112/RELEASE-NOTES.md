A small code-only update for the existing SKUNK rc1 Linux installation. The full rc1 bundle and knowledge ZIP are not required again.

The owner reported all-dead-letter tasks and authorized separately billed retries. **The original VPS error is still awaiting diagnostic output; this release does not claim verified recovery of that unknown error.**

- New runs retry recoverable model/connection/HTTP/schema/database-lock failures up to four task attempts, with backoff and Retry-After.
- Prior billed/uncertain reservations are preserved. Scope, target guardrails, persistent budgets, concurrency and deadlines remain enforced.
- All failed research now ends failed/blocked. CLI/dashboard show actionable safe failure details and retry waits.
- `skunk diagnose` reconstructs cached context read-only with network/inference disabled. `skunk diagnose --provider` additionally makes one authenticated GET /models to inspect current credentials and model catalog metadata; it sends no model inference or target request.
- The updater verifies original/new hashes, acquires the controller lock, backs up replaced code and preserves database, knowledge, credentials and usage. Local source modifications cause refusal rather than overwrite.

## Update the VPS

Exit the SKUNK CLI with Ctrl+C first. Run this under the same Unix account and SKUNK_DATA_DIR:

```bash
( set -e; skunk_fix_dir=$(mktemp -d); cd "$skunk_fix_dir"; skunk_fix_url=https://github.com/f3rb123/ATLAS/releases/download/skunk-hotfix1-20261112; curl -fL --retry 3 -O "$skunk_fix_url/skunk-retry-hotfix1.tar.gz"; curl -fsSL --retry 3 -O "$skunk_fix_url/skunk-retry-hotfix1.tar.gz.sha256"; sha256sum -c skunk-retry-hotfix1.tar.gz.sha256; tar -xzf skunk-retry-hotfix1.tar.gz; bash skunk-retry-hotfix1/apply.sh; skunk diagnose --provider )
```

Inspect/share the resulting JSON to diagnose the original failure. After the cause is resolved, start your scope command again. Old completed runs are preserved and are not reopened automatically:

```bash
skunk --agents=8 --scope='*.example.com' --ra --prompt='Prioritize API authorization issues'
```

Source: `4e9cf1d`, internal package `atlas`, retry harness `skunk-swarm/2`. This is a build-only hotfix. Source compilation, shell parsing and archive hashes were checked; no application test suites, actual model inference, target scans or VPS deployment were run. See SKUNK-HOTFIX-README.md for details.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `skunk-retry-hotfix1.tar.gz` | 52,494 | `6117d956283144491b291899b9daed3c1178139517aeda630a246e605f729915` |
| `skunk-retry-hotfix1.tar.gz.sha256` | 93 | `ee3fd9ab7615621ca009831f2b3946ccd71989c010c2a3af4eb5b58b6d93246f` |
| `HOTFIX.json` | 1,922 | `996ef43001ce9efab8d0bc7aa3654f9e90db14de70c5fa1b355483460b0dd31f` |
| `SKUNK-HOTFIX-README.md` | 4,392 | `60014db037552df5421e49463cb8ae03af09f8beed5a7ab4bcd7ffb322a6ed0f` |
| `skunk-source-hotfix1.tar.gz` | 1,347,624 | `76dce7ff42f5328f2d6988c96e7c8b66662b70aa16dcdd8ca216b61030c717ac` |
