# SKUNK retry1 code update — 12 November 2026

The owner reported that the rc1 assessment ended with dead-lettered tasks and
explicitly authorized retries even when a prior model request may have been billed.
The original VPS failure has not yet been identified from server diagnostics.
This update implements recovery/diagnostics; it does not claim a verified fix for
an unknown credential, model-availability, network or VPS-specific failure.

## Apply to the existing installation

Exit the SKUNK CLI with Ctrl+C first, including its finished dashboard. Extract
`skunk-retry-hotfix1.tar.gz`, then run:

```bash
bash skunk-retry-hotfix1/apply.sh
```

For a custom installation, pass its path: `bash skunk-retry-hotfix1/apply.sh /opt/skunk`.
Use the same Unix account and `SKUNK_DATA_DIR` used to launch the CLI.

The updater requires the original bundle, checks each old/new module hash,
acquires the controller lock, backs up replaced code and updates both installed
source copies atomically per file. It rolls back applied files on a handled
installation error. Existing local source edits are preserved by refusing to
overwrite unexpected hashes. Database, knowledge/model assets, credentials,
reports, usage counters and uncertain billing reservations are preserved.
The updater starts no assessment, inference or application test.

## Diagnose the failed run

```bash
skunk diagnose
```

This opens the existing database read-only, reports task failures, model pins,
token-budget totals and cached request-construction results. Python network
connects and inference dispatch are disabled during that preflight. It performs
no fresh embedding inference, target requests or database writes, and emits no
keys, raw prompts, vendor error bodies or captured response contents. Cached
reconstruction is labelled; it does not verify current provider operation.

To also check current API authentication and model catalog metadata:

```bash
skunk diagnose --provider
```

The optional check sends one authenticated GET to HackerAI's `/models` endpoint.
It does not send an inference request or contact a scan target. The endpoint is
restricted to the managed HackerAI profile. Unlisted aliases are reported as
unlisted rather than assumed unusable. Copy the resulting JSON for diagnosis.

## Retry behavior for new runs

Start your scope command again after reviewing the diagnostic output:

```bash
skunk --agents=8 --scope='*.example.com' --ra --prompt='Prioritize API authorization issues'
```

New SKUNK runs pin a host-owned policy of up to four task attempts (three retries)
for timeouts, connection failures, HTTP 408/409/425/429/5xx, schema failures and
transient database lock errors. Backoff starts at 4 seconds, then 8 and 16;
provider Retry-After up to 300 seconds takes precedence. Provider circuit
cooldowns, concurrency, deadlines, model/tool/request and monetary/token limits
remain enforced. Each new attempt can incur a separate charge; old uncertain
reservations remain held instead of being erased or reused.

HTTP 401/403, invalid configuration, policy denials and exhausted budgets are
explained and stopped. Repeating an unchanged credential or prohibited target
request is not a recovery mechanism. Pause/cancel still control dispatch.
Older finished runs are preserved; applying code does not reopen them or scan
old targets automatically. Legacy non-SKUNK runs retain their original policy.

Schema correction is bounded to the same four model rounds per role attempt.
New normal/deep runs allow up to 64/160 model calls and 160/400 tool calls to
accommodate the eight responsibilities and bounded recovery. Existing $100 run
and campaign budgets, persistent global cap/allocation and HTTP scope quotas are
unchanged. Increasing call limits does not release billing holds or raise budgets.

Runs with no successful research tasks end failed/blocked. Runs with failed or
cancelled tasks retain incomplete-coverage markers. CLI/dashboard rows show
specific failure messages, safe source locations, attempt counts and retry waits.

## Build evidence

Source compilation, shell parsing, archive construction and checksums are the
build checks. Application tests, actual provider inference, target scans and VPS
deployment have not been performed for this update. Runtime recovery remains
unverified until the actual server diagnostics and an authorized run confirm it.
