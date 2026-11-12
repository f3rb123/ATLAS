# SKUNK flow3 — context packing and specialist scheduling

The owner supplied actual VPS rows showing completed tasks followed by many
`model_call_limit` failures, several `context_limit` failures, and web tasks
proposing unavailable local repository reproductions. This update addresses
those source paths without changing the selected mod models or API token.

## Changes

- Tracking-only SKUNK runs have no run-wide model/tool call ceiling. Counters
  still increment and usage/uncertain reservations remain preserved. Legacy
  bounded ATLAS runs keep their original call and accounting limits.
- Prompt budgets include system text, exact response contracts, output capacity
  and UTF-8 evidence bytes. Selected input schemas remain complete. Annotation
  removal preserves field names, required lists, enums and validation rules.
  Evidence gets separate byte/width/depth/field bounds; a wide dictionary can no
  longer defeat trimming merely by containing many small properties.
- A full allowed-tool catalog remains available. The model receives complete
  schemas selected for its responsibility, and invalid-argument feedback gives
  that schema priority on the next round. Host availability checks use the full
  allowed registry rather than a trimmed display subset. Backend typed-input,
  ownership, scope and proof gates remain authoritative.
- Follow-ups deduplicate by role and cited evidence. After two queued tasks,
  compatible leads are combined into queued work, with up to eight event IDs
  and four questions. Follow-ups are bounded to two generations and eight tasks
  per specialist role. Deferred leads stay on the shared board and mark coverage
  incomplete; they are not silently claimed as investigated.
- The scheduler reserves capacity for the final report. Reporter requests do
  not recursively reopen the research queue.
- Web-only prompts advertise local `experiment` as unavailable. If a model
  nevertheless proposes one without an approved repository, the action is
  blocked and recorded while valid observations/hypotheses are retained. No
  local reproduction or target policy denial is turned into permission.

Per-task reasoning/tool rounds, four task attempts, total task capacity, provider
concurrency/circuit cooldowns, wall-clock and per-target HTTP rate/request limits
remain. So do scope/DNS/redirect checks, destructive database/deletion/OTP guards,
model context/schema limits and independent proof/control verification.

## Apply

Exit the running SKUNK CLI with Ctrl+C, extract `skunk-flow3.tar.gz`, then run:

```bash
bash skunk-flow3/apply.sh
```

The cumulative updater accepts original rc1, retry1 and mod2 source hashes.
It acquires the controller lock, checks hashes, backs up replaced modules and
rolls back handled errors. Both installed source copies are updated. Database,
knowledge/model assets, keys, reports, counters and billing holds are preserved.
It does not reopen old completed runs, launch a scan, or send an inference call.

Restart the original scope command as a new run. The default model IDs remain
`deepseek-v4-mod` and `glm-5.3-mod`, with usage-only accounting. Historical task
states remain as the audit record of the earlier run.

## Verification evidence

Source compilation and shell parsing were checked. Offline diagnostics used
synthetic context shapes and an in-memory scheduler, with network connections
disabled and no provider, target or persistent runtime database activity.

- A broad 94,580-byte synthetic context reproduced the previous packer's
  `context_limit` failure; the new pack was 26,419 bytes under its 34,000-byte
  budget. Selected schemas, required/enumerated fields and operator instructions
  remained intact.
- An 8.6 MB synthetic evidence pack became 32,736 bytes, with 45,424 bytes for
  system/prompt/output allowance under the 64,000-byte physical model bound.
- Three distinct cited leads produced two queued specialist tasks with combined
  evidence. Repeated evidence reused its existing task; a third-generation
  follow-up was deferred.

These are offline diagnostics, not a saved VPS prompt or proof of live recovery.
Full application/browser suites, actual paid model inference, target scans and
VPS execution were not performed. Original/cumulative module preimages and
published file digests are checked for delivery.
