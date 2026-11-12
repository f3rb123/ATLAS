# SKUNK mod2 update — 12 November 2026

The owner requested the Pentest `-mod` counterparts from the supplied model
screenshots, plus usage tracking without SKUNK token/spending caps. This
supersedes the earlier allocation-increase plan and the prior local 50M ceiling
for new SKUNK CLI runs. The original VPS error was TokenBudgetExhausted; the
provider metadata request accepted the existing credential and listed the old
model IDs. New mod-ID inference has not been run during this build.

## Presets

| Responsibility | Model |
| --- | --- |
| Orchestrator | deepseek-v4-mod |
| Recon / endpoint discovery / content discovery | deepseek-v4-mod |
| Classifier | deepseek-v4-mod |
| Exploit / independent validation | glm-5.3-mod |
| Report | deepseek-v4-mod |

Both normal DeepSeek v4 variants map to the pictured DeepSeek v4 Pentest ID.
The endpoint remains https://api.hackerai.sh/v1 and the token is unchanged.
New runs configure these exact aliases; older frozen run pins stay historical.
Every role still uses the shared semantic knowledge hook and exact JSON schema.

## Accounting and controls

New host-created SKUNK runs pin `usage_policy.mode=tracking_only`. Persistent
input/output/cached/reasoning usage, monetary estimates and unknown billing
reservations are retained. Monthly/run/campaign/role monetary caps and local
token-allocation/cap/validation-reserve/contract-ceiling enforcement do not block
those runs. A historical contract flag remains recorded instead of being erased.
Quota calculations for legacy bounded ATLAS runs retain their original behavior.
Only the host-created SKUNK policy enables this mode; prompts, imported reports
and model/tool arguments cannot grant it or edit frozen scope.

The backend continues to enforce provider concurrency/circuit cooldowns,
per-task retry limits, wall-clock/model/tool/HTTP request bounds, model context
and schema checks, pause/cancel, scope/DNS/redirect controls, proof/control
verification and the destructive deletion/database/OTP/flooding prohibitions.
Provider-side credits, model access and rate limits are separate from local
accounting. CLI/dashboard show token usage and AI calls.

## Apply to the existing VPS install

Exit the old SKUNK CLI with Ctrl+C first. Extract `skunk-mod2.tar.gz` and run:

```bash
bash skunk-mod2/apply.sh
```

Pass a custom installation directory as the first argument if needed. Use the
same Unix account and runtime-directory settings as the current installation.
This is cumulative: original rc1 and the shipped retry1 code hashes are accepted.
The updater verifies all payload/current-file hashes, acquires the controller
lock, backs up changed source, and rolls back handled installation failures.
It updates both installed source copies. Database, API token, master key,
knowledge/model assets, reports and usage history are preserved.

Then restart the original scope command:

```bash
skunk --agents=8 --scope='*.example.com' --ra --prompt='Prioritize API authorization issues'
```

Older completed/failed runs are not reopened. The new run uses the new model
presets and accounting policy. `skunk diagnose --provider` can check metadata
without inference/target requests. Its report labels new-run policy separately
from historical ledger ceilings and older run pins.

Source compilation, shell parsing, original/retry1 module preimages and release
asset hashes are the build checks. No application test suites, actual model
inference, target scans or VPS execution were performed for this update.
