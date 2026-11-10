# ATLAS implementation ledger

## 10 November 2026 — current deployment work

[Verified through actual execution, 10 November 2026] Deployment completion is now authorized and in progress. The real public candidate was restored into the previously empty development corpus through the new identity-preserving package service: 21,012 records, 34,229 384-dimensional MiniLM vectors, 39,985 aliases, 21,359 hash-verified raw files and 150 explicitly withheld artifacts. A consistent pre-import DB backup was retained. Repeat restore verified the persisted fingerprint without replacing rows. All five existing labelled hybrid queries found the expected record in the top five through the application's own corpus service. The real pinned-model semantic test now passes. No corpus re-embedding or original-archive modification occurred.

[Verified through actual execution] Corpus package rejection/atomicity, resumable API upload and restore jobs are covered by 17 focused tests; the combined corpus/knowledge/auth regression set passed 61 tests. Frontend TypeScript passed. Skill retrieval/search events now include direct task IDs; password-only authorized scope configuration no longer mandates optional MFA. A real provider, complete web-reference access, remaining features and full release/Compose acceptance are still pending. See docs/DEPLOYMENT_READINESS.md for the live checklist; prior missing-corpus/model statements below describe earlier milestones.


## 2026-11-09 — source recovery and audit

- Recovered supplied source at `2a7a348c49ae3d3994d7cf2e7de1f3dcc925475f` into the existing isolated `/workspace/ATLAS` checkout; branch `work`, two original release tags preserved. No worktree, reset, remote push or VPS operation.
- Matched both release hashes, verified full Git bundle, compared all 153 ZIP files with Git HEAD. No private runtime state was supplied.
- `UV_CACHE_DIR=/workspace/.cache/uv XDG_CACHE_HOME=/workspace/.cache uv sync --frozen`: passed (84 packages). `npm ci --cache /workspace/.cache/npm --prefix apps/web`: passed (39 packages). Lockfiles unchanged.
- `uv run pytest -q -m 'not sandbox and not semantic'`: **84 passed, 4 deselected**, one upstream deprecation warning. `npm run build --prefix apps/web`: passed production build and TypeScript.
- Inspected existing runtime, corpus, gateway, broker, verification, auth, skills, API/UI and deployment paths. Recorded implementation truth table and eight-reference research; added AntiFox per owner update.
- Configuration draft: requested only the three mandatory website hosts and Hugging Face. Runtime application/publishing unverified. No provider secrets requested or invented.
- Added the eight requested living project documents. No application behavior changed in this checkpoint. Next package: shared knowledge runtime plus regression evidence.

## External limits

Original corpus/database and embedding weights withheld; historical public inventory is not a live count. No owner-provider keys, historical 64-resource manifest or VPS supplied. Websites denied by egress before authentication. Local test providers are explicitly synthetic; no remote-target scan occurred.

## 2026-11-09 — first implemented rebuild slice

- Shared knowledge runtime: versioned system policy, persisted availability, bounded task retrieval, eleven typed tools, source attribution, on-demand source/skill lookup, feedback and immutable owner review. Every role/protocol uses the same harness; swarm tool artifacts return to reasoning within a bounded loop.
- SQL tasks and additive migration `0005`: eight differentiated roles, 1–16 slots, concurrency, cited-discovery subscriptions, follow-up review, dedupe, fenced leases/heartbeat, bounded recovery/dead letters, cancellation and partial completion/reporting. Existing FSM remains available as `execution_mode=legacy`.
- Preserved policy/broker/relay and independent proof/control replay; connected swarm hypotheses to separate verifier tasks. No self-confirmed findings, arbitrary shell, live scan or scope widening.
- Improved concurrent gateway reservations/call accounting and provider concurrency; safe undispatched capacity waits requeue. Known interruption is distinct from ambiguous billing. Unknown outcomes remain reserved and require reconciliation.
- One-model-for-all and capability-alias run modes. Actual models remain owner-configured; historical HackerAI IDs are unverified. Automatic failover, advanced recon/MCP management and attack-chain analytics remain pending.
- Password-only private operator access, optional enrolled factors/strict MFA mode, password change/session rotation and existing CSRF/RBAC/cookie/encryption/audit controls. Host recovery preserved. UI adds instructions, agent/model/execution selection and persisted live swarm/usage/source views; conversational engagement chat remains pending.
- Two external MIT methodology references as research-only data with pinned commits, SHA256 and license notices; immutable repeat installation/content integrity. Upstream executable libraries are not silently approved or globally installed.

### Validation on this instance

| Check | Outcome |
|---|---|
| `ATLAS_TEST_POSTGRES_URL_FILE=.runtime/pg-validation-url uv run pytest -q -m 'not semantic'` in supported outer context | **138 passed, 1 deselected**, 24.42s; one real semantic integration needs missing model assets |
| Existing/new Bubblewrap tests | Five sandbox cases included above. Real source proof/control execution; model/corpus fixtures explicitly synthetic |
| PostgreSQL integration | Included above: real pinned pgvector container, migrations 0001–0005 (second upgrade idempotent), four overlapping tasks, fresh physical connections/persistence. Isolated schema removed; no application schemas touched |
| Seven protocol serializers × four roles | Included above; shared policy/tool/retrieval contract with synthetic outputs, not live vendor validation |
| Frontend production build/TypeScript | Passed with swarm component and model selection |
| Final `ATLAS_TEST_PROVIDER_DELAY=0.25 bash scripts/ci-e2e.sh` | **1 browser test passed**, 12.4s: password-only bootstrap access, optional browser WebAuthn, provider/model settings, eight persisted tasks, pause/resume/approval, usage, reports, memory, CLI and limited axe checks. Models/one-record lexical corpus are fixtures |
| New-file Ruff, touched-source undefined-name checks, compilation, shell syntax, diff whitespace | Passed; full legacy lint cleanliness not claimed |
| Production/private Compose config | Parsed with repository placeholder production env. No production stack/VPS deployment claim |
| Wheel | Built; shared runtime and both reference texts/catalog/license notices included |
| `scripts/cloud-install.sh` | Executed with frozen locks/production build; accurately reports semantic assets unavailable |
| `scripts/cloud-start.sh` | API/research/verifier/corpus/web started; actual DB readiness/rendered web request passed; stop/restart retained isolated developer DB/key and additive migration state |

Warnings: upstream Starlette/httpx TestClient deprecation and existing SQLAlchemy vector reflection. Nested sandbox failures were diagnosed and the same tests passed outside the wrapper. Browser integration exposed reservation pressure and orphaned npm frontend processes; fixed safe waiting/interruption handling and direct tracked child startup, then reran successfully. Current browser artifacts now use ignored `.runtime/test-results`; original tracked release evidence is preserved. Dependency declarations/lockfiles unchanged.

### Reusable configuration and remaining work

Confirmed saved: complete `install_script` and `start_skill`, alongside four required-domain additions. Instructions use the existing isolated checkout, restart required services, preserve original data/keys and distinguish retained files from processes. Saving did not apply access or publish. Runtime still reports original enforced policy/revision, no custom allowed hosts and no secret/runtime bindings.

GitHub was empty; source/history are local from the supplied bundle. No push authorized/performed. Fresh-task local-only commit restoration is not established; preserve checkout/bundle. Current developer services use isolated `.runtime/cloud-dev`, with no owner/provider/original corpus provisioned. Publication and production deployment remain unverified.

Next: apply egress additions, finish three inaccessible references, obtain cleared original assets or approved pinned model access, validate real semantic retrieval/labelled queries, configure owner providers securely and perform real-model lab acceptance. Continue routing/fairness, advanced tools, chat and chain work from the roadmap. This is the first implemented slice, not the full rebuild.

## 2026-11-10 — secure provider binding, token quota and content views

- Added `ATLAS_PROVIDER_KEY_FILE` raw-file loading with regular-file/mode/size/newline checks; `.env` is no longer implicitly parsed as config. Dotenv configuration is explicit via `ATLAS_CONFIG_FILE`. The actual owner-supplied key was loaded and sealed in existing provider settings without exposing or reformatting it. A fresh local operator was provisioned only because no owner existed; credentials remain in a private ignored local file. No existing account or production credential was changed.
- Persistent token ledger: authorized ceiling 50M, initial allocation 2M, validation reserve 200K. Reservations share the monetary global lock, include framing/output headroom, cover probes and regular model calls, survive restarts and never reset automatically. Cached/cache-creation/reasoning counters are tracked separately without double counting. Unknown billing holds reservations; reported contract violations freeze dispatch. USD confirmation is separate from token confirmation.
- Actual HackerAI discovery confirmed both exact requested models. Four structured/native-tool capability probes passed with provider-reported usage 4,402 total tokens, zero pending reservations, 1,995,598 allocated tokens remaining. Verified USD pricing remains unavailable; costs are labelled estimates. No model substitution or automatic paid retry occurred.
- Fresh Gitleaks 8.24.3 scan: 2,148 detections across normalized/raw data. Independently checked identity/model metadata accounts for 2,121 false positives. Remaining 23 normalized findings and four raw findings are conservatively withheld in model-facing content views; they are not asserted to be live secrets. Fourteen fields across eight records are masked; three raw artifacts are flagged for export withholding. Stored records/vectors and original ZIP are unchanged. Source-SHA-specific metadata installs the same masks on a new restore.
- Added execution-layer destructive-route/parameter rejection and an immutable metadata-only smoke profile. Private scope evidence remains ignored, not part of source delivery. No SBICard target request performed.
- Focused regression: 91 passed; provider-file/token/gateway subset: 36 passed; TypeScript passes and the production frontend built. Restarted only the five registered ATLAS development children; API/web and 21,012-record/34,229-vector availability recovered. Full swarm, feature and final deployment gates remain in progress.
