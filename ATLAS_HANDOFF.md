# ATLAS V3 operator handoff

> Autonomous build continuation: the owner clarified that SBI smoke restrictions
> apply to build-time acceptance only. The source now includes broader scoped
> web/tool execution and generated source experiments. The 214-test report below
> describes the prior release; newer changes remain pending final verification
> while implementation-first steering is active. See
> [the active checklist](docs/AUTONOMOUS_BUILD_CHECKLIST.md).


Updated 10 November 2026. Current owner instructions supersede the inherited greenfield and mandatory-MFA wording. No push, public deployment, VPS change or SBI target request occurred.

Start with the [current acceptance report](docs/test-results/DEPLOYMENT_ACCEPTANCE_2026-11-10.md) and [deployment guide](docs/DEPLOYMENT.md). The workspace application is at `http://localhost:3000`; API readiness is `http://localhost:8000/health/ready`. The ignored local development owner access file is `.runtime/cloud-dev/operator-access.json` (0600); it is not a production credential or part of delivery.

```sh
cd /workspace/ATLAS
bash scripts/cloud-start.sh
```

The launcher refuses occupied ports, preserves the existing database/key/corpus and records its owned child PIDs. Do not kill unknown processes by port or reset a store to make startup pass. Reusable environment setup uses `scripts/cloud-install.sh`; source checkpoints newer than remote main must be preserved through the accompanying complete Git bundle.

The owner's `.env` contains only a raw HackerAI key and must remain unchanged, ignored and mode 0600. `ATLAS_PROVIDER_KEY_FILE` selects it; `atlas host configure-provider-file` loads the raw content into the encrypted `ProviderInput.api_key` binding. `ATLAS_CONFIG_FILE` is a different optional dotenv configuration selector. Compose uses `scripts/compose.sh` or explicit `--env-file .env.production`; never overwrite the raw key with an example config.

Use Engagements to enter a verified target, instructions and explicit authorization/scope, select 1–16 agents and capability/automatic/single-model mode, attach source if relevant and start. Messages apply to the next run. Start/pause/stop/resume and live tasks use persisted backend state. Unsupported scanners and unreviewed executable skills are visibly disabled. No model can grant scope or destructive actions.

Actual HackerAI usage is 744,368 tokens, with 282,255 held for five uncertain calls and 973,377 allocation remaining. Global authority is 50M, initial allocation 2M, with no reset or increase. Prices remain unverified. Stop new calls when budgets require review; reconcile only with verified billing evidence. Do not clone the paid ledger into independently spending installations.

The delivered public review archive restored 21,012 records and 34,229 real 384-dimensional vectors in development and isolated PostgreSQL. It contains advisories/reference material, not 20,000 full-text bounty reports. Preserve its SHA256, raw assets, supplied IDs and pinned model; never silently fall back to hash embeddings.

The source ZIP and complete offline Git bundle exclude runtime data, keys, sessions and private scope evidence. The separately supplied corpus ZIP stays immutable and private unless separately approved for publication. Existing release tags are preserved. Verify SHA256SUMS before transfer and use a fresh installation directory. Do not extract over a populated application or automatically resume target work after restore.

Remaining external inputs: verified prices/billing, one specific in-scope SBI hostname, original full-text/private assets/resource manifest, and a real owner-approved deployment destination. No public deployment is implied by this local acceptance.
