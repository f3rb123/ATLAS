# Deployment completion work — 10 November 2026

The owner authorized completion of the remaining build, including optional
checks and deployment preparation. Continue in this checkout. Preserve the
supplied ZIP, prior intelligence, keys, database state and original release
tags. Do not substitute fixture success for actual-provider acceptance.

## Execution checklist

| Work package | Current state | Required acceptance |
|---|---|---|
| Identity-preserving corpus restore | Complete in development; real archive and repeat integrity verified | Full real archive preflight, atomic empty-store restore, repeat integrity check, application retrieval and raw omission reporting |
| Bulk transfer API/UI | Implemented; focused API/worker tests and frontend build pass | Bounded resumable upload, durable import job, permission checks, persisted progress and useful errors |
| Shared knowledge and skills | Real application retrieval operational; direct task provenance and output masks added; broader curation pending | All roles and dynamically created specialists use one persisted service; direct task provenance, attributed reviewed references, no whole-corpus prompt injection |
| Scheduler/research/attack chains | Explainable signals/dependencies, attributed research notes and unverified chain links implemented; real-provider lab pending | Explainable priority/freshness, dependency gating, durable collaboration, independent validation gates |
| Model routing | Automatic approved-pool routing/circuits and UI implemented; controlled live swarm pending | Capability/context/cost/health selection, bounded safe retries, circuit state, conservative ambiguous-billing handling |
| Tool management | Central broker registry/API/UI and narrow SecurityTrails/MCP resource adapters implemented; optional scanner harnesses explicitly disabled | Typed registry, protected credentials, versions/health, enable/disable, broker/scope enforcement for every execution path |
| Engagement/chat UX | Durable primary engagement conversation/settings/source/start-stop UI implemented; browser acceptance pending | Persisted target/instructions, explicit scope, agent/model selection, start/stop/resume and real backend activity |
| Complete reference research | Five GitHub sources inspected; three web references remain blocked | Read actual remaining sources once settings apply; distinguish recommendations from observed implementation |
| Optional checks and release | Pending | Real semantic test, sandbox/PG, browser/accessibility, production image/Compose boot, restart/backup/restore, audits and source artifact checksums |
| Actual model acceptance | HackerAI connected; both exact model IDs and structured/tool probes verified; full swarm/lab acceptance pending | Secure provider binding, confirmed models and explicit spend cap; isolated eight-agent lab with actual inference/usage evidence |

## Current provider and scope evidence

HackerAI is configured through the raw file selector `ATLAS_PROVIDER_KEY_FILE`.
The owner-specified `.env` remains raw, untracked, ignored and mode 0600. It is
not implicitly parsed as dotenv configuration. The existing write-only
`ProviderInput.api_key` binding encrypts the credential in application settings;
no key value enters source, arguments, reports or chat.

Both requested IDs were confirmed by actual discovery: `deepseek-v4.1-flash`
and `deepseek-v4-pro`. Both passed actual structured JSON and native tool-call
probes. Provider-reported consumption is 4,402 total tokens (2,354 input,
2,048 output; 204 cached input and 104 reasoning, included in totals), zero
outstanding reservations, 1,995,598 remaining in the initial allocation. USD
prices are unverified and are not presented as confirmed actual cost.

The persistent atomic global ceiling is 50,000,000 tokens, the initial explicit
allocation is 2,000,000, and 200,000 is protected for independent validation.
No automatic reset or silent allocation increase exists. Unknown billing
retains capacity; provider usage above its reservation blocks future calls.

Public internet is now enforced on the running instance. Hugging Face docs
are readable; DeepSeek loads a JavaScript shell; ZSEC/RunMaestro still returned
HTTP 403 and require further normal browser/source inspection. Prior CONNECT
403 evidence predates the applied runtime change.

An owner-supplied private-program screenshot confirms the requested wildcard
scope. Private program details and scope evidence are retained only under the
ignored readiness directory. No target request has occurred. The execution
profile limits the eventual verified-host smoke test to root metadata HEAD
requests, no cookies/authentication, at most two requests and no destructive
routes/parameters. A specific hostname still needs observed scope evidence.

The delivered candidate contains 21,011 advisories and one reference, with no
full-text bounty reports. Do not relabel those records to manufacture historical
report coverage. Original private/full-text assets remain a separate recovery
or permitted-source acquisition dependency.

## Preservation and release boundary

Deployment preparation includes building and starting an isolated local stack,
testing its persistence and producing reproducible private deployment assets.
No real VPS address/authorization or deployment domain/DNS control has been supplied. Provider credentials are locally configured for controlled testing. Do not publish, push, modify remote infrastructure or run
live-target scans under an inferred destination.

Update this checklist, BUILD_LOG.md, NEXT_ACTION.md and requirement status after
each verified package. Record concrete failures and limits instead of declaring
the final product ready prematurely.
