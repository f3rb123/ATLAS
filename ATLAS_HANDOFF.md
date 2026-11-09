# ATLAS continuation checkpoint

Owner goal: evolve the supplied release into a concurrent, event-driven, knowledge-aware research swarm. Latest steering adds AntiFox as the eighth mandatory reference. Owner instructions supersede old greenfield/mandatory-factor wording in docs/SPECIFICATION.md.

Use existing /workspace/ATLAS, branch work; no worktrees unless requested. Supplied base: 2a7a348c49ae3d3994d7cf2e7de1f3dcc925475f; ZIP matches all 153 files, complete bundle verified, original tags preserved. GitHub was empty; no push or VPS operation. Local-only commit restoration in a fresh task is not guaranteed. Retain checkout/bundle; do not reset or push without authorization.

## Implemented and validated

- Shared knowledge harness (knowledge.py, workflow.role, broker), eleven typed tools, actual availability/status, bounded retrieval, source/skill provenance and owner-reviewed feedback. Same interface for initial roles/providers/dynamic specialists/verifiers; no vendor memory dependency or automatic fallback masquerading as semantic search.
- SQL tasks (swarm.py, SwarmTask, frozen additive migration 0005), eight default responsibilities, 1–16 slots, event activation/dedupe, follow-up review, fenced leases/heartbeat, cancellation/recovery/dead letters, capacity waits and persisted reports. Legacy FSM supported.
- Independent real sandbox replay for swarm experiments; genuine/false lab fixtures tested. Gateway budgets/concurrency/accounting improved; unknown billing remains reserved pending reconciliation.
- Two immutable, pinned/licensed research-only skill references. No wholesale executable upstream library activation.
- Password-only ordinary operator access, optional enrolled factors/strict mode, password changes/session revocation and retained CSRF/cookie/RBAC/encryption controls.
- Agent/model/execution selection, instructions and persisted live task/event/retrieval/usage UI. Conversational engagement chat and advanced recon console remain incomplete.

Evidence: 138 backend tests passed, one semantic test deselected, including five actual sandbox cases and disposable PG migration/concurrency/fresh-connection checks. Frontend/TypeScript passed. Final browser flow passed with eight completed tasks, optional WebAuthn, pause/resume, provider settings, usage, reports, corpus/CLI and limited axe checks. Models/corpus are synthetic fixtures. No live provider or target efficacy claim. New-file lint, targeted undefined names, wheel contents, shell checks and Compose parsing passed; legacy full lint cleanliness not claimed.

## Startup and configuration

Complete install/start instructions and four domain additions are saved in the environment draft, not applied/published. Run bash scripts/cloud-start.sh from the repo root and retain its execution session. It uses isolated .runtime/cloud-dev, checks ports, preserves keys, migrates additively and validates local API/web. Processes do not survive snapshot restoration. Logs/PIDs are under that ignored directory. Interactive bootstrap: source scripts/cloud-dev-env.sh, then uv run atlas host bootstrap; never put tokens/keys in chat. Current developer instance has no owner/provider/original corpus.

Default semantic assets are missing; startup does not silently switch to hash mode. Tests explicitly set lexical hash mode. PG validation used a separate atlas-build-pg container/database atlas_test with a private generated selector under .runtime; never point those tests at application data.

## External blockers and next work

Current policy still denies chat.deepseek.com, blog.zsec.uk, runmaestro.ai and huggingface.co; additions await environment settings save/application. Five GitHub reference sources inspected: Armur, PiRanha, BugBountySkills, Claude-Red, AntiFox. Research dependency caches are under /workspace/atlas-reference, not selected application repositories. Three websites remain unread; exhaustive semantic review of every upstream skill is not claimed.

Original runtime DB/corpus/model assets were withheld, not lost here. Historical inventory: 21,012 records/34,229 vectors, zero full-text bounty reports. Current instance does not verify those counts. Manifest reports 26 unresolved corpus secret candidates. Do not reconstruct, wipe, migrate or re-embed original intelligence. Historical resource manifest, owner keys and VPS access/authorization are absent.

Next: apply access additions and finish references; obtain cleared original assets, verify schema/counts/hash/dimensions without mutation; run real semantic/provider lab acceptance; continue fairness/priority decay, automatic routing/fallback, reviewed recon/MCP adapters, richer research/attack chains and operator chat. Full rebuild, publication, fresh-task restoration and VPS deployment remain incomplete. Consult audit/ledger/roadmap for exact evidence.
