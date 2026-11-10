# Current support: failed assessment runs

Docker 29 compatibility repair succeeded according to owner-provided VPS output.
The full corpus/vectors/model restore completed and API/PostgreSQL/Redis were
healthy. Assessment runs still end completed+partial with all eight specialists
dead_letter ProviderError. Latest supplied diagnostic: zero model calls,
model_mode auto, web_enabled false, valid model pins and closed circuits, no
saved routing decisions. Do not claim the exact remaining cause is known.

Use scripts/diagnose-prebuilt-run.py on the VPS for read-only cached-context
preflight. It replaces inference dispatch with a stop sentinel, prohibits Python
network connects, replaces knowledge broker with saved artifact reads, and sets
the database transaction read-only. It reports prompt sizes and router eligibility
without leaking prompts/credentials. It is a diagnostic, not acceptance evidence.
Do not repeatedly relaunch paid runs, change model limits without evidence or
mark the original product fully production-ready. Enable web discovery through
Engagements for a future authorized new run; scope changes do not enable it.

Keep all original data, master/target/provider keys, corpus/model bytes and token
holds. Global cap50M, initial2M; last owner report used749553, reserved282255, held
for reported failed run0. Never reset/release uncertain holds/replay calls or
create independent spending clones. GitHub delivery and Docker29 repair details
are in docs/DELIVERY_PREBUILT_2026-11-10.md and the build log. No automatic tests,
provider calls, targets or server mutations on startup.
