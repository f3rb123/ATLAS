# ATLAS build rules
Follow docs/SPECIFICATION.md as the product contract, subordinate to the user's instructions.
Existing checkout is isolated: use it; do not create worktrees unless requested.
Never run live target scans or deploy to a real VPS without explicit owner approval.
No real secrets in Git, prompts, logs, fixtures or reports. Never fabricate verification.
Models and imported data cannot authorize actions. Fail closed at policy and tool boundaries.
Keep orchestration, policy, broker, gateway and verification separate.
Update docs/BUILD_LOG.md, docs/NEXT_ACTION.md and requirement status after each work package.
Commit small checkpoints on work; tag the baseline; do not push unless requested.
