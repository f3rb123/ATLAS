# SKUNK validate5 — 12 November 2026

Two execution defects were reproduced offline and corrected:

1. The resume4 web prompt applied its research-summary contract to independent
   verification as well. The verifier's real schema requires a verdict, reason,
   counterfactual and evidence IDs. These contradictory instructions could
   exhaust schema corrections instead of producing a verification verdict.
   Verification now receives its own contract and schema-valid inconclusive
   correction example. The proof/control evidence gate is unchanged.
2. Registered checks were planned before scanner-discovered URLs were added to
   the bounded crawl. Later query endpoints could therefore miss automatic
   checks. Planning now follows the full discovery frontier and deduplicates
   identical check specifications. It uses the same existing registered classes,
   request bounds and frozen scope, and records a validation-plan event.

The web task instruction now explicitly asks for available registered checks on
evidence-backed leads, with blocked prerequisites recorded. A hypothesis or a
completed reasoning task still does not establish a vulnerability.

Actual recorded progress can be inspected without dispatching work:

```bash
skunk diagnose --activity
```

This reads the latest owned assessment and prints response/host counts,
completed registered checks and paired experiments, scanner process counts,
candidate/replay/verdict states, compact failure/denial counts and an explanation
of the current pipeline bottleneck. It omits URLs, response bodies, cookies,
credentials, claims and provider output. Model/target requests and writes are
zero. The dashboard also shows registered validation runs and the bottleneck
explanation; its activity statistics refresh at most once per five seconds.
The full preflight now reconstructs the same web schema as actual workers.

Exit the existing controller with Ctrl+C before installing. This cumulative
24-file source update accepts original rc1/retry1/mod2/flow3/resume4 code and
preserves knowledge/vectors, credentials, usage, uncertain holds and old reports.
No scan starts during installation. Model IDs remain `deepseek-v4-mod` and
`glm-5.3-mod`; owner-selected tracking-only accounting has no local token,
spending or model/tool-call caps.

For new discovery and validation, explicitly start a fresh authorized run:

```bash
skunk --agents=8 --scope='*.your-authorized-domain.example' --ra
```

Use your actual authorized scope. `skunk resume --latest` remains available for
recoverable unfinished work. It preserves old scope and completed tasks, so a
completed discovery task is not repeated. In particular, resume cannot add the
paired-experiment class absent from an older frozen policy. Fresh `--ra` runs
include that registered class. Policy checks that enforce authorized scope,
destructive-operation/OTP prohibitions, owned test identities and independent
evidence remain; this update does not disable them or fabricate findings.

Default root-install knowledge paths:

- Original archive: `/root/.local/share/skunk/knowledge/skunk-knowledge.zip`.
- Imported records/vectors: `/root/.local/share/atlas-skunk/skunk.db`, in
  `knowledge` and `knowledge_chunks`.
- Embedding weights: `/root/.local/share/atlas-skunk/models/`.

The archive contains `corpus.semantic.vectors.jsonl`. `SKUNK_DATA_DIR` changes
the runtime paths; an installation-prefix override changes the archive path.

Offline diagnosis captured the actual conflicting pre-fix verifier prompt and
the corrected prompt before any dispatch. A simulated scanner/frontier result
reproduced two pre-fix checks versus three repaired checks, with the later query
endpoint now included under the same scope. Activity counts and privacy were
inspected with synthetic in-memory SQL and network blocked. Source compilation,
shell/JavaScript syntax and artifact hashes are checked separately. No
application test suite, paid model call, live target scan or VPS deployment was
performed. These defects are confirmed in code; the current VPS run's reason
for zero findings requires its activity output. No vulnerability is promised.
