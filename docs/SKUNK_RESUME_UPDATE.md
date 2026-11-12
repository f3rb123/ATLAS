# SKUNK resume4 update — 12 November 2026

This cumulative code update applies to the original SKUNK rc1 installation,
retry1, mod2 or flow3. It preserves the runtime database, API credentials,
knowledge/vector files, usage counters, uncertain billing holds and old reports.
Exit the old SKUNK CLI with Ctrl+C before installing. The installer refuses an
active controller or unrecognized local source edits and starts no assessment.

After installing, run:

```bash
skunk resume --latest
```

An explicit saved run can be selected with `skunk resume --run RUN_ID`. The
latest selection never silently falls back to an older target when the latest
run has no recoverable work. The same local owner and runtime directory must be
used. The loopback dashboard opens on port 6777 with pause/resume/cancel controls;
an existing Tailscale Serve configuration continues to forward that port.

Resume retries recoverable unfinished tasks and cancelled dependents whose
dependencies are now recoverable. Completed tasks and policy-denied tasks keep
their states. A running worker lease, emergency stop, expired authorization,
changed policy hash or unavailable model pin prevents recovery. It retains the
original target, frozen scope, model/provider pins, encrypted credential and
HTTP request quota. It does not rediscover wildcard assets or add identities or
permissions to a saved campaign. Stop an old controller and allow an in-flight
worker lease to expire if recovery reports an active lease.

Each explicit recovery permits four new bounded attempts with backoff. Prior
attempt counts are retained, and prior task failures are copied to durable
history before requeueing. Usage remains tracking-only, with no local token,
spending or model/tool-call caps; context limits, request quotas, scope and hard
destructive-action/OTP prohibitions remain enforced. Retried requests are billed
separately. Unknown prior billing reservations are retained.

New exports use `RUN_ID.resume-N.md`, `.html` and `.json` in the existing
campaign report folder. Original report files/documents remain. A new final
report is scheduled for each recovery cycle.

Web agents now receive a smaller result schema without repository-only surface
maps or local unittest experiments. Exact validation feedback includes field
types/constraints and a minimal JSON example. A completed thinking prefix or a
single unambiguous JSON fence can be decoded; ambiguous objects, duplicate keys
and invalid responses are rejected. Typed tool validation and independent
proof/control verification are unchanged.

The dashboard and Markdown/HTML/JSON reports now expose shared-board hypotheses
as explicitly unverified leads. These do not count as confirmed findings. Reports
also describe missing test identities, unavailable paired HTTP experiments and
bounded wildcard coverage. A successful task is not proof of a vulnerability.

Fresh `--ra` scopes include the registered nondestructive paired HTTP experiment
class. Saved scopes remain frozen; unavailable experiment tools are omitted from
their model catalog. No target accounts or credentials are synthesized.
Wildcard public-index collection retries transient failures up to three times
per registered source and records unavailable/truncated coverage. This still
does not establish a complete inventory of all subdomains.

Default models remain `deepseek-v4-mod` and `glm-5.3-mod`. The dashboard footer
now displays the actual pinned role model IDs.

Validation consists of source compilation, shell syntax, artifact integrity and
synthetic offline recovery/JSON diagnostics with network blocked and in-memory
SQL only. No application test suite, paid inference, live target scan or VPS
deployment was performed. Real provider behavior and saved VPS recovery await
the owner's explicit run; no findings are promised or fabricated.
