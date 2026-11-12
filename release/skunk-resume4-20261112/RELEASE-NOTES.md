Recover the saved SKUNK assessment without rerunning completed tasks. This cumulative update also replaces the web result schema that was accepting repository-only planning fields, improves bounded JSON corrections, exposes unverified shared-board leads and records coverage limitations.

Exit the existing CLI with Ctrl+C, then download and apply this code update under the same account/runtime. Installer execution starts no scan. After installation:

```bash
skunk resume --latest
```

For a specific saved assessment: `skunk resume --run RUN_ID`. The dashboard opens on `127.0.0.1:6777`; existing Tailscale Serve forwarding continues to work.

Recovery preserves the original target, frozen scope/hash, model/provider pins, encrypted credential, completed tasks, cumulative attempts, HTTP quota usage, knowledge/vectors, token/spending records and uncertain billing holds. Four further bounded attempts are allowed per explicit recovery. Prior failures get durable history snapshots. Policy-denied tasks stay denied; expired authorization, emergency stop and live task leases refuse recovery. New exports use `.resume-N` filenames alongside the old reports.

Defaults remain `deepseek-v4-mod` and `glm-5.3-mod`. Usage is tracking-only with no local token, spending or model/tool-call caps. Scope, request quotas, destructive-operation/OTP prohibitions and independent proof/control verification remain enforced. Shared-board leads are explicitly unverified and never counted as confirmed findings. Saved scopes are not expanded; fresh `--ra` scopes include the existing registered paired HTTP experiment class.

The cumulative archive contains 22 source/assets files and accepts original rc1/retry1/mod2/flow3 installations. Unknown local edits are refused; replaced code is backed up. It does not reinstall the 21,012 knowledge records / 34,229 vectors.

Build source: `379c0df570774aa5c037b3e048da795f18a48596`.
Archive: `skunk-resume4.tar.gz`, 85,132 bytes, SHA256 `ff9a4f4a75c59108255616e6d13d674b2d6524714446a67d55073973ac44d3be`.

Source compilation, shell/JavaScript syntax, payload/preimage hashes and synthetic offline recovery/JSON inspection passed. Network was blocked for recovery inspection and SQL was in memory. No application test suite, paid inference, live target request or VPS deployment was performed. Actual VPS/provider recovery awaits the owner's trial. A task completing is not proof of a vulnerability; findings still require independently verified evidence.
