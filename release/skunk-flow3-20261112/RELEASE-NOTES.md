Cumulative update for rc1, retry1 and mod2 installs. Defaults remain deepseek-v4-mod and glm-5.3-mod with ATLAS internals and SKUNK branding.

The owner supplied VPS evidence of completed work followed by model_call_limit, context_limit and unavailable local repository reproductions. This update fixes those harness paths.

## Changes

- Tracking-only SKUNK runs do not stop at run-wide model/tool call counters. Counts and usage are still recorded. Legacy bounded ATLAS enforcement is preserved.
- Exact UTF-8 context packing separates evidence from complete selected input schemas and response contracts. Field names, required lists, enums and constraints remain intact. A wide metadata dictionary cannot evade evidence trimming. The full allowed-tool catalog remains available, with invalid-input schema priority on follow-up.
- Cited-role follow-ups deduplicate and compatible queued leads coalesce. Follow-up generations/per-role work remain bounded, final report capacity is reserved, and deferred leads remain recorded with incomplete coverage.
- Web-only tasks advertise local experiments as unavailable. Unsupported reproduction proposals remain blocked, but valid observations and hypotheses survive. Policy denials do not become permissions.
- Scope, destructive database/deletion/OTP guards, independent proof, model context/schema, per-task rounds/retries, time/request/concurrency controls remain enforced.

## Update

Exit SKUNK with Ctrl+C first, then run under the same account/runtime:

```bash
( set -e; skunk_flow_dir=$(mktemp -d); cd "$skunk_flow_dir"; skunk_flow_url=https://github.com/f3rb123/ATLAS/releases/download/skunk-flow3-20261112; curl -fL --retry 3 -O "$skunk_flow_url/skunk-flow3.tar.gz"; curl -fsSL --retry 3 -O "$skunk_flow_url/skunk-flow3.tar.gz.sha256"; sha256sum -c skunk-flow3.tar.gz.sha256; tar -xzf skunk-flow3.tar.gz; bash skunk-flow3/apply.sh )
```

Then restart your original scope command as a new run. Existing keys, knowledge/model assets, database, reports, counters and uncertain holds are preserved. Historical task errors are not relabelled as successful. The updater verifies current/payload hashes, locks the controller, backs up changed code and rolls back handled errors. It starts no scan or inference.

## Verification

Offline diagnostics (network disabled) reproduced the old context failure on a broad synthetic record; the new context packed to26,419 bytes under34,000. Another8.6MB synthetic pack became32,736 bytes with45,424 for system/prompt/output allowance under64,000. Selected schemas and operator text remained intact. An in-memory scheduler merged three leads into two queued tasks, reused repeated evidence and deferred depth3. These are synthetic diagnostics, not an actual saved VPS prompt or live acceptance.

Source/shell checks and original/cumulative preimages/digests were checked. No full application/browser suites, paid inference, target scans or VPS execution were performed. See SKUNK-FLOW3-OFFLINE-CHECKS.json and SKUNK-FLOW3-README.md.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `skunk-flow3.tar.gz` | 73,448 | `4eb380c013d7000f328c1dd4b3bb8289441b480f2904e788dced53b21cba43de` |
| `skunk-flow3.tar.gz.sha256` | 85 | `0f434df279173972d5bdd1176294252e5edd92590ca6282b9dabd246f2786f5b` |
| `SKUNK-FLOW3-MANIFEST.json` | 6,732 | `39b61a5886add689b5acb67057564adf842a7f818c1c385c6fb0a985238666ba` |
| `SKUNK-FLOW3-README.md` | 4,342 | `ad4a0b14616f9796edcad31e2846f0d00f5b69398d63466aec6c75c74b754369` |
| `SKUNK-FLOW3-OFFLINE-CHECKS.json` | 1,425 | `b3849d26b7bf7051b8a2d0386722e3027263e03a03ccdd0597efd0ddb56aea06` |
| `skunk-source-flow3.tar.gz` | 1,366,307 | `583bbb77a92a9b8f0d8d79b2dbe6bd139ca708e8007a1e14b499fe72e45f3caf` |
