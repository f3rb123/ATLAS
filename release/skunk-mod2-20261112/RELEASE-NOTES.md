Cumulative small update for existing SKUNK rc1/retry1 installations. The internal namespace remains atlas.

## Owner-selected Pentest presets

| Responsibility | Model |
| --- | --- |
| Orchestrator, recon, classifier, report | `deepseek-v4-mod` |
| Exploit / independent validation | `glm-5.3-mod` |

Exact -mod counterparts are taken from the owner's supplied screenshots. The HackerAI endpoint and API token remain unchanged. Actual inference/availability of these new IDs has not been probed in this build.

## TokenBudgetExhausted repair

The owner supplied TokenBudgetExhausted errors and explicitly requested no local token/spending caps. New SKUNK runs pin host-owned tracking-only accounting: local token allocation/cap and monthly/run/campaign/role monetary caps no longer block dispatch. Real usage counters, unknown billing reservations, original ceilings and contract flags remain recorded. Old counters are never zeroed, reservations never discarded, and legacy bounded ATLAS runs retain their policy.

This supersedes the earlier 10M allocation-increase plan. There is no need to run that older budget helper. Provider-side credits/access/rate limits remain the provider's authority. Scope, destructive database/delete/OTP guards, exact schemas, evidence verification, concurrency, bounded retries and request/time/model/tool limits remain enforced.

## Apply the update

Exit the SKUNK CLI with Ctrl+C first. Run under the same Unix account/runtime settings:

```bash
( set -e; skunk_mod_dir=$(mktemp -d); cd "$skunk_mod_dir"; skunk_mod_url=https://github.com/f3rb123/ATLAS/releases/download/skunk-mod2-20261112; curl -fL --retry 3 -O "$skunk_mod_url/skunk-mod2.tar.gz"; curl -fsSL --retry 3 -O "$skunk_mod_url/skunk-mod2.tar.gz.sha256"; sha256sum -c skunk-mod2.tar.gz.sha256; tar -xzf skunk-mod2.tar.gz; bash skunk-mod2/apply.sh )
```

The updater accepts original rc1 and shipped retry1 code hashes, verifies both source copies, backs up replaced modules and rolls back handled install failures. Existing data, API token, knowledge/model assets and usage records are preserved. It starts no scan or inference.

Then restart the original scope command as a **new run**:

```bash
skunk --agents=8 --scope='*.example.com' --ra --prompt='Prioritize API authorization issues'
```

Historical failed tasks retain their old states. The new run uses the mod presets and tracking-only policy. `skunk diagnose --provider` can check catalog metadata without inference or target traffic. See SKUNK-MOD2-README.md for details.

## Build evidence

Source compilation, shell parsing, original rc1 module preimages (16 matches), retry1 module preimages (8 matches), archive construction and SHA256 checks. No application test suites, actual model inference, target scans or VPS execution were performed. Runtime acceptance is not claimed.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `skunk-mod2.tar.gz` | 59,131 | `0ec68c1c94c9d65adb5b823760a1c557eabba8306e9032187929da7c5e0ad71e` |
| `skunk-mod2.tar.gz.sha256` | 84 | `638239bb512f7717ec9aa9795d4310d96188fe5e10d9b5957a46aeee08b851ef` |
| `SKUNK-MOD2-MANIFEST.json` | 4,908 | `339c8ab437944043be2e39580c76eb2cbddd2c7ae22a91ced4d42ca19f9eb898` |
| `SKUNK-MOD2-README.md` | 3,520 | `8100b9504444943caad7cde2190d48b0103a5e97af14c8c21ced00a7c90a76e8` |
| `skunk-source-mod2.tar.gz` | 1,356,841 | `1fb4212e11e256b81da5c479c69c10a9f5f5782b4f09eb273ae5f5b3ac40b082` |
