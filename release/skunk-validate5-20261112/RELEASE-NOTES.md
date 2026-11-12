Fix two reproduced execution defects: resume4 supplied a research-summary instruction to the independent verifier despite its verdict schema, and automatic checks were planned before scanner-discovered URLs joined the bounded crawl. The verifier now receives its own contract, and check planning runs after discovery finishes under the same frozen scope.

Exit the current CLI with Ctrl+C, install this cumulative update, then inspect recorded execution:

```bash
skunk diagnose --activity
```

The compact read-only report separates target responses, completed checks, hypotheses, replay candidates, independent tasks/verdicts and denied/failed work. It starts no model or target requests and omits URLs, bodies, cookies, credentials and claims. Dashboard validation counts and a plain-language bottleneck explanation are included.

To use the discovery correction, explicitly start a fresh deep assessment of your authorized scope:

```bash
skunk --agents=8 --scope='*.your-authorized-domain.example' --ra
```

`skunk resume --latest` still recovers unfinished work; completed discovery and the saved scope remain unchanged. Fresh `--ra` runs include the already registered nondestructive paired HTTP experiment class. Scope, destructive-operation/OTP prohibitions, owned identity requirements and independent proof/control verification remain enforced. No findings are synthesized. The source fixes are reproduced; the current VPS run's actual reason for zero findings needs its activity output.

Defaults remain `deepseek-v4-mod` and `glm-5.3-mod`, with owner-selected tracking-only usage and no local token/spending/model-call/tool-call caps. The update preserves knowledge/vectors, model cache, API credential, cumulative usage/uncertain holds and old reports. Installer execution starts no assessment and refuses unrecognized source edits or an active controller.

Default root-install archive: `/root/.local/share/skunk/knowledge/skunk-knowledge.zip`. Imported vectors are in `/root/.local/share/atlas-skunk/skunk.db` (`knowledge_chunks`); embedding weights are in `/root/.local/share/atlas-skunk/models/`. `SKUNK_DATA_DIR` changes runtime paths.

Source: `78b0b2c814fe62a15804146ac83ed0073f326b30`. Cumulative 24-file archive: `skunk-validate5.tar.gz`, 96,816 bytes, SHA256 `66fd2afc41f395ea2961fde1ffa466cbe8b4c6be6a5bd8a1dc512de9d44a632c`.

Offline reproduction captured the old/corrected actual verifier requests before dispatch and simulated discovery through the tool broker (2 old versus 3 repaired checks for the supplied fixture, including the later endpoint). SQL was in memory, network blocked. Activity output privacy, source compilation, shell/JavaScript syntax and payload/preimage hashes were inspected. No application test suite, paid inference, live target request or VPS deployment was performed. Actual VPS/provider acceptance remains pending.
