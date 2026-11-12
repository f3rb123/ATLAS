# SKUNK CLI

SKUNK is the CLI and live dashboard for the existing **ATLAS** engine. The
internal Python namespace stays `atlas`. This delivery is a build candidate:
**application tests, model calls, target scans and VPS deployment were not run**,
as requested. Compiled runtime/dependency files and pinned native tools are
included; no pip, npm, Docker image build or embedding download is needed on the
VPS. Linux x86_64, system CA certificates and Linux user namespaces are required.
The installer installs `bubblewrap` and Git through APT if bubblewrap is missing
and installation is run as root; otherwise install that host prerequisite first.
The sandbox is never bypassed when a host cannot support it.

Apply the cumulative [flow3 update](SKUNK_FLOW_UPDATE.md) to rc1, retry1 or mod2.
It includes mod model presets, usage-only accounting, context packing and cited
specialist coalescing. New tracking-only runs have no run-wide model/tool call
ceiling. The original rc1 archive is an earlier source snapshot.

## Install

```bash
tar -xzf skunk-linux-x86_64.tar.gz
cd skunk-linux-x86_64
bash install.sh
```

Default installation is `~/.local/share/skunk`; the command is linked into
`~/.local/bin`, or `/usr/local/bin` for root. To choose a different fresh directory:

```bash
bash install.sh /opt/skunk
```

Existing installations and runtime stores are not overwritten. Installation
checks the delivered file hashes and does not start a scan or call a model.

## Token and models

The endpoint is preset to `https://api.hackerai.sh/v1`. No key is included.
The exact environment name `hacker-ai-token` is supported, with `HACKER_AI_TOKEN`
as a Bash-friendly alias. Bash cannot use `export` with a hyphenated variable name.

For normal terminal use without putting the key in a command argument/history:

```bash
read -rsp 'HackerAI token: ' HACKER_AI_TOKEN
printf '\n'
export HACKER_AI_TOKEN
```

Alternatively, `skunk token-set` asks privately and saves a local mode-0600 token
file. Environment values take precedence. Tools/models never receive the provider
credential in their prompts; provider bindings use the existing encrypted vault.
If using an environment manager, configure the literal name `hacker-ai-token`.
For shell tools that support `env`, its syntax is
`env 'hacker-ai-token=REPLACE_ME' skunk ...`; use the hidden prompt above for a real key.

| Responsibility | Preset model |
| --- | --- |
| Orchestrator: planning and coordination | `deepseek-v4-mod` |
| Recon: enumeration and discovery | `deepseek-v4-mod` |
| Classifier: vulnerability classification | `deepseek-v4-mod` |
| Exploit: analysis and validation | `glm-5.3-mod` |
| Report: evidence and report generation | `deepseek-v4-mod` |

Eight concurrent slots are the default. Responsibilities include orchestrator,
three recon specializations, classifier, exploit, independent validation and
report. Choosing fewer slots still schedules all responsibilities. Existing
discovery-driven specialist tasks and the independent evidence gate remain.
No synthetic provider probes are run at startup: each actual work response must
pass the role's exact schema before it can authorize any typed tool request.
Malformed results remain failures; unverified native-tool support is not claimed.

## Run

```bash
skunk --agents=8 --scope='*.example.com' --ra \
  --prompt='Prioritize API object authorization and cite reproducible evidence'
```

```bash
skunk --scope='https://app.example.com'
```

The scan flags are:

- `--agents=N`: concurrent slots, 1–16; default 8.
- `--scope=TARGET`: a hostname, URL, IP, `*.example.com` or `*example.com`.
- `--ra`: deeper recon, registered scanner profiles and non-destructive paired checks.
- `--prompt=TEXT`: up to 4,000 characters of additional research instructions.

Keep wildcard strings quoted. `*example.com` is normalized to `*.example.com`:
it allows real subdomains and excludes the apex and lookalike suffixes. A bare
`*` is rejected. Wildcard discovery uses public certificate and URL indexes;
unavailable/truncated indexes and runtime quotas can leave coverage incomplete.
It never substitutes an apex scan when no subdomains are found. HTTP fallback is
only considered when the frozen scope separately allows it. A single hostname
scope matches that hostname, without silently adding its subdomains.

Invoking the command records the host operator's explicit scope instruction;
use it only for authorized targets. Rate, request, time and model/tool-call bounds remain enforced. New SKUNK
runs track token usage without local token or spending caps. `--prompt` cannot change these controls or grant scope.

## Dashboard

The scan binds **http://127.0.0.1:6777** before starting any target work. It shows
live findings/candidates, agent tasks and activity, with **Pause**, **Resume** and
**Cancel**. It has no settings pages, extra navigation or public listener.
An occupied dashboard port stops startup before target dispatch.

Pause blocks new dispatches; requests already in flight can finish. Resume
continues nonterminal work and accounts for pause time. Cancel is terminal;
it preserves captured evidence. Ctrl+C cancels and closes the controller.
After a scan finishes the dashboard stays available until Ctrl+C. A controller
restart does not automatically resume old targets. A private file lock prevents
two CLI controllers using the same runtime store.

For the VPS and phone on the same Tailscale network, run in another VPS terminal:

```bash
tailscale serve --bg --https=8443 http://127.0.0.1:6777
```

Open the HTTPS URL Tailscale prints. Use a free Serve port if 8443 is already used.
The local control API uses a per-process control nonce and no cross-origin access.

## Knowledge file and report folder

The archive includes `knowledge/skunk-knowledge.zip`, the **unchanged original
corpus file**. SHA256:

```text
e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025
```

It contains **21,012 advisory/reference records, 34,229 existing 384-dimensional
vectors and the pinned MiniLM ONNX/tokenizer assets**. Full-text bounty report
count is **zero**. Original record/chunk IDs, vector values, source licenses and
model identity remain intact; they are not regenerated or replaced with hash
embeddings. First scan restores the file into the private runtime store once.

To see the expected folder:

```bash
skunk knowledge folder
```

To copy a separately supplied original file into place and import it:

```bash
mkdir -p ~/.local/share/atlas-skunk/knowledge
cp /path/to/skunk-knowledge.zip ~/.local/share/atlas-skunk/knowledge/
skunk knowledge import ~/.local/share/atlas-skunk/knowledge/skunk-knowledge.zip
```

To add your own permitted reports:

```bash
skunk knowledge add /path/to/reports-folder
```

The importer supports text, Markdown, HTML, PDF, DOCX, JSON/JSONL, CSV and supported
ZIP imports, within existing size/part limits. Newly added reports are embedded
locally with the same pinned model. Source metadata and report claims are
untrusted references. All role profiles use the same mandatory retrieval hook and
can make selective `knowledge.*` queries; models do not receive the whole file.

Runtime data, encrypted provider settings, model assets and reports live under
`~/.local/share/atlas-skunk`. Reports are exported as Markdown, HTML and JSON in
`reports/<campaign-id>/`. Set `SKUNK_DATA_DIR` before launching to select another
private store. Original ATLAS modules and the `bin/atlas-admin` entry point are
included for the existing advanced services; they are not extra dashboard pages.

## Hard guardrails and preserved boundaries

The execution boundary rejects destructive HTTP verbs and deletion routes,
destructive database/query/body actions, encoded/comment-split destructive SQL,
and named OTP/SMS/email delivery/reset flows. Arbitrary shell and direct database
administration are not model capabilities. All target traffic still uses the
frozen scope, DNS/address checks, redirect checks, request quotas and typed
broker. The shared system policy and role-specific prompts reinforce these rules
but do not replace them. Unknown endpoints can have unknown side effects; the
guard is a bounded deterministic policy, not a claim of formal safety for every
application. Its runtime behavior has not been tested in this build.

Confirmed findings still require independent fresh proof/control evidence.
Unverified hypotheses and incomplete runs remain labeled as such. The supplied
historical token floor and uncertain reservations are preserved on a fresh store;
existing ledgers are never reset. New SKUNK runs use host-authorized tracking-only
accounting; historical ledger ceilings remain recorded without blocking those runs. Do not run independent spending clones against
the same original budget. To continue an existing deployment's exact live ledger,
perform an explicit state migration rather than discarding the original database.

The prebuilt contains the same eight pinned native tools as the original release:
httpx, katana, nuclei, ffuf, subfinder, dnsx, naabu and gau, with upstream licenses.
Waybackurls remains owner-managed; raw Amass/masscan remain external-result
imports, as in the original release. This delivery does not invent adapters for
unsupported tools or claim runtime acceptance that has not been performed.
