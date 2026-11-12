SKUNK CLI 3.1.0rc1, backed by the ATLAS engine. Build candidate for Linux x86_64; runtime acceptance has not been performed.

## Download and install

The full `skunk-linux-x86_64.tar.gz` archive includes the portable Python runtime, locked dependencies, eight pinned native tools, source, install script, and the original knowledge/model ZIP. The separate knowledge ZIP is optional when downloading the full bundle.

```bash
curl -fL --retry 3 -O https://github.com/f3rb123/ATLAS/releases/download/skunk-v3.1.0rc1-20261112/skunk-linux-x86_64.tar.gz
curl -fL --retry 3 -O https://github.com/f3rb123/ATLAS/releases/download/skunk-v3.1.0rc1-20261112/skunk-linux-x86_64.tar.gz.sha256
sha256sum -c skunk-linux-x86_64.tar.gz.sha256
tar -xzf skunk-linux-x86_64.tar.gz
cd skunk-linux-x86_64
bash install.sh
skunk token-set
```

Run only on targets you are authorized to assess:

```bash
skunk --agents=8 --scope='*.example.com' --ra --prompt='Prioritize API authorization issues'
```

The live dashboard starts at `http://127.0.0.1:6777`, with findings, activity, Pause, Resume and Cancel. See the attached `SKUNK-README.md` for phone/Tailscale access and importing your own report folder.

## Presets and preserved data

- Endpoint: `https://api.hackerai.sh/v1`; token variable: `hacker-ai-token` or `HACKER_AI_TOKEN`. No token or VPS password is included.
- Eight default concurrent slots. Orchestrator/classifier: `deepseek-v4-pro`; recon/report: `deepseek-v4-flash`; exploit/independent validation: `glm-5.3`.
- Original knowledge: **21,012 reference/advisory records**, **34,229 vectors**, **384 dimensions**, original pinned MiniLM model. These are not 20,000 full-text bounty reports; full-text bounty report count is zero.
- Target policy and role prompts prohibit destructive deletion/database operations and OTP/messaging/reset flooding; scope and broker gates remain in place.
- Historical public spending floor and uncertain holds are preserved. Continuing an existing installation's precise ledger requires its actual store; do not create independent spending clones.

## Build identity and limits

The binary bundle and attached `skunk-source.tar.gz` were built from `44000e6f8a9ece1f27cf0b269a52b6015d92620c`. Subsequent source-branch commits only record delivery documentation. All six original delivery files are attached unchanged, with `SHA256SUMS` covering them.

This is a **build-only prerelease**: no application startup, tests, model calls, browser exercise, target scans or VPS deployment were run, as requested. Source compilation, dependency/package assembly and asset digests were checked. Runtime success, production acceptance and exhaustive wildcard discovery are not claimed. Linux x86_64 with glibc, CA certificates, user namespaces and bubblewrap are required; the installer can install bubblewrap and Git through APT when run as root.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `skunk-linux-x86_64.tar.gz` | 528,370,151 | `41d4660e6c32c0823c76905894fac06cf667ef42f520944634bdaafd825c5abb` |
| `skunk-linux-x86_64.tar.gz.sha256` | 92 | `07912a00a16ef37a3885120a513e55078e13996f77654b33ad105cac096363d3` |
| `skunk-knowledge.zip` | 256,406,385 | `e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025` |
| `skunk-source.tar.gz` | 1,331,275 | `598388183532eb3f2fb08422a78694dc36718f1dc442a53673e28ef3fd2b0100` |
| `SKUNK-README.md` | 8,815 | `27c5bb39fd26a0893030344853b19d54cd0b84c2e044bc270a9c5dcae548a308` |
| `SKUNK-BUILD-RECORD.json` | 981 | `d2ba8e8834676c49a7f56b1a4fcbd9c5bbb6d60f4d246099f5e8510a8330fda4` |
