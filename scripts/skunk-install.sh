#!/usr/bin/env bash
set -euo pipefail
bundle="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
prefix="${1:-$HOME/.local/share/skunk}"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'This prebuilt package requires Linux x86_64.' >&2
  exit 1
fi
cd "$bundle"
sha256sum --check --quiet SHA256SUMS
if [[ -e "$prefix" ]]; then
  echo "Install destination already exists: $prefix. Choose a fresh destination; existing state was preserved." >&2
  exit 1
fi
if ! command -v bwrap >/dev/null || ! command -v git >/dev/null; then
  if [[ "$(id -u)" == 0 ]] && command -v apt-get >/dev/null; then
    apt-get update
    apt-get install -y --no-install-recommends bubblewrap git
  else
    echo 'Install the host bubblewrap package for isolated native scanners; no sandbox fallback is enabled.' >&2
    exit 1
  fi
fi
mkdir -p "$(dirname -- "$prefix")"
mkdir -m 700 "$prefix"
cp -a runtime app tools knowledge bin README.md BUILD-RECORD.json "$prefix/"
linkdir="$HOME/.local/bin"
if [[ "$(id -u)" == 0 ]]; then linkdir=/usr/local/bin; fi
mkdir -p "$linkdir"
if [[ -e "$linkdir/skunk" || -L "$linkdir/skunk" ]]; then
  echo "The skunk command already exists; use $prefix/bin/skunk or choose a different host command." >&2
else
  ln -s "$prefix/bin/skunk" "$linkdir/skunk"
fi
echo "Installed: $prefix"
echo 'Set your token: skunk token-set'
echo "Start: $prefix/bin/skunk --agents=8 --scope='*.example.com' --ra --prompt='Prioritize API authorization boundaries'"
echo 'Dashboard starts with the scan on http://127.0.0.1:6777.'
echo 'No scan, model request, corpus import or application test was started by this installer.'
