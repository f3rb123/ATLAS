#!/usr/bin/env bash
set -euo pipefail
skunk_mod_dir="$(mktemp -d)"
trap 'rm -rf -- "$skunk_mod_dir"' EXIT
cd "$skunk_mod_dir"
curl --fail --location --silent --show-error --retry 3 --max-time 60 \
  https://github.com/f3rb123/ATLAS/releases/download/skunk-mod2-20261112/skunk-mod2.tar.gz \
  --output skunk-mod2.tar.gz
printf '%s  %s\n' 0ec68c1c94c9d65adb5b823760a1c557eabba8306e9032187929da7c5e0ad71e skunk-mod2.tar.gz | sha256sum --check --quiet
tar -xzf skunk-mod2.tar.gz
bash skunk-mod2/apply.sh "$@"
