#!/usr/bin/env bash
set -euo pipefail
skunk_validation_dir="$(mktemp -d)"
trap 'rm -rf -- "$skunk_validation_dir"' EXIT
cd "$skunk_validation_dir"
curl --fail --location --silent --show-error --retry 3 --max-time 60 \
  https://github.com/f3rb123/ATLAS/releases/download/skunk-validate5-20261112/skunk-validate5.tar.gz \
  --output skunk-validate5.tar.gz
printf '%s  %s\n' 66fd2afc41f395ea2961fde1ffa466cbe8b4c6be6a5bd8a1dc512de9d44a632c skunk-validate5.tar.gz | sha256sum --check --quiet
tar -xzf skunk-validate5.tar.gz
bash skunk-validate5/apply.sh "$@"
