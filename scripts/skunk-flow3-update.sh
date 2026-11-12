#!/usr/bin/env bash
set -euo pipefail
skunk_flow_dir="$(mktemp -d)"
trap 'rm -rf -- "$skunk_flow_dir"' EXIT
cd "$skunk_flow_dir"
curl --fail --location --silent --show-error --retry 3 --max-time 60 \
  https://github.com/f3rb123/ATLAS/releases/download/skunk-flow3-20261112/skunk-flow3.tar.gz \
  --output skunk-flow3.tar.gz
printf '%s  %s\n' 4eb380c013d7000f328c1dd4b3bb8289441b480f2904e788dced53b21cba43de skunk-flow3.tar.gz | sha256sum --check --quiet
tar -xzf skunk-flow3.tar.gz
bash skunk-flow3/apply.sh "$@"
