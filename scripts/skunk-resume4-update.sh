#!/usr/bin/env bash
set -euo pipefail
skunk_resume_dir="$(mktemp -d)"
trap 'rm -rf -- "$skunk_resume_dir"' EXIT
cd "$skunk_resume_dir"
curl --fail --location --silent --show-error --retry 3 --max-time 60 \
  https://github.com/f3rb123/ATLAS/releases/download/skunk-resume4-20261112/skunk-resume4.tar.gz \
  --output skunk-resume4.tar.gz
printf '%s  %s\n' ff9a4f4a75c59108255616e6d13d674b2d6524714446a67d55073973ac44d3be skunk-resume4.tar.gz | sha256sum --check --quiet
tar -xzf skunk-resume4.tar.gz
bash skunk-resume4/apply.sh "$@"
