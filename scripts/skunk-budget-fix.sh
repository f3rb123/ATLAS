#!/usr/bin/env bash
set -euo pipefail
entry="$(command -v skunk || true)"
if [[ -z "$entry" ]]; then
  echo 'The skunk command was not found. Use the same Unix account as the installation.' >&2
  exit 1
fi
resolved="$(readlink -f -- "$entry")"
prefix="$(cd -- "$(dirname -- "$resolved")/.." && pwd)"
if [[ ! -x "$prefix/runtime/bin/python3" ]]; then
  echo 'The installed SKUNK standalone Python was not found.' >&2
  exit 1
fi
budget_file="$(mktemp)"
trap 'rm -f -- "$budget_file"' EXIT
curl --fail --silent --show-error --location --retry 3 --max-time 30 \
  https://raw.githubusercontent.com/f3rb123/ATLAS/ec2f6474691cf6ea9712d1e725eb2cb3ff25ab74/atlas/skunk_budget.py \
  --output "$budget_file"
printf '%s  %s\n' fc9da0af87893c48b358e0e145ca546513bb192d95dd17f1d64182648fcbcb01 "$budget_file" | sha256sum --check --status
"$prefix/runtime/bin/python3" -I "$budget_file" "$@"
