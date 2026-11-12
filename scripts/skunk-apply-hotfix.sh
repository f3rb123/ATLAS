#!/usr/bin/env bash
set -euo pipefail
package="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
prefix="${1:-${SKUNK_INSTALL_ROOT:-}}"
if [[ -z "$prefix" ]]; then
  entry="$(command -v skunk || true)"
  if [[ -n "$entry" ]]; then
    resolved="$(readlink -f -- "$entry")"
    prefix="$(cd -- "$(dirname -- "$resolved")/.." && pwd)"
  else
    prefix="$HOME/.local/share/skunk"
  fi
fi
if [[ ! -x "$prefix/runtime/bin/python3" ]]; then
  echo 'Installed SKUNK runtime not found. Pass its installation directory to apply.sh.' >&2
  exit 1
fi
exec "$prefix/runtime/bin/python3" -I "$package/apply.py" --prefix "$prefix" --package "$package"
