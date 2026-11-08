#!/usr/bin/env bash
# Read-only prerequisite checks. Does not change SSH, firewall, users or services.
set -euo pipefail
command -v docker >/dev/null
docker compose version
for path in /proc/sys/user/max_user_namespaces /proc/sys/kernel/unprivileged_userns_clone; do
  if [ -r "$path" ]; then printf '%s: ' "$path"; cat "$path"; fi
done
df -h .
free -h
printf '%s\n' 'Review docs/DEPLOYMENT.md, existing SSH-key access, DNS/TLS, bind address, disk encryption and off-host recovery before exposure.'
