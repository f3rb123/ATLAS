#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker_local=(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock)
compose=("${docker_local[@]}" compose --env-file .env.prebuilt --project-name atlas-prebuilt -f compose.yaml -f compose.prebuilt.yaml)
case "${1:-status}" in
  status) "${compose[@]}" ps ;;
  bootstrap) "${compose[@]}" exec api atlas host bootstrap ;;
  start) "${compose[@]}" up -d --no-build --pull never ;;
  stop) "${compose[@]}" stop ;;
  logs) "${compose[@]}" logs --tail 100 "${@:2}" ;;
  ca-cert) "${compose[@]}" exec -T proxy cat /data/caddy/pki/authorities/local/root.crt ;;
  *) echo 'Usage: prebuilt-control.sh [status|bootstrap|start|stop|logs [service]|ca-cert]' >&2; exit 1 ;;
esac
