#!/usr/bin/env bash
# Install the supplied images and corpus; never compile, pull, reset or re-embed.
set -euo pipefail
umask 077
app_dir=$(cd "$(dirname "$0")/.." && pwd)
bundle_dir=$(cd "$app_dir/.." && pwd)
payload_dir="$bundle_dir/payload"
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo 'This bundle requires Linux x86-64.' >&2; exit 1; }
for required in docker python3 sha256sum flock; do command -v "$required" >/dev/null || { echo "Missing prerequisite: $required" >&2; exit 1; }; done
[[ -f "$bundle_dir/SHA256SUMS" && -f "$payload_dir/container-images.tar.gz" && -f "$payload_dir/atlas-v3-public-corpus-review.zip" ]] || { echo 'Extract the complete prebuilt bundle before installation.' >&2; exit 1; }
exec 9>"$bundle_dir/.install.lock"
flock -n 9 || { echo 'Another installer is running.' >&2; exit 1; }
cd "$bundle_dir"
sha256sum --check --quiet SHA256SUMS
docker_local=(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock)
"${docker_local[@]}" info >/dev/null
"${docker_local[@]}" compose version >/dev/null
"${docker_local[@]}" load --input "$payload_dir/container-images.tar.gz"
python3 "$app_dir/scripts/prebuilt-images.py" "$payload_dir/IMAGES.json"
cd "$app_dir"
config_file="$app_dir/.env.prebuilt"
if [[ ! -e "$config_file" ]]; then
  (set -o noclobber; cat > "$config_file" <<'CONFIG'
ATLAS_ENV=production
ATLAS_HOST=atlas.localhost
ATLAS_BIND_IP=127.0.0.1
ATLAS_HTTPS_PORT=8443
ATLAS_EXTERNAL_URL=https://atlas.localhost:8443
ATLAS_GLOBAL_TOKEN_CAP=50000000
ATLAS_TOKEN_ALLOCATION=2000000
ATLAS_VALIDATION_TOKEN_RESERVE=200000
ATLAS_WORKER_CONCURRENCY=8
ATLAS_REQUIRE_MFA=false
CONFIG
  )
  chmod 600 "$config_file"
fi
python3 scripts/prepare-secrets.py
compose=("${docker_local[@]}" compose --env-file "$config_file" --project-name atlas-prebuilt -f compose.yaml -f compose.prebuilt.yaml)
"${compose[@]}" config --quiet
# Initialisation runs only additive migrations and preserves existing keys/state.
"${compose[@]}" up -d --wait --wait-timeout 120 --no-build --pull never postgres redis
"${compose[@]}" run --rm --no-deps -T init
# Do not start the UI/workers until both persistent budget and knowledge exist.
"${compose[@]}" run --rm --no-deps -T --volume "$payload_dir/BUDGET-FLOOR.json:/prebuilt-budget.json:ro" api python - /prebuilt-budget.json < scripts/seed-prebuilt-budget.py
"${compose[@]}" run --rm --no-deps -T api atlas host corpus-restore - --sha256 e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025 < "$payload_dir/atlas-v3-public-corpus-review.zip"
"${compose[@]}" up -d --no-build --pull never
printf '%s\n' 'Prebuilt images loaded; supplied corpus, vectors and local model assets restored.'
printf '%s\n' 'Private address: https://atlas.localhost:8443 (or your preserved .env.prebuilt configuration).'
printf '%s\n' 'Next: ./scripts/prebuilt-control.sh bootstrap — create your owner account; configure your provider key securely in the UI.'
printf '%s\n' 'No target scan, provider inference or application acceptance test was requested by this installer.'
