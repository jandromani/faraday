#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
LAB_DIR=$(mktemp -d)
export COMPOSE_PROJECT_NAME="faraday-pilot-$$"
trap 'docker compose -f deploy/pilot/compose.yml --profile adversary down --volumes --remove-orphans >/dev/null 2>&1 || true; rm -rf "$LAB_DIR"' EXIT HUP INT TERM
rmdir "$LAB_DIR"
export FARADAY_LAB_DIR="$LAB_DIR"
export FARADAY_APP_DIR="$ROOT"
export FARADAY_HOST_UID="$(id -u)"
export FARADAY_HOST_GID="$(id -g)"
if [ "$FARADAY_HOST_UID" -eq 0 ]; then echo 'Run the pilot as a non-root user' >&2; exit 1; fi
docker compose -f deploy/pilot/compose.yml pull --quiet
node scripts/prepare-pilot-lab.mjs "$LAB_DIR"
docker compose -f deploy/pilot/compose.yml --profile adversary up -d backend gateway outside
docker compose -f deploy/pilot/compose.yml run --rm --no-deps dummy-agent
docker compose -f deploy/pilot/compose.yml --profile adversary run --rm --no-deps egress-control
BACKEND_HOST=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(docker compose -f deploy/pilot/compose.yml ps -q backend)")
EGRESS_HOST=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(docker compose -f deploy/pilot/compose.yml --profile adversary ps -q outside)")
docker compose -f deploy/pilot/compose.yml --profile adversary run --rm --no-deps -e FARADAY_TEST_BACKEND_HOST="$BACKEND_HOST" -e FARADAY_TEST_EGRESS_HOST="$EGRESS_HOST" rogue-tool
