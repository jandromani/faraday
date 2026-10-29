#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
LAB_DIR=$(mktemp -d)
trap 'docker compose -f deploy/pilot/compose.yml down --volumes --remove-orphans >/dev/null 2>&1 || true; rm -rf "$LAB_DIR"' EXIT HUP INT TERM
rmdir "$LAB_DIR"
export FARADAY_LAB_DIR="$LAB_DIR"
export FARADAY_APP_DIR="$ROOT"
export FARADAY_HOST_UID="$(id -u)"
export FARADAY_HOST_GID="$(id -g)"
docker compose -f deploy/pilot/compose.yml pull --quiet
node scripts/prepare-pilot-lab.mjs "$LAB_DIR"
docker compose -f deploy/pilot/compose.yml config --format json > "$LAB_DIR/compose-effective.json"
node scripts/check-pilot-deployment.mjs "$LAB_DIR/compose-effective.json"
docker compose -f deploy/pilot/compose.yml up -d backend gateway
docker compose -f deploy/pilot/compose.yml run --rm dummy-agent
docker compose -f deploy/pilot/compose.yml run --rm rogue-agent
