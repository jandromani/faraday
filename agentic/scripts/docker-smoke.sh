#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
LAB_DIR=$(mktemp -d)
trap 'docker compose -f deploy/lab/compose.yml down --volumes --remove-orphans >/dev/null 2>&1 || true; rm -rf "$LAB_DIR"' EXIT HUP INT TERM
rmdir "$LAB_DIR"
export FARADAY_LAB_DIR="$LAB_DIR"
export FARADAY_APP_DIR="$ROOT"
export FARADAY_HOST_UID="$(id -u)"
export FARADAY_HOST_GID="$(id -g)"
# Pull image before creating 30-second proof-of-possession credentials.
docker compose -f deploy/lab/compose.yml pull --quiet
node scripts/prepare-authority-lab.mjs "$LAB_DIR"
export FARADAY_LAB_DIR="$LAB_DIR"
export FARADAY_APP_DIR="$ROOT"
export FARADAY_HOST_UID="$(id -u)"
export FARADAY_HOST_GID="$(id -g)"
docker compose -f deploy/lab/compose.yml up --abort-on-container-exit --exit-code-from dummy-agent
