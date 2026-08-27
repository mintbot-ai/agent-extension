#!/usr/bin/env bash
# sample-memory — AXP standalone uninstall (§9). Idempotent: safe if already gone.
set -euo pipefail

EXT_NAME="sample-memory"
PREFIX="${AXP_PREFIX:-/opt/${EXT_NAME}}"
STATE_DIR="${AXP_STATE_DIR:-/var/lib/axp/ext.example.com/${EXT_NAME}}"
SERVICE_NAME="falkordb-samplemem.service"
PURGE="${AXP_PURGE:-0}"   # set to 1 to also remove state/data (the graph!)

log() { echo "[sample-memory] $*"; }

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}"
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

if command -v docker >/dev/null 2>&1; then
  docker rm -f samplemem-falkordb >/dev/null 2>&1 || true
fi

rm -rf "${PREFIX}"

if [ "${PURGE}" = "1" ]; then
  log "AXP_PURGE=1 — removing state and graph data at ${STATE_DIR}"
  rm -rf "${STATE_DIR}"
else
  log "kept state at ${STATE_DIR} (set AXP_PURGE=1 to remove the graph too)."
fi

log "uninstall complete."
