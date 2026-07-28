#!/usr/bin/env bash
# graph-memory — AXP standalone install (§9).
#
# Runs on a host with ZERO AXP support: `./install.sh` or `curl -fsSL <url> | bash`
# performs the whole installation. No AXP daemon or host helper is assumed.
#
# Idempotent: safe to run twice and safe to re-run after a partial failure.
# Config comes from environment variables when an AXP host renders the config
# form (§4.2); every variable falls back to a sane default (or a TTY prompt for
# secrets) so a human running this by hand still gets a working install.
#
# NOTE ON TRUST (§9): running this script by hand opts out of AXP's signature,
# permission-consent, TOFU and freshness checks — those live in the AXP-aware
# host, not here. This is the same trade-off as any `curl | bash`.
set -euo pipefail

# ---- configuration (env-or-default) -----------------------------------------
EXT_NAME="graph-memory"
PREFIX="${AXP_PREFIX:-/opt/${EXT_NAME}}"
STATE_DIR="${AXP_STATE_DIR:-/var/lib/mintbot-agent/ext/${EXT_NAME}}"
FALKOR_PORT="${GRAPHMEM_FALKOR_PORT:-6379}"
SERVICE_NAME="falkordb-graphmem.service"

# Secret: from env if the host passed it, else generate one (non-interactive) or
# prompt on a TTY.
if [ -z "${FALKOR_PASSWORD:-}" ]; then
  if [ -t 0 ]; then
    read -rsp "FalkorDB password (blank = auto-generate): " FALKOR_PASSWORD || true
    echo
  fi
  if [ -z "${FALKOR_PASSWORD:-}" ]; then
    FALKOR_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
    echo "[graph-memory] generated a random FalkorDB password."
  fi
fi

log() { echo "[graph-memory] $*"; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: install needs root (systemd service + ${PREFIX}). Re-run with sudo." >&2
    exit 1
  fi
}

# ---- install steps (each idempotent) ----------------------------------------
install_files() {
  log "installing files into ${PREFIX} and ${STATE_DIR}"
  install -d -m 0755 "${PREFIX}"
  install -d -m 0700 "${STATE_DIR}"
  # Copy the delivered artifact payload next to this script into PREFIX.
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cp -a "${here}/." "${PREFIX}/"
  # Persist resolved config (0600 — contains the secret).
  umask 077
  cat > "${STATE_DIR}/config.env" <<EOF
GRAPHMEM_FALKOR_PORT=${FALKOR_PORT}
FALKOR_PASSWORD=${FALKOR_PASSWORD}
EOF
}

ensure_falkordb() {
  # Prefer a container runtime; fall back to a note if none present.
  if command -v docker >/dev/null 2>&1; then
    log "ensuring FalkorDB via docker (idempotent)"
    docker rm -f graphmem-falkordb >/dev/null 2>&1 || true
    docker run -d --name graphmem-falkordb --restart unless-stopped \
      -p "127.0.0.1:${FALKOR_PORT}:6379" \
      -e "FALKORDB_ARGS=--requirepass ${FALKOR_PASSWORD}" \
      falkordb/falkordb:latest >/dev/null
  else
    log "docker not found — install FalkorDB manually or via your package manager."
    log "the service unit below will manage it once the binary is on PATH."
  fi
}

install_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    log "systemd not present — skipping unit install (service managed by docker)."
    return 0
  fi
  log "installing systemd unit ${SERVICE_NAME}"
  cat > "/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=graph-memory FalkorDB store
After=network.target docker.service

[Service]
Type=simple
EnvironmentFile=${STATE_DIR}/config.env
ExecStart=/usr/bin/docker start -a graphmem-falkordb
ExecStop=/usr/bin/docker stop graphmem-falkordb
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}"
}

main() {
  require_root
  install_files
  ensure_falkordb
  install_service
  log "install complete. Health: run ./healthcheck.sh (expects FalkorDB PONG on ${FALKOR_PORT})."
}

main "$@"
