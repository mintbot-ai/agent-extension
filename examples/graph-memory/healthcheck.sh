#!/usr/bin/env bash
# graph-memory — AXP health hook (§5). Exit 0 = healthy, non-zero = unhealthy;
# the host surfaces this as green/red. Standalone and side-effect-free.
set -euo pipefail

EXT_NAME="graph-memory"
STATE_DIR="${AXP_STATE_DIR:-/var/lib/mintbot-agent/ext/${EXT_NAME}}"
FALKOR_PORT="${GRAPHMEM_FALKOR_PORT:-6379}"

# Load persisted config if present (for the port + password).
if [ -f "${STATE_DIR}/config.env" ]; then
  # shellcheck disable=SC1090
  . "${STATE_DIR}/config.env"
fi

fail() { echo "[graph-memory] UNHEALTHY: $*" >&2; exit 1; }

# Prefer redis-cli; fall back to a raw TCP PING if it is not installed.
if command -v redis-cli >/dev/null 2>&1; then
  auth=()
  [ -n "${FALKOR_PASSWORD:-}" ] && auth=(-a "${FALKOR_PASSWORD}")
  reply="$(redis-cli -p "${FALKOR_PORT}" "${auth[@]}" ping 2>/dev/null || true)"
  [ "${reply}" = "PONG" ] || fail "FalkorDB did not answer PING on port ${FALKOR_PORT}"
else
  # Bash /dev/tcp fallback: just check the port accepts a connection.
  (exec 3<>"/dev/tcp/127.0.0.1/${FALKOR_PORT}") 2>/dev/null \
    || fail "nothing listening on 127.0.0.1:${FALKOR_PORT}"
  exec 3>&- 2>/dev/null || true
fi

echo "[graph-memory] healthy: FalkorDB responding on ${FALKOR_PORT}"
exit 0
