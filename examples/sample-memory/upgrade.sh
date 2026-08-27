#!/usr/bin/env bash
# sample-memory — AXP upgrade hook (§5, §7). Receives the previous version in
# $AXP_FROM_VERSION so a migration can branch on where it came from.
# Idempotent and standalone, exactly like install.sh (§9).
set -euo pipefail

EXT_NAME="sample-memory"
STATE_DIR="${AXP_STATE_DIR:-/var/lib/axp/ext.example.com/${EXT_NAME}}"
FROM_VERSION="${AXP_FROM_VERSION:-unknown}"

log() { echo "[sample-memory] $*"; }
log "upgrading from version: ${FROM_VERSION}"

# Example migration gate: bump the on-disk graph schema only when crossing the
# version where its layout changed. Real migrations live in migrations/.
case "${FROM_VERSION}" in
  0.1.*)
    log "applying 0.1 -> 0.2 graph schema migration"
    # e.g. run migrations/0002_temporal_edges.sh against FalkorDB here.
    ;;
  *)
    log "no schema migration needed from ${FROM_VERSION}"
    ;;
esac

# Re-run the installer to converge files + service to the new version.
# install.sh is idempotent, so this is safe.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "${here}/install.sh"

log "upgrade complete."
