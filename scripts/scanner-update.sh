#!/usr/bin/env bash
# The "Scanner update": bring the built-in scanner to the newest published Sentinel image, safely, without touching the server.
#   scripts/scanner-update.sh
# It pulls the moving tag scanner.lock.json names (ghcr.io/hevnsnt/cvengine-sentinel:main), and only when that is not the image already running it lets
# the scanner finish its tasks, starts the new container and waits until it is healthy AND has checked in with a contract version this server accepts.
# Otherwise it puts the previous image back and says why (the log, and the Sentinels page). A failed pull keeps the running scanner. Nothing is stopped
# or changed when the scanner already runs the newest image. A scanner held with CVENGINE_SCANNER_IMAGE in .env (a digest or a tag) is left alone.
#
# For a host that does not use the updater, run it from cron (or a timer) in the checkout, for example daily:
#   17 4 * * *  cd /opt/cvengine && scripts/scanner-update.sh >> /var/log/cvengine-scanner-update.log 2>&1
# Settings (environment or the same keys in .env): CVENGINE_SCANNER_READY_SECONDS (300), CVENGINE_SCANNER_DRAIN_SECONDS (900).
set -Euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -f .env ] || { echo "scanner-update.sh: .env not found: run this from the CVEngine directory of a running installation." >&2; exit 1; }
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
# the Compose files, env file and project the installation runs with (an overlay must not be dropped)
. scripts/compose-layout.sh
cvengine_compose_layout || exit 1
. scripts/scanner.sh
# one run at a time, and never beside an update of the server (it holds the updater lock)
state=$(git rev-parse --git-path cvengine-auto-deploy 2>/dev/null) || state=.
mkdir -p "$state" 2>/dev/null || true
if command -v flock >/dev/null 2>&1; then
  exec 7>"$state/scanner-update.lock"
  flock -n 7 || { log "another scanner update is still working"; exit 0; }
  if [ -f scripts/update-state.py ]; then
    update_state=$(python3 scripts/update-state.py directory 2>/dev/null) || update_state=''
    if [ -n "$update_state" ] && [ -e "$update_state/update.lock" ] && ! flock -n "$update_state/update.lock" true; then
      log "an update of the server is running; the scanner is updated with it"
      exit 0
    fi
  fi
fi
cvengine_scanner_update "${COMPOSE[@]}"
case "$CVENGINE_SCANNER_RESULT" in done) date +%s > "$state/scanner-update.last" 2>/dev/null || true ;; esac  # busy or no pull: the next scheduled run tries again
