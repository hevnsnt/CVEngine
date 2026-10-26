#!/usr/bin/env bash
# Installs the host-side half of CVEngine's auto-update: a cron entry that starts scripts/update-watch.sh every minute. The
# watcher listens for the whole minute, so an update an administrator approves in Settings > Updates starts within seconds, and it
# reports that it is alive so the app can tell when nothing on the host is listening. It only ever acts on an approved update.
# Run once, as the user that owns this checkout and may run Docker:   scripts/install-updater.sh
# Remove with:                                                        scripts/install-updater.sh --remove
# A host that runs a different compose file than docker-compose.yml (the dev box runs docker-compose.dev.yml)
# installs with:   CVENGINE_COMPOSE_FILE=docker-compose.dev.yml scripts/install-updater.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MARK="# cvengine-auto-update"
CURRENT=$(crontab -l 2>/dev/null | grep -vF "$MARK" || true)

if [ "${1:-}" = "--remove" ]; then
  printf '%s\n' "$CURRENT" | crontab -
  echo "Removed the CVEngine update cron entry."
  exit 0
fi

COMPOSE_FILE=${CVENGINE_COMPOSE_FILE:-}
ENVPREFIX=""
if [ -n "$COMPOSE_FILE" ]; then
  if ! [[ $COMPOSE_FILE =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $ROOT/$COMPOSE_FILE ]]; then
    echo "CVENGINE_COMPOSE_FILE must name a compose file in $ROOT (got '$COMPOSE_FILE')." >&2
    exit 1
  fi
  ENVPREFIX="CVENGINE_COMPOSE_FILE=$COMPOSE_FILE "
fi

chmod +x "$ROOT/scripts/apply-update.sh"
chmod +x "$ROOT/scripts/update-watch.sh"
printf '%s\n* * * * * %s%s/scripts/update-watch.sh >/dev/null 2>&1 %s\n' "$CURRENT" "$ENVPREFIX" "$ROOT" "$MARK" | sed '/^$/d' | crontab -
echo "Installed: $ROOT/scripts/update-watch.sh starts every minute and applies an approved update within seconds (log: $ROOT/web/.update-log)${COMPOSE_FILE:+, deploying with $COMPOSE_FILE}."
