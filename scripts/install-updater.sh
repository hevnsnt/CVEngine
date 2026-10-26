#!/usr/bin/env bash
# Installs the host-side half of CVEngine's auto-update: a cron entry that starts scripts/update-watch.sh every minute. The
# watcher listens for the whole minute, so an update an administrator approves in Settings > Updates starts within seconds, and it
# reports that it is alive so the app can tell when nothing on the host is listening. It only ever acts on an approved update.
# Run once, as the user that owns this checkout and may run Docker:   scripts/install-updater.sh
# Remove with:                                                        scripts/install-updater.sh --remove
# A host that runs a different compose file than docker-compose.yml (the dev box runs docker-compose.dev.yml)
# installs with:   CVENGINE_COMPOSE_FILES=docker-compose.dev.yml scripts/install-updater.sh
# (also CVENGINE_COMPOSE_ENV_FILE and CVENGINE_COMPOSE_PROJECT; with none of them the layout the running stack was started with is used)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MARK="# cvengine-auto-update"
CURRENT=$(crontab -l 2>/dev/null | grep -vF "$MARK" || true)

if [ "${1:-}" = "--remove" ]; then
  printf '%s\n' "$CURRENT" | crontab -
  echo "Removed the CVEngine update cron entry."
  exit 0
fi

# The Compose layout the update deploys with, when the install has one of its own (the dev box runs docker-compose.dev.yml; a host behind
# its own proxy adds an overlay and an env file). Left empty, apply-update.sh uses the layout the running stack was started with.
COMPOSE_FILE=${CVENGINE_COMPOSE_FILES:-${CVENGINE_COMPOSE_FILE:-}}
ENV_FILE=${CVENGINE_COMPOSE_ENV_FILE:-}
PROJECT=${CVENGINE_COMPOSE_PROJECT:-}
ENVPREFIX=""
if [ -n "$COMPOSE_FILE" ]; then
  for name in ${COMPOSE_FILE//,/ }; do
    if ! [[ $name =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $ROOT/$name ]]; then
      echo "CVENGINE_COMPOSE_FILES must name compose files in $ROOT (got '$name')." >&2
      exit 1
    fi
  done
  ENVPREFIX="CVENGINE_COMPOSE_FILES=$COMPOSE_FILE "
fi
if [ -n "$ENV_FILE" ]; then
  if ! [[ $ENV_FILE =~ ^[A-Za-z0-9._-]+$ && -f $ROOT/$ENV_FILE ]]; then
    echo "CVENGINE_COMPOSE_ENV_FILE must name a file in $ROOT (got '$ENV_FILE')." >&2
    exit 1
  fi
  ENVPREFIX="${ENVPREFIX}CVENGINE_COMPOSE_ENV_FILE=$ENV_FILE "
fi
if [ -n "$PROJECT" ]; then
  if ! [[ $PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    echo "CVENGINE_COMPOSE_PROJECT must be a lowercase Compose project name (got '$PROJECT')." >&2
    exit 1
  fi
  ENVPREFIX="${ENVPREFIX}CVENGINE_COMPOSE_PROJECT=$PROJECT "
fi

chmod +x "$ROOT/scripts/apply-update.sh"
chmod +x "$ROOT/scripts/update-watch.sh"
printf '%s\n* * * * * %s%s/scripts/update-watch.sh >/dev/null 2>&1 %s\n' "$CURRENT" "$ENVPREFIX" "$ROOT" "$MARK" | sed '/^$/d' | crontab -
echo "Installed: $ROOT/scripts/update-watch.sh starts every minute and applies an approved update within seconds (log: $ROOT/web/.update-log)${COMPOSE_FILE:+, deploying with $COMPOSE_FILE}${ENV_FILE:+ and $ENV_FILE}."
# Start listening now rather than at the top of the next minute, so an approval already waiting is applied at once and Settings > Updates
# sees the heartbeat straight away. (CVENGINE_NO_START=1 only installs the cron entry.)
if [ -z "${CVENGINE_NO_START:-}" ]; then
  nohup env ${COMPOSE_FILE:+CVENGINE_COMPOSE_FILES=$COMPOSE_FILE} ${ENV_FILE:+CVENGINE_COMPOSE_ENV_FILE=$ENV_FILE} ${PROJECT:+CVENGINE_COMPOSE_PROJECT=$PROJECT} "$ROOT/scripts/update-watch.sh" >/dev/null 2>&1 &
  echo "The watcher is running now; an approved update starts within seconds."
fi
