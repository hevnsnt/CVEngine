#!/usr/bin/env bash
# Applies an update an administrator approved in CVEngine (Settings > Updates).
#
# The web container only writes the approved commit to web/.update-approved; it has no git or Docker access.
# This script runs on the host (cron or a systemd timer, see scripts/install-updater.sh) and:
#   1. does nothing unless an approval exists;
#   2. accepts only a 40-character commit id that is reachable from origin/<current branch>;
#   3. refuses to touch a checkout with uncommitted changes to tracked files (a modified or deleted .env does not
#      count: it is backed up before the merge and put back after it, because .env used to be tracked and an
#      update that untracks it would otherwise delete it);
#   4. fast-forwards to exactly that commit, rebuilds and restarts app services while leaving db/Redis containers running;
#   5. if it fails before the database is migrated (the build, or the migration itself), returns to the previous
#      commit and restarts it. Once the migration has succeeded the previous code is never put back, because it would
#      run on the new schema: the restart is retried and, if it still fails, the approval is kept so the next run
#      retries it. Schema migrations are never rolled back.
# Results are appended to web/.update-log. Needs git, make and Docker, and a clone that can `git fetch origin`.
#
# CVENGINE_COMPOSE_FILE may select a root-level dev compose file. Ordinary updates deliberately keep db/Redis
# containers running. A PostgreSQL major-version migration requires a separate maintenance operation. An update
# waits while recorded scans or targeted jobs are running; operators should drain other worker work as well.
set -euo pipefail

cd "$(dirname "$0")/.."
FLAG=web/.update-approved
LOG=web/.update-log
[ -f "$FLAG" ] || exit 0

exec 9>web/.update-lock
flock -n 9 || exit 0  # another run is in progress

# .env is kept in a private (0600) temporary copy during the merge and removed when the script ends; its
# contents are never printed or logged.
ENV_BACKUP=
ENV_MODE=
cleanup() { [ -z "$ENV_BACKUP" ] || rm -f "$ENV_BACKUP"; }
trap cleanup EXIT

backup_env() {
  [ -f .env ] || return 0
  ENV_MODE=$(stat -c %a .env 2>/dev/null || echo 600)
  ENV_BACKUP=$(umask 077 && mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX") || return 1
  chmod 600 "$ENV_BACKUP"
  cat .env > "$ENV_BACKUP"
  # a still-tracked .env that is edited would block the merge; its content is safe in the backup
  if git ls-files --error-unmatch .env >/dev/null 2>&1; then git checkout -- .env 2>/dev/null || true; fi
}

restore_env() {
  [ -n "$ENV_BACKUP" ] && [ -s "$ENV_BACKUP" ] || return 0
  if cat "$ENV_BACKUP" > .env && chmod "$ENV_MODE" .env; then
    return 0
  fi
  log "could not restore .env; the copy is kept at $ENV_BACKUP (mode 600), move it back by hand"
  ENV_BACKUP=
}

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

COMPOSE_FILE_OVERRIDE=${CVENGINE_COMPOSE_FILE:-}
if [ -n "$COMPOSE_FILE_OVERRIDE" ] && ! [[ $COMPOSE_FILE_OVERRIDE =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $COMPOSE_FILE_OVERRIDE ]]; then
  log "refusing: CVENGINE_COMPOSE_FILE must be a compose file in the repository root (got '$COMPOSE_FILE_OVERRIDE')"
  exit 1
fi

# How far the last deploy got; "migrated" means the database already has the new schema.
DEPLOY_STAGE=
deploy() {
  git rev-parse HEAD > web/.commit 2>/dev/null || true
  local compose=(docker compose -f "${COMPOSE_FILE_OVERRIDE:-docker-compose.yml}")
  local services=(web celery celery-beat) listed
  # the dev compose file has no proxy service; recreate it only where it exists (keep it if the list cannot be read)
  if listed=$("${compose[@]}" config --services 2>/dev/null); then
    if grep -qx proxy <<<"$listed"; then services+=(proxy); fi
  else
    services+=(proxy)
  fi
  DEPLOY_STAGE=build
  "${compose[@]}" build web celery celery-beat || return 1
  DEPLOY_STAGE=datastores
  "${compose[@]}" up -d --no-recreate db redis || return 1
  DEPLOY_STAGE=migrate
  "${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py migrate --noinput || return 1
  DEPLOY_STAGE=migrated
  "${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py collectstatic --noinput || return 1
  "${compose[@]}" up -d --no-deps --force-recreate "${services[@]}"
}

RUNNING_QUERY="from django.apps import apps; from startScan.models import ScanHistory; n=ScanHistory.objects.filter(scan_status=1).count(); n+=sum(m.objects.filter(status='running').count() for m in apps.get_models() if m.__name__ in ('OnDemandValidation','DeferredRetest','TriageCall')); print(n)"

running_scans() {
  local compose=(docker compose -f "${COMPOSE_FILE_OVERRIDE:-docker-compose.yml}") out
  out=$("${compose[@]}" exec -T web python3 manage.py shell -c "$RUNNING_QUERY" 2>/dev/null | tail -n1) || true
  if ! [[ $out =~ ^[0-9]+$ ]]; then
    # web is down, which is when an update may be needed most: ask the database from a one-off container
    out=$("${compose[@]}" run --rm --no-deps -T --entrypoint python3 web manage.py shell -c "$RUNNING_QUERY" 2>/dev/null | tail -n1) || true
  fi
  printf '%s\n' "$out"
}

SHA=$(head -n1 "$FLAG" | tr -d '[:space:]')
if ! [[ $SHA =~ ^[0-9a-f]{40}$ ]]; then
  log "refusing: approval file does not hold a commit id"
  rm -f "$FLAG"
  exit 1
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
git fetch --quiet origin "$BRANCH"
if ! git merge-base --is-ancestor "$SHA" "origin/$BRANCH"; then
  log "refusing: $SHA is not on origin/$BRANCH"
  rm -f "$FLAG"
  exit 1
fi
if [ -n "$(git status --porcelain --untracked-files=no | grep -vE '^.. "?\.env"?$' || true)" ]; then
  log "refusing: the checkout has local changes to tracked files; commit or stash them (approval kept, will retry)"
  exit 1
fi

RUNNING=$(running_scans)
if ! [[ $RUNNING =~ ^[0-9]+$ ]]; then
  log "refusing: could not verify active scans; approval kept for retry"
  exit 1
fi
if [[ $RUNNING =~ ^[1-9][0-9]*$ ]]; then
  log "waiting: $RUNNING scan(s) running; an update restarts the workers (approval kept, will retry)"
  exit 0
fi

PREV=$(git rev-parse HEAD)
if [ "$PREV" = "$SHA" ]; then
  log "already at $SHA"
  echo "$SHA" > web/.commit
  rm -f "$FLAG"
  exit 0
fi

log "updating $PREV -> $SHA"
backup_env
if ! git merge --ff-only "$SHA" >>"$LOG" 2>&1; then
  restore_env
  log "refusing: $SHA is not a fast-forward of the local branch"
  rm -f "$FLAG"
  exit 1
fi
restore_env

if deploy >>"$LOG" 2>&1; then
  echo "$SHA" > web/.commit
  rm -f "$FLAG"
  log "updated to $SHA"
elif [ "$DEPLOY_STAGE" = migrated ]; then
  # The database already has $SHA's schema, so $PREV's code must not run on it: keep $SHA and retry the restart.
  log "restarting $SHA failed after its migrations ran; keeping $SHA and retrying the restart"
  if deploy >>"$LOG" 2>&1; then
    echo "$SHA" > web/.commit
    rm -f "$FLAG"
    log "updated to $SHA"
  else
    log "could not restart $SHA; the database is already migrated, so $PREV is not restored. The approval is kept and the next run retries; see $LOG"
    exit 1
  fi
else
  log "update failed before the database was migrated (at: $DEPLOY_STAGE); returning to $PREV"
  git reset --hard "$PREV" >>"$LOG" 2>&1
  restore_env
  deploy >>"$LOG" 2>&1 || log "could not restart the previous version; redeploy by hand"
  rm -f "$FLAG"
  exit 1
fi
