#!/usr/bin/env bash
# What an update does to the services: build, keep the datastores, migrate, collect static files, recreate the application processes.
# Sourced by scripts/apply-update.sh AFTER the new files are in place, so a change here (a new step, a new image to refresh) takes effect
# in the very update that delivers it. The update script itself is the copy already on the host and only changes on the next update.
# Not run on its own: it uses the update script's COMPOSE, STATE_HELPER, phase and log, and sets DEPLOY_STAGE for its rollback decision.

# The proxy shows its friendly maintenance page (web/static/cve/maintenance.html) for as long as this flag file exists. It is set after the
# build and before the database changes. The build is not "untouched": ./web is a bind mount, so the new files are already under the running
# containers, and a worker that restarts during the build loads the new code against the old schema (reNgine/schema_guard.py answers those
# requests 503 with Retry-After instead of 500 until the migration has run). The flag is set before the database changes, because from then until the new web service answers the
# old code runs on a new schema or nothing runs at all, and a visitor would get an error page. It is always removed when the deploy ends,
# failed or not: a failed update must not claim "back soon", and a retry sets it again. A host that was stopped mid-update can leave it
# behind; `rm config/nginx/state/maintenance` (or the next update, or make up) clears it.
MAINTENANCE_FLAG=config/nginx/state/maintenance
maintenance_on() { mkdir -p "$(dirname "$MAINTENANCE_FLAG")" 2>/dev/null && : >"$MAINTENANCE_FLAG" 2>/dev/null || log "could not set the maintenance flag; visitors may see an error page while the update runs"; }
maintenance_off() { rm -f "$MAINTENANCE_FLAG" 2>/dev/null || true; }

deploy_current() {
  local status=0
  deploy_steps || status=$?
  maintenance_off
  return "$status"
}

# A dump just before the migrations (scripts/db-backup.sh; CVENGINE_UPDATE_BACKUPS says how many to keep, default 3, and 0 takes none). A migration
# is never rolled back, so this is the only way back from one that goes wrong half way. A dump that cannot be made stops the update before the
# database is touched: DEPLOY_STAGE is still datastores, so the previous version is put back.
BACKUP_FILE=
backup_database() {
  BACKUP_FILE=
  if ! BACKUP_FILE=$(scripts/db-backup.sh "$STATE" -- "${COMPOSE[@]}"); then
    log "the database backup failed, so the database is not migrated; fix that (disk space, the database container) and approve again, or set CVENGINE_UPDATE_BACKUPS=0 to update without one"
    return 1
  fi
  BACKUP_FILE=$(printf '%s\n' "$BACKUP_FILE" | tail -n1)
  [ -z "$BACKUP_FILE" ] || log "backed up the database to $BACKUP_FILE before migrating"
  return 0
}

# How many migrations the database has applied; fails when that cannot be read.
applied_migrations() {
  local plan
  plan=$("${COMPOSE[@]}" run --rm --no-deps -T --entrypoint python3 web manage.py showmigrations --plan 2>/dev/null) || return 1
  grep -c '^\[X\]' <<<"$plan" || true
}

# Every migration runs in a transaction of its own, so a failed batch can leave the first ones applied. The previous code must never be put back
# on a schema that is partly migrated: when the count of applied migrations changed (or cannot be read), the stage becomes "migrated", which the
# script that applies the update answers by keeping the new code and saying so, not by rolling back.
run_migrations() {
  local before after
  before=$(applied_migrations) || before=''
  "${COMPOSE[@]}" run --rm --no-deps --entrypoint python3 web manage.py migrate --noinput && return 0
  after=$(applied_migrations) || after=''
  if [ -z "$before" ] || [ "$before" != "$after" ]; then
    DEPLOY_STAGE=migrated
    log "the migration failed after it had started changing the database (or the database cannot be read), so the previous version is NOT put back on it: the new code stays, scanning stays paused and the approval is kept"
    if [ -n "$BACKUP_FILE" ] && mv -f "$BACKUP_FILE" "${BACKUP_FILE%/*}/premigration-failed-${BACKUP_FILE##*/}" 2>/dev/null; then
      log "the dump taken before it is kept as ${BACKUP_FILE%/*}/premigration-failed-${BACKUP_FILE##*/} and is never removed automatically"
    fi
  fi
  return 1
}

deploy_steps() {
  python3 "$STATE_HELPER" commit "$(git rev-parse HEAD)" || return 1
  local compose=("${COMPOSE[@]}")
  local services=(web celery celery-beat) listed=''
  # the dev compose file has no proxy service; recreate it only where it exists (keep it if the list cannot be read)
  if listed=$("${compose[@]}" config --services 2>/dev/null); then
    if grep -qx proxy <<<"$listed"; then services+=(proxy); fi
  else
    listed=''
    services+=(proxy)
  fi
  DEPLOY_STAGE=build
  phase applying "$DEPLOY_STAGE"
  check_disk || return 1
  # The proxy image is a moving tag and is meant to move with every update (nginx's security releases). It is fetched here, before anything is
  # stopped, and an unreachable registry only keeps the image already on the host: a pull that failed inside `up` after the migration (as
  # `pull_policy: always` did) failed an update that was otherwise done, and an offline host could never update at all.
  if grep -qx proxy <<<"$listed"; then
    "${compose[@]}" pull --quiet proxy || log "could not pull the newest proxy image (offline, or the registry is limiting pulls); the one on this host is kept"
  fi
  "${compose[@]}" build web celery celery-beat || return 1
  maintenance_on
  DEPLOY_STAGE=datastores
  phase applying "$DEPLOY_STAGE"
  "${compose[@]}" up -d --no-recreate db redis || return 1
  phase applying backup
  backup_database || return 1
  DEPLOY_STAGE=migrate
  phase applying "$DEPLOY_STAGE"
  run_migrations || return 1
  DEPLOY_STAGE=migrated
  phase applying "$DEPLOY_STAGE"
  "${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py collectstatic --noinput || return 1
  # The web interface certificate is renewed here when its check is due, so the proxy recreated below starts with the new one (a host with
  # neither the update watcher nor cron has no other trigger). A failure is logged and never stops the update.
  if [ -f scripts/renew-certs.sh ]; then
    scripts/renew-certs.sh --if-due --no-reload >/dev/null 2>&1 || log "the certificate check failed (see the Settings > Updates page); the update goes on"
  fi
  "${compose[@]}" up -d --no-deps --force-recreate "${services[@]}" || return 1
  # The Tailscale sidecar shares the celery container's network namespace by container id, so it is orphaned (no tailscale0, no tailnet route
  # for scans) when celery is recreated. Only present when the profile is on.
  if grep -qx tailscale <<<"$listed"; then
    "${compose[@]}" up -d --no-deps --force-recreate tailscale || log "could not restart the Tailscale sidecar: run docker compose up -d --force-recreate tailscale, or scans of tailnet addresses fail"
  fi
  verify_running "${services[@]}" || return 1
  # still DEPLOY_STAGE=migrated: a failure here is a failure AFTER the migration, and the script that applies the update (the copy already on
  # the host, which only knows build, datastores, migrate and migrated) must keep the new code and retry, never put the old code on the new schema
  phase applying verifying
  verify_serving || return 1
  prune_old_images
}

# `up -d` can leave a service created but not started (a published port that is already taken, for one): that is a failed update, not a done one.
verify_running() {
  local compose=("${COMPOSE[@]}") running missing service attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    running=$("${compose[@]}" ps --status running --services 2>/dev/null) || running=''
    missing=''
    for service in "$@"; do grep -qx "$service" <<<"$running" || missing="$missing $service"; done
    [ -z "$missing" ] && return 0
    sleep "${CVENGINE_VERIFY_POLL:-2}"
  done
  log "after the restart these services are not running:$missing (see docker compose ps and docker compose logs)"
  return 1
}

# "Running" is what Docker says about a container that may be restarting over and over, and an update that only checked that reported "done"
# for a web service that never came up, or one whose database lacked what its code needs. After the restart the web service must ANSWER (any
# status under 500: the redirect to the login page counts, and so does a 400 for a host name it does not allow) and no migration may be
# waiting. The web entrypoint migrates when it starts, so a migration still waiting here means something else went wrong: it is applied
# once, and if it still cannot be the update fails visibly instead of reporting success on an install that returns errors.
verify_serving() {
  local compose=("${COMPOSE[@]}") attempt served=0
  for attempt in $(seq 1 "${CVENGINE_VERIFY_WEB_TRIES:-90}"); do
    if "${compose[@]}" exec -T web python3 -c "import http.client, sys; c = http.client.HTTPConnection('127.0.0.1', 8000, timeout=5); c.request('GET', '/', headers={'Host': 'localhost'}); sys.exit(0 if c.getresponse().status < 500 else 1)" >/dev/null 2>&1; then served=1; break; fi
    sleep "${CVENGINE_VERIFY_POLL:-2}"
  done
  if [ "$served" != 1 ]; then
    log "after the restart the web service does not answer (see docker compose logs web)"
    return 1
  fi
  if ! "${compose[@]}" exec -T web python3 manage.py migrate --check >/dev/null 2>&1; then
    log "the web service answers but the database has migrations waiting; applying them"
    "${compose[@]}" exec -T web python3 manage.py migrate --noinput || return 1
    if ! "${compose[@]}" exec -T web python3 manage.py migrate --check >/dev/null 2>&1; then
      log "migrations are still waiting after migrate; the update is not complete"
      return 1
    fi
  fi
}

# An update builds a new image of a few gigabytes on top of the one it replaces, and a build that runs out of space fails half way, after the
# files were merged and scanning was paused. Look first: too little room is a plain message and a retry, not a half-applied update. The amount
# is CVENGINE_UPDATE_MIN_FREE_MB (default 6144). If Docker's directory cannot be found or measured the check says nothing.
check_disk() {
  local need=${CVENGINE_UPDATE_MIN_FREE_MB:-6144} root free
  root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null) || root=''
  [ -n "$root" ] && [ -d "$root" ] || root=/var/lib/docker
  free=$(df -Pm "$root" 2>/dev/null | awk 'NR == 2 {print $4}')
  [[ $free =~ ^[0-9]+$ ]] || return 0
  if (( free < need )); then
    log "only ${free} MB are free where Docker keeps its images ($root); an update needs about ${need} MB for the new image. Free space (docker image prune -a, docker builder prune), then approve again"
    return 1
  fi
}

# The image this update replaced is untagged now and nothing uses it; every update used to leave one behind (a few gigabytes each) until the disk filled.
# Only after a verified update: until then the old image is the way back. Dangling images only, so nothing that is tagged or in use is touched.
prune_old_images() {
  docker image prune -f >/dev/null 2>&1 || log "could not remove the replaced image; it is only taking disk space"
  return 0
}
