#!/usr/bin/env bash
# What an update does to the services: build, keep the datastores, migrate, collect static files, recreate the application processes.
# Sourced by scripts/apply-update.sh AFTER the new files are in place, so a change here (a new step, a new image to refresh) takes effect
# in the very update that delivers it. The update script itself is the copy already on the host and only changes on the next update.
# Not run on its own: it uses the update script's COMPOSE, STATE_HELPER, phase and log, and sets DEPLOY_STAGE for its rollback decision.

# The proxy shows its friendly maintenance page (web/static/cve/maintenance.html) for as long as the flag file config/nginx/state/maintenance exists
# (and says "the update did not finish" when config/nginx/state/maintenance-failed exists too). ./web is a bind mount, so the moment the update
# changes a file the running containers already read the new code on the old image; the page therefore goes up BEFORE the files change, and
# scripts/apply-update.sh (this repository's copy, and the host's once it has been updated) owns it: it puts the page up before the branch switch and the
# fast-forward, keeps it through the build and the swap, and removes it only after verify_serving below succeeded. It says so by exporting
# UPDATE_OWNS_MAINTENANCE=1. A host whose copy of apply-update.sh is older (the first update that delivers this) does not, and then this file does what it
# can: the page goes up as the first step of the deploy (right after the merge, before the build), and a failed deploy leaves it up (the older script
# puts the previous version back, whose deploy removes it; a retry after the migration sets it again). A host that was stopped mid-update can leave
# the flag behind; `rm config/nginx/state/maintenance*` (or the next update, or make up) clears it.
MAINTENANCE_FLAG=config/nginx/state/maintenance
# folder and files readable by everyone: the proxy checks them as an unprivileged user, whatever umask this script runs under
maintenance_on() { mkdir -p "$(dirname "$MAINTENANCE_FLAG")" 2>/dev/null && chmod 755 "$(dirname "$MAINTENANCE_FLAG")" 2>/dev/null && rm -f "$MAINTENANCE_FLAG-failed" && : >"$MAINTENANCE_FLAG" 2>/dev/null && chmod 644 "$MAINTENANCE_FLAG" 2>/dev/null || log "could not set the maintenance flag; visitors may see an error page while the update runs"; }
maintenance_off() { rm -f "$MAINTENANCE_FLAG" "$MAINTENANCE_FLAG-failed" 2>/dev/null || true; }
maintenance_failed() { : >"$MAINTENANCE_FLAG" 2>/dev/null && chmod 644 "$MAINTENANCE_FLAG" 2>/dev/null; : >"$MAINTENANCE_FLAG-failed" 2>/dev/null && chmod 644 "$MAINTENANCE_FLAG-failed" 2>/dev/null; true; }

# the page's live status (scripts/update-status.py); the update script defines it too and wins
declare -F cv_status >/dev/null || cv_status() { [ -f scripts/update-status.py ] && CV_STATUS_LOG="${LOG:-}" python3 scripts/update-status.py "$@" >/dev/null 2>&1; return 0; }

deploy_current() {
  local status=0
  if [ -z "${UPDATE_OWNS_MAINTENANCE:-}" ]; then cv_status begin "$(git rev-parse HEAD)"; fi
  if [ -n "${UPDATE_OWNS_MAINTENANCE:-}" ]; then
    # the caller put the page up before it changed any file and takes it down after a verified update; it is set again here only for a deploy
    # that is run on its own
    [ -e "$MAINTENANCE_FLAG" ] || maintenance_on
    deploy_steps || status=$?
    return "$status"
  fi
  maintenance_on
  deploy_steps || status=$?
  if [ "$status" = 0 ]; then
    cv_status clear
    maintenance_off
  elif [ "$DEPLOY_STAGE" = migrated ]; then
    cv_status fail restart_failed no
    maintenance_failed  # new code on a migrated database, services not (all) up: never a normal page
  fi
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
  cv_status step build
  check_disk || return 1
  # The proxy image is a moving tag and is meant to move with every update (nginx's security releases). It is fetched here, before anything is
  # stopped, and an unreachable registry only keeps the image already on the host: a pull that failed inside `up` after the migration (as
  # `pull_policy: always` did) failed an update that was otherwise done, and an offline host could never update at all.
  if grep -qx proxy <<<"$listed"; then
    "${compose[@]}" pull --quiet proxy || log "could not pull the newest proxy image (offline, or the registry is limiting pulls); the one on this host is kept"
  fi
  build_free_memory
  SENTINEL_SHA=$(scripts/sentinel-ref.sh 2>/dev/null) || SENTINEL_SHA=''  # the newest Sentinel library, resolved now (docs/UPDATES.md)
  export SENTINEL_SHA
  if ! "${compose[@]}" build web celery celery-beat; then
    build_restore_memory
    DEPLOY_WHY="The new version could not be built (see the update log). Nothing was changed: the version that was running is still running."
    log "$DEPLOY_WHY"
    return 1
  fi
  # The AI reviewer has its own small image (docs/AI-REVIEWER.md). A failed build never fails the update: scanning does not need it, and the
  # next update builds it again.
  if grep -qx reviewer <<<"$listed"; then
    "${compose[@]}" build reviewer || log "could not build the AI reviewer image; scanning is not affected (the next update tries again)"
  fi
  build_restore_memory
  # Which scanners run, decided before anything is stopped and before the scanner's image is fetched (it removes the scanner when the answer is external)
  # (scripts/host-fit.sh, the rules scripts/update.sh and install.sh use too; after the build, because the count of Sentinels is read with the new image).
  # The answer the Update button's dialog collected comes with the approval (web/.update-sentinels, read without following a link); without one (the button
  # of an older server, a check that could not be made, automatic updates) the automatic default applies: the host-size rule, and a scanner is never removed.
  local fit_plan=''
  if [ -f scripts/host-fit.sh ]; then
    . scripts/host-fit.sh
    fit_plan=$(python3 scripts/update-state.py sentinels-choice 2>/dev/null) || fit_plan=''
    cvengine_fit_run "$fit_plan" "${compose[@]}" || true
    [ -z "$cv_fit_short" ] || phase applying "build: $cv_fit_short"
  fi
  # The built-in scanner's pinned image (scanner.lock.json): pulled now, before anything is stopped. It never fails the update (scripts/scanner.sh).
  if [ -f scripts/scanner.sh ]; then
    . scripts/scanner.sh
    cvengine_scanner_fetch "${compose[@]}"
  fi
  DEPLOY_STAGE=datastores
  phase applying "$DEPLOY_STAGE"
  # Compose reads ${REDIS_PASSWORD} from the --env-file it is given (an overlay's .env.vps), so the password goes there too
  if . scripts/redis-password.sh && cvengine_ensure_redis_password "$(cvengine_compose_env_file "${compose[@]}")"; then
    # an installation without a broker password gets one: Redis is recreated with it now, and every client below with the new address
    log "the Redis broker had no password: generated one (REDIS_PASSWORD in .env) and recreating Redis with it; queued tasks are lost once"
    "${compose[@]}" up -d --no-recreate db || return 1
    "${compose[@]}" up -d --no-deps --force-recreate redis || return 1
  else
    "${compose[@]}" up -d --no-recreate db redis || return 1
  fi
  # The database's own settings are in the compose file (max_connections). `up -d --no-deps db` recreates the db container only when its
  # definition changed since it was created (once, on the update that brings the change: a restart of a few seconds), and is a no-op otherwise.
  "${compose[@]}" up -d --no-deps db || return 1
  for _ in $(seq 1 60); do "${compose[@]}" exec -T db pg_isready -q >/dev/null 2>&1 && break; sleep 1; done
  phase applying backup
  cv_status step backup
  backup_database || return 1
  DEPLOY_STAGE=migrate
  phase applying "$DEPLOY_STAGE"
  cv_status step migrating
  run_migrations || return 1
  DEPLOY_STAGE=migrated
  phase applying "$DEPLOY_STAGE"
  "${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py collectstatic --noinput || return 1
  # The web interface certificate is renewed here when its check is due, so the proxy recreated below starts with the new one (a host with
  # neither the update watcher nor cron has no other trigger). A failure is logged and never stops the update.
  if [ -f scripts/renew-certs.sh ]; then
    scripts/renew-certs.sh --if-due --no-reload >/dev/null 2>&1 || log "the certificate check failed (see the Settings > Updates page); the update goes on"
  fi
  cv_status step starting
  "${compose[@]}" up -d --no-deps --force-recreate "${services[@]}" || return 1
  # The Tailscale sidecar shares the celery container's network namespace by container id, so it is orphaned (no tailscale0, no tailnet route
  # for scans) when celery is recreated. Only present when the profile is on.
  if grep -qx tailscale <<<"$listed"; then
    "${compose[@]}" up -d --no-deps --force-recreate tailscale || log "could not restart the Tailscale sidecar: run docker compose up -d --force-recreate tailscale, or scans of tailnet addresses fail"
  fi
  # The AI reviewer is recreated after the application (it waits for the server's token on its own); it is not in verify_running, and its
  # failing to start never fails the update.
  if grep -qx reviewer <<<"$listed"; then
    "${compose[@]}" up -d --no-deps --force-recreate reviewer || log "could not start the AI reviewer (docker compose up -d reviewer); scanning is not affected"
  fi
  verify_running "${services[@]}" || return 1
  # still DEPLOY_STAGE=migrated: a failure here is a failure AFTER the migration, and the script that applies the update (the copy already on
  # the host, which only knows build, datastores, migrate and migrated) must keep the new code and retry, never put the old code on the new schema
  phase applying verifying
  cv_status step verifying
  verify_serving || return 1
  # The built-in scanner, once the server answers: recreated after celery (it shares celery's network namespace), kept on the new image only once a
  # heartbeat of it reaches the server, else put back on the previous one. Never a failed update: until it runs, the scans that need it wait.
  if declare -F cvengine_scanner_start >/dev/null; then
    phase applying scanner
    cv_status step scanner
    cvengine_scanner_start "${compose[@]}"
  fi
  if declare -F cvengine_fit_budget >/dev/null; then cvengine_fit_budget "${compose[@]}" || true; fi
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
# files were merged and scanning was paused. Look first: too little room is a plain sentence and a retry, not a half-applied update. The estimate and
# the rule are in scripts/update-disk.sh (the first 1.3 to 1.4 update needs about 14 GB: the scanner image alone is 5.1 GB). Below it the updater first
# removes what is safe to remove (untagged images, the build cache; never a tagged image or a volume) and measures again. If Docker's directory cannot
# be measured the check says nothing. DEPLOY_WHY is the sentence the Update screen shows when the update ends here.
DEPLOY_WHY=${DEPLOY_WHY:-}
check_disk() {
  local plan=''
  if [ ! -f scripts/update-disk.sh ]; then return 0; fi
  . scripts/update-disk.sh
  plan=$(python3 scripts/update-state.py sentinels-choice 2>/dev/null) || plan=''
  cvengine_disk_check "$plan" && return 0
  DEPLOY_WHY=$cv_disk_sentence
  log "$cv_disk_sentence (nothing was stopped or changed)"
  return 1
}

# The cold build of the server image needs about 2 GiB (a 1 GiB cap fails in the nuclei compile). On a host under 7 GB (the rule of scripts/host-fit.sh) the
# heavy containers that can come back safely are stopped for the build and started again right after it, with or without a build that worked: the
# built-in scanner and the celery workers (their memory stays resident after the scans drain, and the build then competes with it, swaps or is killed).
# Never db, redis, web or proxy, and beat is small. CVENGINE_UPDATE_STOP_CELERY=0 (environment or .env) turns it off.
BUILD_STOPPED=()
build_free_memory() {
  local compose=("${COMPOSE[@]}") kb off running svc
  BUILD_STOPPED=()
  [ -f scripts/host-fit.sh ] || return 0
  . scripts/host-fit.sh
  off=$(cvengine_fit_value CVENGINE_UPDATE_STOP_CELERY .env)
  [ "$off" != 0 ] || return 0
  kb=$(cvengine_fit_mem_kb)
  (( kb > 0 && kb < cv_fit_small_kb )) || return 0
  running=$("${compose[@]}" ps --status running --services 2>/dev/null) || running=''
  for svc in scanner celery; do  # the scanner first: it shares celery's network
    grep -qx "$svc" <<<"$running" && BUILD_STOPPED+=("$svc")
  done
  [ "${#BUILD_STOPPED[@]}" -gt 0 ] || return 0
  log "this host has $(cvengine_fit_gb "$kb") of memory and the build needs about 2 GB: stopping ${BUILD_STOPPED[*]} for the build; they start again right after it (the update has stopped them already when it moves the files, this is the fallback for a deploy run on its own)"
  phase applying "build: ${BUILD_STOPPED[*]} stopped for the build"
  "${compose[@]}" stop -t 30 "${BUILD_STOPPED[@]}" >/dev/null 2>&1 || log "could not stop ${BUILD_STOPPED[*]} cleanly; the build goes on"
}

build_restore_memory() {  # always, build worked or not: nothing stays stopped
  local compose=("${COMPOSE[@]}") svc ordered=() ok=1 listed=''
  [ "${#BUILD_STOPPED[@]}" -gt 0 ] || return 0
  for svc in celery scanner; do  # celery first: the scanner joins its network
    for s in "${BUILD_STOPPED[@]}"; do [ "$s" = "$svc" ] && ordered+=("$svc"); done
  done
  for svc in "${ordered[@]}"; do
    "${compose[@]}" start "$svc" >/dev/null 2>&1 || { ok=0; log "could not start $svc again after the build (docker compose start $svc)"; }
  done
  # the Tailscale sidecar shares celery's network namespace by container id: it follows celery's restart
  if listed=$("${compose[@]}" config --services 2>/dev/null) && grep -qx tailscale <<<"$listed" && grep -qx celery <<<"${ordered[*]}"; then
    "${compose[@]}" restart tailscale >/dev/null 2>&1 || true
  fi
  [ "$ok" = 1 ] && log "${ordered[*]} started again after the build"
  BUILD_STOPPED=()
  return 0
}

# The image this update replaced is untagged now and nothing uses it; every update used to leave one behind (a few gigabytes each) until the disk filled.
# Only after a verified update: until then the old image is the way back. Dangling images only, so nothing that is tagged or in use is touched.
prune_old_images() {
  docker image prune -f >/dev/null 2>&1 || log "could not remove the replaced image; it is only taking disk space"
  return 0
}
