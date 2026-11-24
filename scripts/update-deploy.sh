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

# The built-in scanner's image (scanner.lock.json; about 5 GB) is fetched ONCE per update. Where the files have not changed yet, the site is still up and
# a pull changes nothing the running containers read, so it is better made before the page goes up (minutes on a small host). That is only
# scripts/apply-update.sh (this repository's copy), which does it before the merge and says so in CV_SCANNER_PREFETCHED (the image it was for).
# A host whose copy of apply-update.sh is older has merged already when deploy_current runs: ./web (a bind mount) then holds the new code under the
# old image, so nothing may come before the page, and the fetch is made from the deploy steps, under it.
#   once   from the deploy steps, after the host-fit decision: fetches only when no early fetch was made for the image the new files name (the lock changed,
#          the scanner was off then and is on now, there was none, or the host's script is older). It never fails the update (scripts/scanner.sh).
CV_SCANNER_PREFETCHED=${CV_SCANNER_PREFETCHED:-}
deploy_scanner_fetch() {  # once
  local ref
  [ -f scripts/scanner.sh ] || return 0
  . scripts/scanner.sh
  ref=$(cvengine_scanner_wanted_image "${COMPOSE[@]}" 2>/dev/null) || ref=''
  if [ -n "$ref" ] && [ "$ref" = "$CV_SCANNER_PREFETCHED" ]; then
    log "the built-in scanner image ($ref) was already fetched before the maintenance page went up"
    return 0
  fi
  cvengine_scanner_fetch "${COMPOSE[@]}"
}

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
  # This host's apply-update.sh is older than this file: it has already merged, so ./web (a bind mount) holds the new code under the old image
  # and the page goes up NOW, as the very first step. The scanner image is fetched under the page (deploy_scanner_fetch once, in the steps), never
  # before it: a 5 GB pull takes minutes on a small host and the visitor would see the old image on new files the whole time.
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

# The database owner's commands (migrate, showmigrations, the app role's check) run in a one-off container of the migrate service
# (docker-compose.yml, web/migrate-entrypoint.sh): the only container with the owner's password; web, celery and celery-beat do not have it.
# A Compose layout without that service (an install's own file that replaces docker-compose.yml) keeps the old way: a one-off web container
# with CVENGINE_DB_ROLE=owner. deploy_steps sets CV_OWNER_SERVICE from the services the layout defines.
CV_OWNER_SERVICE=migrate
owner_run() {  # owner_run [-T] manage.py ARGS...
  local tty=()
  if [ "${1:-}" = -T ]; then tty=(-T); shift; fi
  if [ "$CV_OWNER_SERVICE" = migrate ]; then
    "${COMPOSE[@]}" run --rm --no-deps ${tty[@]+"${tty[@]}"} migrate python3 "$@"
  else
    "${COMPOSE[@]}" run --rm --no-deps ${tty[@]+"${tty[@]}"} -e CVENGINE_DB_ROLE=owner --entrypoint python3 web "$@"
  fi
}

# Before anything is migrated or restarted: the application must be able to run without the owner's password. cvengine_owner_password_check
# refuses a layout that still hands it to another service (an overlay's environment); cvengine_db_gate creates and grants the app role in the
# migrate service and checks that it logs in, and fails with the one-line fix when it does not (unless CVENGINE_DB_ALLOW_OWNER_FALLBACK=1).
# Still DEPLOY_STAGE=datastores, so a failure here puts the previous version back on the unchanged database.
check_db_roles() {
  local out status=0 line
  [ "$CV_OWNER_SERVICE" = migrate ] && [ -f scripts/db-app-role.sh ] || return 0
  . scripts/db-app-role.sh
  out=$(cvengine_owner_password_check "${COMPOSE[@]}" 2>&1) || status=$?
  if [ "$status" = 0 ]; then out=$(cvengine_db_gate "${COMPOSE[@]}" 2>&1) || status=$?; fi
  while IFS= read -r line; do [ -z "$line" ] || log "$line"; done <<<"$out"
  [ "$status" = 0 ] && return 0
  line=$(grep -m1 '^Fix:' <<<"$out" || true)
  DEPLOY_WHY="The update stopped before migrating: the server would have to run with the database owner's password. ${line:-See the update log.}"
  return 1
}

# How many migrations the database has applied; fails when that cannot be read.
applied_migrations() {
  local plan
  plan=$(owner_run -T manage.py showmigrations --plan 2>/dev/null) || return 1
  grep -c '^\[X\]' <<<"$plan" || true
}

# Every migration runs in a transaction of its own, so a failed batch can leave the first ones applied. The previous code must never be put back
# on a schema that is partly migrated: when the count of applied migrations changed (or cannot be read), the stage becomes "migrated", which the
# script that applies the update answers by keeping the new code and saying so, not by rolling back.
run_migrations() {
  local before after
  before=$(applied_migrations) || before=''
  # as the database's owner role, in the migrate service; the migrate also creates or updates the app role and grants it (web/reNgine/db_roles.py)
  owner_run manage.py migrate --noinput && return 0
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

# On 1.4 an assessment holds a discovery slot while it waits for a Sentinel, so DISCOVERY_CONCURRENCY below 4 (a leftover of the 1.3 era, when the pool
# only ran discovery) lets ONE host be assessed at a time for the whole instance while the Sentinels idle, and it pins the value: the server's own sizing
# (autotune range 4 to 32) is not allowed to move it. Say so in the update log (the Update screen shows it). (The pin is removed by cvengine_fit_review, scripts/host-review.py, before this runs; this says so only when that could not run, and edits nothing.)
# A Sentinel that is live, or the built-in scanner (on unless CVENGINE_BUILTIN_SCANNER=0), is what makes it matter. Always returns 0.
warn_discovery_pin() {
  local value builtin live env_file=''
  if [ -f scripts/redis-password.sh ]; then . scripts/redis-password.sh; env_file=$(cvengine_compose_env_file "$@" 2>/dev/null || true); fi
  declare -F cvengine_fit_value >/dev/null || return 0
  value=$(cvengine_fit_value DISCOVERY_CONCURRENCY "$env_file")
  [[ $value =~ ^[0-9]+$ ]] || return 0
  value=$((10#$value))
  (( value < 4 )) || return 0
  builtin=$(cvengine_fit_value CVENGINE_BUILTIN_SCANNER "$env_file")
  live=$(cvengine_fit_externals "$@" 2>/dev/null || true)
  if [[ $builtin == 0 && ( $live == 0 ) ]]; then return 0; fi
  log "Warning: Hosts assessed at once is held at $value by DISCOVERY_CONCURRENCY in .env, so only $value host$([ "$value" = 1 ] || echo s) $([ "$value" = 1 ] && echo is || echo are) assessed at a time and your Sentinels wait for work. Remove that line from .env and run docker compose up -d celery; the server then sizes it itself. (This update does not change your .env.)"
  return 0
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
  # where the owner's commands run (owner_run): the migrate service, unless the layout lacks it (and when the list cannot be read, it is there)
  CV_OWNER_SERVICE=migrate
  if [ -n "$listed" ] && ! grep -qx migrate <<<"$listed"; then CV_OWNER_SERVICE=web; fi
  DEPLOY_STAGE=build
  phase applying "$DEPLOY_STAGE"
  cv_status step build
  check_disk || return 1
  # proxy_network's fixed subnet must be free before anything is stopped or migrated (scripts/client-address.sh); a clash would stop `up` half way
  if [ -f scripts/client-address.sh ] && . scripts/client-address.sh; then
    local clash
    if ! clash=$(cvengine_proxy_network_check "${compose[@]}"); then
      DEPLOY_WHY="The update stopped before changing anything: $clash"
      log "$DEPLOY_WHY"
      return 1
    fi
  fi
  # The proxy image is pinned by digest (scripts/image_pins.py): a new nginx release arrives with the commit that moved the pin. It is fetched here,
  # before anything is stopped, and an unreachable registry only keeps the image already on the host: a pull that failed inside `up` after the
  # migration (as `pull_policy: always` did) failed an update that was otherwise done, and an offline host could never update at all.
  if grep -qx proxy <<<"$listed"; then
    "${compose[@]}" pull --quiet proxy || log "could not pull the newest proxy image (offline, or the registry is limiting pulls); the one on this host is kept"
  fi
  # Redis and Postgres are pinned by digest too (redis:alpine, postgres:18-alpine at the digest scripts/image_pins.py wrote). Fetched here with the
  # proxy, before anything is stopped; the datastores step below recreates each one only when its pin moved. A failed pull keeps the images on this host.
  if grep -qx proxy <<<"$listed"; then  # the production stack, as for the proxy: the dev stack pulls nothing
    "${compose[@]}" pull --quiet db redis || log "could not pull the newest Redis and Postgres images (offline, or the registry is limiting pulls); the ones on this host are kept"
  fi
  build_free_memory
  # the Sentinel library is the commit web/requirements.txt pins: nothing is resolved at build time (docs/UPDATES.md)
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
  # The application runs as its own account (uid 10002) from this image on: the paths it writes (the volumes, the Django secret, its own update
  # requests in web/) are handed to it before anything of the new image runs (the host-fit count below, the migrate service, the application).
  # Idempotent: an install that has it already changes nothing (scripts/app-ownership.sh, web/ownership.sh).
  app_ownership || return 1
  # Which scanners run, decided before anything is stopped and before the scanner's image is fetched (it removes the scanner when the answer is external)
  # (scripts/host-fit.sh, the rules scripts/update.sh and install.sh use too; after the build, because the count of Sentinels is read with the new image).
  # The answer the Update button's dialog collected comes with the approval (web/.update-sentinels, read without following a link); without one (the button
  # of an older server, a check that could not be made, automatic updates) the automatic default applies: the host-size rule, and a scanner is never removed.
  local fit_plan=''
  if [ -f scripts/host-fit.sh ]; then
    . scripts/host-fit.sh
    load_update_sentinels
    fit_plan=$CV_UPDATE_SENTINELS
    cvengine_fit_run "$fit_plan" "${compose[@]}" || true
    [ -z "$cv_fit_short" ] || phase applying "build: $cv_fit_short"
  fi
  warn_discovery_pin "${compose[@]}"
  # The built-in scanner's image (scanner.lock.json): normally fetched already, before the page went up (deploy_scanner_fetch). It never fails the update.
  deploy_scanner_fetch once
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
  # The least privilege database role the server runs as (scripts/db-app-role.sh): an installation without its password gets one now, in .env and
  # the Compose env file. The migrate below creates the role with it and grants it; web, celery and celery-beat, recreated after that, run as it.
  if [ -f scripts/db-app-role.sh ] && . scripts/db-app-role.sh && cvengine_ensure_db_app_password "$(cvengine_compose_env_file "${compose[@]}")"; then
    log "the server had no database role of its own: generated its password (CVENGINE_DB_APP_PASSWORD in .env); the migration creates the role and the server runs as it from this update on"
  fi
  # The upstream secret a host nginx sends so the proxy believes its X-Forwarded-For (scripts/client-address.sh): generated when there is none, in .env
  # and the Compose env file; the proxy recreated below loads it. Until the host nginx sends it nothing changes (docs/DEPLOYMENT.md).
  if [ -f scripts/client-address.sh ] && . scripts/client-address.sh && cvengine_ensure_upstream_secret "$(cvengine_compose_env_file "${compose[@]}")"; then
    log "generated the upstream secret (CVENGINE_UPSTREAM_SECRET in .env); a host nginx in front of the proxy needs it to pass on the client address: scripts/client-address-check.sh --snippet"
  fi
  # The database's own settings are in the compose file (max_connections). `up -d --no-deps db` recreates the db container only when its
  # definition changed since it was created (once, on the update that brings the change: a restart of a few seconds), and is a no-op otherwise.
  "${compose[@]}" up -d --no-deps db || return 1
  # the same for Redis: recreated only when a newer image was pulled above (dispatch is paused and the queues drained by now), else a no-op
  "${compose[@]}" up -d --no-deps redis || return 1
  for _ in $(seq 1 60); do "${compose[@]}" exec -T db pg_isready -q >/dev/null 2>&1 && break; sleep 1; done
  phase applying backup
  cv_status step backup
  backup_database || return 1
  check_db_roles || return 1
  DEPLOY_STAGE=migrate
  phase applying "$DEPLOY_STAGE"
  cv_status step migrating
  run_migrations || return 1
  DEPLOY_STAGE=migrated
  phase applying "$DEPLOY_STAGE"
  # in celery, the one service that writes the static volume (web and the proxy mount it read-only)
  "${compose[@]}" run --rm --no-deps --entrypoint python3 celery manage.py collectstatic --noinput || return 1
  # The web interface certificate is renewed here when its check is due, so the proxy recreated below starts with the new one (a host with
  # neither the update watcher nor cron has no other trigger). A failure is logged and never stops the update.
  if [ -f scripts/renew-certs.sh ]; then
    scripts/renew-certs.sh --if-due --no-reload >/dev/null 2>&1 || log "the certificate check failed (see the Settings > Updates page); the update goes on"
  fi
  cv_status step starting
  # again, for what the old containers (which ran as root) wrote since the first pass; nothing to do on a second update
  app_ownership || return 1
  "${compose[@]}" up -d --no-deps --force-recreate "${services[@]}" || return 1
  # The Tailscale sidecar (tailscale profile) is not recreated here: it runs in the built-in scanner's network namespace, not celery's, and is put
  # back into it when the scanner is started below (scripts/scanner.sh, cvengine_scanner_sidecar), including on an install that had it in celery's.
  # The AI reviewer is recreated after the application (it waits for the server's token on its own); it is not in verify_running, and its
  # failing to start never fails the update.
  if grep -qx reviewer <<<"$listed"; then
    "${compose[@]}" up -d --no-deps --force-recreate reviewer || log "could not start the AI reviewer (docker compose up -d reviewer); scanning is not affected"
  fi
  verify_running "${services[@]}" || return 1
  # The old in-stack OpenVAS containers, which docker-compose.yml no longer defines, are stopped and removed; their volumes are kept.
  if [ -f scripts/retire-openvas.sh ]; then
    # shellcheck source=scripts/retire-openvas.sh
    . scripts/retire-openvas.sh
    cvengine_retire_openvas || true
  fi
  # still DEPLOY_STAGE=migrated: a failure here is a failure AFTER the migration, and the script that applies the update (the copy already on
  # the host, which only knows build, datastores, migrate and migrated) must keep the new code and retry, never put the old code on the new schema
  phase applying verifying
  cv_status step verifying
  verify_serving || return 1
  # The proxy is what visitors reach, and a proxy whose configuration nginx refuses restarts over and over while `ps` calls it running.
  if printf '%s\n' "${services[@]}" | grep -qx proxy; then verify_proxy || return 1; fi
  # Which database role web, celery and celery-beat run as; a warning when any still uses the owner role (never fails the update).
  if declare -F cvengine_db_role_report >/dev/null; then
    while IFS= read -r line; do [ -z "$line" ] || log "$line"; done < <(cvengine_db_role_report "${compose[@]}")
  fi
  # Whether the real client address reaches the server (scripts/client-address.sh): one probe through the public name, compared with what
  # Cloudflare saw. A report in the update log, never a failure; the probe route passes the maintenance page (config/nginx/rengine.conf).
  if declare -F cvengine_client_address_report >/dev/null; then
    while IFS= read -r line; do [ -z "$line" ] || log "$line"; done < <(cvengine_client_address_report "${compose[@]}" 2>/dev/null)
  fi
  # The built-in scanner, once the server answers: recreated on its own network (the Tailscale sidecar follows it), kept on the new image only once a
  # heartbeat of it reaches the server, else put back on the previous one. Never a failed update: until it runs, the scans that need it wait.
  if declare -F cvengine_scanner_start >/dev/null; then
    phase applying scanner
    cv_status step scanner
    cvengine_scanner_start "${compose[@]}"
  fi
  if declare -F cvengine_fit_budget >/dev/null; then cvengine_fit_budget "${compose[@]}" || true; fi
  prune_old_images
}

# The one-off ownership service (scripts/app-ownership.sh): one log line; a failure stops the deploy before the application is recreated.
app_ownership() {
  local out
  [ -f scripts/app-ownership.sh ] || return 0
  . scripts/app-ownership.sh
  if out=$(cvengine_app_ownership "${COMPOSE[@]}"); then
    log "$out"
    return 0
  fi
  log "$out"
  DEPLOY_WHY="The application's files could not be handed to its own account (docker compose run --rm ownership; see the update log)."
  return 1
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

# The bundled proxy must load its configuration and stay up. verify_running saw it "running", which is also what Docker says between two restarts
# of a proxy nginx refuses to start (a 1.5 develop build did that: its map did not fit nginx's hash bucket), and verify_serving asks the web
# service directly, not through the proxy. So the update reported "done" and took the maintenance page down while every visitor got no answer.
# Here nginx checks the configuration it runs with (`nginx -t` in the proxy container) and the container's restart count must not move while it
# is watched. A proxy that fails is a failed update after the migration: the new code is kept, the deploy retried, the page says it did not finish.
verify_proxy() {
  local compose=("${COMPOSE[@]}") attempt id before after said=''
  for attempt in $(seq 1 "${CVENGINE_VERIFY_PROXY_TRIES:-15}"); do
    id=$("${compose[@]}" ps -q proxy 2>/dev/null | head -n 1) || id=''
    before=''
    [ -z "$id" ] || before=$(docker inspect -f '{{.RestartCount}}' "$id" 2>/dev/null) || before=''
    if said=$("${compose[@]}" exec -T proxy nginx -t 2>&1); then
      sleep "${CVENGINE_VERIFY_POLL:-2}"
      after=''
      [ -z "$id" ] || after=$(docker inspect -f '{{.RestartCount}}' "$id" 2>/dev/null) || after=''
      [ "$before" = "$after" ] && return 0
      said="the proxy container restarted while it was watched (restart count ${before:-?} then ${after:-?})"
    fi
    sleep "${CVENGINE_VERIFY_POLL:-2}"
  done
  said=$(printf '%s\n' "$said" | grep -iE 'emerg|error|restart' | tail -n 1 || true)
  [ -n "$said" ] || said=$("${compose[@]}" logs --tail 20 proxy 2>/dev/null | grep -iE 'emerg|error' | tail -n 1 || true)
  log "after the restart the proxy does not stay up, so visitors get no answer: ${said:-see docker compose logs proxy}"
  DEPLOY_WHY="The proxy (nginx) does not start with the new configuration: ${said:-see docker compose logs proxy}"
  return 1
}

# "Running" is what Docker says about a container that may be restarting over and over, and an update that only checked that reported "done"
# for a web service that never came up, or one whose database lacked what its code needs. After the restart the web service must ANSWER (any
# status under 500: the redirect to the login page counts, and so does a 400 for a host name it does not allow) and no migration may be
# waiting. The migrate service ran before the restart, so a migration still waiting here means something else went wrong: it is applied
# once (in the migrate service again), and if it still cannot be the update fails visibly instead of reporting success on an install that returns errors.
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
    owner_run -T manage.py migrate --noinput || return 1
    if ! "${compose[@]}" exec -T web python3 manage.py migrate --check >/dev/null 2>&1; then
      log "migrations are still waiting after migrate; the update is not complete"
      return 1
    fi
  fi
  verify_workers || return 1
}

# A web service that answers says nothing about the Celery workers, and an update that was "done" with only some of them running left the queues
# unconsumed (the maintenance page was already gone). All four named workers must answer, each with its own queue, before the update is done and the
# maintenance page is removed: discovery_worker, cve_feed_worker, validation_priority_worker and classic_worker. The check is the container's own
# (web/celery_healthcheck.py, the HEALTHCHECK of the celery service), run in the recreated container; the entrypoint's start work (migrations wait,
# collectstatic, template updates) can take minutes, so it is asked again for CVENGINE_VERIFY_WORKERS_SECONDS (default 600).
verify_workers() {
  local compose=("${COMPOSE[@]}") waited=0 limit="${CVENGINE_VERIFY_WORKERS_SECONDS:-600}" said=''
  while :; do
    said=$("${compose[@]}" exec -T celery python3 celery_healthcheck.py 2>&1) && return 0
    [ "$waited" -ge "$limit" ] && break
    sleep "${CVENGINE_VERIFY_WORKERS_POLL:-5}"
    waited=$((waited + ${CVENGINE_VERIFY_WORKERS_POLL:-5}))
  done
  DEPLOY_WHY="The new version started, but not every background worker answers (${said:-the check could not run}). Scanning stays paused and the maintenance page stays up until they do: run docker compose restart celery, then retry the update."
  log "$DEPLOY_WHY"
  return 1
}

# An update builds a new image of a few gigabytes on top of the one it replaces, and a build that runs out of space fails half way, after the
# files were merged and scanning was paused. Look first: too little room is a plain sentence and a retry, not a half-applied update. The estimate and
# the rule are in scripts/update-disk.sh (the first 1.3 to 1.4 update needs about 14 GB: the scanner image alone is 5.1 GB). Below it the updater first
# removes what is safe to remove (untagged images, the build cache; never a tagged image or a volume) and measures again. If Docker's directory cannot
# be measured the check says nothing. DEPLOY_WHY is the sentence the Update screen shows when the update ends here.
DEPLOY_WHY=${DEPLOY_WHY:-}
# The Approve dialog's answer to "which scanners run" (web/.update-sentinels), needed by the disk check and by the scanner plan below. scripts/apply-update.sh
# reads it once per run and hands it over in CV_UPDATE_SENTINELS (empty when there is none). An older apply-update.sh does not: then it is read here once,
# on first use, and kept for the rest of the deploy, so the disk check no longer takes it from the scanner plan.
load_update_sentinels() {
  [ -z "${CV_UPDATE_SENTINELS+x}" ] || return 0
  CV_UPDATE_SENTINELS=$(python3 scripts/update-state.py sentinels-choice 2>/dev/null) || CV_UPDATE_SENTINELS=''
  export CV_UPDATE_SENTINELS
}
check_disk() {
  local plan=''
  if [ ! -f scripts/update-disk.sh ]; then return 0; fi
  . scripts/update-disk.sh
  load_update_sentinels
  plan=$CV_UPDATE_SENTINELS
  cvengine_disk_check "$plan" && return 0
  DEPLOY_WHY=$cv_disk_sentence
  log "$cv_disk_sentence (nothing was stopped or changed)"
  return 1
}

# The cold build of the server image needs about 2 GiB (it used to compile nuclei; its Python packages still need room to build). On a host under 7 GB (the rule of scripts/host-fit.sh) the
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
  for svc in scanner celery; do
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
  for svc in celery scanner; do
    for s in "${BUILD_STOPPED[@]}"; do [ "$s" = "$svc" ] && ordered+=("$svc"); done
  done
  for svc in "${ordered[@]}"; do
    "${compose[@]}" start "$svc" >/dev/null 2>&1 || { ok=0; log "could not start $svc again after the build (docker compose start $svc)"; }
  done
  # the Tailscale sidecar shares the scanner's network namespace by container id: it follows the scanner's restart
  if listed=$("${compose[@]}" config --services 2>/dev/null) && grep -qx tailscale <<<"$listed" && grep -qw scanner <<<"${ordered[*]}"; then
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
