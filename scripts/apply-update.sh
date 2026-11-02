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
#   4. fast-forwards to exactly that commit, rebuilds and restarts app services while leaving the Redis container running (the db container is
#      recreated only when its compose definition changed, e.g. max_connections);
#   5. if it fails before the database is migrated (the build, or the migration itself), returns to the previous
#      commit and restarts it. Once the migration has succeeded the previous code is never put back, because it would
#      run on the new schema: the restart is retried and, if it still fails, the approval is kept so the next run
#      retries it. Schema migrations are never rolled back.
# Results are retained in Git-private state and safely published to web/.update-log.
# Needs python3, git and Docker, and a clone that can `git fetch origin`.
#
# The Compose layout is the one the running stack was started with, or CVENGINE_COMPOSE_FILES / CVENGINE_COMPOSE_ENV_FILE /
# CVENGINE_COMPOSE_PROJECT (environment or .env, the settings scripts/update.sh reads); see resolve_layout below. Ordinary updates
# deliberately keep db/Redis containers running (db is recreated only when its compose definition changed). A PostgreSQL major-version migration requires a separate maintenance operation. An update
# waits while recorded scans or targeted jobs are running, up to CVENGINE_UPDATE_DRAIN_SECONDS (environment or .env, default 300); past that it
#    proceeds and interrupts them (cveFeed.reaper.expire_orphaned_running closes out what the restart leaves behind within one reaper tick).
#    Operators should drain other worker work as well.
# A dump of the database is taken just before the migrations (scripts/update-deploy.sh, CVENGINE_UPDATE_BACKUPS, default 3 kept). Which branches an
# approval may name (CVENGINE_UPDATE_BRANCHES, default: any) and whether the commit must be signed (CVENGINE_UPDATE_REQUIRE_SIGNED=1) are set in
# .env on the host: the web container, which writes the approval, cannot change them. See docs/UPDATES.md, "What the host trusts".
set -euo pipefail

cd "$(dirname "$0")/.."
# root (cron, a systemd unit) in a checkout owned by whoever cloned it: git refuses it ("dubious ownership") unless this one is named. Root
# already runs this checkout's scripts, so naming it adds no trust.
export GIT_CONFIG_COUNT=$(( ${GIT_CONFIG_COUNT:-0} + 1 ))
export "GIT_CONFIG_KEY_$((GIT_CONFIG_COUNT - 1))=safe.directory" "GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT - 1))=$PWD"
FLAG=web/.update-approved
BRANCH_FLAG=web/.update-branch  # the branch the administrator chose in Settings; optional
clear_approval() { rm -f "$FLAG" "$BRANCH_FLAG"; }
[ -e "$FLAG" ] || [ -L "$FLAG" ] || exit 0
STATE=$(python3 scripts/update-state.py directory)
LOG="$STATE/update.log"
# cron discards this script's output, so a command that fails under `set -e` used to end the run without a trace and the
# banner waited for ever. Say which command stopped it; Settings > Updates shows the published log.
set -E
trap 'printf "%s the update script stopped at line %s: %s\n" "$(date -u +%FT%TZ)" "$LINENO" "$BASH_COMMAND" >>"$LOG"' ERR
exec 9>"$STATE/update.lock"
flock -n 9 || exit 0  # another run is in progress
# Retain this safe publisher when rollback restores code without the helper.
STATE_HELPER="$STATE/update-state.py"
cp scripts/update-state.py "$STATE_HELPER"
python3 "$STATE_HELPER" migrate-log "$LOG"

# .env is kept in a private (0600) temporary copy during the merge and removed when the script ends; its
# contents are never printed or logged.
ENV_BACKUP=
ENV_MODE=
cleanup() {
  local status=$?
  [ -z "$ENV_BACKUP" ] || rm -f "$ENV_BACKUP"
  if [ -f "$LOG" ]; then
    local helper=$STATE_HELPER
    [ -f "$helper" ] || helper=scripts/update-state.py  # the copy above is what failed
    python3 "$helper" log "$LOG" || {
      echo "Could not publish UI update log; complete log retained at $LOG" >&2
      status=1
    }
  fi
  return "$status"
}
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
# The watcher (scripts/update-watch.sh) calls this script again every few seconds while an approval is waiting; say each reason once,
# not on every call.
log_once() {
  [ "$(cat "$STATE/last-refusal" 2>/dev/null)" = "$*" ] && return 0
  printf '%s' "$*" > "$STATE/last-refusal"
  log "$*"
}

# The Compose layout this install runs with: every file, the env file and the project name. Recreating the containers from a different
# layout than they were started with (an overlay that frees a host port, memory limits, a separate env file) breaks the site, so:
#   1. CVENGINE_COMPOSE_FILES (comma separated; CVENGINE_COMPOSE_FILE for one), CVENGINE_COMPOSE_ENV_FILE and CVENGINE_COMPOSE_PROJECT,
#      from the environment or .env, say it outright (the same settings scripts/update.sh reads);
#   2. otherwise the layout the running web container was started with is used, so an install with an overlay needs no setting;
#   3. otherwise docker-compose.yml, but not when the checkout holds an overlay of its own that nothing says to use: that stops here.
setting() {
  local name=$1 value=${!1:-}
  if [ -z "$value" ] && [ -f .env ]; then
    value=$(grep -E "^${name}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
    value=${value#[\"\']}; value=${value%[\"\']}
  fi
  printf '%s' "$value"
}

COMPOSE=(docker compose)
COMPOSE_NAMES=()
resolve_layout() {
  local files env_file project detected=0 id labels path name
  files=$(setting CVENGINE_COMPOSE_FILES)
  [ -n "$files" ] || files=$(setting CVENGINE_COMPOSE_FILE)
  env_file=$(setting CVENGINE_COMPOSE_ENV_FILE)
  project=$(setting CVENGINE_COMPOSE_PROJECT)
  if [ -z "$files" ]; then
    id=$(docker ps -a --filter "label=com.docker.compose.project.working_dir=$(pwd)" --filter "label=com.docker.compose.service=web" --format '{{.ID}}' 2>/dev/null | head -n1) || id=''
    if [ -n "$id" ]; then
      labels=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$id" 2>/dev/null) || labels=''
      for path in ${labels//,/ }; do
        name=$(basename "$path")
        if ! [[ $name =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $name && $(dirname "$path") = "$(pwd)" ]]; then
          log_once "refusing: the running stack was started with $path, which is not a compose file in $(pwd); set CVENGINE_COMPOSE_FILES in .env to the files it uses"
          return 1
        fi
        files="${files:+$files,}$name"
      done
      if [ -n "$files" ]; then
        detected=1
        [ -n "$env_file" ] || env_file=$(basename "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.environment_file"}}' "$id" 2>/dev/null)" 2>/dev/null || true)
        [ -f "$env_file" ] || env_file=''
        [ -n "$project" ] || project=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)
      fi
    fi
  fi
  [ -n "$files" ] || files=docker-compose.yml
  if [ -n "$env_file" ]; then
    if ! [[ $env_file =~ ^[A-Za-z0-9._-]+$ && -f $env_file ]]; then log_once "refusing: CVENGINE_COMPOSE_ENV_FILE must name an existing file in $(pwd) (got '$env_file')"; return 1; fi
    COMPOSE+=(--env-file "$env_file")
  fi
  if [ -n "$project" ]; then
    if ! [[ $project =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then log_once "refusing: CVENGINE_COMPOSE_PROJECT must be a lowercase Compose project name (got '$project')"; return 1; fi
    COMPOSE+=(-p "$project")
  fi
  for name in ${files//,/ }; do
    if ! [[ $name =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $name ]]; then
      log_once "refusing: Compose file '$name' must be a .yml file in $(pwd) (CVENGINE_COMPOSE_FILES)"
      return 1
    fi
    COMPOSE+=(-f "$name")
    COMPOSE_NAMES+=("$name")
  done
  if [ "$detected" = 0 ] && [ -z "$(setting CVENGINE_COMPOSE_FILES)$(setting CVENGINE_COMPOSE_FILE)" ]; then
    local other used
    for other in docker-compose*.yml docker-compose*.yaml; do
      [ -f "$other" ] || continue
      git ls-files --error-unmatch "$other" >/dev/null 2>&1 && continue  # one of the repository's own files, not this install's overlay
      used=0
      for name in "${COMPOSE_NAMES[@]}"; do [ "$name" = "$other" ] && used=1; done
      if [ "$used" = 0 ]; then
        log_once "refusing: $other is in this checkout but nothing says to deploy with it, and recreating the containers without it can take the site down (a host proxy on port 443, memory limits). Set CVENGINE_COMPOSE_FILES=docker-compose.yml,$other (and CVENGINE_COMPOSE_ENV_FILE, if the install has one) in .env, then approve again"
        return 1
      fi
    done
  fi
}

# How far the last deploy got; "migrated" means the database already has the new schema.
DEPLOY_STAGE=
deploy_builtin() {
  python3 "$STATE_HELPER" commit "$(git rev-parse HEAD)" || return 1
  local compose=("${COMPOSE[@]}")
  local services=(web celery celery-beat) listed
  # the dev compose file has no proxy service; recreate it only where it exists (keep it if the list cannot be read)
  if listed=$("${compose[@]}" config --services 2>/dev/null); then
    if grep -qx proxy <<<"$listed"; then services+=(proxy); fi
  else
    services+=(proxy)
  fi
  DEPLOY_STAGE=build
  phase applying "$DEPLOY_STAGE"
  "${compose[@]}" build web celery celery-beat || return 1
  DEPLOY_STAGE=datastores
  phase applying "$DEPLOY_STAGE"
  "${compose[@]}" up -d --no-recreate db redis || return 1
  # The database's own settings are in the compose file (max_connections). `up -d --no-deps db` recreates the db container only when its
  # definition changed since it was created (once, on the update that brings the change: a restart of a few seconds), and is a no-op otherwise.
  "${compose[@]}" up -d --no-deps db || return 1
  for _ in $(seq 1 60); do "${compose[@]}" exec -T db pg_isready -q >/dev/null 2>&1 && break; sleep 1; done
  DEPLOY_STAGE=migrate
  phase applying "$DEPLOY_STAGE"
  "${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py migrate --noinput || return 1
  DEPLOY_STAGE=migrated
  phase applying "$DEPLOY_STAGE"
  "${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py collectstatic --noinput || return 1
  "${compose[@]}" up -d --no-deps --force-recreate "${services[@]}" || return 1
  verify_running "${services[@]}"
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

# What an update does to the services is read from scripts/update-deploy.sh, AFTER the new files are merged: this script is the copy already
# on the host, so anything added to it would only run on the update after the one that delivers it (a new image to refresh, say). The
# copy above is the fallback for a checkout without that file (a rollback to a version older than this one).
deploy() {
  if [ -f scripts/update-deploy.sh ]; then
    # shellcheck source=update-deploy.sh
    . scripts/update-deploy.sh && deploy_current
  else
    deploy_builtin
  fi
}

RUNNING_QUERY="from django.apps import apps; from startScan.models import ScanHistory; n=ScanHistory.objects.filter(scan_status=1).count(); n+=sum(m.objects.filter(status='running').count() for m in apps.get_models() if m.__name__ in ('OnDemandValidation','DeferredRetest','TriageCall')); print(n)"

running_scans() {
  local compose=("${COMPOSE[@]}") out
  out=$("${compose[@]}" exec -T web python3 manage.py shell -c "$RUNNING_QUERY" 2>/dev/null | tail -n1) || true
  if ! [[ $out =~ ^[0-9]+$ ]]; then
    # web is down, which is when an update may be needed most: ask the database from a one-off container
    out=$("${compose[@]}" run --rm --no-deps -T --entrypoint python3 web manage.py shell -c "$RUNNING_QUERY" 2>/dev/null | tail -n1) || true
  fi
  printf '%s\n' "$out"
}

# Phase file and scan-pause for Settings > Updates to show live progress and avoid a restart interrupting a scan.
# Both are best-effort: a failure here never blocks the update itself, since nothing this script already did
# without them was any less safe.
phase() { python3 "$STATE_HELPER" phase "$1" "${2:-}" "${3:-}" >>"$LOG" 2>&1 || true; }
# Where the new build stands against the tracked branch, for the app's banner (scripts/update-state.py upstream). The checkout's own copy of the
# helper, not the one kept at the start of this run: the update may be what brings the action. Best-effort; the watcher repeats it every half hour.
refresh_upstream() { if [ -f scripts/update-state.py ]; then python3 scripts/update-state.py upstream >>"$LOG" 2>&1 || true; fi; }

pause_scanning() {
  local compose=("${COMPOSE[@]}")
  "${compose[@]}" exec -T web python3 manage.py update_scan_pause --request >>"$LOG" 2>&1 ||
    "${compose[@]}" run --rm --no-deps -T --entrypoint python3 web manage.py update_scan_pause --request >>"$LOG" 2>&1 ||
    log "could not request the update's scan-pause; scanning was not paused for this run"
}

resume_scanning() {
  local compose=("${COMPOSE[@]}")
  "${compose[@]}" exec -T web python3 manage.py update_scan_pause --release >>"$LOG" 2>&1 ||
    "${compose[@]}" run --rm --no-deps -T --entrypoint python3 web manage.py update_scan_pause --release >>"$LOG" 2>&1 ||
    log "could not release the update's scan-pause; release it by hand in Settings > Scan control"
}

# web/.commit is written when a deploy STARTS (the build needs it), so on its own it cannot say the deploy finished: a run that was
# stopped after the files were merged but before the migration (the host rebooted, the timer was killed) left the new files, that
# marker and an old database, and the next approval was answered "already at" with the schema unmigrated. A deploy counts as finished
# only when this host-side marker, written after the services were recreated, names the commit too, and the database has no migration
# waiting. If either cannot be confirmed the deploy runs again (a rebuild that finds nothing to do is harmless).
mark_deployed() { printf '%s\n' "$1" > "$STATE/deployed-commit" 2>>"$LOG" || true; }
deployed_commit() { head -n1 "$STATE/deployed-commit" 2>/dev/null | tr 'A-F' 'a-f' || true; }
schema_current() {
  local compose=("${COMPOSE[@]}")
  "${compose[@]}" exec -T web python3 manage.py migrate --check >/dev/null 2>&1 ||
    "${compose[@]}" run --rm --no-deps -T --entrypoint python3 web manage.py migrate --check >/dev/null 2>&1
}

if ! SHA=$(python3 "$STATE_HELPER" approval); then
  log "refusing: approval file does not hold a commit id"
  clear_approval
  exit 1
fi

if ! resolve_layout; then
  phase failed "this install's Compose layout is unclear or unusable; the update log says what to set (CVENGINE_COMPOSE_FILES in .env). The approval is kept and retries by itself"
  exit 1
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
# The update branch chosen in Settings. When it is not the branch checked out here, the checkout moves to it (an upgrade only), and
# when it cannot, the reason is shown in Settings > Updates.
WANT=$(python3 "$STATE_HELPER" approval-branch 2>/dev/null || true)
[ -n "$WANT" ] || WANT=$BRANCH
# The branch name comes from the web container (web/.update-branch). Without CVENGINE_UPDATE_BRANCHES any origin branch is accepted, as before;
# with it (comma separated, set in .env on the host) only the listed ones are.
ALLOWED=$(setting CVENGINE_UPDATE_BRANCHES)
if [ -n "$ALLOWED" ] && ! grep -qxF -- "$WANT" < <(tr ', ' '\n\n' <<<"$ALLOWED"); then
  log "refusing: the update branch $WANT is not in CVENGINE_UPDATE_BRANCHES ($ALLOWED)"
  phase failed "this server only updates from $ALLOWED (CVENGINE_UPDATE_BRANCHES in .env). Choose one of those under Settings > Updates > Update source, then approve again"
  clear_approval
  exit 1
fi
if ! git fetch --quiet origin "+refs/heads/$WANT:refs/remotes/origin/$WANT" >>"$LOG" 2>&1; then
  log_once "refusing: could not fetch origin/$WANT (network, credentials, or no such branch); approval kept, will retry"
  phase draining "the host could not reach origin/$WANT; it keeps retrying (see the update log)"
  exit 1
fi
if ! git merge-base --is-ancestor "$SHA" "origin/$WANT"; then
  log "refusing: $SHA is not on origin/$WANT"
  phase failed "the approved commit is not on $WANT. Check the update branch in Settings > Updates, then check for updates and approve again"
  clear_approval
  exit 1
fi
if [ "$(setting CVENGINE_UPDATE_REQUIRE_SIGNED)" = 1 ] && ! git verify-commit "$SHA" >>"$LOG" 2>&1; then
  log "refusing: $SHA has no valid signature from a key this host trusts (CVENGINE_UPDATE_REQUIRE_SIGNED=1)"
  phase failed "the approved commit is not signed by a key this server trusts (CVENGINE_UPDATE_REQUIRE_SIGNED=1 in .env). Import the signer's public key into root's keyring, or approve a signed commit"
  clear_approval
  exit 1
fi
SWITCH=0
if [ "$WANT" != "$BRANCH" ]; then
  if [ "$BRANCH" = HEAD ]; then
    log "refusing: this checkout is not on a branch (detached HEAD), so it cannot be moved to $WANT"
    phase failed "the checkout on this server is not on a branch, so it cannot move to $WANT: run git checkout $WANT there, then approve again"
    clear_approval
    exit 1
  fi
  # Moving to another branch is an upgrade when it contains the installed commit, or, when the two have diverged (a hotfix on one that the
  # other carries as its own commit), when it still has every database migration the installed code has: migrations are never rolled back.
  if ! git merge-base --is-ancestor HEAD "origin/$WANT"; then
    migration_files='^web/[^/]+/migrations/[^/]+\.py$'
    missing=$(comm -23 <(git ls-files | grep -E "$migration_files" | sort) <(git ls-tree -r --name-only "origin/$WANT" | grep -E "$migration_files" | sort) | head -n 3 | paste -sd, -)
    if [ -n "$missing" ]; then
      log "refusing: moving from $BRANCH to $WANT would go to code without migrations the installed code has ($missing); database migrations are not rolled back"
      phase failed "moving this server from $BRANCH to $WANT would be a downgrade: $WANT lacks database migrations that are installed. Choose a branch that has them, or switch by hand"
      clear_approval
      exit 1
    fi
    log "$BRANCH and $WANT have diverged, but $WANT has every installed database migration; switching"
  fi
  if git rev-parse --verify --quiet "refs/heads/$WANT" >/dev/null && ! git merge-base --is-ancestor "refs/heads/$WANT" "origin/$WANT"; then
    log "refusing: the local branch $WANT has commits that are not on origin/$WANT, so it is not switched to"
    phase failed "the local branch $WANT on this server has commits that are not on origin/$WANT. Push or remove them, then approve again"
    clear_approval
    exit 1
  fi
  SWITCH=1
fi
# The update moves the checkout forward and never merges. Commits of this server's own that the approved commit does not have cannot be moved
# past, and finding out only at the merge below would first pause scanning and wait for the running scans to drain. (An approved commit this
# checkout already contains is fine: nothing moves, and the services are rebuilt.)
if [ "$SWITCH" = 0 ] && ! git merge-base --is-ancestor HEAD "$SHA" && ! git merge-base --is-ancestor "$SHA" HEAD; then
  OWN=$(git rev-list --count "$SHA..HEAD" 2>/dev/null || echo some)
  log "refusing: this checkout has $OWN commit(s) of its own that $SHA does not have, so it cannot be fast-forwarded to it"
  phase failed "this server has $OWN commit(s) of its own, so it cannot be fast-forwarded: on the server run git fetch origin, git merge origin/$WANT, then make up"
  clear_approval
  exit 1
fi
DIRTY=$(git status --porcelain --untracked-files=no | grep -vE '^.. "?\.env"?$' || true)
if [ -n "$DIRTY" ]; then
  names=$(printf '%s\n' "$DIRTY" | sed 's/^...//' | head -n 5 | paste -sd, -)
  log_once "refusing: the checkout has local changes to tracked files ($names); commit or stash them (approval kept, will retry)"
  phase failed "the host checkout has local changes to tracked files ($names); commit or stash them, the update then retries by itself"
  exit 1
fi

# A deploy that fails after the migration keeps the approval (the old code must not run on the new schema), and the watcher then asks again every
# 30 seconds: a full rebuild, maintenance page and recreate each time, for ever. Stop after a few failed runs for the same commit; approving
# again starts a new count. CVENGINE_UPDATE_MAX_ATTEMPTS (environment or .env, default 3).
ATTEMPTS_FILE="$STATE/deploy-attempts"  # "<commit> <failed runs>"
MAX_ATTEMPTS=$(setting CVENGINE_UPDATE_MAX_ATTEMPTS)
[[ $MAX_ATTEMPTS =~ ^[1-9][0-9]{0,2}$ ]] || MAX_ATTEMPTS=3
TRIES=0
if [ -f "$ATTEMPTS_FILE" ]; then
  read -r TRIED_SHA TRIED_N <"$ATTEMPTS_FILE" || true
  if [ "${TRIED_SHA:-}" = "$SHA" ] && [[ ${TRIED_N:-} =~ ^[0-9]+$ ]]; then TRIES=$TRIED_N; else rm -f "$ATTEMPTS_FILE"; fi
fi
if (( TRIES >= MAX_ATTEMPTS )); then
  rm -f "$ATTEMPTS_FILE"
  log "giving up on $SHA: $TRIES runs in a row failed after the database was migrated. The approval is removed; fix the cause (see the lines above and docker compose logs), then approve again"
  phase failed "the update to $SHA failed $TRIES times after its database migration and is no longer retried. The cause is in the update log; scanning stays paused until it is fixed or resumed under Activity"
  clear_approval
  exit 1
fi
pause_scanning
RUNNING=$(running_scans)
if ! [[ $RUNNING =~ ^[0-9]+$ ]]; then
  resume_scanning
  log "refusing: could not verify active scans; approval kept for retry"
  exit 1
fi
DRAIN_SINCE_FILE="$STATE/draining-since"
# How long a drain wait may run before the update proceeds anyway and interrupts whatever is still running, rather than waiting
# without end (a scan that outlives this, or was never going to finish because the worker holding it is already gone, used to
# block every later update): default 5 minutes, an administrator may raise or lower it.
DRAIN_MAX=$(setting CVENGINE_UPDATE_DRAIN_SECONDS)  # the environment or .env; cron's own environment is bare, so .env is where it is set
[[ $DRAIN_MAX =~ ^[0-9]{1,6}$ ]] && DRAIN_MAX=$((10#$DRAIN_MAX)) || DRAIN_MAX=300  # whole seconds; anything else is the default
if [[ $RUNNING =~ ^[1-9][0-9]*$ ]]; then
  NOW=$(date +%s)
  SINCE=$(cat "$DRAIN_SINCE_FILE" 2>/dev/null || true)
  [[ $SINCE =~ ^[0-9]+$ ]] || { SINCE=$NOW; printf '%s' "$NOW" > "$DRAIN_SINCE_FILE"; }
  ELAPSED=$((NOW - SINCE))
  if (( ELAPSED >= DRAIN_MAX )); then
    log "forcing ahead: $RUNNING scan(s)/job(s) still running after ${ELAPSED}s (over the ${DRAIN_MAX}s drain limit); the update proceeds and interrupts them now (cveFeed.reaper closes out what the restart leaves behind)"
    phase draining "forcing the update after ${DRAIN_MAX}s: $RUNNING scan(s)/job(s) interrupted" "$RUNNING"
    rm -f "$DRAIN_SINCE_FILE" "$STATE/last-wait" "$STATE/last-refusal"
    # falls through to the deploy below: not a refusal, and not another wait
  else
    if [ "$(cat "$STATE/last-wait" 2>/dev/null)" != "$RUNNING" ]; then
      phase draining "waiting for $RUNNING scan(s) to finish (forcing ahead in $((DRAIN_MAX - ELAPSED))s if still running)" "$RUNNING"
      log "waiting: $RUNNING scan(s) running; forcing ahead in $((DRAIN_MAX - ELAPSED))s if still running (approval kept, will retry)"
      printf '%s' "$RUNNING" > "$STATE/last-wait"
    fi
    # This is a normal, expected wait, not a failure the ERR trap should narrate ("stopped at line N") on every poll: the two log
    # lines above already say why. The trap is restored by the next invocation (a fresh shell), so every later command keeps it.
    trap - ERR
    exit 3  # "still waiting": the watcher polls slowly for this; cron treats any status the same
  fi
fi
rm -f "$STATE/last-wait" "$STATE/last-refusal" "$DRAIN_SINCE_FILE"

PREV=$(git rev-parse HEAD)
SWITCHED=0
if [ "$SWITCH" = 1 ]; then
  log "switching this checkout from $BRANCH to $WANT"
  phase applying "switching this server from $BRANCH to $WANT"
  backup_env
  if { git rev-parse --verify --quiet "refs/heads/$WANT" >/dev/null && git checkout -q "$WANT"; } >>"$LOG" 2>&1 ||
     git checkout -q -b "$WANT" "origin/$WANT" >>"$LOG" 2>&1; then
    SWITCHED=1
    restore_env
  else
    restore_env
    git checkout -q -f "$BRANCH" >>"$LOG" 2>&1 || true
    resume_scanning
    log "refusing: could not switch the checkout from $BRANCH to $WANT (see the lines above)"
    phase failed "could not switch this server from $BRANCH to $WANT; the update log has the git error. Fix it there or set the update branch back to $BRANCH"
    clear_approval
    exit 1
  fi
fi
restore_branch() { if [ "$SWITCHED" = 1 ]; then git checkout -q -f "$BRANCH" >>"$LOG" 2>&1 || true; fi; }
# The files can already be at $SHA while the running containers are older (someone ran `git pull` by hand, which is also how a host
# without this updater is brought up to date the first time). web/.commit is the commit the running build was made from.
BUILT=$(head -n1 web/.commit 2>/dev/null | tr 'A-F' 'a-f' || true)
# (HEAD contains the approved commit: it is $SHA itself, or a checkout with commits of its own that has merged it, and what is built is HEAD)
if git merge-base --is-ancestor "$SHA" HEAD && [ "$BUILT" = "$PREV" ] && [ "$(deployed_commit)" = "$PREV" ] && schema_current; then
  log "already at $SHA"
  python3 "$STATE_HELPER" commit "$PREV"
  refresh_upstream
  clear_approval
  resume_scanning
  phase done
  exit 0
fi

if [ "$PREV" = "$SHA" ]; then
  if [ "$BUILT" = "$SHA" ]; then
    log "the files are at $SHA but a finished deploy of it is not on record or the database has migrations waiting (an earlier update was interrupted); deploying it again"
  else
    log "the files are at $SHA but the running build is ${BUILT:-unknown}; rebuilding"
  fi
  phase applying "files are current, rebuilding the services"
else
  log "updating $PREV -> $SHA"
  phase applying merging
  backup_env
  if ! git merge --ff-only "$SHA" >>"$LOG" 2>&1; then
    restore_env
    restore_branch
    resume_scanning
    log "refusing: $SHA is not a fast-forward of the local branch"
    phase failed "$SHA cannot be fast-forwarded onto this server's checkout (see the update log); merge it by hand with git merge, then scripts/update.sh or make up"
    clear_approval
    exit 1
  fi
  restore_env
fi

if deploy >>"$LOG" 2>&1; then
  python3 "$STATE_HELPER" commit "$(git rev-parse HEAD)"
  refresh_upstream
  mark_deployed "$(git rev-parse HEAD)"
  rm -f "$ATTEMPTS_FILE"
  clear_approval
  resume_scanning
  phase done
  log "updated to $SHA"
elif [ "$DEPLOY_STAGE" = migrated ]; then
  # The database already has $SHA's schema (or part of it), so $PREV's code must not run on it: keep $SHA and retry the restart.
  log "restarting $SHA failed after its migrations ran; keeping $SHA and retrying the restart"
  if deploy >>"$LOG" 2>&1; then
    python3 "$STATE_HELPER" commit "$(git rev-parse HEAD)"
    refresh_upstream
    mark_deployed "$(git rev-parse HEAD)"
    rm -f "$ATTEMPTS_FILE"
    clear_approval
    resume_scanning
    phase done
    log "updated to $SHA"
  else
    printf '%s %s\n' "$SHA" "$((TRIES + 1))" >"$ATTEMPTS_FILE"
    phase failed "restart of $SHA failed after migration; database already on new schema, scanning stays paused (run $((TRIES + 1)) of $MAX_ATTEMPTS)"
    log "could not restart $SHA; the database is already migrated (or part way), so $PREV is not restored. Run $((TRIES + 1)) of $MAX_ATTEMPTS: the approval is kept and the next run retries until then; see $LOG"
    exit 1
  fi
else
  log "update failed before the database was migrated (at: $DEPLOY_STAGE); returning to $PREV"
  restore_branch
  git reset --hard "$PREV" >>"$LOG" 2>&1
  restore_env
  # The way back must not fail the check that sent it here: a build that stopped for lack of disk space is put back with what is already on the host.
  if CVENGINE_UPDATE_MIN_FREE_MB=0 deploy >>"$LOG" 2>&1; then
    mark_deployed "$PREV"
    resume_scanning
    phase done
  else
    log "could not restart the previous version; redeploy by hand"
    phase failed "could not restart $PREV after rolling back a failed update; scanning stays paused"
  fi
  clear_approval
  exit 1
fi
