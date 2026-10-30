#!/usr/bin/env bash
# Deploys every new master commit automatically, but only while Settings > Updates is set to Automatic (the default is Manual, and then it does
# nothing). Run it from a timer: scripts/install-auto-deploy.sh.
#
# When master on GitHub is ahead of this checkout, it backs up the database and the secret key, then
# runs scripts/update.sh --stop-scans: running scans stop cleanly, the scheduler and workers pause, the
# update is applied and verified, and the stopped scans are queued again. When master has not moved it
# does nothing. A commit that failed to deploy is retried at most once an hour.
#
# Settings, from the environment or the same keys in .env (plus the CVENGINE_COMPOSE_* layout that
# scripts/update.sh reads):
#   CVENGINE_AUTO_DEPLOY_BACKUPS        Database backups to keep (default 7; 0 skips the backup)
#   CVENGINE_AUTO_DEPLOY_RETRY_SECONDS  Wait before retrying a commit that failed (default 3600)
#   CVENGINE_AUTO_DEPLOY_DRAIN_SECONDS  Longest wait for active tasks during the update (default 1800)
set -Euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
# root (a systemd unit) in a checkout owned by whoever cloned it: git refuses it ("dubious ownership") unless this one is named. Root already
# runs this checkout's scripts, so naming it adds no trust.
export GIT_CONFIG_COUNT=$(( ${GIT_CONFIG_COUNT:-0} + 1 ))
export "GIT_CONFIG_KEY_$((GIT_CONFIG_COUNT - 1))=safe.directory" "GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT - 1))=$PWD"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

# A setting from the environment, else the last matching line of .env. .env is never sourced.
setting() {
    local name=$1 fallback=$2 value=${!1:-}
    if [[ -z $value && -f .env ]]; then
        value=$(grep -E "^${name}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
        value=${value#[\"\']}; value=${value%[\"\']}
    fi
    [[ $value =~ ^[0-9]+$ ]] || value=$fallback
    printf '%s' "$value"
}
keep_backups=$(setting CVENGINE_AUTO_DEPLOY_BACKUPS 7)
retry_seconds=$(setting CVENGINE_AUTO_DEPLOY_RETRY_SECONDS 3600)
drain_seconds=$(setting CVENGINE_AUTO_DEPLOY_DRAIN_SECONDS 1800)

state=$(git rev-parse --git-path cvengine-auto-deploy)
mkdir -p "$state/backups"
chmod 700 "$state" "$state/backups"
# The web interface certificate is renewed before it expires whatever the update mode is (scripts/renew-certs.sh: a no-op until its next
# check is due, twice a day). A host with this timer and no update watcher has no other trigger for it.
if [[ -f scripts/renew-certs.sh ]]; then scripts/renew-certs.sh --if-due >>"$state/cert.log" 2>&1 || log "The certificate check failed; see $state/cert.log"; fi
exec 8>"$state/lock"
flock -n 8 || { log "Another auto-deploy run is still working."; exit 0; }

# Nothing here changes the code of an install unless its administrator chose Automatic in Settings > Updates (web/.update-mode). The default,
# and anything unreadable, is Manual: the timer stays installed and does nothing.
mode=$(python3 scripts/update-state.py mode 2>/dev/null) || mode=manual
if [[ $mode != auto ]]; then
    if [[ $(cat "$state/mode-note" 2>/dev/null) != manual ]]; then
        log "Updates are set to Manual in Settings > Updates, so nothing is deployed automatically. Choose Automatic there to turn this on."
        printf manual > "$state/mode-note"
    fi
    exit 0
fi
printf auto > "$state/mode-note"

# This only ever deploys master (scripts/update.sh refuses any other branch). A checkout that was moved to another branch (Settings > Updates >
# Update source) would otherwise back up the database and fail inside update.sh at every retry.
branch=$(git branch --show-current 2>/dev/null) || branch=''
if [[ $branch != master ]]; then
    if [[ $(cat "$state/branch-note" 2>/dev/null) != "${branch:-detached}" ]]; then
        log "This checkout is on ${branch:-no branch (detached HEAD)}, not master, so automatic deployment does nothing. Updates for it are approved in Settings > Updates."
        printf '%s' "${branch:-detached}" > "$state/branch-note"
    fi
    exit 0
fi
rm -f "$state/branch-note"

latest=$(timeout 60 git ls-remote origin refs/heads/master 2>/dev/null | cut -f1) || latest=''
if [[ ! $latest =~ ^[0-9a-f]{40}$ ]]; then
    log "Could not read master from origin; will try again on the next run."
    exit 0
fi
current=$(git rev-parse HEAD)
# Level with master means master is in this checkout, not that HEAD is master's commit: a checkout with commits of its own never equals it
if git cat-file -e "$latest^{commit}" 2>/dev/null && git merge-base --is-ancestor "$latest" HEAD; then
    rm -f "$state/diverged-note"
    exit 0
fi
# Master has commits this checkout lacks. If the checkout also has commits of its own it cannot be fast-forwarded (update.sh only moves forward), and
# trying would back up the database and stop at every retry: say so once for this master commit and wait for the merge to be done by hand.
if timeout 120 git fetch --quiet origin master 2>/dev/null && ! git merge-base --is-ancestor HEAD "$latest" 2>/dev/null; then
    if [[ $(cat "$state/diverged-note" 2>/dev/null) != "$latest" ]]; then
        log "Master moved to ${latest:0:8}, but this checkout has $(git rev-list --count "$latest..HEAD" 2>/dev/null || echo some) commit(s) of its own, so it cannot be fast-forwarded and nothing is deployed. Merge it by hand (git fetch origin && git merge origin/master), then run scripts/update.sh."
        printf '%s' "$latest" > "$state/diverged-note"
    fi
    exit 0
fi
rm -f "$state/diverged-note"

# Leave a manual or approved update alone while it holds the updater lock.
if [[ -x scripts/update-state.py || -f scripts/update-state.py ]]; then
    update_state=$(python3 scripts/update-state.py directory 2>/dev/null) || update_state=''
    if [[ -n $update_state && -e $update_state/update.lock ]] && ! flock -n "$update_state/update.lock" true; then
        log "An update is already running; master ${latest:0:8} will be deployed on a later run."
        exit 0
    fi
fi

if [[ -f $state/failed ]]; then
    read -r failed_sha failed_at < "$state/failed" || true
    if [[ ${failed_sha:-} == "$latest" && ${failed_at:-0} =~ ^[0-9]+$ ]] && (( $(date +%s) - failed_at < retry_seconds )); then
        exit 0
    fi
fi

log "Master moved ${current:0:8} -> ${latest:0:8}; deploying."

if (( keep_backups > 0 )); then
    db=$(docker ps -q --filter label=com.docker.compose.service=db \
        --filter "label=com.docker.compose.project.working_dir=$PWD" 2>/dev/null | head -n1) || db=''
    if [[ -z $db ]]; then
        log "No running database container for $PWD; not deploying without a backup."
        exit 1
    fi
    backup="$state/backups/cvengine-$(date -u +%Y%m%dT%H%M%SZ)-${current:0:8}.sql.gz"
    if ! (umask 077; docker exec "$db" sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > "$backup") ||
            [[ $(gzip -dc "$backup" 2>/dev/null | head -c 64 | wc -c) -lt 64 ]]; then
        rm -f "$backup"
        log "The database backup failed; not deploying."
        exit 1
    fi
    if [[ -f web/secret ]] && ! cmp -s web/secret "$state/backups/secret"; then
        (umask 077; cp web/secret "$state/backups/secret")
    fi
    ls -1t "$state"/backups/cvengine-*.sql.gz 2>/dev/null | tail -n +"$((keep_backups + 1))" | xargs -r rm -f
    log "Backed up the database to $backup."
fi

# (the backup above is this run's; update.sh does not take a second one)
CVENGINE_UPDATE_BACKUPS=0 CVENGINE_UPDATE_DRAIN_SECONDS=$drain_seconds scripts/update.sh --stop-scans
status=$?
if (( status == 0 )); then
    rm -f "$state/failed"
    log "Deployed ${latest:0:8}."
    exit 0
fi
printf '%s %s\n' "$latest" "$(date +%s)" > "$state/failed"
log "Deploying ${latest:0:8} failed (exit $status). The updater restored what it could; retrying in ${retry_seconds}s or on the next commit."
exit "$status"
