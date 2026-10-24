#!/usr/bin/env bash
# CVEngine updater: brings a running install to the latest master without losing work.
#
# It fetches the new code and builds images while everything keeps running, pauses the scheduler
# and the workers' queue consumers, lets active tasks finish, applies migrations, recreates the
# application containers, and waits until the site, every worker queue and the scheduler answer.
# It never stops host services, never replaces the database or Redis, and never deletes a volume.
#
# Usage: scripts/update.sh [--check] [--stop-scans] [--help]
#   --check       Preflight only. Shows the Compose layout, port owners, database volumes, workers
#                 and scans, and says whether an update can run now. Changes nothing.
#   --stop-scans  Stop running and queued discovery scans cleanly instead of waiting for them,
#                 and queue them again once the update is done.
#
# Settings, from the environment or the same keys in .env:
#   CVENGINE_COMPOSE_FILES         Compose files, comma separated (default docker-compose.yml).
#                                  For example: docker-compose.yml,docker-compose.override-host.yml
#   CVENGINE_COMPOSE_ENV_FILE      Compose --env-file, for example .env.production
#   CVENGINE_COMPOSE_PROJECT       Compose project name (-p)
#   CVENGINE_UPDATE_DRAIN_SECONDS  Longest wait for active tasks, 1 to 10800 (default 10800)
#   CVENGINE_UPDATE_READY_SECONDS  Longest wait for readiness, 1 to 900 (default 600)
#   CVENGINE_UPDATE_STOP_SCANS=1   Same as --stop-scans
# CVENGINE_COMPOSE_FILE (a single file) is still accepted.
set -Eeuo pipefail

self_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$self_dir/.." && pwd)
[[ -d $repo_root/web ]] || repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$repo_root"
self="$repo_root/scripts/update.sh"
started_at=$SECONDS

usage() { sed -n '2,/^set -Eeuo/p' "$self" | sed '$d' | sed -E 's/^# ?//'; }

check_only=0
after_fetch=0
stop_scans=0
for arg in "$@"; do
    case $arg in
        --check) check_only=1 ;;
        --stop-scans) stop_scans=1 ;;
        --after-fetch) after_fetch=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
    esac
done
forward_args=()
(( stop_scans )) && forward_args+=(--stop-scans)

die() {
    echo "ERROR: $*" >&2
    [[ -z ${diagnostic_log:-} || ! -s $diagnostic_log ]] || echo "Command diagnostics: $diagnostic_log (private; review before sharing)." >&2
    exit 1
}
step() { echo; echo "==> $*"; }
failure() {
    local status=$?
    trap - ERR
    echo "Update failed at $(git rev-parse --short HEAD 2>/dev/null || echo unknown). No database rollback was attempted." >&2
    [[ -z ${diagnostic_log:-} || ! -s $diagnostic_log ]] || echo "Command diagnostics: $diagnostic_log (private; review before sharing)." >&2
    "${compose[@]}" ps >&2 || true
    exit "$status"
}
trap failure ERR

# A setting from the environment, else the last matching line of .env. .env is never sourced.
setting() {
    local name=$1 value=${!1:-}
    if [[ -z $value && -f .env ]]; then
        value=$(grep -E "^${name}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
        value=${value#[\"\']}; value=${value%[\"\']}
    fi
    printf '%s' "$value"
}

for command in git docker flock curl python3; do
    command -v "$command" >/dev/null || die "Missing command: $command"
done
[[ -f .env ]] || die "Missing .env in $(pwd)."
[[ -d web ]] || die "Run this script from a CVEngine checkout."
(( stop_scans )) || [[ $(setting CVENGINE_UPDATE_STOP_SCANS) != 1 ]] || { stop_scans=1; forward_args+=(--stop-scans); }

# The Compose layout: every file, plus the env file and project name when the install uses them.
compose_files=$(setting CVENGINE_COMPOSE_FILES)
[[ -n $compose_files ]] || compose_files=$(setting CVENGINE_COMPOSE_FILE)
[[ -n $compose_files ]] || compose_files=docker-compose.yml
compose=(docker compose)
compose_env_file=$(setting CVENGINE_COMPOSE_ENV_FILE)
if [[ -n $compose_env_file ]]; then
    [[ $compose_env_file =~ ^[A-Za-z0-9._-]+$ && -f $compose_env_file ]] ||
        die 'CVENGINE_COMPOSE_ENV_FILE must name an existing file in the repository root.'
    compose+=(--env-file "$compose_env_file")
fi
compose_project=$(setting CVENGINE_COMPOSE_PROJECT)
if [[ -n $compose_project ]]; then
    [[ $compose_project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die 'CVENGINE_COMPOSE_PROJECT must be a lowercase Compose project name.'
    compose+=(-p "$compose_project")
fi
dev_stack=0
file_names=()
IFS=', ' read -r -a requested_files <<< "${compose_files//:/,}"
for file in "${requested_files[@]}"; do
    [[ -n $file ]] || continue
    [[ $file =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $file ]] ||
        die "Compose file '$file' must be a .yml file in the repository root (CVENGINE_COMPOSE_FILES)."
    [[ $file == docker-compose.dev.yml ]] && dev_stack=1
    compose+=(-f "$file")
    file_names+=("$file")
done
(( ${#file_names[@]} )) || die 'No Compose file selected.'

[[ "$(git branch --show-current)" == master ]] || die "Checkout must be on master."
[[ -z "$(git status --porcelain --untracked-files=no)" ]] ||
    die "Tracked files have local changes; commit or stash them first."
# Older installations tracked .env. Do not let a pull remove their configuration.
if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    die ".env is still tracked; migrate it using scripts/apply-update.sh first."
fi
docker info >/dev/null
docker compose version >/dev/null

# Run a Django snippet in the web container. Prints nothing when web is not running.
web_python() {
    local code=$1; shift
    [[ -n $("${compose[@]}" ps -q --status running web 2>/dev/null) ]] || return 0
    "${compose[@]}" exec -T "$@" web python3 manage.py shell -c "$code" 2>>"${diagnostic_log:-/dev/null}" || true
}

scan_count_code=$(cat <<'PY'
from startScan.models import ScanHistory
print("SCANS", ScanHistory.objects.filter(scan_status=1).count(), ScanHistory.objects.filter(scan_status=-1).count())
PY
)

# Snapshot running and queued discovery scans with their bbot mode, then stop them through the
# app's own stop path: the stop flag ends each scanner cleanly and frees its memory and claims.
scan_stop_code=$(cat <<'PY'
import base64, json
from django.contrib.auth import get_user_model
from agentapi.services import _abort_scan
from reNgine.celery import app
from startScan.models import ScanActivity, ScanHistory
modes = {}
def note(args):
    if args:
        modes[int(args[0])] = args[1] if len(args) > 1 else None
try:
    with app.connection_for_read() as conn:
        for raw in conn.default_channel.client.lrange("discovery_queue", 0, -1):
            message = json.loads(raw)
            if str(message.get("headers", {}).get("task", "")).endswith("run_bbot_discovery"):
                note(json.loads(base64.b64decode(message["body"]))[0])
except Exception:
    pass
try:
    for tasks in (app.control.inspect(timeout=5).active() or {}).values():
        for task in tasks:
            if str(task.get("name", "")).endswith("run_bbot_discovery"):
                note(task.get("args") or [])
except Exception:
    pass
user = get_user_model().objects.filter(is_superuser=True).order_by("id").first()
rows = []
for scan in ScanHistory.objects.filter(scan_status__in=(-1, 1)).select_related("domain").order_by("id"):
    if ScanActivity.objects.filter(scan_of=scan, name="bbot_discovery").exists():
        rows.append({"scan": scan.id, "domain": scan.domain_id, "mode": modes.get(scan.id)})
    _abort_scan(scan, user)
print("REQUEUE_JSON " + json.dumps(rows))
PY
)

scan_requeue_code=$(cat <<'PY'
import json, os
from collections import defaultdict
from cveFeed.discovery import start_discoveries
from targetApp.models import Domain
by_mode = defaultdict(list)
for row in json.loads(os.environ["CVENGINE_REQUEUE"]):
    domain = Domain.objects.filter(id=row["domain"]).first()
    if domain:
        by_mode[row.get("mode") or "standard"].append(domain)
queued = sum(len(start_discoveries(domains, mode=mode, quiet=True)) for mode, domains in by_mode.items())
print("REQUEUED", queued)
PY
)
requeue_file=web/.update-requeue.json

# Published host ports that something other than Docker already holds, from the Compose config
# and the kernel's listening sockets. One line per conflict: service, address, port, owner.
port_conflicts() {
    command -v ss >/dev/null || { echo 'Note: ss is not installed; skipped the port ownership check.'; return 0; }
    local config listeners
    config=$("${compose[@]}" config --format json 2>>"${diagnostic_log:-/dev/null}") || return 0
    listeners=$(ss -ltnpH 2>/dev/null) || listeners=''
    printf '%s\0%s' "$config" "$listeners" | python3 -c '
import json, re, sys
config, listeners = sys.stdin.buffer.read().split(b"\0", 1)
try:
    services = json.loads(config).get("services") or {}
except ValueError:
    sys.exit(0)
wild = {"", "0.0.0.0", "::", "*", "[::]"}
held = []
for line in listeners.decode(errors="replace").splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    address, _, port = parts[3].rpartition(":")
    owner = re.search(r"\(\(\"([^\"]+)\",pid=(\d+)", line)
    held.append((address.strip("[]"), port, owner.group(1) if owner else "an unknown process", owner.group(2) if owner else ""))
for name, service in services.items():
    for mapping in service.get("ports") or []:
        published, host_ip = str(mapping.get("published") or ""), str(mapping.get("host_ip") or "")
        for address, port, process, pid in held:
            if port != published or process == "docker-proxy":
                continue
            if address in wild or host_ip in wild or address == host_ip:
                print(name + "|" + (host_ip or "0.0.0.0") + "|" + published + "|" + process + ((" (pid " + pid + ")") if pid else ""))
'
}

# The local URL that proves the stack answers: the proxy's published HTTPS port, else web's port.
ready_url_from_config() {
    local config
    config=$("${compose[@]}" config --format json 2>>"${diagnostic_log:-/dev/null}") || return 0
    printf '%s' "$config" | python3 -c '
import json, sys
try:
    services = json.load(sys.stdin).get("services") or {}
except ValueError:
    sys.exit(0)
def host(mapping):
    ip = str(mapping.get("host_ip") or "")
    return "127.0.0.1" if ip in ("", "0.0.0.0", "::") else ip
for mapping in (services.get("proxy") or {}).get("ports") or []:
    if int(mapping.get("target") or 0) == 443 and mapping.get("published"):
        print("https://" + host(mapping) + ":" + str(mapping["published"]) + "/"); sys.exit(0)
for mapping in (services.get("web") or {}).get("ports") or []:
    if int(mapping.get("target") or 0) == 8000 and mapping.get("published"):
        print("http://" + host(mapping) + ":" + str(mapping["published"]) + "/"); sys.exit(0)
'
}

# Warn when the running containers were started from other Compose files than this update uses.
layout_drift() {
    local id labels
    id=$("${compose[@]}" ps -q web 2>/dev/null | head -n1) || return 0
    [[ -n $id ]] || return 0
    labels=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$id" 2>/dev/null) || return 0
    [[ -n $labels ]] || return 0
    local running wanted
    running=$(tr ',' '\n' <<< "$labels" | xargs -n1 basename 2>/dev/null | sort | paste -sd, -)
    wanted=$(printf '%s\n' "${file_names[@]}" | sort | paste -sd, -)
    [[ $running == "$wanted" ]] && return 0
    echo "Note: the running containers were started with $running; this update recreates them with $wanted."
}

# Point out Compose files in the repository root that this install has but the update does not use.
unused_overlays() {
    local file used
    for file in docker-compose*.yml docker-compose*.yaml compose*.yml compose*.yaml; do
        [[ -f $file ]] || continue
        git ls-files --error-unmatch "$file" >/dev/null 2>&1 && continue
        used=0
        for wanted in "${file_names[@]}"; do [[ $wanted == "$file" ]] && used=1; done
        (( used )) || echo "Note: $file is not part of this update. If your install uses it, add it to CVENGINE_COMPOSE_FILES."
    done
}

legacy_database_volume() {
    local volume_names
    volume_names=$("${compose[@]}" config --format json | python3 -c '
import json, sys
config = json.load(sys.stdin)
project = config["name"]
volume = config["volumes"]["postgres18_data"].get("name") or project + "_postgres18_data"
print(project + "_postgres_data")
print(volume)
') || die 'Could not identify database volumes safely.'
    mapfile -t database_volumes <<< "$volume_names"
    docker volume inspect "${database_volumes[0]}" >/dev/null 2>&1 &&
        ! docker volume inspect "${database_volumes[1]}" >/dev/null 2>&1
}
upgrade_command='scripts/upgrade-postgres.sh'
(( dev_stack )) && upgrade_command='scripts/upgrade-postgres.sh --dev'

if (( check_only )); then
    trap - ERR
    problems=0
    echo "CVEngine update preflight (changes nothing)"
    echo "  Checkout:  $(git rev-parse --short HEAD) on master"
    latest=$(git ls-remote origin refs/heads/master 2>/dev/null | cut -f1) || latest=''
    if [[ -z $latest ]]; then echo "  GitHub:    could not reach origin"; problems=1
    elif [[ $latest == "$(git rev-parse HEAD)" ]]; then echo "  GitHub:    up to date"
    else echo "  GitHub:    ${latest:0:8} is available"; fi
    echo "  Compose:   ${compose[*]}"
    if ! "${compose[@]}" config --quiet 2>/dev/null; then echo "  Config:    INVALID"; problems=1; fi
    layout_drift
    unused_overlays
    conflicts=$(port_conflicts)
    if [[ $conflicts == Note:* ]]; then echo "  Ports:     ${conflicts#Note: }"
    elif [[ -n $conflicts ]]; then
        while IFS='|' read -r service address port owner; do
            echo "  Ports:     $service publishes $address:$port, which $owner already holds"
        done <<< "$conflicts"; problems=1
    else echo "  Ports:     free or already Docker's"; fi
    if legacy_database_volume; then echo "  Database:  PostgreSQL 12 volume needs $upgrade_command first"; problems=1
    else echo "  Database:  ready"; fi
    scans=$(web_python "$scan_count_code" | grep '^SCANS ' || true)
    if [[ -n $scans ]]; then
        read -r _ running queued <<< "$scans"
        echo "  Scans:     $running running, $queued queued$( (( running + queued )) && { (( stop_scans )) && echo ' (they will be stopped and queued again)' || echo ' (the drain waits for running ones; --stop-scans stops and re-queues them)'; })"
    else echo "  Scans:     web is not running, so scans could not be counted"; fi
    [[ ! -s $requeue_file ]] || echo "  Pending:   $requeue_file holds scans to queue again after the next successful update"
    if (( problems )); then echo "Result: fix the items above before updating."; exit 1; fi
    echo "Result: ready. Run scripts/update.sh${forward_args[*]:+ ${forward_args[*]}}"
    exit 0
fi

if (( after_fetch )); then
    # Re-exec of the just-fetched script, still holding descriptor 9 and the updater lock.
    flock -n 9 || die "Updater lock was not inherited."
else
    exec 9>web/.update-lock
    flock -n 9 || die "Another update is running."
    step "Fetching the latest master"
    from_commit=$(git rev-parse --short HEAD)
    from_sha=$(git rev-parse HEAD)
    git fetch origin master
    git merge --ff-only origin/master
    CVENGINE_UPDATE_FROM="$from_commit" CVENGINE_UPDATE_FROM_SHA="$from_sha" exec bash "$self" --after-fetch "${forward_args[@]}"
fi
from_commit=${CVENGINE_UPDATE_FROM:-unknown}
from_sha=${CVENGINE_UPDATE_FROM_SHA:-}
database_migrated=0
# The checkout was fast-forwarded before the build and the migration, and ./web is bind-mounted into web, celery and
# Beat. Until the migration succeeds, a failed or interrupted update puts the previous commit back, so restarted
# workers and Beat never run new code on the old schema (Beat's "migrate --check" would then fail forever).
revert_unmigrated() {
    (( database_migrated )) && return 0
    [[ -n $from_sha ]] || return 0
    [[ $(git rev-parse HEAD 2>/dev/null) != "$from_sha" ]] || return 0
    if git reset --keep "$from_sha" >/dev/null 2>&1; then
        echo "Returned the checkout to $from_commit because the update stopped before the database was migrated." >&2
    else
        echo "Could not return the checkout to $from_commit; run: git reset --keep $from_sha" >&2
    fi
}
trap 'code=$?; trap - EXIT; (( code == 0 )) || revert_unmigrated; exit "$code"' EXIT
"${compose[@]}" config --quiet
diagnostic_log=$(mktemp /tmp/cvengine-update.XXXXXX)
chmod 600 "$diagnostic_log"
echo "Updating $from_commit -> $(git rev-parse --short HEAD) with: ${compose[*]}"
layout_drift
unused_overlays

conflicts=$(port_conflicts)
if [[ -n $conflicts && $conflicts != Note:* ]]; then
    while IFS='|' read -r service address port owner; do
        echo "ERROR: $service would publish $address:$port, but $owner already holds it." >&2
    done <<< "$conflicts"
    die 'A published port is taken. If a host proxy fronts CVEngine, add its Compose overlay with CVENGINE_COMPOSE_FILES; otherwise free the port.'
fi
[[ $conflicts != Note:* ]] || echo "$conflicts"

# A former PostgreSQL 12 installation needs an explicit dump/restore. Compose would
# otherwise create an empty PostgreSQL 18 volume and make a successful HTTP response
# look like a successful update with the old data missing.
if legacy_database_volume; then
    die "Legacy PostgreSQL volume exists without a PostgreSQL 18 volume. Run and verify $upgrade_command before this routine update."
fi

scans=$(web_python "$scan_count_code" | grep '^SCANS ' || true)
if [[ -n $scans ]]; then
    read -r _ running_scans queued_scans <<< "$scans"
    echo "Scans: $running_scans running, $queued_scans queued."
    if (( running_scans > 0 && ! stop_scans )); then
        echo "The drain waits for running scans to finish. Use --stop-scans to stop them now and queue them again after the update."
    fi
fi

# Do the expensive, fallible build while the old workers are still processing work.
# Only then pause dispatch and perform a bounded drain before migration/recreation.
step 'Building application images while everything keeps running'
"${compose[@]}" build web celery celery-beat

# Freeze consumers, not producers: requests arriving during maintenance stay in Redis for
# the restarted workers. Each worker's original queues are captured so a failed update can
# restore precisely its prior routing. Beat is stopped before the drain to prevent new sweeps.
step 'Checking the workers'
if ! queue_snapshot=$("${compose[@]}" exec -T celery celery -A reNgine.tasks inspect -j -t 5 active_queues 2>>"$diagnostic_log"); then
    # An absent managed worker can be repaired by recreating it. A running container
    # whose workers cannot be inspected is different: its active jobs are unknown.
    running_celery=$("${compose[@]}" ps -q --status running celery) || die 'Could not inspect the Celery container.'
    [[ -z $running_celery ]] || die 'Celery is running but worker state is unknown; cannot drain active jobs safely.'
    queue_snapshot='{}'
    echo 'Celery container is stopped; queued broker work will be preserved while workers are repaired.'
fi
snapshot_records=$(printf '%s' "$queue_snapshot" | python3 -c '
import json, sys
try:
    workers = json.load(sys.stdin)
    if not isinstance(workers, dict): raise ValueError("invalid worker snapshot")
    for name, queues in workers.items():
        if not isinstance(name, str) or not isinstance(queues, list): raise ValueError("invalid worker snapshot")
        print("W|" + name)
        for queue in queues:
            if not isinstance(queue, dict) or not isinstance(queue.get("name"), str): raise ValueError("invalid queue")
            print("Q|" + name + "|" + queue["name"])
except (ValueError, TypeError, KeyError, AttributeError):
    sys.exit(1)
') || die 'Worker queue snapshot is invalid; cannot drain active jobs safely.'
consumer_pairs=()
worker_names=()
if [[ -n $snapshot_records ]]; then
    while IFS= read -r record; do
        if [[ $record == W\|* ]]; then
            worker_names+=("${record#W|}")
        elif [[ $record == Q\|* ]]; then
            consumer_pairs+=("${record#Q|}")
        fi
    done <<< "$snapshot_records"
fi
if (( ${#worker_names[@]} < 4 )); then
    echo "Only ${#worker_names[@]} of four expected worker processes responded; the update will repair missing workers after draining reachable ones." >&2
fi
# A silent worker may still be running a scan even though it does not answer Celery
# inspect. Read only process identities inside the managed container; if any named
# worker is unresponsive, stopping the container could kill unknown active work.
running_celery=$("${compose[@]}" ps -q --status running celery) || die 'Could not inspect the Celery container.'
if [[ -n $running_celery ]]; then
    process_workers=$("${compose[@]}" exec -T celery python3 -c '
import os
for pid in os.listdir("/proc"):
    if not pid.isdecimal() or int(pid) == os.getpid():
        continue
    try:
        parts = open("/proc/" + pid + "/cmdline", "rb").read().split(b"\0")
    except (OSError, ValueError):
        continue
    if b"celery" not in os.path.basename(parts[0]) or b"worker" not in parts:
        continue
    for index, part in enumerate(parts[:-1]):
        if part == b"-n":
            print(parts[index + 1].decode("utf-8", "replace").split("@", 1)[0])
            break
' 2>/dev/null) || die 'Could not inspect managed Celery processes; active work is unknown.'
    while IFS= read -r process_worker; do
        [[ -n $process_worker ]] || continue
        found=0
        for worker in "${worker_names[@]}"; do
            [[ ${worker%%@*} == "$process_worker" ]] && found=1
        done
        (( found )) || die "Worker process $process_worker is running but does not answer inspection; active work is unknown."
    done <<< "$process_workers"
fi
dispatch_paused=0
workers_stopped=0
database_migrated=0
app_recreated=0
beat_was_running=$("${compose[@]}" ps -q --status running celery-beat) || die 'Could not inspect Celery Beat container state.'
restore_dispatch() {
    local code=$?
    trap - EXIT
    (( code == 0 )) || revert_unmigrated  # first, so anything restarted below runs the code that matches the schema
    if [[ -s $requeue_file ]] && (( code != 0 )); then
        echo "Stopped scans are saved in $requeue_file; the next successful update queues them again." >&2
    fi
    if (( dispatch_paused )); then
        if (( database_migrated )); then
            # The new worker fleet may be healthy even when HTTP/proxy readiness failed.
            # Do not leave periodic dispatch stopped in that case: Docker's "restart:
            # always" does not undo an explicit compose stop.
            if (( app_recreated )) && worker_queues_ready; then
                echo 'Updated workers are ready; restoring Celery Beat despite the incomplete HTTP readiness check...' >&2
                if "${compose[@]}" up -d --no-deps celery-beat >/dev/null 2>>"$diagnostic_log"; then
                    for attempt in {1..6}; do
                        if beat_ready; then
                            echo 'Celery Beat is running. The update still failed; inspect the reported readiness issue.' >&2
                            exit "$code"
                        fi
                        sleep 5
                    done
                fi
                echo 'Celery Beat could not be restored. Inspect its container log and start it after fixing the reported issue.' >&2
            else
                echo 'Migration was applied but updated workers are not ready; Beat remains paused to avoid dispatch to an incomplete topology.' >&2
            fi
            "${compose[@]}" stop celery-beat >/dev/null 2>&1 || true
            exit "$code"
        fi
        echo 'Restoring prior worker consumers and Celery Beat after an incomplete update...' >&2
        if (( workers_stopped )); then
            "${compose[@]}" start celery >/dev/null 2>&1 || echo 'Could not restart Celery workers.' >&2
        fi
        for pair in "${consumer_pairs[@]}"; do
            worker=${pair%%|*}; queue=${pair#*|}
            "${compose[@]}" exec -T celery celery -A reNgine.tasks control -j -t 5 -d "$worker" add_consumer "$queue" \
                >/dev/null 2>&1 || echo "Could not restore consumer $worker/$queue; inspect worker queues." >&2
        done
        if [[ -n $beat_was_running ]]; then
            "${compose[@]}" start celery-beat >/dev/null 2>&1 || echo 'Could not restart Celery Beat.' >&2
        fi
    fi
    exit "$code"
}
trap restore_dispatch EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
drain_seconds=${CVENGINE_UPDATE_DRAIN_SECONDS:-$(setting CVENGINE_UPDATE_DRAIN_SECONDS)}
drain_seconds=${drain_seconds:-10800}
[[ $drain_seconds =~ ^[0-9]+$ ]] && (( drain_seconds >= 1 && drain_seconds <= 10800 )) ||
    die 'CVENGINE_UPDATE_DRAIN_SECONDS must be from 1 to 10800.'
# checked now, before anything is paused or migrated; it is only used once the new containers start
ready_seconds=${CVENGINE_UPDATE_READY_SECONDS:-$(setting CVENGINE_UPDATE_READY_SECONDS)}
ready_seconds=${ready_seconds:-600}
[[ $ready_seconds =~ ^[0-9]+$ ]] && (( ready_seconds >= 1 && ready_seconds <= 900 )) ||
    die 'CVENGINE_UPDATE_READY_SECONDS must be from 1 to 900.'

if (( stop_scans )); then
    step 'Stopping scans so the drain is quick; they are queued again after the update'
    stopped=$(web_python "$scan_stop_code" | grep '^REQUEUE_JSON ' | head -n1 || true)
    stopped=${stopped#REQUEUE_JSON }
    if [[ -n $stopped && $stopped != '[]' ]]; then
        merged=$(python3 -c '
import json, sys, os
old = json.load(open(sys.argv[1])) if os.path.exists(sys.argv[1]) and os.path.getsize(sys.argv[1]) else []
seen = {row["domain"] for row in old}
print(json.dumps(old + [row for row in json.loads(sys.argv[2]) if row["domain"] not in seen]))
' "$requeue_file" "$stopped")
        (umask 077; printf '%s\n' "$merged" > "$requeue_file")
        echo "Stopped $(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$stopped") discovery scan(s); saved them to $requeue_file."
    else
        echo 'No discovery scans were running or queued.'
    fi
fi

dispatch_paused=1
step 'Pausing Beat and worker consumers; new requests remain queued in Redis'
if [[ -n $beat_was_running ]]; then "${compose[@]}" stop -t 30 celery-beat; fi
last_consumer_worker=''
for pair in "${consumer_pairs[@]}"; do
    worker=${pair%%|*}; queue=${pair#*|}
    if [[ $worker != "$last_consumer_worker" ]]; then
        echo "Pausing queue consumers on $worker..."
        last_consumer_worker=$worker
    fi
    "${compose[@]}" exec -T celery celery -A reNgine.tasks control -j -t 5 -d "$worker" cancel_consumer "$queue" \
        >/dev/null 2>>"$diagnostic_log" || die "Could not pause $worker/$queue."
done
step "Letting active work finish (up to ${drain_seconds}s)"
drain_deadline=$((SECONDS + drain_seconds))
drain_started=$SECONDS
last_drain_report=-30
while :; do
    if (( ${#worker_names[@]} == 0 )); then
        echo 'No managed Celery workers are reachable; there are no managed active tasks to drain.'
        break
    fi
    activity=$("${compose[@]}" exec -T celery celery -A reNgine.tasks inspect -j -t 5 active 2>>"$diagnostic_log") ||
        die 'Could not inspect active tasks during drain.'
    reserved=$("${compose[@]}" exec -T celery celery -A reNgine.tasks inspect -j -t 5 reserved 2>>"$diagnostic_log") ||
        die 'Could not inspect reserved tasks during drain.'
    scheduled=$("${compose[@]}" exec -T celery celery -A reNgine.tasks inspect -j -t 5 scheduled 2>>"$diagnostic_log") ||
        die 'Could not inspect scheduled tasks during drain.'
    queue_state=$("${compose[@]}" exec -T celery celery -A reNgine.tasks inspect -j -t 5 active_queues 2>>"$diagnostic_log") ||
        die 'Could not inspect queue consumers during drain.'
    worker_list=$(IFS=,; echo "${worker_names[*]}")
    drain_state=$(printf '%s\0' "$activity" "$reserved" "$scheduled" "$queue_state" "$worker_list" | python3 -c '
import json, sys
try:
    parts = sys.stdin.buffer.read().split(b"\0")
    active, reserved, scheduled, queues = (json.loads(x) for x in parts[:4])
    expected = set(filter(None, parts[4].decode().split(",")))
    if any(not isinstance(x, dict) or not expected <= set(x) for x in (active, reserved, scheduled, queues)):
        raise ValueError("worker disappeared")
    if any(queues[name] for name in expected): raise ValueError("consumer still active")
    counts = [sum(len(part[name]) for name in expected) for part in (active, reserved, scheduled)]
    names = sorted({str(task.get("name", "unknown")) for part in (active, reserved, scheduled)
                    for name in expected for task in part[name] if isinstance(task, dict)})
    names = ["".join(c for c in name if c.isalnum() or c in "_.-")[:80] for name in names[:6]]
    print("|".join([*(str(count) for count in counts), ",".join(names)]))
except (ValueError, TypeError, KeyError):
    sys.exit(1)
') ||
        die 'A worker disappeared or still consumes new tasks; update paused.'
    IFS='|' read -r active_count reserved_count scheduled_count task_names <<< "$drain_state"
    remaining=$((active_count + reserved_count + scheduled_count))
    [[ $remaining =~ ^[0-9]+$ ]] || die 'Could not count active tasks.'
    if (( SECONDS - last_drain_report >= 30 )); then
        echo "Drain: $active_count active, $reserved_count reserved, $scheduled_count scheduled; $((SECONDS - drain_started))s elapsed, ${drain_seconds}s maximum${task_names:+; tasks: $task_names}."
        last_drain_report=$SECONDS
    fi
    (( remaining == 0 )) && break
    if (( SECONDS >= drain_deadline )); then
        die "$remaining task(s) still active after the bounded drain; update aborted without killing them."
    fi
    sleep 5
done
echo 'All active and reserved worker tasks finished; stopping workers without replacing Redis...'
"${compose[@]}" stop -t 60 celery
workers_stopped=1

step 'Applying migrations; the database and broker containers stay in place'
"${compose[@]}" up -d --no-recreate db redis
"${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py migrate --noinput
database_migrated=1
# The proxy reads a shared static volume. Refresh it before the new web/JS is
# served; the Celery entrypoint can spend minutes installing optional tools.
echo 'Publishing current static assets to the proxy volume...'
"${compose[@]}" run --rm --no-deps --entrypoint python3 web manage.py collectstatic --noinput
services=(web celery celery-beat)
ready_url=http://127.0.0.1:8000/
if "${compose[@]}" config --services | grep -qx proxy; then
    services+=(proxy)
    ready_url=https://127.0.0.1/
fi
configured_url=$(ready_url_from_config || true)
[[ -z $configured_url ]] || ready_url=$configured_url
# Source is bind-mounted; recreate application processes, but never recreate the broker here.
step "Recreating application processes: ${services[*]}"
"${compose[@]}" up -d --no-deps --force-recreate "${services[@]}"
app_recreated=1

worker_queues_ready() {
    local queues
    queues=$("${compose[@]}" exec -T celery celery -A reNgine.tasks inspect active_queues -j -t 5 2>/dev/null) || return 1
    printf '%s' "$queues" | python3 -c '
import json, sys
try:
    workers = json.load(sys.stdin)
    expected = {"discovery_worker": "discovery_queue", "cve_feed_worker": "cve_feed_queue",
                "validation_priority_worker": "validation_priority_queue", "classic_worker": "api_queue"}
    # Celery may report either the configured node name or celery@<node>.
    def owns(name, worker):
        return name == worker or name.startswith(worker + "@") or name.endswith("@" + worker)
    ok = all(any(owns(name, worker) and any(q.get("name") == queue for q in listed)
                 for name, listed in workers.items()) for worker, queue in expected.items())
except (ValueError, TypeError, AttributeError):
    ok = False
sys.exit(0 if ok else 1)
' >/dev/null
}

beat_ready() {
    "${compose[@]}" exec -T celery-beat python3 -c \
        "import sys; a=[x for x in open('/proc/1/cmdline','rb').read().split(b'\\0') if x]; n=[x.rsplit(b'/',1)[-1] for x in a]; sys.exit(0 if b'celery' in n and b'beat' in a and not any(x.endswith(b'-entrypoint.sh') for x in n) else 1)" \
        >/dev/null 2>&1
}

# The legacy Celery entrypoint still prepares optional scanners at startup. Its
# bounded network retries can exceed three minutes before all workers answer.
step "Waiting up to ${ready_seconds}s for $ready_url, all worker queues and Celery Beat"
deadline=$((SECONDS + ready_seconds))
status=unknown
while (( SECONDS < deadline )); do
    status=$(curl -k -s --max-time 5 -o /dev/null -w '%{http_code}' \
        "$ready_url" || true)
    if [[ "$status" =~ ^[23][0-9][0-9]$ ]] && worker_queues_ready && beat_ready; then
        git rev-parse HEAD > web/.commit
        dispatch_paused=0
        requeued=''
        if [[ -s $requeue_file ]]; then
            plan=$(cat "$requeue_file")
            requeued=$(web_python "$scan_requeue_code" -e "CVENGINE_REQUEUE=$plan" | grep '^REQUEUED ' | head -n1 || true)
            if [[ -n $requeued ]]; then rm -f "$requeue_file"; else
                echo "Could not queue the stopped scans again; they stay in $requeue_file for the next update." >&2; fi
        fi
        echo
        echo "Updated $from_commit -> $(git rev-parse --short HEAD) in $(( (SECONDS - started_at) / 60 ))m $(( (SECONDS - started_at) % 60 ))s."
        echo "Local HTTP returned $status at $ready_url; every worker queue and Celery Beat are running."
        [[ -z $requeued ]] || echo "Queued ${requeued#REQUEUED } stopped scan(s) again."
        echo "This local check does not validate the public hostname, TLS certificate or task execution."
        "${compose[@]}" ps
        rm -f "$diagnostic_log"
        exit 0
    fi
    sleep 5
done
echo "Readiness failed: last local HTTP status $status; check worker queues and Beat before treating the update as complete." >&2
false
