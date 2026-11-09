#!/bin/bash

# web owns migrations; wait until they are applied (avoids concurrent-migrate race)
until python3 manage.py migrate --check >/dev/null 2>&1; do
    echo "Waiting for web to apply migrations..."
    sleep 3
done

# The built-in scanner's first enrollment blob must not wait for the beat task (every five minutes). CVENGINE_BUILTIN_SCANNER=0 revokes it instead,
# and never a reason for the container not to start.
python3 manage.py ensure_builtin_scanner >/dev/null 2>&1 || true
# The same for the AI reviewer container's token (docs/AI-REVIEWER.md); CVENGINE_REVIEWER=0 revokes it instead.
python3 manage.py ensure_reviewer_token >/dev/null 2>&1 || true

# (This used to run `makemigrations` for five apps against the bind-mounted source, which is the git checkout on the host: model drift became
# untracked migration files that later conflicted with the real ones. A migration is written and committed by a developer; CI checks for drift.)

# Not --clear: the static volume is the one the proxy serves, and emptying it at every start left /staticfiles/ empty for as long as the
# container took to get here (a crash loop kept it empty). The update publishes the new files first (collectstatic in update-deploy.sh).
python3 manage.py collectstatic --no-input

# Load the default engines, keywords and external tools the install does not have yet. A row that is already there is never overwritten: an
# administrator's edit to a built-in engine must survive every restart and update (this used to be `loaddata`, which rewrote every field).
python3 manage.py load_default_fixtures fixtures/default_scan_engines.yaml fixtures/external_tools.yaml

# Temporary fix for whatportis bug - See https://github.com/yogeshojha/rengine/issues/984
# (path looked up, not hard-coded: it depends on the Python version and the virtual environment)
WHATPORTIS_CLI=$(python3 -c "import os, whatportis; print(os.path.join(os.path.dirname(whatportis.__file__), 'cli.py'))")
sed -i 's/purge()/truncate()/g' "$WHATPORTIS_CLI"

# update whatportis
yes | whatportis --update

# store scan_results
if [ ! -d "/usr/src/scan_results" ]
then
  mkdir /usr/src/scan_results
fi
# Only root and the bundled nginx (gid 101 in nginx:alpine; the proxy serves /protected_media/ from this volume, read-only) may enter it: no other
# account in this container has any business with scan output, PDF reports or log archives. Applied at every start.
chgrp 101 /usr/src/scan_results && chmod 0750 /usr/src/scan_results || echo "Could not restrict /usr/src/scan_results to root and the proxy"

# the one tool the server runs itself (it refreshes and reads the template set); every scan runs on a Sentinel
nuclei -version

# geeknik/the-nuclei-templates produces false positives (#1521), drop copies left by older installs
if [ -d "/root/nuclei-templates/geeknik_nuclei_templates" ];
then
  echo "Removing Geeknik Nuclei templates"
  rm -rf /root/nuclei-templates/geeknik_nuclei_templates
fi

# a third-party template that used to be fetched from a branch on every start is no longer downloaded: unreviewed, unpinned
# content must not enter the template set. A copy left by an older install is removed.
rm -f ~/nuclei-templates/ssrf_nagli.yaml

# TEMPORARY FIX, httpcore is causing issues with celery, removing it as temp fix
#python3 -m pip uninstall -y httpcore

loglevel='info'
if [ "$DEBUG" == "1" ]; then
    loglevel='debug'
fi

generate_worker_command() {
    local queue=$1
    local concurrency=$2
    local worker_name=$3
    local app=${4:-"reNgine.tasks"}
    local directory=${5:-"/usr/src/app/reNgine/"}
    local include=$6

    local base_command="celery -A $app worker --pool=gevent --optimization=fair --autoscale=$concurrency,1 --loglevel=$loglevel -Q $queue -n $worker_name"
    if [ "$queue" = "validation_priority_queue" ]; then
        base_command+=" --prefetch-multiplier=1"
    fi
    if [ -n "$include" ]; then
        base_command+=" -I $include"
    fi

    if [ "$CELERY_AUTORELOAD" == "1" ]; then
        echo "watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"$directory\" -- $base_command &"
    else
        echo "$base_command &"
    fi
}

# An update kills the workers holding messages they took and never started; Redis hands those back only after the visibility timeout
# (12 hours). Nothing of this stack consumes yet, so what is still unacknowledged is orphaned: return it to its queues now.
python3 manage.py requeue_unacked || echo "Could not return the unacknowledged broker messages (they are returned after the visibility timeout)"

echo "Starting Celery Workers..."

# Three gevent workers instead of one process per queue: every worker process loads all of Django (150-250 MB), so
# the old fleet of ~24 idled most of the container's memory. Auto-restart on .py edits is opt-in (CELERY_AUTORELOAD=1):
# it kills any scan in flight.
# api_queue has no tasks any more (the legacy /api/ surface that used it is gone), but the classic worker keeps consuming it: the
# status page, the update script and the admin worker panel recognise this worker by that queue name.
classic_queues="send_notif_queue,send_task_notif_queue,geo_localize_queue"
# wpscan_queue: a long, per-site, one-per-project-at-a-time pass must not hold a feed worker
# testssl_queue: the daily TLS audit (a minute per port, one sweep at a time) likewise
# bucketscan_queue: the daily cloud storage sweep (a few requests per second, one sweep at a time) likewise
# vhost_queue: the slow, polite sweeps for other sites on an address and for applications under subdirectories (one request at a time)
# udp_queue: the background UDP sweep (it waits on silent ports, one IP at a time) likewise
# openvas_queue: the optional OpenVAS sweep (one GVM task at a time, polled for hours); nothing is queued on it unless the add-on is switched on
# supplier_queue: the daily third-party supplier posture sweep (a few polite requests per supplier, one sweep at a time) likewise
# ctwatch_queue: certificate transparency lookups of new targets (crt.sh rate limits them; a bulk add queues hundreds) must not hold the feed worker
# live_cache_queue: the Live screen's snapshot refresher (cveFeed/live_refresh.py), a few seconds of work every CVENGINE_LIVE_REFRESH_SECONDS. Its own queue
# (a long sweep ahead of it in another queue never blocks it) on this worker, not the discovery, feed or validation ones, whose slots scan work holds for
# hours; the slots here are greenlets (10, CLASSIC_CONCURRENCY; a certificate lookup may sleep up to 30 s in one waiting for crt.sh's pacing), of which the one-at-a-time sweeps above hold a handful. A worker per lane is capped at four (memory, see
# tests/test_entrypoint.py). A refresh that finds no free slot expires (three intervals) and the Live screen computes on request until the next one runs.
classic_queues+=",run_command_queue,api_queue,wpscan_queue,testssl_queue,bucketscan_queue,vhost_queue,udp_queue,openvas_queue,supplier_queue,live_cache_queue,ctwatch_queue"
# screenshot_queue: the web screenshot drain and the hourly sweep (they hand pages to Sentinels and wait for them, one drain at a time: a second task returns at once; no browser runs here)
classic_queues+=",screenshot_queue"
# report_queue: the one-click PDF report (cveFeed/report_export.py): seconds to minutes of work for one person who is waiting for it. Its own queue, so a long feed run or
# a certificate lookup in backoff on the cve_feed worker cannot hold it; the classic worker has the free slots.
classic_queues+=",report_queue"

commands=""
# each discovery run is memory hungry, so discovery gets a small pool of its own
# How many discovery tasks and host assessments run at once: what an App Admin saved on Settings, configMaxxing, else DISCOVERY_CONCURRENCY, else 8.
# (A save also resizes the running worker live, see cveFeed/scan_concurrency.py; this makes a restart or an update land on the same number.)
discovery_concurrency=$(python3 manage.py scan_concurrency_value discovery_concurrency 2>/dev/null | tail -n 1)
if ! [[ "$discovery_concurrency" =~ ^[0-9]+$ ]] || [ "$discovery_concurrency" -lt 1 ]; then
    discovery_concurrency="${DISCOVERY_CONCURRENCY:-8}"
fi
echo "Discovery pool size (autoscale ceiling): $discovery_concurrency"
commands+="$(generate_worker_command "discovery_queue" "$discovery_concurrency" "discovery_worker")"$'\n'
commands+="$(generate_worker_command "cve_feed_queue" "4" "cve_feed_worker")"$'\n'
# A reserved one-at-a-time lane keeps requested validation ahead of routine feed work.
# Redis priority 0 is highest; this worker reserves one task for future severity-aware dispatch.
commands+="$(generate_worker_command "validation_priority_queue" "1" "validation_priority_worker")"$'\n'
commands+="$(generate_worker_command "$classic_queues" "${CLASSIC_CONCURRENCY:-10}" "classic_worker")"$'\n'

# --- start_lanes: the four workers, each its own background job, with its pid and name recorded ---------------------------------------------
# Every line of $commands is one `celery ... -n <node> &`. The pid of each is kept next to the lane's name, so the supervisor below can say WHICH lane
# is gone and check each one itself (waiting for any one child to exit says that something exited, and nothing about which).
lane_names=()
lane_pids=()
start_lanes() {
    local line name
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        name=$(printf '%s\n' "$line" | sed -n 's/.* -n \([a-z_]*\).*/\1/p')
        eval "$line"
        lane_names+=("${name:-lane$((${#lane_pids[@]} + 1))}")
        lane_pids+=("$!")
    done <<<"$commands"
}
start_lanes

# alive: the process exists and is not a zombie that nobody has reaped yet.
lane_alive() {
    kill -0 "$1" 2>/dev/null || return 1
    local state
    state=$(sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -c1-1) || return 0
    [ "$state" != "Z" ]
}

# stop_lanes: a warm stop (SIGTERM: the worker takes no new task and finishes or re-queues what it holds), but BOUNDED. A discovery worker holds host
# assessments that wait on a Sentinel for hours, so an unbounded `wait` here is how a container with ONE dead lane stayed "up" for good with the
# other lanes stopped and the restart policy never reached: it never exits. After CELERY_STOP_GRACE seconds (default 45, under the 60 s of
# stop_grace_period in docker-compose.yml) what is still there is killed; the tasks it held are returned to their queues at the next start
# (manage.py requeue_unacked above).
stop_lanes() {
    trap - TERM INT
    local pid waited=0 grace="${CELERY_STOP_GRACE:-45}"
    for pid in "${lane_pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    while [ "$waited" -lt "$grace" ]; do
        local any=0
        for pid in "${lane_pids[@]}"; do lane_alive "$pid" && any=1; done
        [ "$any" = 0 ] && break
        sleep 1
        waited=$((waited + 1))
    done
    for pid in "${lane_pids[@]}"; do
        if lane_alive "$pid"; then
            echo "Worker process $pid did not stop within ${grace}s; killing it."
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
}

# This shell is the container's main process and the parent of the four workers. As PID 1 (or the child of Docker's init) it only receives
# SIGTERM if a trap asks for it, so without one `docker stop` waited out the grace period and killed the workers mid-task.
trap 'echo "Stop requested; stopping the Celery workers."; stop_lanes; exit 143' TERM INT

# The supervisor. Every CELERY_SUPERVISE_INTERVAL seconds (default 2) each lane's process is checked; when ANY is gone (it crashed, it was killed for
# memory, it failed to start) the others are stopped (bounded, above) and the container EXITS non-zero, so `restart: always` brings all four lanes back
# together: a container must never stay up with a lane that no longer consumes (discovery, the CVE feed, validation or the classic queues).
supervise() {
    local i status
    while true; do
        for i in "${!lane_pids[@]}"; do
            if ! lane_alive "${lane_pids[$i]}"; then
                status=0
                wait "${lane_pids[$i]}" 2>/dev/null || status=$?
                echo "The Celery worker '${lane_names[$i]}' (pid ${lane_pids[$i]}) is gone (status $status); stopping the other workers so the container restarts with all four lanes."
                stop_lanes
                return "$(( status == 0 ? 1 : status ))"
            fi
        done
        sleep "${CELERY_SUPERVISE_INTERVAL:-2}" &
        wait $! 2>/dev/null || true
    done
}
supervise
exit "$?"
