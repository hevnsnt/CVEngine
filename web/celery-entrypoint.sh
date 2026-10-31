#!/bin/bash

# web owns migrations; wait until they are applied (avoids concurrent-migrate race)
until python3 manage.py migrate --check >/dev/null 2>&1; do
    echo "Waiting for web to apply migrations..."
    sleep 3
done

# The built-in scanner's first enrollment blob must not wait for the beat task (every five minutes). A no-op when CVENGINE_BUILTIN_SCANNER is not set,
# and never a reason for the container not to start.
python3 manage.py ensure_builtin_scanner >/dev/null 2>&1 || true

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

# test the scanners the pipeline runs, required for configuration
naabu -version
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
# wpscan_queue: the thorough WPScan pass (hours per site, one per project at a time) must not hold a feed worker
# testssl_queue: the daily TLS audit (a minute per port, one sweep at a time) likewise
# bucketscan_queue: the daily cloud storage sweep (a few requests per second, one sweep at a time) likewise
# vhost_queue: the slow, polite sweeps for other sites on an address and for applications under subdirectories (one request at a time)
# udp_queue: the background UDP sweep (nmap -sU waits on silent ports, one IP at a time) likewise
# openvas_queue: the optional OpenVAS sweep (one GVM task at a time, polled for hours); nothing is queued on it unless the add-on is switched on
# supplier_queue: the daily third-party supplier posture sweep (a few polite requests per supplier, one sweep at a time) likewise
# ctwatch_queue: certificate transparency lookups of new targets (crt.sh rate limits them; a bulk add queues hundreds) must not hold the feed worker
classic_queues+=",run_command_queue,api_queue,wpscan_queue,testssl_queue,bucketscan_queue,vhost_queue,udp_queue,openvas_queue,supplier_queue,ctwatch_queue"

commands=""
# each bbot kitchen-sink run is memory hungry, so discovery gets a small pool of its own
commands+="$(generate_worker_command "discovery_queue" "${DISCOVERY_CONCURRENCY:-8}" "discovery_worker")"$'\n'
commands+="$(generate_worker_command "cve_feed_queue" "4" "cve_feed_worker")"$'\n'
# A reserved one-at-a-time lane keeps requested validation ahead of routine feed work.
# Redis priority 0 is highest; this worker reserves one task for future severity-aware dispatch.
commands+="$(generate_worker_command "validation_priority_queue" "1" "validation_priority_worker")"$'\n'
commands+="$(generate_worker_command "$classic_queues" "${CLASSIC_CONCURRENCY:-20}" "classic_worker")"$'\n'
commands="${commands%&}"

eval "$commands"

# This shell is the container's main process and the parent of the four workers. As PID 1 (or the child of Docker's init) it only receives
# SIGTERM if a trap asks for it, so without one `docker stop` waited out the grace period and killed the workers mid-task. Pass the stop on as a
# warm shutdown (celery finishes or re-queues what it holds), and when ANY worker exits, stop the rest and exit non-zero: `restart: always`
# then brings all four lanes back, where a plain `wait` kept the container "up" with a lane (discovery, the CVE feed) no longer consumed.
stop_workers() {
    trap - TERM INT
    local pids
    pids=$(jobs -p) || true
    # shellcheck disable=SC2086
    [ -z "$pids" ] || kill -TERM $pids 2>/dev/null || true
    wait || true
}
trap 'stop_workers; exit 143' TERM INT
status=0
wait -n || status=$?
echo "A Celery worker exited (status $status); stopping the other workers so the container restarts with all of them."
stop_workers
exit "$(( status == 0 ? 1 : status ))"
