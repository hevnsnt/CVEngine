#!/bin/bash

# web owns migrations; wait until they are applied (avoids concurrent-migrate race)
until python3 manage.py migrate --check >/dev/null 2>&1; do
    echo "Waiting for web to apply migrations..."
    sleep 3
done

# make migrations for specific apps
apps=(
    "targetApp"
    "scanEngine"
    "startScan"
    "dashboard"
    "recon_note"
)

create_migrations() {
    local app=$1
    echo "Creating migrations for $app..."
    python3 manage.py makemigrations $app
    echo "Finished creating migrations for $app"
    echo "----------------------------------------"
}

echo "Starting migration creation process..."

for app in "${apps[@]}"
do
    create_migrations $app
done

echo "Migration creation process completed."

# web owns migrations; wait until they are applied (avoids concurrent-migrate race)
until python3 manage.py migrate --check >/dev/null 2>&1; do
    echo "Waiting for web to apply migrations..."
    sleep 3
done


python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

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
# api_queue tasks live in api.shared_api_tasks, which autodiscovery does not import, so the classic worker includes it.
classic_queues="send_notif_queue,send_task_notif_queue,send_hackerone_report_queue,geo_localize_queue"
# wpscan_queue: the thorough WPScan pass (hours per site, one per project at a time) must not hold a feed worker
# testssl_queue: the daily TLS audit (a minute per port, one sweep at a time) likewise
classic_queues+=",query_whois_queue,run_command_queue,query_reverse_whois_queue,query_ip_history_queue,llm_queue,api_queue,wpscan_queue,testssl_queue"

commands=""
# each bbot kitchen-sink run is memory hungry, so discovery gets a small pool of its own
commands+="$(generate_worker_command "discovery_queue" "${DISCOVERY_CONCURRENCY:-3}" "discovery_worker")"$'\n'
commands+="$(generate_worker_command "cve_feed_queue" "4" "cve_feed_worker")"$'\n'
# A reserved one-at-a-time lane keeps requested validation ahead of routine feed work.
# Redis priority 0 is highest; this worker reserves one task for future severity-aware dispatch.
commands+="$(generate_worker_command "validation_priority_queue" "1" "validation_priority_worker")"$'\n'
commands+="$(generate_worker_command "$classic_queues" "${CLASSIC_CONCURRENCY:-20}" "classic_worker" "reNgine.tasks" "/usr/src/app/reNgine/" "api.shared_api_tasks")"$'\n'
commands="${commands%&}"

eval "$commands"

wait
