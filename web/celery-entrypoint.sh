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

# clone dirsearch default wordlist
if [ ! -d "/usr/src/wordlist" ]
then
  echo "Making Wordlist directory"
  mkdir /usr/src/wordlist
fi

if [ ! -f "/usr/src/wordlist/" ]
then
  echo "Downloading Default Directory Bruteforce Wordlist"
  wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt
fi

# clone Sublist3r
if [ ! -d "/usr/src/github/Sublist3r" ]
then
  echo "Cloning Sublist3r"
  git clone https://github.com/aboul3la/Sublist3r /usr/src/github/Sublist3r
fi
python3 -m pip install -r /usr/src/github/Sublist3r/requirements.txt

# clone OneForAll
if [ ! -d "/usr/src/github/OneForAll" ]
then
  echo "Cloning OneForAll"
  git clone https://github.com/shmilylty/OneForAll /usr/src/github/OneForAll
fi
python3 -m pip install -r /usr/src/github/OneForAll/requirements.txt

# clone eyewitness
if [ ! -d "/usr/src/github/EyeWitness" ]
then
  echo "Cloning EyeWitness"
  git clone https://github.com/FortyNorthSecurity/EyeWitness /usr/src/github/EyeWitness
  pip install -r /usr/src/github/EyeWitness/setup/requirements.txt
fi

# clone vulscan
if [ ! -d "/usr/src/github/scipag_vulscan" ]
then
  echo "Cloning Nmap Vulscan script"
  git clone https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan
  echo "Symlinking to nmap script dir"
  ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan
  echo "Usage in CVEngine, set vulscan/vulscan.nse in nmap_script scanEngine port_scan config parameter"
fi

# install h8mail
python3 -m pip install h8mail

# install gf patterns
if [ ! -d "/root/Gf-Patterns" ];
then
  echo "Installing GF Patterns"
  mkdir ~/.gf
  cp -r $GOPATH/src/github.com/tomnomnom/gf/examples/*.json ~/.gf
  git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns
  mv ~/Gf-Patterns/*.json ~/.gf
fi

# store scan_results
if [ ! -d "/usr/src/scan_results" ]
then
  mkdir /usr/src/scan_results
fi

# test tools, required for configuration
naabu && subfinder
nuclei

# geeknik/the-nuclei-templates produces false positives (#1521), drop copies left by older installs
if [ -d "/root/nuclei-templates/geeknik_nuclei_templates" ];
then
  echo "Removing Geeknik Nuclei templates"
  rm -rf /root/nuclei-templates/geeknik_nuclei_templates
fi

if [ ! -f ~/nuclei-templates/ssrf_nagli.yaml ];
then
  echo "Downloading ssrf_nagli for Nuclei"
  wget https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml -O ~/nuclei-templates/ssrf_nagli.yaml
fi

if [ ! -d "/usr/src/github/CMSeeK" ]
then
  echo "Cloning CMSeeK"
  git clone https://github.com/Tuhinshubhra/CMSeeK /usr/src/github/CMSeeK
  pip install -r /usr/src/github/CMSeeK/requirements.txt
fi

# clone ctfr
if [ ! -d "/usr/src/github/ctfr" ]
then
  echo "Cloning CTFR"
  git clone https://github.com/UnaPibaGeek/ctfr /usr/src/github/ctfr
fi

# clone gooFuzz
if [ ! -d "/usr/src/github/goofuzz" ]
then
  echo "Cloning GooFuzz"
  git clone https://github.com/m3n0sd0n4ld/GooFuzz.git /usr/src/github/goofuzz
  chmod +x /usr/src/github/goofuzz/GooFuzz
fi

# httpx seems to have issue, use alias instead!!!
echo 'alias httpx="/go/bin/httpx"' >> ~/.bashrc

# TEMPORARY FIX, httpcore is causing issues with celery, removing it as temp fix
#python3 -m pip uninstall -y httpcore

# TEMPORARY FIX FOR langchain
pip install tenacity==8.2.2

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

echo "Starting Celery Workers..."

# Three gevent workers instead of one process per queue: every worker process loads all of Django (150-250 MB), so
# the old fleet of ~24 idled most of the container's memory. Auto-restart on .py edits is opt-in (CELERY_AUTORELOAD=1):
# it kills any scan in flight.
# api_queue tasks live in api.shared_api_tasks, which autodiscovery does not import, so the classic worker includes it.
classic_queues="main_scan_queue,initiate_scan_queue,subscan_queue,report_queue,send_notif_queue,send_task_notif_queue"
classic_queues+=",send_file_to_discord_queue,send_hackerone_report_queue,parse_nmap_results_queue,geo_localize_queue"
classic_queues+=",query_whois_queue,remove_duplicate_endpoints_queue,run_command_queue,query_reverse_whois_queue"
classic_queues+=",query_ip_history_queue,llm_queue,dorking_queue,osint_discovery_queue,h8mail_queue"
classic_queues+=",send_scan_notif_queue,api_queue"

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
