#!/usr/bin/env bash
# Thin bootstrap for a Linux server:  sudo ./install.sh
# It checks the machine, installs what is missing (Docker, make), generates every secret and the HTTPS certificate, starts CVEngine, waits until
# it answers, creates the admin account and prints the address. Everything else (targets, scanners, Sentinels, notifications) is set up in the
# browser by the setup wizard: this script asks nothing that matters. On a terminal it offers one optional shortcut, which scanners this server
# will use; without a terminal (a pipe, CI, -n) it asks nothing and takes the safe default, the built-in scanner only. OpenVAS is never installed
# or started: it runs on a Sentinel (docs/OPENVAS.md). Safe to run again: nothing already set is changed, and a running installation keeps its data.
#
#   sudo ./install.sh                        # detect this machine's address and use it
#   sudo ./install.sh --domain scan.example.com   # use a name people will type instead
#   sudo ./install.sh --sentinels=internal   # built-in scanner only (the default; docs/BUILTIN-SCANNER.md)
#   sudo ./install.sh --sentinels=both       # built-in scanner plus external Sentinels you add in the browser
#   sudo ./install.sh --sentinels=external   # external Sentinels only: the built-in scanner is not installed or started
#   sudo ./install.sh -n                     # never ask (also when CI is set or stdin is not a terminal)
#   CVENGINE_INSTALL_PORTS="..."             # ports that must be free before the first start (default: the HTTPS and HTTP ports, 443 and 8082); the tests set it to ""
set -uo pipefail
cd "$(dirname "$0")" || exit 1
started=$SECONDS

usage() {
  echo "Usage: sudo $0 [--domain NAME] [--sentinels internal|both|external] [--no-builtin-scanner] [-n] [-h]"
  echo "  --domain NAME  hostname or IPv4 address people will use to reach CVEngine (default: detected)"
  echo "  --sentinels X  which scanners this server uses (asked on a terminal when not given; docs/BUILTIN-SCANNER.md):"
  echo "                   internal  the built-in scanner only (default)"
  echo "                   both      the built-in scanner plus external Sentinels you add afterwards"
  echo "                   external  external Sentinels only: the built-in scanner is not installed or started"
  echo "  --no-builtin-scanner  same as --sentinels=external"
  echo "  -n, --non-interactive  never ask a question; the flags and the safe defaults decide"
  echo "  -h             show this help"
  echo "OpenVAS is never installed or started by this installer: it runs on a Sentinel you choose to add (docs/OPENVAS.md)."
}

original_args=("$@")
domain=""
sentinels=''        # internal, both or external: from --sentinels or the question; empty means nobody chose
interactive=1
set_sentinels() {
  case $1 in internal|both|external) ;; *) echo "--sentinels takes internal, both or external (got '$1')." >&2; usage >&2; exit 1 ;; esac
  if [ -n "$sentinels" ] && [ "$sentinels" != "$1" ]; then echo "Conflicting choices: $sentinels and $1." >&2; usage >&2; exit 1; fi
  sentinels=$1
}
while [ $# -gt 0 ]; do
  case $1 in
    --domain) domain=${2:-}; [ -n "$domain" ] || { usage; exit 1; }; shift 2 ;;
    --domain=*) domain=${1#--domain=}; shift ;;
    --sentinels) [ -n "${2:-}" ] || { usage >&2; exit 1; }; set_sentinels "$2"; shift 2 ;;
    --sentinels=*) set_sentinels "${1#--sentinels=}"; shift ;;
    --builtin-scanner) set_sentinels internal; shift ;;  # accepted for older scripts: the built-in scanner is on by default
    --no-builtin-scanner) set_sentinels external; shift ;;
    -n|--non-interactive) interactive=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if [ -t 1 ]; then BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'; RESET=$'\033[0m'
else BOLD=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; RESET=''; fi
step() { printf '\n%s==> %s%s\n' "$BLUE$BOLD" "$1" "$RESET"; }
ok()   { printf '%s  ok%s  %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '%s warn%s %s\n' "$YELLOW" "$RESET" "$1"; }
die()  { printf '\n%s  FAILED%s  %s\n' "$RED$BOLD" "$RESET" "$1" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Compose prints one line per downloaded layer when its output is not a terminal (hundreds of lines in a log or a pipe): only on a terminal is it
# left to draw its progress bars. Errors are still printed.
[ -t 1 ] || export COMPOSE_PROGRESS=${COMPOSE_PROGRESS:-quiet}

compose() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi
}

show_logs() {
  printf '\n%sThe last log lines of the services, to help find the cause:%s\n' "$YELLOW" "$RESET" >&2
  compose -f docker-compose.yml logs --tail=25 web proxy db 2>&1 | tail -n 75 >&2 || true
}

# ---------------------------------------------------------------------------------------------------------------------------
step "Checking this machine"

[ "$(uname -s)" = "Linux" ] || die "This installer is for Linux. On Mac or Windows see docs/DEPLOYMENT.md."

if [ "$(id -u)" -ne 0 ]; then
  if have sudo; then
    echo "Needs root to install Docker and bind port 443: running again through sudo."
    exec sudo "$0" "${original_args[@]}"  # not -E: the caller's environment does not come along
  fi
  die "Run this as root:  su -c './install.sh'"
fi
ok "running as root"

case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ok "architecture $(uname -m)" ;;
  *) warn "architecture $(uname -m) is untested; the container images may not exist for it" ;;
esac

mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [ "${mem_kb:-0}" -gt 0 ]; then
  if [ "$mem_kb" -lt 3500000 ]; then warn "only $((mem_kb / 1024)) MB of memory: 8 GB or more is recommended, scans may be killed for lack of memory"
  elif [ "$mem_kb" -lt 7000000 ]; then warn "$((mem_kb / 1024)) MB of memory: 8 GB is recommended with the built-in scanner; its container gets 1 GB here instead of 2 (SCANNER_MEM_LIMIT, docs/DEPLOYMENT.md)"
  else ok "$((mem_kb / 1024)) MB of memory"; fi
fi

free_kb=$(df -Pk . 2>/dev/null | awk 'NR == 2 {print $4}')
if [ -n "${free_kb:-}" ]; then
  if [ "$free_kb" -lt 15000000 ]; then warn "only $((free_kb / 1048576)) GB free here: 20 GB or more is recommended for images, databases and scan results"
  else ok "$((free_kb / 1048576)) GB free disk"; fi
fi

# ---------------------------------------------------------------------------------------------------------------------------
# The one question: which scanners will this server use. Asked only on a terminal, only when nobody chose by flag, and only on a first install:
# a machine that already has an .env keeps what it has (a flag still changes it). Everything else gets the safe default, the built-in scanner only.
env_value() { grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '\r"'"'"' '; }
ask_sentinels() {
  local answer='' tries=0 small=''
  [ "${mem_kb:-0}" -gt 0 ] && [ "$mem_kb" -lt 7000000 ] && small=" This machine has $((mem_kb / 1024)) MB: option 2 or 3 keeps it lighter."
  printf '\n%sWill you add external Sentinels (recommended for scans from other networks and to keep this server light), or use only the built-in scanner?%s\n' "$BOLD" "$RESET"
  cat <<EOF
  1) Built-in scanner only        scans run on this server, in a container capped at 2 GB of memory (the default)
  2) Built-in scanner plus external Sentinels
                                  the built-in one stays; you add Sentinels afterwards (the steps are shown at the end)
  3) External Sentinels only      nothing scans on this server: the built-in scanner is not installed or started,
                                  and its 4.5 GB image is never downloaded. Scans wait until a Sentinel is enrolled.${small}
  OpenVAS is part of none of these: it runs on a Sentinel you choose to add (docs/OPENVAS.md).
EOF
  while [ "$tries" -lt 3 ]; do
    printf 'Choose 1, 2 or 3 [1]: '
    read -r answer || { echo; answer=1; }  # end of input: the default
    case ${answer:-1} in
      1|internal) sentinels=internal; break ;;
      2|both) sentinels=both; break ;;
      3|external) sentinels=external; break ;;
      *) echo "  Please type 1, 2 or 3." ;;
    esac
    tries=$((tries + 1))
  done
  [ -n "$sentinels" ] || { sentinels=internal; echo "  Taking the default: the built-in scanner only."; }
  ok "scanners: $sentinels"
}
if [ -z "$sentinels" ]; then
  if [ "$interactive" -eq 1 ] && [ -t 0 ] && [ -z "${CI:-}" ]; then
    if [ -f .env ] && { [ -n "$(env_value CVENGINE_BUILTIN_SCANNER)" ] || [ -n "$(env_value CVENGINE_SENTINEL_PLAN)" ]; }; then
      ok "keeping the scanner choice already in .env (run again with --sentinels=internal, both or external to change it)"
    elif [ -f .env ] && [ -n "$(env_value POSTGRES_PASSWORD)" ] && ! env_value POSTGRES_PASSWORD | grep -qi 'change-me'; then
      ok "this is an existing installation: its scanner settings stay as they are (--sentinels=internal, both or external changes them)"
    else
      ask_sentinels
    fi
  fi
fi

# packages: only Debian and Ubuntu families are installed for you; anywhere else the missing tool is named
apt_ready=0
pkg_install() {
  if have apt-get; then
    if [ "$apt_ready" -eq 0 ]; then apt-get update -qq || warn "apt-get update failed; trying anyway"; apt_ready=1; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null || die "Could not install: $*"
  else
    die "Please install these with your package manager and run the installer again: $*"
  fi
}

for tool_pkg in curl:curl make:make python3:python3 git:git openssl:openssl; do
  tool=${tool_pkg%%:*}; pkg=${tool_pkg##*:}
  if have "$tool"; then ok "$tool"; else echo "Installing $pkg..."; pkg_install "$pkg"; ok "$tool installed"; fi
done

step "Docker"
if have docker; then
  ok "docker $(docker --version 2>/dev/null | sed 's/Docker version //; s/,.*//')"
else
  echo "Installing Docker (the official convenience script)..."
  docker_installer=$(mktemp) || die "Could not create a temporary file."
  curl -fsSL https://get.docker.com -o "$docker_installer" || die "Could not download Docker's installer. Is this machine online (https://get.docker.com)?"
  sh "$docker_installer" || die "Docker's installer failed. See https://docs.docker.com/engine/install/ and run this again."
  rm -f "$docker_installer"
  ok "docker installed"
fi

if ! docker compose version >/dev/null 2>&1 && ! have docker-compose; then
  echo "Installing the Docker Compose plugin..."
  pkg_install docker-compose-plugin || true
  docker compose version >/dev/null 2>&1 || die "Docker Compose is missing. See https://docs.docker.com/compose/install/ and run this again."
fi
ok "docker compose"
# the compose files use `env_file: - path: .env, required: false`, which needs Compose 2.24; an older one fails later with a schema error
compose_version=$(compose version --short 2>/dev/null | head -n 1 | sed 's/^v//')
if [[ $compose_version =~ ^([0-9]+)\.([0-9]+) ]]; then
  if [ "${BASH_REMATCH[1]}" -lt 2 ] || { [ "${BASH_REMATCH[1]}" -eq 2 ] && [ "${BASH_REMATCH[2]}" -lt 24 ]; }; then
    die "Docker Compose $compose_version is too old: CVEngine needs 2.24 or newer. Update the docker-compose-plugin package (or see https://docs.docker.com/compose/install/) and run this again."
  fi
  ok "docker compose $compose_version"
fi

if ! docker info >/dev/null 2>&1; then
  have systemctl && systemctl enable --now docker >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do docker info >/dev/null 2>&1 && break; sleep 2; done
  docker info >/dev/null 2>&1 || die "The Docker daemon is not running. Start it (systemctl start docker) and run this again."
fi
ok "docker daemon is running"

# ports: our own proxy holding them from a previous run is fine
https_port=${CVENGINE_HTTPS_PORT:-$(env_value CVENGINE_HTTPS_PORT)}; https_port=${https_port:-443}
http_port=${CVENGINE_HTTP_PORT:-$(env_value CVENGINE_HTTP_PORT)}; http_port=${http_port:-8082}
install_ports=${CVENGINE_INSTALL_PORTS-$https_port $http_port}
running_proxy=$(compose -f docker-compose.yml ps -q proxy 2>/dev/null || true)
if [ -z "$running_proxy" ]; then
  port_busy() {
    if have ss; then ss -ltn 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {found = 1} END {exit !found}'
    elif have netstat; then netstat -ltn 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {found = 1} END {exit !found}'
    else return 1; fi
  }
  for port in $install_ports; do
    if port_busy "$port"; then die "Port $port is already in use by another program. Stop it (for example another web server) and run this again."; fi
  done
  ok "ports $install_ports are free"
else
  ok "CVEngine is already running here: rebuilding it from this checkout (this does not fetch new code, see docs/UPDATES.md)"
fi

for host in registry-1.docker.io github.com; do
  if curl -fsS -m 10 -o /dev/null "https://$host" 2>/dev/null || curl -sS -m 10 -o /dev/null -I "https://$host" 2>/dev/null; then ok "can reach $host"
  else warn "cannot reach https://$host: building the images needs it (set up a proxy for Docker if this machine sits behind one)"; fi
done

# ---------------------------------------------------------------------------------------------------------------------------
step "Preparing settings"
CVENGINE_INSTALL_SENTINELS=$sentinels ./scripts/init-env.sh ${domain:+"$domain"} || die "Could not prepare .env"
# A small host: the built-in scanner's container ceiling is 1 GB instead of 2 (an owner's own value is kept)
if [ "${mem_kb:-0}" -gt 0 ] && [ "$mem_kb" -lt 7000000 ] && ! grep -qE '^SCANNER_MEM_LIMIT=' .env; then
  printf 'SCANNER_MEM_LIMIT=1g\n' >> .env
  ok "SCANNER_MEM_LIMIT=1g for this host's memory"
fi
# The proxy's workers (an unprivileged user) read config/nginx at run time. A checkout made with umask 027 or 077 (hardened servers, some root shells)
# leaves it unreadable to them and every page then answers 403: the files are made readable again here.
chmod -R a+rX config 2>/dev/null || true
address=$(grep -E '^DOMAIN_NAME=' .env | tail -n 1 | cut -d= -f2-)
address=${address:-localhost}
ok "address: https://$address/"

# the certificate is made once, and again only when the address changed
cert_file=secrets/certs/rengine.pem
needs_cert=1
if [ -s "$cert_file" ] && have openssl; then
  host=${address%%:*}
  if [[ $host =~ ^[0-9.]+$ || $host == *:* ]]; then check=-checkip; else check=-checkhost; fi
  if openssl x509 -in "$cert_file" -noout "$check" "$host" 2>/dev/null | grep -q "does match certificate"; then needs_cert=0; fi
fi
if [ "$needs_cert" -eq 1 ]; then
  step "Creating the HTTPS certificate"
  make certs || die "Could not create the certificate."
else
  ok "HTTPS certificate already matches $address"
fi

step "Building and starting CVEngine (the first build takes several minutes)"
if ! make build; then show_logs; die "The build failed. The messages above say why; the usual causes are no network, or too little disk space."; fi
if ! make up; then show_logs; die "CVEngine did not start. The log lines above say why."; fi

step "Waiting for CVEngine to answer"
healthy=1
for attempt in $(seq 1 90); do
  code=$(curl -ks -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:$https_port/" 2>/dev/null || echo 000)
  # The proxy answering is not enough (it serves its own 403 maintenance page while the web service is still down, and 401 and 403 are also what a
  # client outside the allowlist gets): the web container must be accepting connections too, which it does only after it has migrated the database.
  case $code in 2??|3??|401|403) compose exec -T web python3 -c 'import socket; socket.create_connection(("127.0.0.1", 8000), 3)' >/dev/null 2>&1 && { healthy=0; break; } ;; esac
  [ $((attempt % 6)) -eq 0 ] && echo "  still starting (about $((attempt * 5 / 60)) minutes in)..."
  sleep 5
done
if [ "$healthy" -ne 0 ]; then show_logs; die "CVEngine did not come up within 7 minutes. The log lines above say why; run 'make logs' to follow them."; fi
ok "the web service is answering"

step "Preparing the database and your admin account"
make migrate >/dev/null 2>&1 || make migrate || { show_logs; die "Database migrations failed."; }
admin_output=$(make admin 2>&1) || { echo "$admin_output" >&2; show_logs; die "Could not create the admin account. Try 'make admin' once the services are up."; }
# the make command echo ("docker compose ... exec") is noise: keep only the account banner
admin_banner=$(printf '%s\n' "$admin_output" | sed -n '/^====/,$p')
account='the account below'
if [ -z "$admin_banner" ]; then
  # an account that already exists (a re-run) prints one sentence among the framework's start-up noise (logo, warnings): only that sentence is kept
  account='your existing admin account'
  admin_banner=$(printf '%s\n' "$admin_output" | grep -E '^The account ' | tail -n 1)
  [ -n "$admin_banner" ] || admin_banner="The admin account is set up. Lost its password? Run: make admin-password"
fi

# The app cannot update itself (it has no Docker access on purpose): a small watcher on this machine applies an update an admin approves in
# Settings > Updates, within seconds. Without it the Approve button does nothing, so it is part of the install. Skipped when automatic
# deployment already looks after updates.
step "Installing the update watcher"
watcher=ok
if ! command -v crontab >/dev/null 2>&1; then
  watcher=missing
  warn "crontab is not available: approving an update in Settings > Updates will not start it. Install cron, then run scripts/install-updater.sh"
elif crontab -l 2>/dev/null | grep -q 'cvengine-auto-deploy' || systemctl is-enabled cvengine-auto-deploy >/dev/null 2>&1; then
  ok "automatic deployment is installed: it deploys new master commits while Settings > Updates is set to Automatic (Approve does nothing until then; scripts/install-updater.sh adds the watcher that acts on it)"
elif watcher_log=$(./scripts/install-updater.sh 2>&1); then
  ok "an update approved in Settings > Updates starts within seconds"
else
  watcher=failed
  warn "could not install the update watcher: $(printf '%s' "$watcher_log" | tail -n 1). Run scripts/install-updater.sh to enable one-click updates"
fi

# What was chosen, as it stands in .env now (a re-run keeps an earlier choice), and what is actually running.
plan=internal
case $(env_value CVENGINE_BUILTIN_SCANNER | tr '[:upper:]' '[:lower:]') in 0|false|no|off) plan=external ;; *) [ "$(env_value CVENGINE_SENTINEL_PLAN)" != both ] || plan=both ;; esac
not_running=''
for svc in db redis web celery celery-beat proxy reviewer; do
  [ -n "$(compose ps --status running -q "$svc" 2>/dev/null)" ] || not_running="$not_running $svc"
done

ca=$(pwd)/secrets/certs/ca.crt
open_url="https://$address/"
{ [ "$https_port" = 443 ] || [[ $address == *:* ]]; } || open_url="https://$address:$https_port/"
printf '\n%s\n' "$GREEN$BOLD  CVEngine is running (installed in $(((SECONDS - started) / 60))m$(printf '%02d' $(((SECONDS - started) % 60)))s).$RESET"
printf '\n  Open:      %shttps://%s%s\n' "$BOLD" "${open_url#https://}" "$RESET"
if [ "$account" = 'the account below' ]; then printf '  Sign in:   with the account below; its generated password is shown only once, here\n'
else printf '  Sign in:   with your existing admin account\n'; fi
printf '%s\n' "$admin_banner" | sed 's/^/             /'
printf '\n  Open it: setup continues in the browser, the setup wizard does the rest.\n'
case $plan in
  external) printf '  Scanners:  external Sentinels only, as chosen: the built-in scanner is not started; the wizard shows how to add a Sentinel.\n' ;;
  both)     printf '  Scanners:  the built-in scanner plus external Sentinels you add in the browser.\n' ;;
  *)        printf '  Scanners:  the built-in scanner (it checks in by itself within a few minutes; Sentinels shows its state).\n' ;;
esac
printf '  OpenVAS:   not installed; it runs on a Sentinel (docs/OPENVAS.md).\n'
printf '\n  Your browser will warn that the certificate is not trusted: it is signed by this server'"'"'s own authority. Continue, or trust once: %s\n' "$ca"
case $watcher in ok) ;; *) warn "no update watcher (see above): Settings > Updates > Approve will not start an update" ;; esac
case $address in
  localhost|127.*) warn "CVEngine only answers on this machine. To reach it from elsewhere: sudo ./install.sh --domain <this server's address or name>" ;;
esac
[ -z "$not_running" ] || warn "not running:$not_running. docker compose logs <name> says why."
exit 0
