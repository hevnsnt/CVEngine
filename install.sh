#!/usr/bin/env bash
# One-command installer for a Linux server:  sudo ./install.sh
# It asks nothing. It checks the machine, installs what is missing (Docker, make), generates every secret and the HTTPS
# certificate, starts CVEngine, waits until it answers, creates the admin account and prints the address and password.
# Safe to run again: nothing already set is changed, and a running installation keeps its data.
#
#   sudo ./install.sh                     # detect this machine's address and use it
#   sudo ./install.sh --domain scan.example.com   # use a name people will type instead
#   sudo ./install.sh -n                  # accepted for older scripts; the installer never prompts
set -uo pipefail
cd "$(dirname "$0")"

usage() {
  echo "Usage: sudo $0 [--domain NAME] [-n] [-h]"
  echo "  --domain NAME  hostname or IPv4 address people will use to reach CVEngine (default: detected)"
  echo "  -n             accepted and ignored: the installer never asks questions"
  echo "  -h             show this help"
}

original_args=("$@")
domain=""
while [ $# -gt 0 ]; do
  case $1 in
    --domain) domain=${2:-}; [ -n "$domain" ] || { usage; exit 1; }; shift 2 ;;
    --domain=*) domain=${1#--domain=}; shift ;;
    -n) shift ;;
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
  if [ "$mem_kb" -lt 3500000 ]; then warn "only $((mem_kb / 1024)) MB of memory: 4 GB or more is recommended, scans may be killed for lack of memory"
  else ok "$((mem_kb / 1024)) MB of memory"; fi
fi

free_kb=$(df -Pk . 2>/dev/null | awk 'NR == 2 {print $4}')
if [ -n "${free_kb:-}" ]; then
  if [ "$free_kb" -lt 15000000 ]; then warn "only $((free_kb / 1048576)) GB free here: 20 GB or more is recommended for images, databases and scan results"
  else ok "$((free_kb / 1048576)) GB free disk"; fi
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

if ! docker info >/dev/null 2>&1; then
  have systemctl && systemctl enable --now docker >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do docker info >/dev/null 2>&1 && break; sleep 2; done
  docker info >/dev/null 2>&1 || die "The Docker daemon is not running. Start it (systemctl start docker) and run this again."
fi
ok "docker daemon is running"

# ports: our own proxy holding them from a previous run is fine
running_proxy=$(compose -f docker-compose.yml ps -q proxy 2>/dev/null || true)
if [ -z "$running_proxy" ]; then
  port_busy() {
    if have ss; then ss -ltn 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {found = 1} END {exit !found}'
    elif have netstat; then netstat -ltn 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {found = 1} END {exit !found}'
    else return 1; fi
  }
  for port in 443 8082; do
    if port_busy "$port"; then die "Port $port is already in use by another program. Stop it (for example another web server) and run this again."; fi
  done
  ok "ports 443 and 8082 are free"
else
  ok "CVEngine is already running here: updating it in place"
fi

for host in registry-1.docker.io github.com; do
  if curl -fsS -m 10 -o /dev/null "https://$host" 2>/dev/null || curl -sS -m 10 -o /dev/null -I "https://$host" 2>/dev/null; then ok "can reach $host"
  else warn "cannot reach https://$host: building the images needs it (set up a proxy for Docker if this machine sits behind one)"; fi
done

# ---------------------------------------------------------------------------------------------------------------------------
step "Preparing settings"
./scripts/init-env.sh ${domain:+"$domain"} || die "Could not prepare .env"
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
  code=$(curl -ks -m 5 -o /dev/null -w '%{http_code}' https://127.0.0.1/ 2>/dev/null || echo 000)
  case $code in 2??|3??|401|403) healthy=0; break ;; esac
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
[ -n "$admin_banner" ] || admin_banner=$admin_output

# The app cannot update itself (it has no Docker access on purpose): a small watcher on this machine applies an update an admin approves in
# Settings > Updates, within seconds. Without it the Approve button does nothing, so it is part of the install. Skipped when automatic
# deployment already looks after updates.
step "Installing the update watcher"
if ! command -v crontab >/dev/null 2>&1; then
  warn "crontab is not available: approving an update in Settings > Updates will not start it. Install cron, then run scripts/install-updater.sh"
elif crontab -l 2>/dev/null | grep -q 'cvengine-auto-deploy' || systemctl is-enabled cvengine-auto-deploy >/dev/null 2>&1; then
  ok "automatic deployment is installed and applies updates; the watcher is not needed"
elif ./scripts/install-updater.sh >/dev/null 2>&1; then
  ok "an update approved in Settings > Updates starts within seconds"
else
  warn "could not install the update watcher: run scripts/install-updater.sh to enable one-click updates"
fi

ca=$(pwd)/secrets/certs/ca.crt
printf '\n%s\n' "$GREEN$BOLD#########################################################################$RESET"
printf '%s\n' "$GREEN$BOLD  CVEngine is installed and running.$RESET"
printf '%s\n' "$GREEN$BOLD#########################################################################$RESET"
printf '\n%s\n\n' "$admin_banner"
cat <<EOF
  1. Open  https://${address}/  and sign in with the account above.
     The setup wizard takes it from there: it starts scanning your first target
     right away, and the CVE feed is already loading in the background.
  2. Your browser will warn that the certificate is not trusted: that is expected,
     it is signed by this server's own authority. Continue past the warning, or
     trust the authority once:  ${ca}
  3. Things you may need later:
       make admin-password   a new admin password, if this one is lost
       make logs             follow the logs
       sudo ./install.sh     run again any time; it updates in place
EOF
case $address in
  localhost|127.*) warn "CVEngine only answers on this machine. To reach it from elsewhere: sudo ./install.sh --domain <this server's address or name>" ;;
esac
exit 0
