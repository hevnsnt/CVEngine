# shellcheck shell=bash
# Sourced by install.sh, scripts/update.sh (command line, cron, unattended) and scripts/update-deploy.sh (the Update button): this server's own
# public addresses for the self exclusion (CVENGINE_SELF_ADDRESSES, web/cveFeed/self_exclusion.py; docs/CONFIGURATION.md).
#
#   . scripts/self-addresses.sh && cvengine_ensure_self_addresses
#       Writes CVENGINE_SELF_ADDRESSES to .env when nobody set it, as a managed line: the same value also goes into CVENGINE_SELF_ADDRESSES_DETECTED,
#       which is how a later run tells its own value from an operator's. A later run detects again and replaces a managed value that is stale. An
#       operator's own CVENGINE_SELF_ADDRESSES (one that differs from CVENGINE_SELF_ADDRESSES_DETECTED) or CVENGINE_OWN_ADDRESSES is never changed.
#       Returns 0 when it wrote, 1 otherwise. It never fails an update: a host that finds no address (offline, private only) keeps what .env says.
#   cvengine_self_addresses_detect
#       Prints the addresses found, comma separated and sorted (nothing when none is found).
#
# How the addresses are found: the global addresses on the host's own interfaces (`ip -o addr show scope global`, temporary and deprecated IPv6
# addresses left out because they rotate), kept only when Python's ipaddress calls them global (no private, shared 100.64/10, ULA or Docker
# bridge address). Only for a family (IPv4, IPv6) with no such address does it ask a fixed list of IP echo services over HTTPS, one at a time,
# each with a short timeout, and it keeps the first answer that is a global address of that family: a host behind NAT learns its public address
# that way. Inside the containers the server cannot see the host's interfaces, which is why the value has to be written here.
#
# CVENGINE_SELF_ADDRESSES_DETECT=0 (in .env or the environment) turns the detection off; nothing is written or asked then.

CV_SELF_ECHO_V4='https://api.ipify.org https://ipv4.icanhazip.com https://checkip.amazonaws.com'
CV_SELF_ECHO_V6='https://api6.ipify.org https://ipv6.icanhazip.com'
CV_SELF_MAX=16   # more addresses than this on one host is not a server's own set; the rest are left out

_cv_self_say() { if declare -F log >/dev/null 2>&1; then log "$*"; else echo "$*"; fi; }

_cv_self_value() {  # KEY: the last value of KEY in .env, quotes and CR removed ('' when absent)
  local value
  [[ -f .env ]] || return 0
  value=$(grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '\r') || value=''
  value=${value#[\"\']}; value=${value%[\"\']}
  printf '%s' "$value"
}

# Reads candidate addresses (one per line, "4 ADDR" or "6 ADDR", or a bare address) on stdin and prints the global ones, one per line, in a stable
# order. With FAMILY (4 or 6) only that family is kept. Anything that is not an address is dropped.
_cv_self_global() {
  python3 -c '
import ipaddress, sys
want = sys.argv[1] if len(sys.argv) > 1 else ""
seen = []
for line in sys.stdin:
    word = line.split()[-1] if line.split() else ""
    try:
        ip = ipaddress.ip_address(word.split("/")[0].split("%")[0])
    except ValueError:
        continue
    if not ip.is_global or ip.is_multicast or (want and str(ip.version) != want):
        continue
    if str(ip) not in seen:
        seen.append(str(ip))
for value in sorted(seen, key=lambda v: (ipaddress.ip_address(v).version, ipaddress.ip_address(v))):
    print(value)
' "${1:-}"
}

_cv_self_interfaces() {  # the global addresses on this host's interfaces, as "4 ADDR" / "6 ADDR" lines
  command -v ip >/dev/null 2>&1 || return 0
  ip -o addr show scope global 2>/dev/null | awk '
    $0 ~ / temporary/ || $0 ~ / deprecated/ { next }
    { for (i = 1; i < NF; i++) if ($i == "inet" || $i == "inet6") { sub(/\/.*/, "", $(i + 1)); print ($i == "inet" ? "4 " : "6 ") $(i + 1) } }'
}

_cv_self_echo() {  # FAMILY: the first global address of that family an echo service answers, or nothing
  local family=$1 url answer list
  command -v curl >/dev/null 2>&1 || return 0
  if [[ $family == 4 ]]; then list=$CV_SELF_ECHO_V4; else list=$CV_SELF_ECHO_V6; fi
  for url in $list; do
    answer=$(curl "-$family" -fsS --connect-timeout 3 --max-time 5 --max-filesize 256 "$url" 2>/dev/null | head -c 64 | tr -d '\r') || answer=''
    answer=$(printf '%s\n' "$answer" | head -n 1 | _cv_self_global "$family" 2>/dev/null) || answer=''
    if [[ -n $answer ]]; then printf '%s\n' "$answer"; return 0; fi
  done
}

cvengine_self_addresses_detect() {
  local found v4 v6 family echoed
  command -v python3 >/dev/null 2>&1 || return 0
  found=$(_cv_self_interfaces | _cv_self_global 2>/dev/null) || found=''
  v4=$(printf '%s\n' "$found" | grep -c '\.' || true)
  v6=$(printf '%s\n' "$found" | grep -c ':' || true)
  for family in 4 6; do
    if [[ $family == 4 && $v4 != 0 ]] || [[ $family == 6 && $v6 != 0 ]]; then continue; fi
    echoed=$(_cv_self_echo "$family")
    [[ -z $echoed ]] || found=$(printf '%s\n%s\n' "$found" "$echoed")
  done
  printf '%s\n' "$found" | _cv_self_global 2>/dev/null | head -n "$CV_SELF_MAX" | paste -sd, -
}

_cv_self_sorted() {  # a comma separated list as one stable string (order and spaces do not count as a change)
  printf '%s' "$1" | tr ', ' '\n\n' | grep -v '^$' | sort -u | paste -sd, -
}

_cv_self_put() {  # VALUE: the two managed lines and their comment in .env, in place (keeps the file's owner and mode), exactly one copy of each
  local value=$1 tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-self.XXXXXX") || return 1
  grep -v -E '^(CVENGINE_SELF_ADDRESSES|CVENGINE_SELF_ADDRESSES_DETECTED)=|^# managed by the updater: this host.s own public addresses' .env > "$tmp" || true
  [[ -z $(tail -c 1 "$tmp") ]] || echo >> "$tmp"
  {
    echo "# managed by the updater: this host's own public addresses (scripts/self-addresses.sh). To set your own, change CVENGINE_SELF_ADDRESSES; it is then kept."
    echo "CVENGINE_SELF_ADDRESSES=$value"
    echo "CVENGINE_SELF_ADDRESSES_DETECTED=$value"
  } >> "$tmp"
  cat "$tmp" > .env
  rm -f -- "$tmp"
  [[ $(grep -c '^CVENGINE_SELF_ADDRESSES=' .env) == 1 && $(grep -c '^CVENGINE_SELF_ADDRESSES_DETECTED=' .env) == 1 ]]
}

cvengine_ensure_self_addresses() {
  local own managed detected switch
  [[ -f .env ]] || return 1
  switch=${CVENGINE_SELF_ADDRESSES_DETECT:-$(_cv_self_value CVENGINE_SELF_ADDRESSES_DETECT)}
  case $switch in 0|off|false|no) return 1 ;; esac
  own=$(_cv_self_value CVENGINE_SELF_ADDRESSES)
  managed=$(_cv_self_value CVENGINE_SELF_ADDRESSES_DETECTED)
  if [[ -n $own && $(_cv_self_sorted "$own") != $(_cv_self_sorted "$managed") ]]; then return 1; fi  # an operator's own value
  if [[ -z $own && -n $(_cv_self_value CVENGINE_OWN_ADDRESSES) ]]; then return 1; fi                # set under the older name
  detected=$(cvengine_self_addresses_detect 2>/dev/null) || detected=''
  if [[ -z $detected ]]; then
    if [[ -z $own ]]; then
      _cv_self_say "Could not find this server's own public address (no public address on its interfaces and no echo service answered), so CVENGINE_SELF_ADDRESSES is not set. Set it in .env when the server's name is behind a CDN, NAT or a load balancer (docs/CONFIGURATION.md)."
    fi
    return 1
  fi
  [[ $(_cv_self_sorted "$detected") != $(_cv_self_sorted "$own") ]] || return 1
  _cv_self_put "$detected" || return 1
  if [[ -n $own ]]; then
    _cv_self_say "This server's public addresses changed: CVENGINE_SELF_ADDRESSES=$detected was written to .env (it was $own); the self exclusion never scans them."
  else
    _cv_self_say "CVENGINE_SELF_ADDRESSES=$detected was written to .env: this server's own public addresses, which the self exclusion never scans."
  fi
  return 0
}
