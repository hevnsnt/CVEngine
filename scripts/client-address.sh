# Sourced by the update scripts, `make up`, scripts/init-env.sh and scripts/client-address-check.sh: the real client address (review r3 S2, S3;
# docs/DEPLOYMENT.md, "Client addresses behind a host proxy").
#
#   . scripts/client-address.sh && cvengine_ensure_upstream_secret [ENV_FILE]
#       Gives the install its upstream secret (CVENGINE_UPSTREAM_SECRET) when it has none: 48 letters and digits, written to .env and, when the
#       install runs with another Compose env file (ENV_FILE, an overlay's .env.vps), to that file too (Compose reads ${VARIABLES} from it).
#       Returns 0 when it wrote one, 1 when there already is one or there is no .env. A value already set is never changed.
#   cvengine_proxy_network_check docker compose [ARGS...]
#       Before anything is changed: fails (with one line saying what to set) when the subnet the layout gives proxy_network overlaps another Docker
#       network, which would make `docker compose up` stop with "Pool overlaps" half way through an update. 0 when it fits, exists already or
#       cannot be read.
#   cvengine_client_address_report docker compose [ARGS...]
#       The check: prints lines that start with "client address:" and always returns 0 (it never fails an update). See client-address-check.sh.
#       Its last line is the server's verdict ("client address: verdict: ..."), which also opens or clears the App Admin notice.
#
# A host nginx in front of the bundled proxy sends the secret in X-CVEngine-Upstream (config/nginx/host-proxy-client-address.conf), and only then
# does the proxy pass its X-Forwarded-For on to the application. Without the secret, or without that snippet, nothing changes: the proxy believes
# no header on 443, as before.
# The shape of a secret: 32 to 256 letters, digits, '-' or '_'. The length is counted apart from the character class: a bound above 255 in a
# POSIX regex is refused by musl (Alpine: the proxy image's grep, a host on Alpine), which made every check of a good secret read as broken.
CV_UPSTREAM_SECRET_RE='^[A-Za-z0-9_-]+$'
cvengine_ca_secret_ok() { [ "${#1}" -ge 32 ] && [ "${#1}" -le 256 ] && [[ $1 =~ $CV_UPSTREAM_SECRET_RE ]]; }

cvengine_ca_value() { [ -f "$2" ] && grep -E "^$1=" "$2" | tail -n 1 | cut -d= -f2- | tr -d '\r' | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' || true; }

cvengine_ca_set() {  # KEY VALUE FILE: replace or append, without the value on a command line (`ps` shows those)
  local key=$1 value=$2 file=$3 tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX") || return 1
  chmod 600 "$tmp"
  if grep -q "^${key}=" "$file"; then
    CVENGINE_AWK_VALUE="$value" awk -v key="$key" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix ENVIRON["CVENGINE_AWK_VALUE"]; next } { print }' "$file" > "$tmp"
  else
    { cat "$file"; [ -z "$(tail -c 1 "$file")" ] || echo; echo "${key}=${value}"; } > "$tmp"
  fi
  cat "$tmp" > "$file"  # in place: keeps the file's owner and mode
  rm -f -- "$tmp"
}

cvengine_ensure_upstream_secret() {
  local env_file=${1:-} effective secret
  [ -f .env ] || return 1
  if [ -z "$env_file" ] || [ "$env_file" = .env ] || [ ! -f "$env_file" ]; then env_file=''; fi
  effective=${env_file:-.env}
  [ -z "$(cvengine_ca_value CVENGINE_UPSTREAM_SECRET "$effective")" ] || return 1
  secret=$(cvengine_ca_value CVENGINE_UPSTREAM_SECRET .env)
  if [ -z "$secret" ]; then
    secret=$(head -c 512 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 48)
    [ ${#secret} -eq 48 ] || return 1
    cvengine_ca_set CVENGINE_UPSTREAM_SECRET "$secret" .env || return 1
  fi
  if [ -n "$env_file" ]; then cvengine_ca_set CVENGINE_UPSTREAM_SECRET "$secret" "$env_file" || return 1; fi
  return 0
}

# The env file Compose reads for ${VARIABLES}: the --env-file of the command line, else .env.
cvengine_ca_env_file() {
  local prev='' arg
  for arg in "$@"; do
    if [ "$prev" = --env-file ]; then printf '%s\n' "$arg"; return 0; fi
    prev=$arg
  done
  printf '.env\n'
}

cvengine_proxy_network_check() {
  local config networks
  config=$("$@" config --format json 2>/dev/null) || return 0
  networks=$(docker network ls -q 2>/dev/null | xargs -r docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null) || return 0
  CV_NETWORKS="$networks" python3 -c '
import ipaddress, json, os, sys
try:
    net = json.load(sys.stdin)["networks"]["proxy_network"]
    name, wanted = net["name"], ipaddress.ip_network(net["ipam"]["config"][0]["subnet"], strict=False)
except (KeyError, IndexError, TypeError, ValueError):
    sys.exit(0)
for line in os.environ.get("CV_NETWORKS", "").splitlines():
    parts = line.split()
    if not parts or parts[0] == name:
        continue
    for subnet in parts[1:]:
        try:
            other = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            continue
        if other.version == wanted.version and other.overlaps(wanted):
            print(f"proxy_network needs {wanted}, which overlaps the Docker network {parts[0]} ({other}): set CVENGINE_PROXY_SUBNET, CVENGINE_PROXY_RANGE and CVENGINE_PROXY_ADDRESS in .env to a free range (docs/CONFIGURATION.md) and update again")
            sys.exit(1)
' <<<"$config"
}

# Prints the host nginx snippet with this install's secret in it (stdout only; the caller decides where it goes).
cvengine_client_address_snippet() {
  local env_file secret
  env_file=$(cvengine_ca_env_file "$@")
  secret=$(cvengine_ca_value CVENGINE_UPSTREAM_SECRET "$env_file")
  cvengine_ca_secret_ok "$secret" || { echo "CVENGINE_UPSTREAM_SECRET in $env_file is missing or not 32 to 256 letters, digits, '-' or '_'; run make up or the update first." >&2; return 1; }
  CVENGINE_AWK_VALUE="$secret" awk '{ gsub(/@CVENGINE_UPSTREAM_SECRET@/, ENVIRON["CVENGINE_AWK_VALUE"]); print }' config/nginx/host-proxy-client-address.conf
}

# One GET of URL with no certificate check (the probe only needs to arrive; the answer carries nothing). Prints the body, at most 4 KiB.
cvengine_ca_fetch() {
  python3 - "$1" <<'PY' 2>/dev/null
import ssl, sys, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    with urllib.request.urlopen(urllib.request.Request(sys.argv[1], headers={'User-Agent': 'cvengine-client-address-check'}), timeout=15, context=ctx) as r:
        sys.stdout.write(r.read(4096).decode('utf-8', 'replace'))
except Exception as exc:  # an HTTP error or no answer: the caller reads the recorded address, not this
    sys.stderr.write(str(exc))
PY
}

# 0 when ADDRESS is private, loopback, link-local or the Docker range (it cannot be a visitor seen through a CDN or a host proxy).
cvengine_ca_internal() {
  python3 -c 'import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1]); ip = getattr(ip, "ipv4_mapped", None) or ip
except ValueError:
    sys.exit(0)
sys.exit(0 if (ip.is_private or ip.is_loopback or ip.is_link_local) else 1)' "$1"
}

# 0 when every entry of the comma separated list is one address (/32 or /128), else 1 (a range lets other containers choose their address).
cvengine_ca_single_addresses() {
  python3 -c 'import ipaddress, sys
nets = [p.strip() for p in sys.argv[1].split(",") if p.strip()]
try:
    sys.exit(0 if all(ipaddress.ip_network(n, strict=False).num_addresses == 1 for n in nets) else 1)
except ValueError:
    sys.exit(1)' "$1"
}

# Every command substitution below ends in `|| true`: it runs in a process substitution of the update script, where a failed pipeline (the proxy
# or web container not answering an exec) set off the updater's error trap and logged "the update script stopped" although nothing stopped.
cvengine_client_address_report() {
  local compose=("$@") env_file secret domain url token recorded seen trusted rendered published verdict
  say() { printf 'client address: %s\n' "$*"; }
  env_file=$(cvengine_ca_env_file "${compose[@]}")
  secret=$(cvengine_ca_value CVENGINE_UPSTREAM_SECRET "$env_file")
  if [ -z "$secret" ]; then
    say "no upstream secret (CVENGINE_UPSTREAM_SECRET in $env_file): the proxy believes no X-Forwarded-For on 443, as before. make up or the next update generates one."
  elif ! cvengine_ca_secret_ok "$secret"; then
    say "CVENGINE_UPSTREAM_SECRET in $env_file is not 32 to 256 letters, digits, '-' or '_': the proxy believes no X-Forwarded-For on 443. Remove the line; the next update generates a new one."
  fi
  rendered=$("${compose[@]}" exec -T proxy sh -c 'grep -cE "^\"k[A-Za-z0-9_-]{32}[A-Za-z0-9_-]*\"" /etc/nginx/conf.d/cvengine-upstream-secret.inc 2>/dev/null || true' 2>/dev/null | tr -dc '0-9' || true)
  if [ -n "$secret" ] && [ "${rendered:-0}" = 0 ]; then
    say "the running proxy has no upstream secret loaded (it was started before the secret existed, or an overlay drops its environment or its templates mount): docker compose up -d --force-recreate proxy"
  fi
  trusted=$("${compose[@]}" exec -T web python3 manage.py client_address_probe trusted 2>/dev/null | sed -n 's/^probe: //p' | tail -n 1 | tr -d '\r' || true)
  if [ -n "$trusted" ] && ! cvengine_ca_single_addresses "$trusted"; then
    say "warning: CVENGINE_TRUSTED_PROXIES is $trusted. A range lets any container in it (the built-in scanner, the AI reviewer) choose the client address the server records and bans. Remove CVENGINE_TRUSTED_PROXIES from .env so the default (the proxy's own address) applies, unless your own proxy needs it (docs/CONFIGURATION.md)."
  fi
  domain=$(cvengine_ca_value DOMAIN_NAME "$env_file")
  [ -n "$domain" ] || domain=$(cvengine_ca_value DOMAIN_NAME .env)
  url=${CVENGINE_CLIENT_ADDRESS_URL:-https://$domain}
  url=${url%/}
  if [ -z "$domain" ] && [ -z "${CVENGINE_CLIENT_ADDRESS_URL:-}" ]; then
    say "no DOMAIN_NAME: the probe was not sent"
    return 0
  fi
  token=$("${compose[@]}" exec -T web python3 manage.py client_address_probe start 2>/dev/null | sed -n 's/^probe: //p' | tail -n 1 | tr -dc '0-9a-f' || true)
  if [ ${#token} -ne 32 ]; then
    say "the web service could not issue a probe token; the check was skipped"
    return 0
  fi
  cvengine_ca_fetch "$url/client-address-probe/$token/" >/dev/null
  recorded=$("${compose[@]}" exec -T web python3 manage.py client_address_probe read "$token" 2>/dev/null | sed -n 's/^probe: //p' | tail -n 1 | tr -d '\r' || true)
  seen=$(cvengine_ca_fetch "$url/cdn-cgi/trace" | sed -n 's/^ip=//p' | head -n 1 | tr -d '\r' || true)
  if [ -z "$recorded" ]; then
    say "the probe sent to $url did not reach the server (DNS, a firewall, the IP allowlist or the maintenance page in front); nothing to compare"
  elif [ -n "$seen" ] && [ "$seen" = "$recorded" ]; then
    say "ok: a request through $url arrived as $recorded, the address Cloudflare saw. The real client address reaches the server."
  elif [ -n "$seen" ]; then
    say "PROBLEM: a request through $url arrived as $recorded, but Cloudflare saw $seen. Every visitor shares one address: the sign-in lockout, bans and the IP allowlist act on all of them at once. Install the host nginx snippet (scripts/client-address-check.sh --snippet; docs/DEPLOYMENT.md, \"Client addresses behind a host proxy\")."
  elif cvengine_ca_internal "$recorded"; then
    say "a request through $url arrived as $recorded, an internal address. If nothing is in front of the bundled proxy (the probe went straight to this host) that is expected. If a host nginx or a CDN is in front, it is not passing the client address: install the snippet (scripts/client-address-check.sh --snippet)."
  else
    say "a request through $url arrived as $recorded, a public address (no Cloudflare trace to compare with): it should be this host's own public address."
  fi
  # What it means, decided by the server (cveFeed/client_address.py) from the label the proxy put on the probe and where the proxy's port 443 is
  # published: nothing in front of the proxy (nothing to do), ok, or a host proxy whose address is not believed yet. The server opens the App Admin
  # notice with the lines to install (Settings, Updates and the status strip) or clears it; nothing here believes or changes a header.
  if [ -n "$recorded" ]; then
    published=$("${compose[@]}" port proxy 443 2>/dev/null | tr -d '\r' | head -n 4 | tr '\n' ' ')
    verdict=$("${compose[@]}" exec -T web python3 manage.py client_address_probe verdict "$token" --seen "$seen" --published "$published" 2>/dev/null \
      | sed -n 's/^probe: //p' | tail -n 1 | tr -d '\r')
    [ -z "$verdict" ] || say "$verdict"
  fi
  return 0
}
