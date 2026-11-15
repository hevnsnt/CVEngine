# shellcheck shell=bash
# Sourced by scripts/update.sh and install.sh (never run). On a HOSTED server (hosted/README.md: CVENGINE_HOSTED=1 in the environment or .env) the proxy
# answers 403 to any request that lacks the edge secret, so the local readiness checks that ask it for a page must send the secret too. This sets the
# array CVL_EDGE_CURL to the curl arguments that do (`-H @FILE`: curl reads the header line from the file, so the secret is never on a command
# line, where `ps` shows it to every user), and to nothing when hosted mode is off or the file is missing: a normal installation runs exactly the
# command it always did.
#   curl -k -s ... ${CVL_EDGE_CURL[@]+"${CVL_EDGE_CURL[@]}"} "$url"
# The file is /etc/cvl/edge-header (CVL_EDGE_HEADER_FILE moves it); hosted/gen-edge-auth.sh writes it.
# shellcheck disable=SC2034  # CVL_EDGE_CURL is read by the script that sources this file
cvengine_hosted_edge_args() {
  local on=${CVENGINE_HOSTED:-} file=${CVL_EDGE_HEADER_FILE:-/etc/cvl/edge-header}
  CVL_EDGE_CURL=()
  if [ -z "$on" ] && [ -f .env ]; then
    on=$(grep -E '^CVENGINE_HOSTED=' .env 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '\r"'"'"' ') || on=''
  fi
  case $(printf '%s' "$on" | tr '[:upper:]' '[:lower:]') in ''|0|false|no|off) return 0 ;; esac
  if [ -r "$file" ]; then
    CVL_EDGE_CURL=(-H "@$file")
  else
    echo "Hosted mode is on but $file cannot be read: the local check may be refused with 403." >&2
  fi
  return 0
}
