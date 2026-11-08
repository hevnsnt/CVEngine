#!/usr/bin/env bash
# Requests the site once a second while an update runs and records what a visitor and an API client (a Sentinel) would get, next to the commit the
# checkout is at, so probe-check.sh can prove the maintenance page was up from the instant the files changed until the new site answered and was
# never an old image serving new code. Run in the background; stops when $HOME/probe.stop exists.
#   probe.sh            one sample a second into $HOME/probe.log:  <epoch> <http code> <page marker 0|1> <api code> <retry-after 0|1> <head>
set -uo pipefail
. "$GITHUB_WORKSPACE/.github/rehearsal/lib.sh"
rm -f "$HOME/probe.stop" "$HOME/probe.log"
body=$(mktemp); hdr=$(mktemp)
while [ ! -e "$HOME/probe.stop" ]; do
  now=$(date +%s)
  code=$(curl -sk -m 4 -D "$hdr" -o "$body" -w '%{http_code}' "https://127.0.0.1:$(port)/" 2>/dev/null) || code=000
  marker=0; grep -q 'We are rebuilding cvENGINE\|The update did not finish' "$body" 2>/dev/null && marker=1
  api=$(curl -sk -m 4 -D "$hdr" -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "https://127.0.0.1:$(port)/api/v1/sentinel/tasks/1/result" 2>/dev/null) || api=000
  retry=0; grep -qi '^retry-after:' "$hdr" 2>/dev/null && retry=1
  head=$(git -C "$HOME/cvengine" rev-parse HEAD 2>/dev/null | cut -c1-12)
  echo "$now $code $marker $api $retry ${head:-none}" >> "$HOME/probe.log"
  sleep 1
done
