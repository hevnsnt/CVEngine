#!/usr/bin/env bash
# Reads $HOME/probe.log (rehearsal/probe.sh) after an update and fails unless:
#   1. the maintenance page was seen (status 503 and the page text) at least once;
#   2. from the first sample at which the checkout was no longer at the installed commit, until the site answered again, EVERY sample was the
#      maintenance page or a refused connection (the proxy being recreated): never a 200, a redirect, or an error from the application, which
#      would be the old image running the new files (./web is a bind mount);
#   3. that includes the first sample after the files changed: the page was up BEFORE the fast-forward, not after the build;
#   4. an API client (a Sentinel posting a result) got 503 with Retry-After (or a refused connection) in the same window, never a 500 or a hang;
#   5. once the site answers again it keeps answering: no 503 after the first good sample.
# usage: probe-check.sh <installed commit> [grace samples] [1 to require the live status steps]   (a prefix is enough)
# The first update from a version that predates the fix runs the host's OLD apply-update.sh up to the merge: the page then goes up as the first step of
# the new deploy file, a second or two after the merge, so that update is checked with a grace of 4 samples. An update applied by the new scripts
# (the second one of the overlay job) is checked with none: the page is up before the files change.
set -euo pipefail
log="$HOME/probe.log"; installed=${1:?installed commit}; installed=${installed:0:12}; grace=${2:-0}
[ -s "$log" ] || { echo "::error::the probe recorded nothing"; exit 1; }
awk -v installed="$installed" -v grace="$grace" -v needstatus="${3:-0}" '
  function bad(msg) { print "::error::" msg; failed = 1 }
  { t=$1; code=$2; marker=$3; api=$4; retry=$5; head=$6; n++ }
  head != installed && head != "none" && !changed { changed = 1; first_changed = n; print "files changed at sample " n " (" t ")" }
  code == 503 && marker == 1 { seen++ }
  {
    ingrace = (changed && (n - first_changed) < grace)
    if (changed && !served && !ingrace) {
      if (code == 200 || code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
        if (!seen) bad("sample " n ": the site answered " code " with the files already changed and the maintenance page never shown")
        else served = n
      } else if (code != 503 && code != 000 && code != 502 && code != 504) {
        bad("sample " n ": status " code " during the update (an application error on a half-new build, not the maintenance page)")
      } else if (code == 503 && marker != 1) {
        bad("sample " n ": 503 without the maintenance page text")
      }
      if (api != 503 && api != 000 && api != 502 && api != 504 && !(served)) bad("sample " n ": an API client got " api " during the update (want 503)")
      if (api == 503 && retry != 1 && !served) bad("sample " n ": the API 503 carried no Retry-After")
      if (n == first_changed && grace == 0 && !(code == 503 && marker == 1)) bad("the first sample with changed files (" code ", marker " marker ") was not the maintenance page: it went up after the files changed")
    }
    if (served && code == 503) bad("sample " n ": the maintenance page came back after the site had answered")
  }
  $7 != "" && $7 != "-" { steps[$7] = 1 }
  END {
    if (needstatus) {
      if (!("working:build" in steps)) bad("the live status never showed the build step (/maintenance-status.json)")
      if (!("working:starting" in steps) && !("working:verifying" in steps) && !("working:migrating" in steps)) bad("the live status never showed a later step")
    }
    if (!changed) bad("the checkout never moved from " installed " during the probe")
    if (!seen) bad("the maintenance page (503 with its text) was never served")
    if (!served) bad("the site never answered again")
    printf "%d samples, %d maintenance pages, site back at sample %d\n", n, seen, served
    exit failed
  }' "$log"
