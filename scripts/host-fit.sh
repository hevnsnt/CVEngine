# shellcheck shell=bash
# Sourced by install.sh, scripts/update.sh (command line, cron, unattended), scripts/update-deploy.sh (the Update button) and scripts/apply-scanner-plan.sh
# (Settings > Sentinels): what fits this host. One place for the rules, so a fresh install and an update agree.
#
#   The host-size rule (cvengine_fit_scanner_limit): the built-in scanner's container ceiling, SCANNER_MEM_LIMIT
#       host memory                 SCANNER_MEM_LIMIT
#       under 7 GB (7000000 kB)     1g
#       7 GB or more                not written (docker-compose.yml's default, 3g)
#   An owner's own SCANNER_MEM_LIMIT, or any CVENGINE_BUILTIN_SCANNER, is never touched by the rule.
#
#   cvengine_fit_run PLAN COMPOSE...   before anything is stopped. PLAN is an answer somebody gave (internal, both, external: the Update button's dialog, or
#                                      update.sh --sentinels), else empty. With an answer it is applied; without one the automatic default applies: the host-size
#                                      rule, and a scanner is never removed (an unattended update asks nothing and blocks on nothing).
#   cvengine_fit_budget COMPOSE...     after the containers started: do the memory limits add up to more than 90 percent of the host?
#
# CVENGINE_HOST_MEM_MB overrides the host's memory (the tests and rehearsals fake a small host with it; nothing else sets it).
# It reads and writes .env and the env file Compose reads, and prints plain lines through log() when the caller has one.

cv_fit_small_kb=7000000
cv_fit_short=''   # a few words for the Update page's status line, set by cvengine_fit_run (empty when nothing was decided)

_cv_fit_say() { if declare -F log >/dev/null 2>&1; then log "$*"; else echo "$*"; fi; }

cvengine_fit_mem_kb() {  # host memory in kB, 0 when it cannot be read
  local mb=${CVENGINE_HOST_MEM_MB:-}
  if [[ $mb =~ ^[0-9]+$ ]] && (( mb > 0 )); then echo $(( mb * 1024 )); return 0; fi
  awk '/^MemTotal:/ {print $2; found=1} END {if (!found) print 0}' /proc/meminfo 2>/dev/null || echo 0
}

cvengine_fit_scanner_limit() {  # KB: the SCANNER_MEM_LIMIT the rule gives a host of that size, nothing for a host that keeps the default
  local kb=${1:-0}
  if (( kb > 0 && kb < cv_fit_small_kb )); then echo 1g; fi
}

cvengine_fit_rule_table() {
  echo 'host memory               SCANNER_MEM_LIMIT'
  echo 'under 7 GB                1g'
  echo '7 GB or more              default (3g), nothing written'
}

cvengine_fit_gb() {  # KB: "4.5 GB"
  awk -v kb="${1:-0}" 'BEGIN { v = kb / 1048576; s = sprintf("%.1f", v); sub(/\.0$/, "", s); print s " GB" }'
}

_cv_fit_env_file() {  # the env file Compose reads: the --env-file on the command line, else .env
  local prev='' arg
  for arg in "$@"; do
    if [[ $prev == --env-file ]]; then printf '%s\n' "$arg"; return 0; fi
    prev=$arg
  done
  printf '.env\n'
}

cvengine_fit_value() {  # KEY ENVFILE: from the environment, else the env file, else .env ('' when nobody set it)
  local key=$1 file=$2 value=${!1:-} f
  if [[ -z $value ]]; then
    for f in "$file" .env; do
      [[ -f $f ]] || continue
      value=$(grep -E "^${key}=" "$f" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
      value=${value#[\"\']}; value=${value%[\"\']}
      [[ -z $value ]] || break
    done
  fi
  printf '%s' "$value"
}

_cv_fit_put() {  # FILE KEY VALUE [NOTE]: set KEY in FILE in place (replacing a line of it), keeping the file's owner and mode
  local file=$1 key=$2 value=$3 note=${4:-} tmp
  [[ -f $file ]] || return 0
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-fit.XXXXXX") || return 1
  grep -v "^${key}=" "$file" > "$tmp" || true
  [[ -z $(tail -c 1 "$tmp") ]] || echo >> "$tmp"
  [[ -z $note ]] || echo "# $note" >> "$tmp"
  echo "${key}=${value}" >> "$tmp"
  cat "$tmp" > "$file"
  rm -f -- "$tmp"
}

cvengine_fit_write() {  # KEY VALUE ENVFILE [NOTE]: into .env and, when different, the env file Compose reads
  _cv_fit_put .env "$1" "$2" "${4:-}"
  [[ $3 == .env ]] || _cv_fit_put "$3" "$1" "$2" "${4:-}"
}

# Host-size rule. Prints one line when it wrote, one when an owner's own value is left (only on a host the rule would have changed).
cvengine_fit_memory() {  # ENVFILE
  local file=$1 kb limit own
  kb=$(cvengine_fit_mem_kb)
  (( kb > 0 )) || return 0
  limit=$(cvengine_fit_scanner_limit "$kb")
  [[ -n $limit ]] || return 0
  own=$(cvengine_fit_value SCANNER_MEM_LIMIT "$file")
  if [[ -n $own ]]; then
    _cv_fit_say "SCANNER_MEM_LIMIT=$own is already set, so it is left as it is (a host with $(cvengine_fit_gb "$kb") of memory would get $limit)."
    return 0
  fi
  [[ -z $(cvengine_fit_value CVENGINE_BUILTIN_SCANNER "$file") ]] || return 0  # somebody already decided about the scanner itself
  cvengine_fit_write SCANNER_MEM_LIMIT "$limit" "$file" "written by the updater: this host has $(cvengine_fit_gb "$kb") of memory (under 7 GB: the built-in scanner gets 1g)"
  cv_fit_short="the built-in scanner is limited to $limit for this host's memory"
  _cv_fit_say "This host has $(cvengine_fit_gb "$kb") of memory, so SCANNER_MEM_LIMIT=$limit was written to .env: the built-in scanner may use at most 1 GB (hosts under 7 GB get 1g; docs/DEPLOYMENT.md#memory)."
}

cvengine_fit_plan_words() {
  case $1 in
    external) echo "Sentinels of your own only (the built-in scanner is removed)" ;;
    both) echo "your Sentinels and the built-in scanner" ;;
    *) echo "the built-in scanner only" ;;
  esac
}

# An answer: the three choices install.sh asks. scripts/init-env.sh writes the keys (CVENGINE_BUILTIN_SCANNER=0 for external, =1 back on for the others);
# CVENGINE_SENTINEL_PLAN records the answer itself, so nothing asks again.
cvengine_fit_apply_plan() {  # PLAN ENVFILE
  local plan=$1 file=$2 switch
  case $plan in internal|both|external) ;; *) _cv_fit_say "ignored a scanner choice that is not internal, both or external"; return 1 ;; esac
  if [[ ! -f scripts/init-env.sh ]] || ! CVENGINE_INSTALL_SENTINELS=$plan bash scripts/init-env.sh >/dev/null 2>&1; then
    _cv_fit_say "could not write the scanner choice to .env"; return 1
  fi
  cvengine_fit_write CVENGINE_SENTINEL_PLAN "$plan" "$file"
  switch=$(grep -E '^CVENGINE_BUILTIN_SCANNER=' .env 2>/dev/null | tail -n1 | cut -d= -f2- || true)
  if [[ -n $switch && $file != .env ]]; then _cv_fit_put "$file" CVENGINE_BUILTIN_SCANNER "$switch"; fi
  return 0
}

cvengine_fit_externals() {  # COMPOSE...: how many Sentinels of the owner's own are live on the RUNNING server, or nothing when it cannot say
  local out
  [[ -n $("$@" ps -q --status running web 2>/dev/null) ]] || return 0
  out=$("$@" exec -T web python3 manage.py external_sentinels 2>/dev/null) || return 0
  out=$(grep -E '^EXTERNAL_SENTINELS_LIVE [0-9]+$' <<<"$out" | tail -n1 | cut -d' ' -f2) || out=''
  printf '%s' "$out"
}

cvengine_fit_run() {  # PLAN COMPOSE...
  local plan=$1 file live limit; shift
  file=$(_cv_fit_env_file "$@")
  cv_fit_short=''
  if [[ -n $plan ]]; then
    if cvengine_fit_apply_plan "$plan" "$file"; then
      _cv_fit_say "Which scanners run: $(cvengine_fit_plan_words "$plan")."
      cv_fit_short="scanners: $(cvengine_fit_plan_words "$plan")"
      if [[ $plan == external ]]; then
        live=$(cvengine_fit_externals "$@")
        [[ $live != 0 ]] || _cv_fit_say "Note: no Sentinel of your own is live right now. Until one is, scans that need a scanner wait. Choose the built-in scanner again in Settings > Sentinels to undo this."
      fi
      [[ ! -f scripts/update-state.py ]] || python3 scripts/update-state.py notice clear >/dev/null 2>&1 || true
    fi
    cvengine_fit_memory "$file"
    return 0
  fi
  cvengine_fit_memory "$file"
  # no answer: the automatic default. Whether anybody chose before is in .env; the running server says how many Sentinels of their own are live.
  [[ -z $(cvengine_fit_value CVENGINE_BUILTIN_SCANNER "$file")$(cvengine_fit_value CVENGINE_SENTINEL_PLAN "$file") ]] || return 0
  live=$(cvengine_fit_externals "$@")
  if [[ -z $live ]]; then
    _cv_fit_say "Could not ask the running server how many Sentinels of your own are live (it may be an older version), so which scanners run is not changed."
    return 0
  fi
  if (( live >= 2 )); then
    limit=$(cvengine_fit_value SCANNER_MEM_LIMIT "$file"); limit=${limit:-3g}
    _cv_fit_say "You have $live Sentinels of your own that are live. The built-in scanner is only their last resort, but it holds up to ${limit} of memory. It was kept, because a scanner is never removed without your answer. To free the memory, choose Sentinels only in Settings > Sentinels; from the command line: scripts/update.sh --sentinels external."
    cv_fit_short="the built-in scanner was kept; you have $live Sentinels of your own (Settings > Sentinels)"
    [[ ! -f scripts/update-state.py ]] || python3 scripts/update-state.py notice scanner_kept "$(printf '%s' "$limit" | tr '[:upper:]' '[:lower:]')" "$live" >/dev/null 2>&1 || true
  fi
}

cvengine_fit_budget() {  # COMPOSE...
  local kb ids id line total=0 largest=0 largest_name='' bytes name parts='' var total_kb
  kb=$(cvengine_fit_mem_kb)
  (( kb > 0 )) || return 0
  ids=$("$@" ps -q 2>/dev/null) || return 0
  for id in $ids; do
    line=$(docker inspect -f '{{.HostConfig.Memory}} {{index .Config.Labels "com.docker.compose.service"}}' "$id" 2>/dev/null) || continue
    bytes=${line%% *}; name=${line#* }
    [[ $bytes =~ ^[0-9]+$ ]] && (( bytes > 0 )) || continue
    total=$(( total + bytes ))
    parts+="${parts:+, }$name $(cvengine_fit_gb $(( bytes / 1024 )))"
    if (( bytes > largest )); then largest=$bytes; largest_name=$name; fi
  done
  (( total > 0 )) || return 0
  total_kb=$(( total / 1024 ))
  if (( total_kb * 100 > kb * 90 )); then
    case $largest_name in
      celery) var=CELERY_MEM_LIMIT ;; celery-beat) var=BEAT_MEM_LIMIT ;; web) var=WEB_MEM_LIMIT ;;
      scanner) var=SCANNER_MEM_LIMIT ;; reviewer) var=REVIEWER_MEM_LIMIT ;; db) var=DB_MEM_LIMIT ;; *) var='' ;;
    esac
    _cv_fit_say "Memory warning: the containers may use up to $(cvengine_fit_gb "$total_kb") together ($parts), more than 90 percent of this host's $(cvengine_fit_gb "$kb"). The largest is $largest_name at $(cvengine_fit_gb $(( largest / 1024 )))${var:+; lower it with $var in .env, then run docker compose up -d $largest_name}. Containers rarely all peak at once, but one that does can be killed for lack of memory."
  else
    _cv_fit_say "Memory budget: the container limits add up to $(cvengine_fit_gb "$total_kb") on a host with $(cvengine_fit_gb "$kb") (under 90 percent)."
  fi
}
