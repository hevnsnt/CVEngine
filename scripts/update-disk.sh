# shellcheck shell=bash
# Sourced by scripts/update-deploy.sh (before the update stops anything), scripts/apply-update.sh (before it pauses scanning) and
# scripts/update-watch.sh (so Settings > Updates can say it before an administrator approves): is there room for this update?
#
#   Where: the file system under Docker's data directory (docker info: Docker Root Dir; /var/lib/docker when it cannot be read).
#   How much is needed (cvengine_disk_need_mb), an ESTIMATE made of what the first 1.4 update measured (docs/UPDATES.md#disk-space):
#       8900 MB  the new server image (1.6 GB, celery and beat share it), the AI reviewer (0.25 GB), a cold build cache (4.7 GB; the nuclei compile layer
#                alone is 3.2 GB) and about 2 GB to work in (the database dump, logs, the old image that is only removed after a verified update)
#     + 5100 MB  the built-in scanner's image, when the scanner is on and that image is not on this host yet
#     = 14000 MB for a 1.3 to 1.4 update (a host that has no scanner image), 8900 MB for one that already has it or has the scanner off.
#   It is a conservative estimate, not a prediction: the sizes of an image that is going to be pulled are not known before it is pulled, so they are the
#   measured ones. CVENGINE_UPDATE_MIN_FREE_MB (environment or .env) replaces it outright (the rollback sets 0: the way back needs no new space).
#   CVENGINE_FAKE_DISK_FREE_MB (environment or .env) replaces the measured free space: for the tests and rehearsals, nothing else sets it.
#
#   cvengine_disk_check [PLAN]    0 when there is room. Otherwise it removes what is safe to remove (dangling images, the build cache: never a tagged
#                                 image, never a volume), measures again, and returns 1 with cv_disk_sentence set when it is still short.
#   cvengine_disk_report          writes web/.update-disk.json (through scripts/update-state.py) for the Update screen; prints nothing.

cv_disk_floor_mb=8900
cv_disk_scanner_mb=5100
cv_disk_sentence=''

_cv_disk_value() {  # KEY: from the environment, else .env ('' when nobody set it)
  local key=$1 value=${!1:-}
  if [[ -z $value && -f .env ]]; then
    value=$(grep -E "^${key}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
    value=${value#[\"\']}; value=${value%[\"\']}
  fi
  printf '%s' "$value"
}

cvengine_disk_root() {
  local root
  root=$(timeout 30 docker info --format '{{.DockerRootDir}}' 2>/dev/null) || root=''
  [[ -n $root ]] || root=/var/lib/docker
  printf '%s' "$root"
}

cvengine_disk_free_mb() {  # prints MB free where Docker keeps its data, nothing when it cannot be measured
  local fake root path free
  fake=$(_cv_disk_value CVENGINE_FAKE_DISK_FREE_MB)
  if [[ $fake =~ ^[0-9]+$ ]]; then printf '%s' "$fake"; return 0; fi
  root=$(cvengine_disk_root)
  # a user that cannot enter Docker's directory (it is root's) measures the nearest parent it can: the same file system in every layout but a separate /var/lib/docker mount
  path=$root
  while [[ -n $path ]]; do
    free=$(df -Pm "$path" 2>/dev/null | awk 'NR == 2 {print $4}') || free=''
    if [[ $free =~ ^[0-9]+$ ]]; then printf '%s' "$free"; return 0; fi
    [[ $path == / ]] && break
    path=$(dirname "$path")
  done
  return 0
}

cvengine_disk_scanner_missing() {  # PLAN: 0 when the built-in scanner will be pulled by this update (it is on, and its image is not here yet)
  local plan=${1:-} switch ref
  [[ $plan != external ]] || return 1
  switch=$(_cv_disk_value CVENGINE_BUILTIN_SCANNER | tr '[:upper:]' '[:lower:]')
  case $switch in 0|false|no|off) return 1 ;; esac
  # the checkout the update is moving to (or has moved to) says which image; one that has no scanner (a 1.3 checkout before the merge) is counted
  # as missing: the update brings it
  if [[ -f scanner.lock.json && -f scripts/scanner_lock.py ]]; then
    ref=$(_cv_disk_value CVENGINE_SCANNER_IMAGE)
    [[ -n $ref ]] || ref=$(python3 scripts/scanner_lock.py ref 2>/dev/null) || ref=''
    if [[ -n $ref ]] && docker image inspect "$ref" >/dev/null 2>&1; then return 1; fi
  fi
  return 0
}

cvengine_disk_need_mb() {  # [PLAN]
  local own plan=${1:-}
  own=$(_cv_disk_value CVENGINE_UPDATE_MIN_FREE_MB)
  if [[ $own =~ ^[0-9]+$ ]]; then printf '%s' "$((10#$own))"; return 0; fi
  if cvengine_disk_scanner_missing "$plan"; then printf '%s' $((cv_disk_floor_mb + cv_disk_scanner_mb)); else printf '%s' "$cv_disk_floor_mb"; fi
}

cvengine_disk_gb_up() { echo $(( ($1 + 999) / 1000 )); }   # MB -> whole GB, rounded up (what is needed)
cvengine_disk_gb_down() { echo $(( $1 / 1000 )); }         # MB -> whole GB, rounded down (what is there)

cvengine_disk_sentence_for() {  # NEED_MB FREE_MB: the plain sentence the Update screen and the updater both say
  printf 'This update needs about %s GB of free disk; this server has %s GB free. Free some space or add disk, then try again.' \
    "$(cvengine_disk_gb_up "$1")" "$(cvengine_disk_gb_down "$2")"
}

_cv_disk_say() { if declare -F log >/dev/null 2>&1; then log "$*"; else echo "$*"; fi; }

# What the updater may do on its own, without risk: dangling (untagged) images and the build cache. Never a tagged image, never a volume.
cvengine_disk_selfhelp() {
  _cv_disk_say "not enough disk space: removing untagged images and the build cache (docker image prune, docker builder prune), never a tagged image or a volume"
  timeout 600 docker image prune -f >/dev/null 2>&1 || _cv_disk_say "could not remove untagged images"
  timeout 600 docker builder prune -f >/dev/null 2>&1 || _cv_disk_say "could not remove the build cache"
}

cvengine_disk_check() {  # [PLAN]
  local need free plan=${1:-}
  cv_disk_sentence=''
  need=$(cvengine_disk_need_mb "$plan")
  free=$(cvengine_disk_free_mb)
  [[ $free =~ ^[0-9]+$ ]] || return 0  # cannot be measured: says nothing, as before
  (( free >= need )) && return 0
  cvengine_disk_selfhelp
  free=$(cvengine_disk_free_mb)
  [[ $free =~ ^[0-9]+$ ]] || return 0
  (( free >= need )) && { _cv_disk_say "freed enough space: ${free} MB are free now (this update needs about ${need} MB)"; return 0; }
  cv_disk_sentence=$(cvengine_disk_sentence_for "$need" "$free")
  return 1
}

cvengine_disk_report() {  # for the Update screen; the web container cannot ask Docker
  local need free
  free=$(cvengine_disk_free_mb)
  [[ $free =~ ^[0-9]+$ ]] || return 0
  need=$(cvengine_disk_need_mb)
  python3 scripts/update-state.py disk "$free" "$need" >/dev/null 2>&1 || true
}
