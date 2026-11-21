# shellcheck shell=bash
# Sourced by scripts/update.sh, scripts/update-deploy.sh and `make up`: removes the containers of the old in-stack OpenVAS (Greenbone) add-on.
#
#   . scripts/retire-openvas.sh && cvengine_retire_openvas
#
# docker-compose.yml no longer defines the `openvas-*` services (OpenVAS runs on a Sentinel, kind `openvas`, docs/OPENVAS.md), so on an install that
# had the `openvas` profile running they would stay up as orphans, holding about 4 GB of memory, with nothing driving them. This stops and removes
# every container of this checkout's Compose project whose service name starts with `openvas-` (found by the labels Compose puts on them, so the
# compose file is not needed), and the project's `openvas_network`. Their data volumes (the feeds and the gvmd database, about 60 GB) are KEPT and
# the command that removes them is printed. Does nothing when there is nothing to remove, and never fails what sources it.
cvengine_retire_openvas() {
  local dir id service ids='' projects='' project log
  if declare -F log >/dev/null 2>&1; then log=log; else log=_cvengine_retire_openvas_say; fi
  dir=$(pwd)
  for id in $(docker ps -aq --filter "label=com.docker.compose.project.working_dir=$dir" 2>/dev/null); do
    service=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$id" 2>/dev/null) || continue
    case "$service" in openvas-*) ;; *) continue ;; esac
    ids="$ids $id"
    project=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id" 2>/dev/null) || project=''
    case " $projects " in *" $project "*) ;; *) projects="$projects $project" ;; esac
  done
  [ -n "$ids" ] || return 0
  # shellcheck disable=SC2086  # the ids are docker's own hexadecimal ids
  docker stop -t 30 $ids >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  if docker rm -f $ids >/dev/null 2>&1; then
    "$log" "removed the containers of the old in-stack OpenVAS add-on (OpenVAS runs on a Sentinel now, docs/OPENVAS.md); its data volumes are kept"
  else
    "$log" "could not remove the containers of the old in-stack OpenVAS add-on; remove them with: docker rm -f$ids"
  fi
  for project in $projects; do
    [ -n "$project" ] || continue
    docker network rm "${project}_openvas_network" >/dev/null 2>&1 || true
    "$log" "to free their disk (about 60 GB), remove the old OpenVAS volumes: docker volume ls -q --filter label=com.docker.compose.project=$project | grep '_openvas_' | xargs -r docker volume rm"
  done
  return 0
}

_cvengine_retire_openvas_say() { echo "$*" >&2; }
