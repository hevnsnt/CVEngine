#!/usr/bin/env bash
# Checks that Docker's disk has room for the OpenVAS (Greenbone) add-on before its containers start and its feeds load. Measured on a first start
# (issue #394): the gvmd database 27.7 GB, the raw SCAP feed 11.4 GB and the images about 20 GB, about 59 GB in all, and a disk that fills up
# mid-load leaves a half-loaded feed behind. Prints why and exits 1 when there is not enough room; exits 0 (with a warning) when it cannot tell.
#   scripts/openvas-disk-check.sh        (make openvas-up and scripts/openvas-sync.sh run it before starting anything)
# CVENGINE_OPENVAS_MIN_FREE_GB (the environment or .env) sets the floor in GB, and 0 skips the check. Without it: 60 GB before the first start,
# 15 GB once the add-on's database volume exists (the feeds and images are already there; updates and results still grow).
# Where the free space is read: the Docker data directory when it is on this machine (Linux), else from inside a running container of this stack
# (Docker Desktop keeps its data directory in a VM, whose disk the containers' file systems are on).
set -uo pipefail
cd "$(dirname "$0")/.." || exit

setting() {
  local key=$1 value=${!1:-}
  if [ -z "$value" ] && [ -f .env ]; then
    value=$(grep -E "^${key}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
    value=${value#[\"\']}; value=${value%[\"\']}
  fi
  printf '%s' "$value"
}

need=$(setting CVENGINE_OPENVAS_MIN_FREE_GB)
if [ -n "$need" ]; then
  [[ $need =~ ^[0-9]+$ ]] || { echo "CVENGINE_OPENVAS_MIN_FREE_GB must be a whole number of GB (got '$need')."; exit 1; }
  [ "$need" -eq 0 ] && exit 0
elif docker volume ls -q 2>/dev/null | grep -Eq '(^|_)openvas_psql_data_vol$'; then
  need=15
else
  need=60
fi

free_kb=''
root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null) || root=''
if [ -n "$root" ] && [ -d "$root" ]; then
  free_kb=$(df -Pk "$root" 2>/dev/null | awk 'NR == 2 { print $4 }') || free_kb=''
fi
if ! [[ $free_kb =~ ^[0-9]+$ ]]; then
  id=$(docker ps --filter "label=com.docker.compose.project.working_dir=$(pwd)" --filter "label=com.docker.compose.service=celery" --format '{{.ID}}' 2>/dev/null | head -n1) || id=''
  [ -z "$id" ] || free_kb=$(docker exec "$id" df -Pk / 2>/dev/null | awk 'NR == 2 { print $4 }') || free_kb=''
fi
if ! [[ $free_kb =~ ^[0-9]+$ ]]; then
  echo "Could not read the free space of Docker's disk; the OpenVAS add-on needs about $need GB there (docs/OPENVAS.md). Starting anyway."
  exit 0
fi
free_gb=$(( free_kb / 1048576 ))
if [ "$free_gb" -lt "$need" ]; then
  echo "Docker's disk has $free_gb GB free; OpenVAS needs about $need GB (database, feeds, images). Free space or enlarge Docker's disk, or set CVENGINE_OPENVAS_MIN_FREE_GB (0 skips this check)"
  exit 1
fi
exit 0
