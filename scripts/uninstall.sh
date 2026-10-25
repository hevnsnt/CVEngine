#!/bin/bash
# Removes THIS CVEngine installation: the containers, volumes, networks and built images of its Docker Compose project, and nothing
# else. Everything is matched by the exact Compose project label (or by `docker compose down` with this checkout's own Compose
# files), never by a name that merely contains a word, so another application on the host, including a separate reNgine install,
# is not touched.
#
# The project is, in order: CVENGINE_COMPOSE_PROJECT, COMPOSE_PROJECT_NAME, then the checkout directory's name (Compose's own default).
# Compose files come from CVENGINE_COMPOSE_FILES (default docker-compose.yml), as in scripts/update.sh. Settings are read from the
# environment, then .env; .env is never sourced.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

DANGER='\e[31m'; SUCCESS='\e[32m'; WARNING='\e[33m'; INFO='\e[34m'; RESET='\e[0m'

print_status() {
    echo -e "${INFO}--------------------------------------------------${RESET}"
    echo -e "${INFO}$1${RESET}"
    echo -e "${INFO}--------------------------------------------------${RESET}"
}
die() { echo -e "${DANGER}ERROR: $*${RESET}" >&2; exit 1; }

setting() {
    local name=$1 value=${!1:-}
    if [[ -z $value && -f .env ]]; then
        value=$(grep -E "^${name}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
        value=${value#[\"\']}; value=${value%[\"\']}
    fi
    printf '%s' "$value"
}

command -v docker >/dev/null || die 'docker is not installed.'
docker info >/dev/null 2>&1 || die 'Cannot reach the Docker daemon. Run this as a user that can use Docker (for example with sudo).'
docker compose version >/dev/null 2>&1 || die 'The Docker Compose plugin (docker compose) is required.'

project=$(setting CVENGINE_COMPOSE_PROJECT)
[[ -n $project ]] || project=$(setting COMPOSE_PROJECT_NAME)
[[ -n $project ]] || project=$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
[[ $project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "Cannot work out this installation's Compose project name (got '$project'). Set CVENGINE_COMPOSE_PROJECT."

compose=(docker compose -p "$project")
compose_env_file=$(setting CVENGINE_COMPOSE_ENV_FILE)
if [[ -n $compose_env_file ]]; then
    [[ $compose_env_file =~ ^[A-Za-z0-9._-]+$ && -f $compose_env_file ]] ||
        die 'CVENGINE_COMPOSE_ENV_FILE must name an existing file in the repository root.'
    compose+=(--env-file "$compose_env_file")
fi
compose_files=$(setting CVENGINE_COMPOSE_FILES)
[[ -n $compose_files ]] || compose_files=$(setting CVENGINE_COMPOSE_FILE)
[[ -n $compose_files ]] || compose_files=docker-compose.yml
IFS=', ' read -r -a requested_files <<< "${compose_files//:/,}"
selected=0
for file in "${requested_files[@]}"; do
    [[ -n $file ]] || continue
    [[ $file =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $file ]] || die "Compose file '$file' must be a .yml file in the repository root."
    compose+=(-f "$file")
    selected=1
done
(( selected )) || die 'No Compose file selected.'

label="com.docker.compose.project=$project"
containers=$(docker ps -a --filter "label=$label" --format '{{.Names}}')
volumes=$(docker volume ls --filter "label=$label" --format '{{.Name}}')
networks=$(docker network ls --filter "label=$label" --format '{{.Name}}')

print_status "WARNING: You are about to uninstall CVEngine (Compose project '$project')"
echo -e "${DANGER}This removes the containers, volumes (database, scan results, templates), networks and built images of that project.${RESET}"
echo -e "${DANGER}It is not reversible. Nothing outside project '$project' is touched.${RESET}"
echo
echo "Containers:"; [[ -n $containers ]] && sed 's/^/  /' <<< "$containers" || echo '  (none)'
echo "Volumes:";    [[ -n $volumes ]]    && sed 's/^/  /' <<< "$volumes"    || echo '  (none)'
echo "Networks:";   [[ -n $networks ]]   && sed 's/^/  /' <<< "$networks"   || echo '  (none)'
echo
read -p "$(echo -e "${WARNING}Type yes to remove all of the above: ${RESET}")" -r CONFIRM
if [[ ${CONFIRM,,} != yes && ${CONFIRM,,} != y ]]; then
    print_status "${WARNING}Uninstall aborted. Nothing was removed.${RESET}"
    exit 0
fi

print_status "Stopping and removing the project's containers, networks, volumes and built images..."
"${compose[@]}" down --volumes --remove-orphans --rmi local

# Anything of the project the compose files no longer describe (an older layout), still matched by the exact project label.
leftover_containers=$(docker ps -a -q --filter "label=$label")
[[ -z $leftover_containers ]] || docker rm -f $leftover_containers
leftover_volumes=$(docker volume ls -q --filter "label=$label")
[[ -z $leftover_volumes ]] || docker volume rm $leftover_volumes
leftover_networks=$(docker network ls -q --filter "label=$label")
[[ -z $leftover_networks ]] || docker network rm $leftover_networks

print_status "${SUCCESS}CVEngine uninstall process has been completed.${RESET}"
