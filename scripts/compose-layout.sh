# Sourced by the scripts that run `docker compose` against a running installation (enable-redis-auth.sh, rotate-field-key.sh): it sets COMPOSE to
# `docker compose` plus the Compose files, env file and project the installation runs with, so recreating a service never drops an overlay (a
# host proxy that owns port 443, memory limits) or an env file. The same rules as scripts/update.sh and scripts/apply-update.sh:
#   1. CVENGINE_COMPOSE_FILES (or CVENGINE_COMPOSE_FILE), CVENGINE_COMPOSE_ENV_FILE and CVENGINE_COMPOSE_PROJECT, from the environment or .env;
#   2. otherwise what the running web container was started with;
#   3. otherwise docker-compose.yml.
# Call from the repository root. Returns 1, after saying why on stderr, when the layout cannot be worked out safely.
cvengine_compose_layout() {
  local files env_file project id labels path name
  _cvengine_setting() {
    local key=$1 value=${!1:-}
    if [ -z "$value" ] && [ -f .env ]; then
      value=$(grep -E "^${key}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
      value=${value#[\"\']}; value=${value%[\"\']}
    fi
    printf '%s' "$value"
  }
  COMPOSE=(docker compose)
  docker compose version >/dev/null 2>&1 || ! command -v docker-compose >/dev/null 2>&1 || COMPOSE=(docker-compose)  # the old standalone binary
  files=$(_cvengine_setting CVENGINE_COMPOSE_FILES)
  [ -n "$files" ] || files=$(_cvengine_setting CVENGINE_COMPOSE_FILE)
  env_file=$(_cvengine_setting CVENGINE_COMPOSE_ENV_FILE)
  project=$(_cvengine_setting CVENGINE_COMPOSE_PROJECT)
  if [ -z "$files" ]; then
    id=$(docker ps -a --filter "label=com.docker.compose.project.working_dir=$(pwd)" --filter "label=com.docker.compose.service=web" --format '{{.ID}}' 2>/dev/null | head -n1) || id=''
    if [ -n "$id" ]; then
      labels=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$id" 2>/dev/null) || labels=''
      for path in ${labels//,/ }; do
        name=$(basename "$path")
        if ! [[ $name =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $name && $(dirname "$path") = "$(pwd)" ]]; then
          echo "The running stack was started with $path, which is not a Compose file in $(pwd). Set CVENGINE_COMPOSE_FILES (and CVENGINE_COMPOSE_ENV_FILE) in .env to the files it uses." >&2
          return 1
        fi
        files="${files:+$files,}$name"
      done
      if [ -n "$files" ]; then
        [ -n "$env_file" ] || env_file=$(basename "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.environment_file"}}' "$id" 2>/dev/null)" 2>/dev/null || true)
        [ -f "$env_file" ] || env_file=''
        [ -n "$project" ] || project=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)
      fi
    fi
  fi
  [ -n "$files" ] || files=docker-compose.yml
  if [ -n "$env_file" ]; then
    [[ $env_file =~ ^[A-Za-z0-9._-]+$ && -f $env_file ]] || { echo "CVENGINE_COMPOSE_ENV_FILE must name a file in $(pwd) (got '$env_file')." >&2; return 1; }
    COMPOSE+=(--env-file "$env_file")
  fi
  if [ -n "$project" ]; then
    [[ $project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo "CVENGINE_COMPOSE_PROJECT must be a lowercase Compose project name (got '$project')." >&2; return 1; }
    COMPOSE+=(-p "$project")
  fi
  for name in ${files//,/ }; do
    [[ $name =~ ^[A-Za-z0-9._-]+\.ya?ml$ && -f $name ]] || { echo "Compose file '$name' must be a .yml file in $(pwd) (CVENGINE_COMPOSE_FILES)." >&2; return 1; }
    COMPOSE+=(-f "$name")
  done
}
