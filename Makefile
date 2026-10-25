-include .env
.DEFAULT_GOAL:=help

# Credits: https://github.com/sherifabdlnaby/elastdocker/

# This for future release of Compose that will use Docker Buildkit, which is much efficient.
COMPOSE_PREFIX_CMD := COMPOSE_DOCKER_CLI_BUILD=1

COMPOSE_ALL_FILES := -f docker-compose.yml
SERVICES          := db web proxy redis celery celery-beat

# Check if 'docker compose' command is available, otherwise use 'docker-compose'
DOCKER_COMPOSE := $(shell if command -v docker > /dev/null && docker compose version > /dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
$(info Using: $(shell echo "$(DOCKER_COMPOSE)"))

# --------------------------

.PHONY: check-env check-secrets certs up build username changepassword migrate down stop restart rm test logs images help

# .env is not tracked. Create it from the example on first use, then stop so it can be edited.
check-env:
	@test -f .env || { cp .env.example .env; echo "Created .env from .env.example. Edit it (DOMAIN_NAME and every change-me value), then run make again."; exit 1; }

# First-run guard: refuse to continue while a password still holds the public example value from .env.example.
# (Not part of up/build/down, so an existing deployment's updates and restarts are never blocked by it.)
check-secrets: check-env
	@bad=$$(grep -iE '^(POSTGRES_PASSWORD|DJANGO_SUPERUSER_PASSWORD|AUTHORITY_PASSWORD)=.*change-me' .env | cut -d= -f1 | tr '\n' ' '); \
	if [ -n "$$bad" ]; then echo "Refusing to continue: .env still has the example placeholder for: $$bad"; echo "Set a real value for each (for example: openssl rand -base64 24), then run make again."; exit 1; fi

certs: check-secrets	## Generate the HTTPS certificate.
	@${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} -f docker-compose.setup.yml run --rm certs

up: check-env		## Build and start all services.
	@./scripts/upgrade-postgres.sh
	@python3 scripts/update-state.py commit "$$(git rev-parse HEAD)"
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} up -d --build ${SERVICES}

build: check-env		## Build all services.
	@python3 scripts/update-state.py commit "$$(git rev-parse HEAD)"
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} build ${SERVICES}

username: check-secrets	## Create an admin account (use after make up).
ifeq ($(isNonInteractive), true)
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} exec web python3 manage.py createsuperuser --username ${DJANGO_SUPERUSER_USERNAME} --email ${DJANGO_SUPERUSER_EMAIL} --noinput
else
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} exec web python3 manage.py createsuperuser
endif

changepassword:	## Change password for user
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} exec web python3 manage.py changepassword

migrate:		## Apply migrations
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} exec web python3 manage.py migrate

down:			## Down all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} down

stop:			## Stop all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} stop ${SERVICES}

restart:		## Restart all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} restart ${SERVICES}

rm:				## Remove all services containers.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_ALL_FILES) rm -f ${SERVICES}

test:			## Run the test suite (the stack must be running).
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_ALL_FILES) exec celery python3 manage.py test tests

logs:			## Tail all logs with -n 1000.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_ALL_FILES) logs --follow --tail=1000 ${SERVICES}

images:			## Show all Docker images.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_ALL_FILES) images ${SERVICES}

help:			## Show this help.
	@echo "Make application Docker images and manage containers using Docker Compose files."
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m (default: help)\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
