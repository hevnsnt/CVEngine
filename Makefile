-include .env
.DEFAULT_GOAL:=help

# Credits: https://github.com/sherifabdlnaby/elastdocker/

# This for future release of Compose that will use Docker Buildkit, which is much efficient.
COMPOSE_PREFIX_CMD := COMPOSE_DOCKER_CLI_BUILD=1

COMPOSE_ALL_FILES := -f docker-compose.yml
SERVICES          := db web proxy redis celery celery-beat reviewer

# Check if 'docker compose' command is available, otherwise use 'docker-compose'
DOCKER_COMPOSE := $(shell if command -v docker > /dev/null && docker compose version > /dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
$(info Using: $(shell echo "$(DOCKER_COMPOSE)"))

# --------------------------

.PHONY: rotate-secrets db-backup db-backup-schedule restore-check check-env check-secrets certs up build admin admin-password username changepassword migrate dbshell down stop restart rm test logs images help inventory-sync uninstall-updater scanner-build scanner-update scanner-logs

# .env is not tracked. Create it on first use, with the passwords generated and DOMAIN_NAME set to this machine's address.
check-env:
	@test -f .env || ./scripts/init-env.sh

# First-run guard: refuse to continue while a password still holds the public example value from .env.example, and say how to fix it.
# (Not part of up/build/down, so an existing deployment's updates and restarts are never blocked by it.)
check-secrets: check-env
	@bad=$$(grep -iE '^(POSTGRES_PASSWORD|AUTHORITY_PASSWORD)=.*change-me' .env | cut -d= -f1 | tr '\n' ' '); \
	if [ -n "$$bad" ]; then echo "Refusing to continue: .env still has the example placeholder for: $$bad"; echo "Run ./scripts/init-env.sh to generate them (or set your own), then run make again."; exit 1; fi

certs: check-secrets	## Generate the HTTPS certificate.
	@${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} -f docker-compose.setup.yml run --rm certs

up: check-env		## Build and start all services.
	@rm -f config/nginx/state/maintenance config/nginx/state/maintenance-failed
	@# an install made before 1.5.0: its .env, overlay and certificates get the new names beside the old ones (scripts/legacy_names.py)
	@python3 scripts/legacy_names.py migrate -- ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES}
	@./scripts/upgrade-postgres.sh
	@python3 scripts/update-state.py commit "$$(git rev-parse HEAD)"
	@python3 scripts/update-state.py upstream || true
	@# a broker without a password gets one (Redis and its clients are recreated below, as their settings changed)
	@bash -c '. scripts/redis-password.sh && cvengine_ensure_redis_password "$(CVENGINE_COMPOSE_ENV_FILE)" && echo "The Redis broker had no password: generated one (REDIS_PASSWORD in .env)." || true'
	@# the least privilege database role the server runs as gets its password; the migrate service below creates the role (docs/CONFIGURATION.md)
	@bash -c '. scripts/db-app-role.sh && cvengine_ensure_db_app_password "$(CVENGINE_COMPOSE_ENV_FILE)" && echo "Generated the password of the database role the server runs as (CVENGINE_DB_APP_PASSWORD in .env)." || true'
	@# the secret a host nginx sends so the proxy believes its X-Forwarded-For (docs/DEPLOYMENT.md, Client addresses behind a host proxy)
	@bash -c '. scripts/client-address.sh && cvengine_ensure_upstream_secret "$(CVENGINE_COMPOSE_ENV_FILE)" && echo "Generated the upstream secret (CVENGINE_UPSTREAM_SECRET in .env); a host nginx in front of the proxy needs it: scripts/client-address-check.sh --snippet" || true'
	@# Only the one-off migrate service gets the database owner's password. It runs here, before the application starts, in the foreground so its
	@# output shows: the migrations, then the app role's grants and login check, which stops make up with the one-line fix when the role cannot be
	@# used (CVENGINE_DB_ALLOW_OWNER_FALLBACK=1 in .env is the explicit way to run on the owner role instead).
	@bash -c '. scripts/db-app-role.sh && cvengine_owner_password_check ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES}'
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} build web
	@# The application runs as its own account (uid 10002): the one-off ownership service hands it the paths it writes (the volumes, the Django
	@# secret, its update requests in web/) before the migrate service and the application start; it prints one line and changes nothing the
	@# second time (scripts/app-ownership.sh, web/ownership.sh). It runs again right before the application is recreated below.
	@bash -c '. scripts/app-ownership.sh && cvengine_app_ownership ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES}'
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} up -d db redis
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} run --rm -e CVENGINE_DB_ALLOW_OWNER_FALLBACK=$$(bash -c '. scripts/db-app-role.sh && cvengine_db_owner_fallback "$(CVENGINE_COMPOSE_ENV_FILE)"') migrate
	@bash -c '. scripts/app-ownership.sh && cvengine_app_ownership ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES}'
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} up -d --build --no-deps ${SERVICES}
	@# the old in-stack OpenVAS containers (no longer in docker-compose.yml) are stopped and removed; their volumes are kept
	@bash -c '. scripts/retire-openvas.sh && cvengine_retire_openvas'
	@# The built-in scanner (docs/BUILTIN-SCANNER.md), on its own network: the newest published image is fetched and the scanner recreated, and the optional
	@# Tailscale sidecar, which runs in the scanner's network namespace, is put back into the new one (cvengine_scanner_sidecar; naming services above leaves
	@# profile services out). With CVENGINE_BUILTIN_SCANNER=0 both are taken away instead. Never fails make up: until it runs, the scans that need it wait.
	@bash -c '. scripts/scanner.sh && cvengine_scanner_fetch ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} && cvengine_scanner_start --no-wait ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES}'

build: check-env		## Build all services.
	@python3 scripts/update-state.py commit "$$(git rev-parse HEAD)"
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} build ${SERVICES}

admin:		## Create the admin account; its password is generated and printed once (after make up).
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} run --rm --no-deps -T migrate python3 manage.py create_admin

admin-password:	## Lost the admin password? Generate a new one and print it once.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} run --rm --no-deps -T migrate python3 manage.py create_admin --reset

export-cve-seed:	## Write this instance's whole CVE catalog to web/cve-seed.jsonl.gz (see docs/PIPELINE.md, Seeding the catalog).
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} exec -T web python3 manage.py export_cve_seed --out /var/lib/cvengine/web/cve-seed.jsonl.gz

redis-auth:	## Put a password on the Redis broker of an older installation (see docs/CONFIGURATION.md).
	./scripts/enable-redis-auth.sh

rotate-field-key:	## Rotate the key that encrypts stored API keys and webhook URLs (see docs/CONFIGURATION.md).
	./scripts/rotate-field-key.sh

rotate-secrets:	## Rotate the database, Redis and field keys and the Django secret, then verify (ARGS=--dry-run shows the plan; docs/CONFIGURATION.md).
	./scripts/rotate-secrets.sh $(ARGS)

db-backup:	## Dump the database now into the nightly dump folder (backups/db; see docs/DEPLOYMENT.md, Backups).
	./scripts/db-backup-daily.sh

db-backup-schedule:	## Dump the database every night at 03:17 and keep CVENGINE_DB_BACKUP_DAYS days (a crontab line; see docs/DEPLOYMENT.md, Backups).
	./scripts/install-db-backup.sh

restore-check:	## Restore the newest dump into a throwaway database, count rows, drop it (see docs/DEPLOYMENT.md, Backups).
	./scripts/restore-check.sh

username: check-secrets	## Create an admin account of your own choosing (asks for the password; use after make up).
ifeq ($(isNonInteractive), true)
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} run --rm --no-deps migrate python3 manage.py createsuperuser --username ${DJANGO_SUPERUSER_USERNAME} --email ${DJANGO_SUPERUSER_EMAIL} --noinput
else
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} run --rm --no-deps migrate python3 manage.py createsuperuser
endif

changepassword:	## Change password for user
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} exec web python3 manage.py changepassword

migrate:		## Apply migrations as the database's owner role, in the one-off migrate service (which also grants and checks the app role the server runs as)
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} run --rm --no-deps -e CVENGINE_DB_ALLOW_OWNER_FALLBACK=$$(bash -c '. scripts/db-app-role.sh && cvengine_db_owner_fallback "$(CVENGINE_COMPOSE_ENV_FILE)"') migrate

dbshell:		## A psql prompt as the database's owner role, inside the db container (no password leaves it)
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} exec db sh -c 'exec psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

down:			## Down all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} down

stop:			## Stop all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} stop ${SERVICES}

restart:		## Restart all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} restart ${SERVICES}

rm:				## Remove all services containers.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_ALL_FILES) rm -f ${SERVICES}

test:			## Run the test suite (the stack must be running; as the owner role, which creates the test database, in the migrate service).
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_ALL_FILES) run --rm --no-deps migrate python3 manage.py test tests

uninstall-updater:	## Remove the host's update watcher (the cron line install.sh added); run with sudo if install.sh ran as root (docs/UPDATES.md).
	bash scripts/uninstall-updater.sh

scanner-build:	## Build the built-in scanner image from source, the known-good floor commit scanner.lock.json names (the offline fallback when the published image cannot be pulled).
	@tag=$$(bash -c '. scripts/scanner.sh && cvengine_scanner_build' | tail -n1) && echo "Built $$tag (also cvengine-sentinel-local:latest)." && \
	echo "To run it instead of the published image, set CVENGINE_SCANNER_IMAGE=$$tag in .env, then make up. Remove the line to follow the newest published image again."

scanner-update:	## Bring the built-in scanner to the newest published image: pull, start, keep it only once it checked in, else put the previous one back.
	@scripts/scanner-update.sh

scanner-logs:	## Tail the built-in scanner's log.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_ALL_FILES} logs --follow --tail=200 scanner

inventory-sync:	## Copy the host inventory reporter scripts to the copies the server hands out (web/static/cve/inventory).
	cp -p scripts/inventory/cvengine-inventory.sh scripts/inventory/cvengine-inventory.py scripts/inventory/cvengine-inventory.ps1 web/static/cve/inventory/

logs:			## Tail all logs with -n 1000.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_ALL_FILES) logs --follow --tail=1000 ${SERVICES}

images:			## Show all Docker images.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_ALL_FILES) images ${SERVICES}

help:			## Show this help.
	@echo "Make application Docker images and manage containers using Docker Compose files."
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m (default: help)\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
