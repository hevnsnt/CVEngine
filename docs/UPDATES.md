# Updates

CVEngine checks its GitHub repository twice a day (05:23 and 17:23 UTC) and asks an administrator before anything changes. Nothing installs automatically.

1. **Check.** The check reads the head of the configured branch (default `hevnsnt/CVEngine@master`) and compares it with the installed commit (the first line of `web/.commit`, written by `make up` and `make build`). A private repository needs a fine-grained read-only token, entered under Settings, Updates, Update source and stored write-only.
2. **Ask.** When something newer exists, superusers see a bar at the top of every page and a Settings, Updates page listing the commits. They can approve, dismiss (until a newer commit appears), or check again.
3. **Apply.** Approving writes the approved commit id to `web/.update-approved`. The web container has no Git or Docker access, so `scripts/apply-update.sh` fast-forwards to that commit, builds application images, applies Django migrations, and recreates application processes. It keeps the existing PostgreSQL and Redis containers and waits while scans or validation jobs are running. On failure it restarts the previous code. Database migrations are not rolled back.

Install the host side once, as the user that owns the checkout and can run Docker:

```bash
scripts/install-updater.sh            # cron entry, every 5 minutes; remove with --remove
```

The script only acts on an approval. It refuses, and logs to `web/.update-log`, when the approved id is not a full commit id, is not reachable from `origin/<checked-out branch>` (keep the checkout on the branch set under Update source), is not a fast-forward, or the checkout has uncommitted changes to tracked files other than `.env` (in that last case it keeps the approval and retries). Approvals and cancellations are in the audit log.

Without the host script an approval waits. To update by hand, run the updater from a clean `master` checkout:

```bash
scripts/update.sh --check        # preflight: layout, ports, database, workers, scans; changes nothing
scripts/update.sh                # update, waiting for running scans to finish
scripts/update.sh --stop-scans   # update now: stop scans cleanly and queue them again afterward
scripts/update.sh --force        # do not wait: stop scans (queued again afterward) and the workers, then update
```

It:

1. fetches the new code and builds the images while everything keeps running;
2. checks that no host service already holds a port the stack publishes, and that no old PostgreSQL 12 volume needs [UPGRADE.md](UPGRADE.md) first;
3. pauses the scheduler and the workers' queue consumers and lets active tasks finish, reporting progress every 30 seconds (up to three hours, `CVENGINE_UPDATE_DRAIN_SECONDS`). With `--stop-scans`, running and queued discovery scans are stopped through the app first, so the drain takes seconds. A busy worker can miss a status reply, and a restarted worker resumes its queues, so the update stops only when a worker misses 12 replies in a row (`CVENGINE_UPDATE_MISSING_POLLS`) or still consumes after being paused three times. The error names the worker or queue;
4. applies migrations, publishes static files, and recreates web, the workers, the scheduler, and the proxy, keeping the database and Redis;
5. waits up to ten minutes (`CVENGINE_UPDATE_READY_SECONDS`) until the site, every worker queue, and the scheduler answer, then queues any stopped scans again.

`--force` skips the drain. It stops discovery scans (and queues them again afterwards, as `--stop-scans`), pauses what it can, and stops the workers with a 10-second grace. A worker that cannot be inspected or paused does not stop it. Any other task running at that moment is lost and runs again when its schedule next fires. It still keeps the database, Redis and volumes, and a failed migration still stops the update.

New work stays queued in Redis throughout. If the drain times out or is interrupted, the previous workers and scheduler resume untouched, and stopped scans wait in the host-private `$(git rev-parse --git-path cvengine-update)/requeue.json` for the next successful update. A failure after migration leaves the new code in place and reports what to check, and startup warnings go to a private file whose path the script prints.

### Custom Compose layouts

The updater uses `docker-compose.yml` by default. An install that adds its own Compose files, a separate env file, or a project name sets them once in `.env`, and every Compose call uses them:

```bash
CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.host.yml
CVENGINE_COMPOSE_ENV_FILE=.env.production
CVENGINE_COMPOSE_PROJECT=cvengine
```

For the development stack, use `CVENGINE_COMPOSE_FILES=docker-compose.dev.yml`. The updater notes when the running containers were started with different files, and when an untracked Compose file in the repository root is not part of the update.


`.env` is no longer tracked in git (`.env.example` is). On an install made before that change, a plain pull would delete an unedited `.env` and stop on an edited one. `scripts/apply-update.sh` handles this: a modified or deleted `.env` does not count as a local change, it copies `.env` to a private temporary file (mode 0600, never printed or logged) before the merge, puts it back afterwards (also after a rollback) and removes the copy when it ends. For a manual `git pull` on such an install, keep a copy yourself:

```bash
cp .env /tmp/cvengine.env && git checkout -- .env && git pull && cp /tmp/cvengine.env .env
```

For the host updater, set `CVENGINE_COMPOSE_FILE` before running `scripts/install-updater.sh` to deploy with another Compose file.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [UPGRADE.md](UPGRADE.md) for moving an old install across a major version, [documentation index](README.md).

### Automatic deployment

To deploy every new `master` commit without anyone running a command, install the timer once, as root, on the server:

```bash
scripts/install-auto-deploy.sh            # checks master every 3 minutes
scripts/install-auto-deploy.sh --remove   # turn it off
```

When `master` on GitHub moves ahead of the checkout, `scripts/auto-deploy.sh`:

1. backs up the database and the secret key (the last 7 backups are kept in `.git/cvengine-auto-deploy/backups`);
2. runs `scripts/update.sh --stop-scans`, which stops running scans cleanly, pauses the scheduler and workers, applies and verifies the update, and queues the stopped scans again.

It never deploys without a backup, waits while another update holds the updater lock, and retries a commit that failed at most once an hour. The installer runs `scripts/update.sh --check` first and refuses an install that is not ready. Logs are in `journalctl -u cvengine-auto-deploy`. It uses the same Compose layout settings as the updater, so an install with an overlay keeps it. Use either automatic deployment or the approval-based host updater above, not both.

### Host update state

Both updater scripts share a lock under `git rev-parse --git-path cvengine-update`, outside the container's writable `web` mount. Approval updates keep the authoritative log there and publish a UI copy to `web/.update-log` by atomic replacement. Commit markers use the same safe publication. Approval files must be regular, single-link files containing one full commit ID; symlinks and special files are refused.

The manual updater keeps stopped-scan plans in that private directory. A regular legacy `web/.update-requeue.json` is imported once with size and structure checks, then removed. An unsafe or malformed legacy plan stops the update for operator inspection. `--check` remains read-only. These changes preserve worker draining, datastore containers, migration-aware rollback, and readiness checks.
