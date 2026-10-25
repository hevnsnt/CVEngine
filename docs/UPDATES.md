# Updates

Three ways to stay current. Pick one.

| Way | Who acts | Best for |
| --- | --- | --- |
| [Automatic deployment](#automatic-deployment) | nobody | A server that should always run the latest `master` |
| [Approval in the app](#approval-in-the-app) | an administrator clicks Approve | Installs that want a human in the loop |
| [By hand](#by-hand) | you run one command | Everything else |

All three use the same updater logic: build while everything keeps running, let active work finish, migrate, restart, verify, and keep the database and Redis in place. Moving an old install across the PostgreSQL 18 change is in [UPGRADE.md](UPGRADE.md).

## Automatic deployment

Needs a Linux host with systemd. Install the timer once, as root, in the checkout:

```bash
scripts/install-auto-deploy.sh            # checks master every 3 minutes
scripts/install-auto-deploy.sh --remove   # turn it off
```

When `origin/master` moves ahead of the checkout, `scripts/auto-deploy.sh`:

1. backs up the database and the secret key (the last 7 are kept in `.git/cvengine-auto-deploy/backups`);
2. runs `scripts/update.sh --stop-scans`, which stops running scans cleanly, applies and verifies the update, and queues the stopped scans again.

With backups turned on (the default) it never deploys without one. It waits while another update holds the lock and retries a failed commit at most once an hour. The installer runs `scripts/update.sh --check` first and refuses an install that is not ready. Logs: `journalctl -u cvengine-auto-deploy`. Tuning variables are in [CONFIGURATION.md](CONFIGURATION.md#updates). Use this or the approval updater, not both.

## Approval in the app

CVEngine checks its GitHub repository twice a day (05:23 and 17:23 UTC) and tells superusers when something newer exists. It installs nothing by itself.

1. **Check.** The check reads the head of the configured branch (default `hevnsnt/CVEngine@master`) and compares it with the installed commit (the first line of `web/.commit`, written by `make up` and `make build`). A private repository needs a fine-grained read-only token under **Settings, Updates, Update source**, stored write-only.
2. **Ask.** A bar at the top of every page and **Settings, Updates** list the new commits. Superusers can approve, dismiss (until a newer commit appears), or check again.
3. **Apply.** Approving writes the commit id to `web/.update-approved`. The web container has no Git or Docker access, so the host script `scripts/apply-update.sh` does the work: it fast-forwards to that commit, builds, migrates, recreates the application containers, waits while scans or validation jobs run, and on failure restarts the previous code. Migrations are not rolled back.

Install the host side once, as the user that owns the checkout and can run Docker:

```bash
scripts/install-updater.sh            # cron entry, every 5 minutes; remove with --remove
```

It refuses, and logs to `web/.update-log`, when the approved id is not a full commit id, is not reachable from `origin/<checked-out branch>`, is not a fast-forward, or the checkout has uncommitted changes to tracked files other than `.env` (it keeps the approval and retries in that case). Approvals and cancellations are in the audit log. Without the host script an approval simply waits. Set `CVENGINE_COMPOSE_FILE` before installing it to deploy with a different Compose file.

## By hand

From a clean `master` checkout:

```bash
scripts/update.sh --check        # preflight: layout, ports, database, scans; changes nothing
scripts/update.sh                # update, waiting for running scans to finish
scripts/update.sh --stop-scans   # update now: stop scans cleanly and queue them again afterward
scripts/update.sh --force        # do not wait: stop scans and the workers, then update
```

It:

1. fetches the code and builds the images while everything keeps running;
2. checks that no host service holds a port the stack publishes, and that no old PostgreSQL 12 volume needs [UPGRADE.md](UPGRADE.md) first;
3. pauses the scheduler and the workers' queue consumers and waits for active tasks, reporting every 30 seconds (up to three hours). With `--stop-scans` running and queued discovery scans are stopped through the app first, so the wait takes seconds. It stops only when a worker misses 12 status replies in a row or keeps consuming after three pauses, and the error names the worker or queue;
4. applies migrations, publishes static files, and recreates web, the workers, the scheduler, and the proxy;
5. waits up to ten minutes until the site, every worker queue, and the scheduler answer, then queues any stopped scans again.

`--force` skips the wait. It stops discovery scans (queued again afterwards), pauses what it can, and stops the workers with a 10-second grace. Any other task running at that moment is lost and runs again when its schedule next fires. A failed migration still stops the update.

New work stays queued in Redis throughout. If the wait times out or is interrupted, the previous workers resume untouched and stopped scans wait in a private file under `.git/cvengine-update` for the next successful update. A failure after migration leaves the new code in place and says what to check.

### Custom Compose layouts

The updater uses `docker-compose.yml` by default. An install with its own Compose files, a separate env file, or a project name sets them once in `.env`:

```bash
CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.host.yml
CVENGINE_COMPOSE_ENV_FILE=.env.production
CVENGINE_COMPOSE_PROJECT=cvengine
```

For the development stack use `CVENGINE_COMPOSE_FILES=docker-compose.dev.yml`. The updater warns when the running containers were started with different files.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
