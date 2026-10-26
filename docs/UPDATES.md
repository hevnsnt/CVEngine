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

1. backs up the database and the secret key (the last 7 are kept in `.git/cvengine-auto-deploy/backups`, mode 0700, for rolling back on this machine; do not copy that folder off the machine as one unit, because the dump and the key that opens its older secrets sit together there);
2. runs `scripts/update.sh --stop-scans`, which stops running scans cleanly, applies and verifies the update, and queues the stopped scans again.

With backups turned on (the default) it never deploys without one. It waits while another update holds the lock and retries a failed commit at most once an hour. The installer runs `scripts/update.sh --check` first and refuses an install that is not ready. Logs: `journalctl -u cvengine-auto-deploy`. Tuning variables are in [CONFIGURATION.md](CONFIGURATION.md#updates). Use this or the approval updater, not both.

## Approval in the app

CVEngine checks its GitHub repository twice a day (05:23 and 17:23 UTC) and tells superusers when something newer exists. It installs nothing by itself.

1. **Check.** The check reads the head of the configured branch (default `hevnsnt/CVEngine@master`) and compares it with the installed commit (the first line of `web/.commit`, written by `make up` and `make build`). A private repository needs a fine-grained read-only token under **Settings, Updates, Update source**, stored write-only.
2. **Ask.** A bar at the top of every page and **Settings, Updates** list the new commits. Superusers can approve, dismiss (until a newer commit appears), or check again.
3. **Apply.** Approving writes the commit id to `web/.update-approved`. The web container has no Git or Docker access, so the host script `scripts/apply-update.sh` does the work: it pauses new scan dispatch (active scans are left to finish, never stopped), fast-forwards to that commit, builds, migrates, recreates the application containers, and on failure restarts the previous code; scanning resumes once the run reaches a stable state, whether that is the new commit or the restored previous one. Migrations are not rolled back. **Settings, Updates** shows the live phase (`draining`, `applying`, `done`, `failed`) and whether scanning is currently paused for the update, from `GET /cve/api/settings/updates`'s `phase`, `phase_detail`, `phase_scans_running`, `phase_changed_at`, and `scans_paused_by_update` fields.

Install the host side once, as the user that owns the checkout and can run Docker:

```bash
scripts/install-updater.sh            # a watcher the cron entry starts every minute; remove with --remove
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

For the development stack use `CVENGINE_COMPOSE_FILES=docker-compose.dev.yml`. `update.sh` and `apply-update.sh` both use the files, env file and project the running `web` container was started with when none of the three settings is given (an install that sets them uses what it set). `apply-update.sh` (the in-app updater) reads the same three settings, and without them it recreates the stack with the files, env file and project the running `web` container was started with, so a host with an overlay needs no setting. It refuses, keeps the approval and says what to set when the checkout holds an overlay (an untracked `docker-compose.*.yml`) that nothing says to use, or when the running stack came from files outside the checkout. A restart that leaves a service created but not running (a published port that is already taken) is a failed update, not a finished one.

## Branches and releases

- `master` holds released versions only. Each release is tagged (`v1.0`, `v1.1`, ...); pushing the tag, or running the Release workflow by hand, publishes the GitHub release with that version's section of the [changelog](../CHANGELOG.md) as its notes (`.github/workflows/release.yml`). A patch such as `v1.0.1` keeps the notes of `v1.0` and adds its own short section at the end. The tag must match `web/.version`.
- `develop` is the next version in progress (`web/.version` reads the next version with a `-dev` suffix, such as `v1.2-dev` once `v1.1` is released). Changes go to `develop` by pull request, and `develop` is merged into `master` for a release.
- Keep an installation on `master` (the default update source); `update.sh` and automatic deployment only work on `master`. Use `develop` only on a test server. Approving an update from another branch than the one checked out on the server (the branch set under Settings, Updates, Update source) makes the host script move its checkout to that branch first, as long as it is an upgrade: the branch must contain the installed commit and the local branch must not hold commits that are not on `origin`. A branch that does not exist, a detached checkout, a dirty checkout and a would-be downgrade are refused with the reason shown in Settings, Updates, and nothing moves. Migrations are never rolled back, which is why going back to an older branch is not done for you.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).

## An approved update that never starts

The web app has no Docker or git access, on purpose. When you click **Approve update** it only records the approval; a small watcher on the server (`scripts/update-watch.sh`, started by cron every minute, installed by `./install.sh` and by `scripts/install-updater.sh`) sees it within about two seconds and runs the update: scans are paused, running ones finish, the files are updated, the containers are rebuilt and restarted, and scanning resumes. It also writes a heartbeat every 15 seconds, and Settings > Updates shows "Host updater: listening" or, when it does not report, says so and what to do. An older updater (a cron entry that runs `scripts/apply-update.sh` every 5 minutes) does not report but still works, with up to 5 minutes before an approval starts; run `scripts/install-updater.sh` again to switch it to the watcher.

### First time, or a server that has never had the updater

A server that was installed before the watcher existed has no `scripts/install-updater.sh` and nothing that reads the approval, so Approve does nothing there. Bring it up to date by hand once, from the CVEngine folder on the server:

```
cd /opt/cvengine && git pull --ff-only && sudo scripts/install-updater.sh
```

That pulls the current code, installs the watcher and starts it at once. A pending approval is then applied straight away: the script sees that the files are current but the running build is older (`web/.commit`) and rebuilds the services. Settings > Updates shows this command with a Copy button whenever no host updater is reporting, plus the steps an update goes through, what each one is waiting on and about how long it takes (about 3 to 6 minutes once nothing is scanning; a running scan is waited for).

If the bar says the host updater is not reporting, or an approval does not start:

1. `crontab -l | grep cvengine` on the host: no line means the updater is not installed; run `scripts/install-updater.sh` (as the user that owns the checkout and may run Docker).
2. `tail -30 web/.update-log`: the script writes why it refused (local changes to tracked files, an unreachable origin, a commit that is not on the branch) or which command stopped it. Each reason is written once, not on every check.
3. `scripts/apply-update.sh` run by hand prints the same lines to the terminal, and applies a pending approval at once.
4. `git status --short` in the checkout: a modified tracked file (other than `.env`) blocks the update until it is committed or stashed.
