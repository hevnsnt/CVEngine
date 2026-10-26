# Updates

Three ways to stay current. Pick one. Running `install.sh` again is not an update: it rebuilds the code you already have checked out and does not fetch anything new.

| Way | Who acts | Script | Best for |
| --- | --- | --- | --- |
| [Automatic deployment](#automatic-deployment) | nobody | `scripts/update.sh`, started by a timer | A server that should always run the latest `master` |
| [Approval in the app](#approval-in-the-app) | an administrator clicks Approve | `scripts/apply-update.sh`, started by cron | Installs that want a human in the loop |
| [By hand](#by-hand) | you run one command | `scripts/update.sh` | Everything else |

All three keep the database and Redis in place and need a Git checkout, because every updater works through Git. The release page also offers `.zip` and `.tar.gz` source archives with a `SHA256SUMS` file, for reading, mirroring, and offline transfer. They cannot be updated in place. Moving an old install across the PostgreSQL 18 change is in [UPGRADE.md](UPGRADE.md).

The two scripts differ in how carefully they restart:

| | `update.sh` (manual, automatic) | `apply-update.sh` (approval) |
| --- | --- | --- |
| Builds | while everything keeps running | after merging the new commit |
| Waits for | all active, reserved, and scheduled tasks (workers and scheduler paused) | running scans, on-demand validations, deferred re-tests, and triage calls (no time limit; it retries every 5 minutes) |
| Checks for an old PostgreSQL 12 volume | yes | no (read [UPGRADE.md](UPGRADE.md) first) |
| Verifies the site, workers, and scheduler afterward | yes | no |
| Stops scans | only with `--stop-scans` or `--force`; automatic deployment always does | never |

## Automatic deployment

Needs a Linux host with systemd. Install the timer once, as root, in the checkout:

```bash
scripts/install-auto-deploy.sh            # checks master every 3 minutes
scripts/install-auto-deploy.sh --remove   # turn it off
```

The timer first fires 5 minutes after boot, then 3 minutes after each run ends. When `origin/master` moves ahead of the checkout, `scripts/auto-deploy.sh`:

1. backs up the database and the secret key. The last 7 database dumps are kept in `.git/cvengine-auto-deploy/backups`. The secret key is one file, `backups/secret`, replaced when it changes;
2. runs `scripts/update.sh --stop-scans`, which stops every running and queued scan, applies and verifies the update, and queues the stopped discovery scans again.

With backups turned on (the default) it never deploys without one. A failed backup is retried on the next timer run. A commit whose update failed is retried after an hour. It waits while another update holds the lock (`.git/cvengine-update/update.lock`, shared by all updaters), and its drain limit is 30 minutes. The installer runs `scripts/update.sh --check` first and refuses an install that is not ready. Logs: `journalctl -u cvengine-auto-deploy`. Tuning variables are in [CONFIGURATION.md](CONFIGURATION.md#updates). Use this or the approval updater, not both.

## Approval in the app

cvENGINE checks its GitHub repository twice a day (05:23 and 17:23 UTC) and tells superusers when something newer exists. It installs nothing by itself.

1. **Check.** The check reads the head of the configured branch (default `hevnsnt/CVEngine@master`) and compares it with the installed commit (the first line of `web/.commit`). `make up`, `make build`, `update.sh`, and `apply-update.sh` write it. A plain `docker compose up` does not, and the installed commit then shows as unknown. A private repository needs a fine-grained read-only token under **Settings, Updates, Update source**, stored write-only.
2. **Ask.** A bar at the top of every page shows the newest commit message and how many commits are new. **Settings, Updates** lists up to 20 of them and is the only place to **Check now**. Superusers can approve, dismiss (offered while an update is available, until a newer commit appears), or check again.
3. **Apply.** Approving writes the commit id to `web/.update-approved`. The web container has no Git or Docker access, so the host script `scripts/apply-update.sh` does the work. It turns on the global scanning pause, waits for running scans, fast-forwards to that commit, builds, migrates, and recreates the application containers. Migrations are not rolled back.

**The pause.** It is the same global pause as **Activity, Resume scanning**. Work that touches targets or spends AI budget (scans, validation, triage, reviews, the certificate watch, scheduled work) waits and retries every 60 seconds. Anything already running continues, and feeds and bookkeeping carry on. A pause you set yourself is neither claimed nor released by the update.

**Progress.** While an approved update runs, an orange bar on every page (superusers) shows the phase: waiting for scans, rebuilding, resuming, or failed, with the time since approval. It greys out the page while the services restart. **Settings, Updates** lists each step with what it waits on and how long it usually takes (about 3 to 6 minutes once nothing is scanning), and when no host updater is reporting it shows the command to run. The same data is in `GET /cve/api/settings/updates`: `phase` (`idle`, `draining`, `applying`, `done`, `failed`), `phase_detail`, `phase_scans_running`, `phase_changed_at`, `scans_paused_by_update`, and `host_updater` (`seen`, `alive`, `age_seconds`). Only `apply-update.sh` reports phases, and only `update-watch.sh` the heartbeat.

**Failure.** Before the migration, a failure puts the previous commit back and restarts it, and scanning resumes. After the migration it keeps the new commit and retries the restart once. If that also fails, the approval stays for the next run, the phase becomes `failed`, and scanning stays paused. If a pause is left behind, an App Admin releases it under **All projects, Activity, Global scanning control, Resume scanning**.

The host side is a watcher that cron starts every minute (`scripts/update-watch.sh`). It sees an approval within about two seconds, and tells the app it is alive every 15 seconds, so **Settings, Updates** says when nothing on the server is listening and shows the command to run. `./install.sh` installs it. An install made before v1.1.3 has none, and the first update it needs by hand installs it: `scripts/update.sh` leaves the watcher behind when it succeeds, so that one manual update is the last one. To install it without updating:

```bash
scripts/install-updater.sh            # cron entry, started every minute; remove with --remove
```

It logs to `.git/cvengine-update/update.log` (a copy is published as `web/.update-log`). It keeps the approval and retries when the checkout has uncommitted changes to tracked files other than `.env`, when scans are running, or when it cannot verify them. For an id that is not a full commit id, a commit not on `origin/<checked-out branch>` (the usual cause: the update branch in Settings is not the branch checked out on the server; the page says so), or one that is not a fast-forward, it refuses and deletes the approval file. The app can keep showing "approved" after a refused or rolled-back update: cancel the approval and approve again once the cause is fixed. Approvals and cancellations are in the audit log. Without the host script an approval simply waits. Set `CVENGINE_COMPOSE_FILE` (a single file in the checkout root) before installing it to deploy with a different Compose file.

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
3. pauses the scheduler and the workers' queue consumers and waits for active, reserved, and scheduled tasks, reporting every 30 seconds (up to three hours). With `--stop-scans`, every running and queued scan is stopped through the app first, so the wait takes seconds. It stops, and resumes the old workers, when the time limit passes, a worker misses 12 status polls in a row, a worker keeps consuming after three pauses, or a worker cannot be inspected or paused. The error names the worker or queue;
4. applies migrations, publishes static files, and recreates web, the workers, the scheduler, and the proxy;
5. waits up to ten minutes until the site, every worker queue, and the scheduler answer, then queues any stopped discovery scans again, as new scans in their original mode. Other kinds of scan stay stopped.

`--force` skips the wait. It stops scans (discovery scans are queued again afterwards), pauses what it can, and stops the workers with a 10-second grace. Any other task running at that moment is lost and runs again when its schedule next fires. A failed migration still stops the update.

New work stays queued in Redis throughout. If the wait times out or the update stops before the migration, the checkout is put back with `git reset --keep`, the previous workers resume untouched, and stopped scans wait in a private file under `.git/cvengine-update` for the next successful update. A failure after the migration leaves the new code in place and says what to check.

### Custom Compose layouts

`update.sh` and automatic deployment use `docker-compose.yml` by default. An install with its own Compose files, a separate env file, or a project name sets them once in `.env`:

```bash
CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.host.yml
CVENGINE_COMPOSE_ENV_FILE=.env.production
CVENGINE_COMPOSE_PROJECT=cvengine
```

For the development stack use `CVENGINE_COMPOSE_FILES=docker-compose.dev.yml`. `update.sh` and `apply-update.sh` both use the files, env file and project the running `web` container was started with when none of the three settings is given (an install that sets them uses what it set). `apply-update.sh` (the in-app updater) reads the same three settings, and without them it recreates the stack with the files, env file and project the running `web` container was started with, so a host with an overlay needs no setting. It refuses, keeps the approval and says what to set when the checkout holds an overlay (an untracked `docker-compose.*.yml`) that nothing says to use, or when the running stack came from files outside the checkout. A restart that leaves a service created but not running (a published port that is already taken) is a failed update, not a finished one.

## Branches and releases

- `master` holds released versions only. Each release is tagged (`v1.0`, `v1.1`, ...); pushing the tag, or running the Release workflow by hand, publishes the GitHub release with that version's section of the [changelog](../CHANGELOG.md) as its notes, plus the source archives and checksums (`.github/workflows/release.yml`). A patch such as `v1.0.1` keeps the notes of `v1.0` and adds its own short section at the end. The tag must match `web/.version`.
- `develop` is the next version in progress (its `web/.version` may carry a `-dev` suffix). Changes go to `develop` by pull request, and `develop` is merged into `master` for a release.
- Keep an installation on `master` (the default update source); `update.sh` and automatic deployment only work on `master`. Use `develop` only on a test server. Approving an update from another branch than the one checked out on the server (the branch set under Settings, Updates, Update source) makes the host script move its checkout to that branch first, as long as it is an upgrade: the branch must contain the installed commit and the local branch must not hold commits that are not on `origin`. A branch that does not exist, a detached checkout, a dirty checkout and a would-be downgrade are refused with the reason shown in Settings, Updates, and nothing moves. Migrations are never rolled back, which is why going back to an older branch is not done for you.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
