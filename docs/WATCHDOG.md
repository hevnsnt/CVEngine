# The watchdog

A process that watches this server from outside the workers and puts right what it safely can. It exists because everything that used to watch the workers was itself a Celery task, a beat entry or a check inside the worker container, so it stopped with the thing it watched. In the 1.3.7 to 1.4 update on one production instance three of the four worker lanes (`cve_feed`, `validation_priority`, `classic`) were gone while the container stayed up; every queue grew; no notice said so. Then a leftover `DISCOVERY_CONCURRENCY=1` in `.env` kept one host assessment at a time while two Sentinels idled.

It is on by default. Switch it off for everything with the **Watchdog** switch on **Administration, Watchdog**, or `CVENGINE_WATCHDOG=0` in `.env` (the host side reads it too); each rule has its own switch on the same panel.

## How it runs

```
host: scripts/update-watch.sh  (cron starts it every minute; it already supervises updates)
   every 30 s   scripts/watchdog.sh tick  ->  docker compose exec -T web python3 manage.py watchdog_tick
   every 2 s    web/.watchdog-action?     ->  scripts/watchdog.sh act   (restart celery, restart celery-beat, prune dangling images)
```

- **`manage.py watchdog_tick` runs in the web container**, not in Celery. It never waits on a worker. It takes one snapshot, applies the rules, records what it did and ends. It stops itself after 25 seconds (`SIGALRM`), its own timer kills the process at 33 seconds even when a database or broker call is stuck, and the host script wraps it in `timeout` as a third bound. A tick that fails or hangs changes nothing.
- **Actions that need Docker go through a request file**, the pattern every host action here uses (the web container has no Docker access on purpose). The tick writes `web/.watchdog-action` (`{id, action, rule, at}`: three named actions, nothing else); the host reads it without following a link, removes it, does the one action and answers in `web/.watchdog-result`. A request nobody serves in 10 minutes is an escalation ("is `update-watch.sh` running?"), not a silent wait.
- **The Compose layout** is the one the installation runs with, from `scripts/compose-layout.sh` (the file `renew-certs.sh`, `scanner-update.sh` and the others already share): `CVENGINE_COMPOSE_FILES`, `CVENGINE_COMPOSE_ENV_FILE` and `CVENGINE_COMPOSE_PROJECT` from the environment or `.env`, else what the running web container was started with. Recreating a service never drops an overlay. (`apply-update.sh` keeps its own copy, which also refuses a checkout with an overlay nothing says to use; the host's copy of that script must stay self-contained for rollbacks.)
- **One tick and one action at a time** (`$STATE/watchdog.lock`, `$STATE/watchdog-act.lock`, each taken without waiting). If the host watcher itself stops, nothing ticks; the panel then says "Not running" in red, and the rule rows say "Not known" instead of a stale green.

## Standing down during an update

The watchdog never fights an update. Both sides check, and any one of these means "stand down":

| Where | What |
| --- | --- |
| web tick | `web/.update-approved` exists, the phase (`web/.update-phase.json`) is `draining` or `applying` (a phase nobody refreshed for two hours is a script that died, not an update), or `web/.update-lock` is held (tested without waiting) |
| host | the same files, plus `$STATE/update.lock` (the update script's lock) held, plus the maintenance page flag (`config/nginx/state/maintenance`) |

While standing down no rule acts, and a check that falls due waits for the update to end (an update restarts the workers by design). When the host is asked for something while standing down it answers `standdown`: nothing was done, so it does not count as an attempt and is asked again later. For the length of an action the host **takes `$STATE/update.lock`** (without waiting), so an approval that arrives meanwhile waits for it and the two never recreate containers at once. The upgrade rehearsal runs an update with the watchdog ticking.

## The tick: one snapshot

Cheap and bounded: a few Redis reads, one broadcast to the workers (`active_queues`, returns as soon as all four lanes answer; waits 3 seconds only when one is silent), and a handful of small queries with a 5 second statement timeout. Every part is read by its own probe; a part that cannot be read is **unknown**, and **a rule never acts on an unknown**: with Redis down the watchdog does not restart the workers.

Queue lengths and unacknowledged messages (and the oldest age), which lanes answer and what they consume, completions and free slots per lane (only while a queue has work), the scheduler heartbeat, Sentinel slots (live, busy, waiting, due work), the discovery pool ceiling and where it comes from, database connections, free disk, container memory, scans running, queued and quiet, and the update state. The latest snapshot is in Redis for five minutes and in the database (`WatchdogState`, rule `_all`).

## The rules

Every rule has the same gates, in this order: the switches, standing down, **hysteresis** (the symptom must hold for the rule's time; a tick that sees it gone starts the clock again), the **flap guard** (see R10), a **minimum gap** between actions, and an **hourly and a daily cap**. The counters live in the database, so a restart of the web container does not reset them. Times are shown in the viewer's own time (the zone chosen in preferences).

| Rule | Symptom | After | Action | Gap / caps |
| --- | --- | --- | --- | --- |
| **R1 Workers answer** | a lane does not answer, or answers without its queue (any of the four). **A lane that missed a ping is not counted gone while it shows work**: it finished a task in the last 90 seconds, or it has a task running that started less than 30 minutes ago (each worker records a task's start, so a lane in one long task is busy, not dead) | 3 min | recreate `celery` (and the scanner and Tailscale sidecar that share its network) through the host; once it is verified, return the unacknowledged messages no worker holds to their queues (only when every lane answered; see R5) | 15 min, 2 an hour, 16 a day |
| **R2 Workers take their work** | a lane answers, its queue grows and no task finishes for 10 min, **and its pool has free slots** (a pool full of long scans is busy, not hung) | 10 min | the same as R1 | same |
| **R3 Hosts assessed at once is not starved** | the discovery ceiling is below the auto-tune minimum (4) while host assessments wait and Sentinels have free slots and nothing queued | 2 min | raise it to 4 through the saved layer, **only when `.env` pins it** (see below) | 10 min, 3 an hour, 10 a day |
| **R4 Idle Sentinels are fed** | live Sentinels with free slots, nothing queued for them and checks due | 5 min | run `feed_sentinels` in the tick itself (not through Celery), and `work_planner.tick()` ([the work planner](PIPELINE.md#the-work-planner)), which queues the due SSH and secrets checks; "checks due" counts the planner's ready checks as well | 10 min, 4 an hour |
| **R5 No message stuck unacknowledged** | messages unacknowledged for over 30 min that **no worker holds** (a worker with a full pool legitimately holds what it has not started) | at once | return those messages to their queues. **Never while a lane is silent or the workers' answer is partial**: a busy worker that missed the ping may still hold the message, and returning it would run the task twice. The event log says when a return was skipped for that reason | 10 min, 2 an hour |
| **R6 Scheduler ticks** | the beat heartbeat (every 15 s) is older than 2 min | 2 min | recreate `celery-beat` through the host | 15 min, 4 a day |
| **R7 Disk and memory have room** | under 10 percent or 5 GB free, or container memory over 90 percent | 2 min | pause the **automatic starting** of work (running work carries on; it is the update drain pause, so nothing is aborted); for disk, ask the host to remove dangling images and build cache (`docker image prune`, `docker builder prune`: never a tagged image or a volume). The pause is released when the pressure is gone, and only if it is the watchdog's (a person's own pause is never touched) | 30 min, 6 a day |
| **R8 Database connections have room** | 85 percent of `max_connections` in use, or a session idle in a transaction for over 10 min | 2 min | a notice only | none |
| **R9 No scan is stuck running** | a running scan with no activity for an hour, whose Celery task exists nowhere and with no stage waiting on Sentinels (`ghost_scans`, the test the updater uses) | at once | mark it failed with "interrupted: no worker held this scan ... (closed by the watchdog)" so the queue moves | 10 min, 24 a day |

**Sentinel watchdogs.** Each pass (outside an update) the watchdog also reads what every live Sentinel's own watchdog reports (`sentinel_settings.watchdog_problem`) and keeps one administrator notice, "N Sentinels with a watchdog problem", while a Sentinel's watchdog has not run for 3 minutes or has stopped three stuck tasks in an hour. It changes nothing and resolves itself when none is left.

Nothing deletes data. Every action is a container recreate (never a volume), a Redis requeue, a flag that clears itself, or an interrupted note on a scan that nothing was working on. The AI reviewer may explain what the watchdog did in its diagnosis; no rule depends on it.

### R3 in detail: the layer, and letting go

`resolve()` in `cveFeed/scan_concurrency.py` takes the value saved on the Settings page first, then the environment pin, then the auto-tuner, then the default; so the **saved layer** is the one that beats `.env`, and it is the only one that does. When `DISCOVERY_CONCURRENCY` in `.env` is 1 to 3, R3 saves 4 there through `scan_concurrency.update()` as the system actor `watchdog` (audited, and the live discovery worker is resized at once with Celery's `autoscale`). It never edits `.env`. It does this **only when the value comes from the environment**: a value a person saved in Settings is never overridden (the panel says who saved it and that it is left alone), and a value the auto-tuner chose is left to the auto-tuner.

The override is recorded in `WatchdogState` as the watchdog's, and is **released** (the saved value is cleared, so the auto-tuner takes over) when the environment no longer pins the field (the variable is removed, or raised to 4 or more), and is dropped without touching anything when a person saves a value of their own. The notice and the Health panel say it in these words: *Hosts assessed at once: held by DISCOVERY_CONCURRENCY in .env, raised to 4 by the watchdog*, with how to undo it.

### R10: the check after an action, and the flap guard

Every action is followed by a check. For a host action the clock starts when the host **finished** (its answer file), 2 minutes later; for a local action 2 minutes after it. After a restart the host carried out, the check gives the workers the same warm-up an update gets (10 minutes from when the host finished): a lane that has not answered yet is starting, not unfixed, so the watchdog keeps looking every 30 seconds and escalates only if the symptom is still there when the warm-up ends. A host that refused or failed is checked at once. Two outcomes:

- **Cleared**: a `fixed` line is recorded ("Verified: ...") and the notice becomes an information line that expires after a day.
- **Not cleared**: **one** escalation notice with the evidence and the exact next step ("The workers still do not answer. Next step: run `docker compose restart celery`, then read `docker compose logs --tail 100 celery`"), and the rule stops acting **for an hour** (no restart loops). The row turns red until the symptom goes away.

## What you see

- **Administration, Watchdog** (App Admin; the Scanners page links to it): the **Watchdog** panel: the switch, whether it is ticking, each rule in plain words with a green, amber or red edge and a word (not colour alone), **What the watchdog changed** (the settings it holds that are still in force, with how to undo each) and the **last 20 actions** (when, rule, what happened).
- **The notice strip** (App Admins): one notice per rule that needed acting or could not be fixed, for example *The workers stopped answering at 18:12; the watchdog restarted them at 18:15 and they answer again*, or *The workers stopped answering; the watchdog could not fix it. Next step: run `docker compose restart celery`*. They are `AdminAlert` rows with the code `watchdog_<rule>`; Dismiss works as for any alert, and a dismissed one returns when what it says changes.
- **The activity feed** gets a line for every action and every verified fix, and `WatchdogEvent` (append only, 30 days or 5000 rows) keeps when, rule, observation, action and result. No secrets are written to any of these.

## Settings

| Setting | Where | Default |
| --- | --- | --- |
| **Watchdog** (instance setting) | Administration, Watchdog, the Switch off button; `POST /cve/api/admin/watchdog {"enabled": false}` | on |
| per rule switch | the same panel; `{"rule": "R3", "enabled": false}` | on |
| `CVENGINE_WATCHDOG=0` | `.env` or the environment of the host and the web container | unset (on) |
| `CVENGINE_WATCHDOG_SECONDS` | the host watcher's tick interval, for tests | 30 |

The host keeps limits of its own whatever the web side asks: at least 10 minutes between two restarts of one kind (30 for the prune) and 24 restarts a day (`$STATE/watchdog-actions.log`), so a bug in the web side cannot loop restarts. `$STATE/watchdog.log` (private to the host, trimmed to 1 MB) records every action and every failed tick; `$STATE` is `git rev-parse --git-path cvengine-update`.

## What it does not do

- It does not restart a container you stopped on purpose a minute ago and is gone for good: R1 sees four absent lanes and recreates `celery` after 3 minutes. Stop it first (`CVENGINE_WATCHDOG=0` or the Switch off button) for maintenance that keeps the workers down, or do it while an update holds the stack.
- It does not touch the database container, Redis, the proxy or any volume.
- It does not fix a cause: after a verified fix the notice stays a day so a person can look at why (`docker compose logs celery`). The `workers_down` check of the AI reviewer (every 30 minutes) is a second, slower opinion on the same thing and may show beside it.

See also [UPDATES.md](UPDATES.md#the-watchdog-and-updates), [CONFIGURATION.md](CONFIGURATION.md#watchdog), [PIPELINE.md](PIPELINE.md#how-many-scans-run-at-once), [AI-REVIEWER.md](AI-REVIEWER.md).
