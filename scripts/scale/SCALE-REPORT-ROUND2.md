# Scale round 2: a 2 GB stack at 3000 targets, 50 Sentinels

Synthetic data only (`manage.py seed_scale_fixture --hosts 3000 --targets 3000 --sentinels 10 --tasks 300000 --task-days 7 --secrets 1500`, then 40 more Sentinels). Docker Compose project with moved ports and a private network:
`db` 512 MB (PostgreSQL 18, `shared_buffers` 128 MB, `pg_stat_statements`), `redis` 256 MB, `web` 1 GB (gunicorn, 2 x 8 threads), `celery` 2 GB (the four worker pools), `celery-beat` 256 MB, with the conductor, reaper and report queue running.
Fixture: 3000 targets, 3000 hosts, 9,000 host rows, 18,029 findings, 6,000 CVE matches, 14,997 triage rows, 1,500 secrets, 9,236 scans, 300,000 Sentinel task rows over seven days (270 MB).
Tools: `scripts/scale/measure.py` (Django test client under `CaptureQueriesContext`, cold and warm, `--explain`), `poll_load.py` (10 dashboard tabs), `sentinel_sim.py` (N Sentinels over HTTP: heartbeat, tasks/next, accept, result), `pg_stat_statements`.

## Out of memory: the report PDF

`docker inspect cvscale2-web-1`: `OOMKilled=true`; the container's `memory.events`: `oom_kill 1`. The render child (WeasyPrint) was killed with -9 after 18 s and the user saw "the PDF could not be rendered".
Peak resident memory of the child (unconstrained container, `nice -n 10`, same HTML):

| report | pages | before | after |
|---|---|---|---|
| 500 hosts / 1000 findings (the defaults) | 673 | 975 MB, 24.5 s | 235 MB, 25.0 s |
| 1500 / 1500 | | 1540 MB, 43.8 s | 272 MB, 43.9 s |
| 3000 / 3000 (caps raised) | | 2856 MB, 83.4 s | 351 MB, 81.1 s |

Cause: WeasyPrint lays out the whole document before it writes a page and keeps every page's boxes (about 1.3 MB a page; laid out 860 MB of the 975, writing the PDF added 10). Not the HTML (2.2 MB), not the fonts, not images (there are none). Fix: PR #527 (chunked render, joined with pypdf, real `Page N of Y` stamped on every page, a plain message and the measured peak when it still runs out).

## Per page and API (3000 targets, warm, db 512 MB, workers running)

Slowest of what a person opens, before this round's PRs (no page in the dashboard, hosts, findings, scans, secrets, sentinels-shell, activity, welcome and scan groups exceeded 300 ms warm except these):

| page / API | cold ms / q | warm ms / q |
|---|---|---|
| hosts search page 1 with facets | 549 / 69 | 260 / 59 |
| hosts search q=nginx | 306 / 59 | 299 / 59 |
| hosts list 50 rows | 214 / 57 | 204 / 57 |
| findings page 1 | 213 / 12 | 178 / 12 |
| findings group=cve | 195 / 12 | 188 / 12 |
| matches | 162 / 8 | 123 / 8 |
| dashboard coverage tile | 522 / 58 | 185 / 48 |
| api/stats (cached 10 s) | 618 / 37 | 5.5 / 12 |
| api/graph | 768 / 34 | 7.5 / 7 |
| sentinels/live, 50 Sentinels | 1826 / 567 | 990 / 324 |
| sentinels (project), 50 Sentinels | 691 / 264 | 616 / 264 |
| system/status | 771 / 102 | 334 / 77 |

Everything else (secrets list and detail, scans list, activity feed, welcome progress poll, scan detail, finding detail, Sentinel `sentinel-tasks`) is 3 to 35 ms warm and 8 to 16 queries.
Sentinel API at 50 Sentinels polling every 3 s (short poll, 4,900 requests in 5 minutes): `heartbeat` p50 63 ms, `tasks/next` p50 47 ms, p95 68 ms, no lock waits, no long transactions (`pg_stat_activity`: 1 to 3 active, the rest idle).

## What the database spent (pg_stat_statements, 50 Sentinels + 10 tabs, 180 s)

Five statements of the Sentinels page were 176 s of the 300 s of database time (1: the last five finished tasks of each Sentinel, 17 ms and 27,000 rows read each; 2: the per-Sentinel hour of activity; 3 to 5: the 24 hour counts, the hour's work and claims, each a sequential or bitmap scan of the 300,000-row table). The claim query (`tasks/next`) is 0.06 ms, the reaper's 0.5 ms; they are fine at this size.
Cache hit ratio 65% at 128 MB shared buffers before, 100% after (the indexes and the removal of the scans). `seq_scan` on tables over 10k rows after the fixes: only `startScan_scanhistory` (1,226 scans of 10k rows, about 1 ms each); `agentapi_sentineltask` 0 sequential, 194,804 index scans. Unused indexes over 1 MB: three foreign-key indexes of `agentapi_sentineltask` (2 MB each; kept, they serve cascading deletes). No deadlocks, 6 temp files of 150 KB.
Connections: 5 to 19 per 3 minutes with no persistent connections (CONN_MAX_AGE was 0: a new connection is 3.8 ms and a backend process; PR #531 sets 60 s on the web container only).

## Fixed (PR #530, #531)

| | before | after |
|---|---|---|
| sentinels/live, 50 Sentinels, warm | 990 ms, 324 q | 124 ms, 177 q |
| same under 50 Sentinels + 10 tabs, p50 / p95 | 7782 / 8435 ms | 160 / 440 ms |
| sentinels (project) | 616 ms, 264 q | 95 ms, 117 q |
| system/status warm | 334 ms | 56 ms |
| rows returned by the database in 180 s | 469 M | 84 M |
| web CPU for the polling | 177 s | 49 s, with 1.6x the requests |
| `tasks/next` p50 / p95 | 46.9 / 68.3 ms | 32.4 / 46.1 ms |
| heartbeat p50 | 63 ms | 43 ms |

## Measured and not changed

* `feed_sentinels` at 50 Sentinels (200 slots, 400 host assessments wanted): 5 s and 6,576 statements per minute-round (4 statements per queued assessment). Bounded by the queue target, off the request path.
* `queue_hot_validations` 1.6 s / 606 q, `reconcile_invalid_correlations` 0.3 s / 411 q, `rescore_all_hosts` 3.6 s, daily `triage_sweep` 21 s / 6,064 q (daily, in a worker).
* `report collect` for a whole project 3.2 s / 2,082 statements (482 in round 1 on a different fixture); runs in the report worker, once per report.
* Conductor: one target per project per round (once a minute) by design (fairness between projects): a single project of 3000 targets is rescanned at 1 target a minute, depth 3, `work_min_gap_hours` 2. `next_targets` costs 27 ms at 3000 targets. No thundering herd is possible: a bulk add queues at most `CVENGINE_BULK_DISCOVER_NOW` (50) at once.
* Dispatcher churn under back-pressure: a stage that finds every Sentinel slot taken queues one row and waits at most `CVENGINE_SENTINEL_QUEUE_TIMEOUT` (300 s), then expires it and leaves its target due. Concurrent waiting rows are bounded by the worker pools (discovery 8, feed 4, ...), so at most about 8 x (3600 / 300) = 96 rows an hour per pool: the owner's cvedemo saw 89 in an hour. It does not grow with the number of targets. Left as is; the banner no longer calls these failures.
* Celery: gevent pools have no max-tasks-per-child; prefetch multiplier 1; autoscale (discovery 8, feed 4, validation 1, classic 10). Resident memory over the 30-minute runs: celery 800 to 900 MB, web 250 to 560 MB, db 170 to 460 MB, redis 10 MB; no growth between the three runs. A multi-hour soak was not run.
* One `celery` worker (the classic pool, doing crt.sh lookups of 3000 fake targets before the network was made private) exited with a segmentation fault once in about 25 minutes; the compose file's `restart: always` restarts the container. Not investigated.
