# Scale report: cvENGINE on a 3-core / 7.9 GB host at 500-3000 tracked hosts

Synthetic data only (`manage.py seed_scale_fixture`, example.test names, 192.0.2.x / 198.51.100.x addresses). Measured on one machine
(3 cores, Postgres and Redis in local containers, **no Celery workers running**), one request at a time, nothing else
running. Cold = shared cache emptied first; warm = best of three repeats with the cache filled. "q" = SQL statements, "db ms" = time Django
measured around them.

## Commands (exact)

```
cd <worktree> && source ~/re-tools/test-env.sh && umask 022
export CELERY_BROKER=redis://127.0.0.1:56379/11 CELERY_BACKEND=redis://127.0.0.1:56379/11 PYTHONPATH=$HOME/re-tools/scale-lib \
       SCALE_DB=cv_scale RENGINE_HOME=$PWD/web DB_EXEC="docker exec -i cvt-pg psql -U cvengine_ci -d postgres"
bash scripts/scale/run_matrix.sh <outdir> 500 1000 2000 3000        # seeds each size from a migrated template, runs scripts/scale/measure.py
cd web && python ../scripts/scale/measure.py --label 3000 --out /tmp/x.json --only "q=nginx" --dups   # one entry, with the repeated statements (N+1)
EXPLAIN=1 bash scripts/scale/run_matrix.sh <outdir> 500                                              # EXPLAIN (ANALYZE, BUFFERS) of the 3 slowest SELECTs per entry
python scripts/scale/compare.py ~/re-tools/scale-results/before-clean ~/re-tools/scale-results/after 3000 250                               # before/after rows
```

Fixture at each size (hosts / subdomain rows / vulnerabilities / CVE matches / triage / hygiene): 500 / 1500 / 3004 / 1000 / 2499 / 254;
1000 / 3000 / 6016 / 2000 / 4999 / 512; 2000 / 6000 / 11913 / 4000 / 9995 / 1032; 3000 / 9000 / 18029 / 6000 / 14997 / 1463.

Results: `~/re-tools/scale-results/before` (the first run; its `api/graph` row ran 33 queries where a clean base runs 780-1916, so that tree already held part of the first fix: not used), `before-clean` (origin/1.4-develop + the fixture commit only: **the baseline used below**), `after` (all PRs merged in a local measuring
branch), `after/pr1` (the first PR alone, 500 and 3000).

## Baseline (origin/1.4-develop), 500 and 3000 hosts

| endpoint | hosts | wall ms (cold) | queries | db ms | warm ms / q |
|---|---|---|---|---|---|
| dashboard: dashboard page shell | 500 | 884 | 17 | 22 | 16 / 12 |
| dashboard: dashboard page shell | 3000 | 544 | 17 | 17 | 8 / 12 |
| dashboard: api/stats (headline counts) | 500 | 373 | 38 | 116 | 14 / 12 |
| dashboard: api/stats (headline counts) | 3000 | 342 | 37 | 196 | 7 / 12 |
| dashboard: api/graph (attack-surface map) | 500 | 1018 | 780 | 364 | 6 / 7 |
| dashboard: api/graph (attack-surface map) | 3000 | 1084 | 1916 | 293 | 5 / 7 |
| dashboard: api/graph-live | 500 | 36 | 13 | 14 | 4 / 7 |
| dashboard: api/graph-live | 3000 | 18 | 13 | 2 | 3 / 7 |
| dashboard: api/discovery | 500 | 241 | 15 | 95 | 10 / 12 |
| dashboard: api/discovery | 3000 | 871 | 15 | 835 | 4 / 12 |
| dashboard: api/activity | 500 | 15 | 8 | 6 | 6 / 8 |
| dashboard: api/activity | 3000 | 4 | 8 | 0 | 6 / 8 |
| dashboard: api/feed | 500 | 14 | 7 | 9 | 7 / 7 |
| dashboard: api/feed | 3000 | 6 | 7 | 3 | 6 / 7 |
| dashboard: coverage (search page_size=1) | 500 | 754 | 71 | 201 | 749 / 71 |
| dashboard: coverage (search page_size=1) | 3000 | 2056 | 71 | 376 | 2045 / 71 |
| dashboard: hygiene top (critical) | 500 | 12 | 8 | 4 | 9 / 8 |
| dashboard: hygiene top (critical) | 3000 | 13 | 10 | 5 | 6 / 8 |
| dashboard: changes (page_size=1) | 500 | 13 | 8 | 9 | 6 / 8 |
| dashboard: changes (page_size=1) | 3000 | 6 | 8 | 1 | 3 / 8 |
| dashboard: findings counts (page_size=0) | 500 | 33 | 9 | 12 | 25 / 9 |
| dashboard: findings counts (page_size=0) | 3000 | 25 | 9 | 10 | 19 / 9 |
| dashboard: stats/history | 500 | 10 | 7 | 3 | 6 / 7 |
| dashboard: stats/history | 3000 | 6 | 7 | 2 | 3 / 7 |
| dashboard: scans (page_size=200) | 500 | 16 | 12 | 4 | 13 / 12 |
| dashboard: scans (page_size=200) | 3000 | 11 | 12 | 5 | 10 / 12 |
| hosts: hosts page shell | 500 | 18 | 10 | 9 | 10 / 10 |
| hosts: hosts page shell | 3000 | 6 | 10 | 0 | 5 / 10 |
| hosts: search page 1 (50 rows, facets) | 500 | 932 | 82 | 194 | 760 / 82 |
| hosts: search page 1 (50 rows, facets) | 3000 | 2136 | 82 | 350 | 2424 / 82 |
| hosts: search page 1 (no facets) | 500 | 187 | 57 | 76 | 183 / 59 |
| hosts: search page 1 (no facets) | 3000 | 226 | 57 | 129 | 195 / 57 |
| hosts: search q=nginx | 500 | 370 | 157 | 185 | 372 / 157 |
| hosts: search q=nginx | 3000 | 814 | 157 | 661 | 799 / 157 |
| hosts: hosts list (50 rows) | 500 | 148 | 56 | 54 | 204 / 56 |
| hosts: hosts list (50 rows) | 3000 | 271 | 56 | 96 | 163 / 56 |
| hosts: hosts list page 40 | 500 | 37 | 7 | 17 | 36 / 7 |
| hosts: hosts list page 40 | 3000 | 277 | 56 | 89 | 198 / 56 |
| hosts: targets list | 500 | 24 | 8 | 13 | 21 / 8 |
| hosts: targets list | 3000 | 31 | 8 | 20 | 29 / 8 |
| findings: findings page shell | 500 | 12 | 10 | 4 | 10 / 10 |
| findings: findings page shell | 3000 | 11 | 10 | 5 | 8 / 10 |
| findings: findings (page 1, 50) | 500 | 73 | 12 | 38 | 82 / 12 |
| findings: findings (page 1, 50) | 3000 | 104 | 12 | 79 | 102 / 12 |
| findings: findings (counts only) | 500 | 29 | 9 | 9 | 20 / 9 |
| findings: findings (counts only) | 3000 | 35 | 9 | 17 | 23 / 9 |
| findings: findings group=cve | 500 | 69 | 12 | 35 | 66 / 12 |
| findings: findings group=cve | 3000 | 124 | 12 | 71 | 114 / 12 |
| findings: matches (50) | 500 | 68 | 8 | 34 | 36 / 8 |
| findings: matches (50) | 3000 | 54 | 8 | 38 | 51 / 8 |
| findings: vulnerabilities (50) | 500 | 45 | 11 | 27 | 41 / 11 |
| findings: vulnerabilities (50) | 3000 | 61 | 11 | 46 | 63 / 11 |
| findings: triage (50) | 500 | 20 | 8 | 11 | 21 / 8 |
| findings: triage (50) | 3000 | 46 | 8 | 40 | 43 / 8 |
| polling: sentinels/live | 500 | 131 | 40 | 34 | 72 / 36 |
| polling: sentinels/live | 3000 | 96 | 40 | 31 | 38 / 36 |
| polling: sentinels/live (304 path) | 500 | 55 | 36 | 16 | 36 / 36 |
| polling: sentinels/live (304 path) | 3000 | 64 | 36 | 26 | 37 / 36 |
| polling: api/stats (304 path) | 500 | 14 | 12 | 4 | 11 / 12 |
| polling: api/stats (304 path) | 3000 | 17 | 12 | 7 | 10 / 12 |
| polling: scans (poll) | 500 | 18 | 12 | 8 | 12 / 12 |
| polling: scans (poll) | 3000 | 23 | 12 | 15 | 15 / 12 |
| polling: api/alive | 500 | 4 | 5 | 0 | 3 / 5 |
| polling: api/alive | 3000 | 6 | 5 | 3 | 4 / 5 |
| polling: api/scanner | 500 | 5 | 6 | 0 | 3 / 6 |
| polling: api/scanner | 3000 | 12 | 6 | 7 | 2 / 6 |
| polling: sentinels (project) | 500 | 34 | 24 | 7 | 38 / 24 |
| polling: sentinels (project) | 3000 | 41 | 24 | 16 | 30 / 24 |
| polling: sentinel-tasks | 500 | 14 | 9 | 8 | 10 / 9 |
| polling: sentinel-tasks | 3000 | 7 | 9 | 1 | 5 / 9 |
| polling: system/status | 500 | 5513 | 132 | 118 | 5106 / 98 |
| polling: system/status | 3000 | 5511 | 130 | 198 | 5102 / 98 |
| queue: work_conductor | 500 | 3 | 6 | 0 |  |
| queue: work_conductor | 3000 | 3 | 6 | 1 |  |
| queue: feed_sentinels | 500 | 20 | 16 | 1 |  |
| queue: feed_sentinels | 3000 | 17 | 16 | 1 |  |
| queue: stage_runs_tick | 500 | 1 | 5 | 0 |  |
| queue: stage_runs_tick | 3000 | 1 | 5 | 0 |  |
| queue: reap_stuck_jobs | 500 | 27562 | 22 | 1 |  |
| queue: reap_stuck_jobs | 3000 | 27357 | 22 | 3 |  |
| queue: background_full_scan | 500 | 139 | 12 | 93 |  |
| queue: background_full_scan | 3000 | 439 | 6 | 430 |  |
| queue: weekly_deep_nuclei | 500 | 35 | 13 | 11 |  |
| queue: weekly_deep_nuclei | 3000 | 17 | 13 | 6 |  |
| queue: retest_sweep | 500 | 5 | 8 | 2 |  |
| queue: retest_sweep | 3000 | 2 | 8 | 1 |  |
| queue: top_up_host_assessments | 500 | 1049 | 2116 | 321 |  |
| queue: top_up_host_assessments | 3000 | 1561 | 2116 | 745 |  |
| queue: queue_hot_validations | 500 | 3456 | 2454 | 1801 |  |
| queue: queue_hot_validations | 3000 | 4253 | 2480 | 2262 |  |
| queue: reconcile_invalid_correlations | 500 | 172 | 159 | 59 |  |
| queue: reconcile_invalid_correlations | 3000 | 505 | 597 | 162 |  |
| queue: evaluate_saved_searches | 500 | 7 | 3 | 1 |  |
| queue: evaluate_saved_searches | 3000 | 4 | 3 | 2 |  |
| queue: autotune | 500 | 28 | 44 | 4 |  |
| queue: autotune | 3000 | 1 | 2 | 0 |  |
| queue: report_resources | 500 | 2045 | 7 | 0 |  |
| queue: report_resources | 3000 | 2112 | 7 | 11 |  |
| queue: watch_certificates_all | 500 | 9 | 7 | 1 |  |
| queue: watch_certificates_all | 3000 | 6 | 3 | 1 |  |
| queue: rediscover_archived_hosts | 500 | 7 | 16 | 0 |  |
| queue: rediscover_archived_hosts | 3000 | 14 | 16 | 9 |  |
| queue: review_inactive_hosts | 500 | 7 | 16 | 0 |  |
| queue: review_inactive_hosts | 3000 | 10 | 16 | 4 |  |
| queue: review_unresolved_hosts | 500 | 5 | 16 | 0 |  |
| queue: review_unresolved_hosts | 3000 | 10 | 16 | 4 |  |
| daily: rescore_all_hosts | 500 | 740 | 22 | 89 |  |
| daily: rescore_all_hosts | 3000 | 0 | 2 | 0 |  |
| daily: run_hygiene_all | 500 | 12 | 5 | 3 |  |
| daily: run_hygiene_all | 3000 | 0 | 2 | 0 |  |
| daily: triage_sweep | 500 | 2155 | 541 | 307 |  |
| daily: triage_sweep | 3000 | 0 | 2 | 0 |  |
| daily: snapshot_daily_stats | 500 | 132 | 17 | 53 |  |
| daily: snapshot_daily_stats | 3000 | 249 | 17 | 178 |  |
| daily: validate_sweep | 500 | 11 | 5 | 5 |  |
| daily: validate_sweep | 3000 | 0 | 2 | 0 |  |
| report: collect (project) | 500 | 2081 | 1592 | 593 |  |
| report: collect (project) | 3000 | 1975 | 477 | 869 |  |
| report: collect (one host) | 500 | 212 | 63 | 103 |  |
| report: collect (one host) | 3000 | 249 | 63 | 138 |  |
| report: collect (project, include closed) | 500 | 1561 | 651 | 494 |  |
| report: collect (project, include closed) | 3000 | 1854 | 496 | 818 |  |
| report: build_html (template) | 500 | 78 | 0 | 0 |  |
| report: build_html (template) | 3000 | 67 | 0 | 0 |  |
| report: render_pdf (child process) | 500 | 42863 | 0 | 0 |  |
| report: render_pdf (child process) | 3000 | 39606 | 0 | 0 |  |

## Baseline: how each row grows from 500 to 3000 hosts

Exponent = slope of log(wall ms) on log(hosts): 0 flat, 1 linear, 2 quadratic. **Nothing is quadratic.** What grows, grows at most linearly;
a row whose *query count* grows is an N+1.

| endpoint | wall ms at 500 / 1000 / 2000 / 3000 | queries at 500 / 1000 / 2000 / 3000 | shape (cold wall) |
|---|---|---|---|
| dashboard: dashboard page shell | 884 / 554 / 517 / 544 | 17 / 17 / 17 / 17 | flat |
| dashboard: api/stats (headline counts) | 373 / 209 / 240 / 342 | 38 / 38 / 37 / 37 | flat |
| dashboard: api/graph (attack-surface map) | 1018 / 816 / 1228 / 1084 | 780 / 1253 / 1939 / 1916 | queries grow with hosts (N+1), exp 0.53 |
| dashboard: api/graph-live | 36 / 11 / 18 / 18 | 13 / 13 / 13 / 13 | cheap |
| dashboard: api/discovery | 241 / 172 / 375 / 871 | 15 / 15 / 15 / 15 | ~linear (exp 0.72) |
| dashboard: api/activity | 15 / 6 / 5 / 4 | 8 / 8 / 8 / 8 | cheap |
| dashboard: api/feed | 14 / 4 / 5 / 6 | 7 / 7 / 7 / 7 | cheap |
| dashboard: coverage (search page_size=1) | 754 / 830 / 1563 / 2056 | 71 / 71 / 71 / 71 | ~linear (exp 0.59) |
| dashboard: hygiene top (critical) | 12 / 14 / 10 / 13 | 8 / 8 / 8 / 10 | cheap |
| dashboard: changes (page_size=1) | 13 / 9 / 6 / 6 | 8 / 8 / 8 / 8 | cheap |
| dashboard: findings counts (page_size=0) | 33 / 16 / 24 / 25 | 9 / 9 / 9 / 9 | cheap |
| dashboard: stats/history | 10 / 13 / 5 / 6 | 7 / 7 / 7 / 7 | cheap |
| dashboard: scans (page_size=200) | 16 / 8 / 15 / 11 | 12 / 12 / 12 / 12 | cheap |
| hosts: hosts page shell | 18 / 9 / 7 / 6 | 10 / 10 / 10 / 10 | cheap |
| hosts: search page 1 (50 rows, facets) | 932 / 849 / 1842 / 2136 | 82 / 82 / 82 / 82 | ~linear (exp 0.53) |
| hosts: search page 1 (no facets) | 187 / 155 / 209 / 226 | 57 / 57 / 57 / 57 | flat |
| hosts: search q=nginx | 370 / 632 / 583 / 814 | 157 / 157 / 157 / 157 | ~linear (exp 0.37) |
| hosts: hosts list (50 rows) | 148 / 142 / 263 / 271 | 56 / 56 / 56 / 56 | ~linear (exp 0.40) |
| hosts: hosts list page 40 | 37 / 45 / 60 / 277 | 7 / 7 / 7 / 56 | queries grow with hosts (N+1), exp 0.92 |
| hosts: targets list | 24 / 27 / 30 / 31 | 8 / 8 / 8 / 8 | cheap |
| findings: findings page shell | 12 / 6 / 10 / 11 | 10 / 10 / 10 / 10 | cheap |
| findings: findings (page 1, 50) | 73 / 70 / 86 / 104 | 12 / 12 / 12 / 12 | flat |
| findings: findings (counts only) | 29 / 19 / 19 / 35 | 9 / 9 / 9 / 9 | cheap |
| findings: findings group=cve | 69 / 66 / 101 / 124 | 12 / 12 / 12 / 12 | ~linear (exp 0.35) |
| findings: matches (50) | 68 / 38 / 52 / 54 | 8 / 8 / 8 / 8 | flat |
| findings: vulnerabilities (50) | 45 / 35 / 56 / 61 | 11 / 11 / 11 / 11 | flat |
| findings: triage (50) | 20 / 24 / 45 / 46 | 8 / 8 / 8 / 8 | cheap |
| polling: sentinels/live | 131 / 60 / 52 / 96 | 40 / 40 / 40 / 40 | flat |
| polling: sentinels/live (304 path) | 55 / 33 / 39 / 64 | 36 / 36 / 36 / 36 | flat |
| polling: api/stats (304 path) | 14 / 10 / 10 / 17 | 12 / 12 / 12 / 12 | cheap |
| polling: scans (poll) | 18 / 9 / 10 / 23 | 12 / 12 / 12 / 12 | cheap |
| polling: api/alive | 4 / 5 / 4 / 6 | 5 / 5 / 5 / 5 | cheap |
| polling: api/scanner | 5 / 4 / 8 / 12 | 6 / 6 / 6 / 6 | cheap |
| polling: sentinels (project) | 34 / 42 / 26 / 41 | 24 / 24 / 24 / 24 | cheap |
| polling: sentinel-tasks | 14 / 6 / 9 / 7 | 9 / 9 / 9 / 9 | cheap |
| polling: system/status | 5513 / 5345 / 5498 / 5511 | 132 / 132 / 130 / 130 | flat |
| queue: work_conductor | 3 / 5 / 5 / 3 | 6 / 6 / 6 / 6 | cheap |
| queue: feed_sentinels | 20 / 21 / 19 / 17 | 16 / 16 / 16 / 16 | cheap |
| queue: stage_runs_tick | 1 / 1 / 1 / 1 | 5 / 5 / 5 / 5 | cheap |
| queue: reap_stuck_jobs | 27562 / 27250 / 27518 / 27357 | 22 / 22 / 22 / 22 | flat |
| queue: background_full_scan | 139 / 166 / 224 / 439 | 12 / 12 / 6 / 6 | ~linear (exp 0.59) |
| queue: weekly_deep_nuclei | 35 / 14 / 23 / 17 | 13 / 13 / 13 / 13 | cheap |
| queue: retest_sweep | 5 / 5 / 3 / 2 | 8 / 8 / 8 / 8 | cheap |
| queue: top_up_host_assessments | 1049 / 1074 / 1112 / 1561 | 2116 / 2118 / 2116 / 2116 | flat |
| queue: queue_hot_validations | 3456 / 3602 / 3456 / 4253 | 2454 / 2421 / 2447 / 2480 | flat |
| queue: reconcile_invalid_correlations | 172 / 533 / 492 / 505 | 159 / 659 / 587 / 597 | queries grow with hosts (N+1), exp 0.67 |
| queue: evaluate_saved_searches | 7 / 9 / 3 / 4 | 3 / 3 / 3 / 3 | cheap |
| queue: autotune | 28 / 40 / 0 / 1 | 44 / 40 / 2 / 2 | cheap |
| queue: report_resources | 2045 / 2094 / 2024 / 2112 | 7 / 7 / 7 / 7 | flat |
| queue: watch_certificates_all | 9 / 15 / 3 / 6 | 7 / 7 / 3 / 3 | cheap |
| queue: rediscover_archived_hosts | 7 / 9 / 5 / 14 | 16 / 16 / 16 / 16 | cheap |
| queue: review_inactive_hosts | 7 / 15 / 8 / 10 | 16 / 16 / 16 / 16 | cheap |
| queue: review_unresolved_hosts | 5 / 14 / 4 / 10 | 16 / 16 / 16 / 16 | cheap |
| daily: rescore_all_hosts | 740 / 1555 / 0 / 0 | 22 / 40 / 2 / 2 | flat |
| daily: run_hygiene_all | 12 / 11 / 4 / 0 | 5 / 5 / 2 / 2 | cheap |
| daily: triage_sweep | 2155 / 2465 / 0 / 0 | 541 / 545 / 2 / 2 | flat |
| daily: snapshot_daily_stats | 132 / 134 / 152 / 249 | 17 / 17 / 17 / 17 | ~linear (exp 0.31) |
| daily: validate_sweep | 11 / 19 / 0 / 0 | 5 / 5 / 2 / 2 | cheap |
| report: collect (project) | 2081 / 1545 / 1601 / 1975 | 1592 / 375 / 353 / 477 | flat |
| report: collect (one host) | 212 / 209 / 199 / 249 | 63 / 66 / 66 / 63 | flat |
| report: collect (project, include closed) | 1561 / 1595 / 1819 / 1854 | 651 / 389 / 367 / 496 | flat |
| report: build_html (template) | 78 / 69 / 70 / 67 | 0 / 0 / 0 / 0 | flat |
| report: render_pdf (child process) | 42863 / 38984 / 38946 / 39606 | 0 / 0 / 0 / 0 | flat |

Reading it:

* **Linear in hosts, cold and warm (nothing cached):** the host search with facets (0.93 s -> 2.1 s), the dashboard coverage tile
  (0.75 s -> 2.1 s, it is the same search with `page_size=1`), `search q=nginx` (0.37 -> 0.81 s), `api/discovery` cold (0.24 -> 0.87 s).
* **N+1 that grows with hosts:** `api/graph` ran 780 / 1253 / 1939 / 1916 queries (about 0.6 per host); `hosts list page 40` only looks
  like growth (the page is empty below 2000 hosts).
* **Flat but too big, independent of host count:** report `collect` (capped at 500 hosts / 1000 findings: 350-480 statements, 1.5-2 s),
  `render_pdf` (about 40 s at every size, because the report is capped at the same ~440 pages), `queue_hot_validations` (2,450 statements, 3.5 s,
  a fixed batch), `top_up_host_assessments` (2,116 statements, 1 s).
* **Flat artifacts of measuring without workers:** `system/status` 5.4 s (`app.control.inspect(timeout=5)` in `cveFeed/admin_api.py`),
  `reap_stuck_jobs` 27 s (three 3 s `inspect` calls and more in `cveFeed/broker_recovery.py` waiting for workers that are not there),
  `report_resources` 2 s. They do not depend on hosts; with workers up the replies are milliseconds. Not measured with workers.
* `daily:` rows show 0 ms from 2000 hosts on (1000 for `triage_sweep`): those tasks guard themselves, so the run is not a measurement there.

## Why the PDF took 40 s

cProfile of the child process (`python -m cveFeed.report_render`) on the 3000-host fixture: 438 pages, 62 s under the profiler, 53 s in WeasyPrint
layout. 27 s of that was `layout/grid.py` (3,023 calls): every `dl.kv` key/value list of the template (one per finding, per host, per tracking box,
3,001 in all) was `display: grid`, and WeasyPrint measures min and max content of every cell of a grid. A further 14 s was
`text/line_break.get_first_line` called 1.07 million times from min-content width computations, which `overflow-wrap: anywhere` on the whole
body forces. Not the query volume (the report's data is built in 2 s before the child starts), not the template render (70 ms), not process
start. The fix (PR #492): inline blocks for `dl.kv` (the text keeps its reading order) and `anywhere` only on table cells.
40 s -> 23 s for the same 460 pages. What is left is about 50 ms per page of ordinary layout.

## Fixes and measured effect (before-clean vs after, cold / warm)

Rows that moved or stay above 250 ms. Each fix has a query-count regression test (see the PR list).

| endpoint | hosts | before cold ms / q / db ms | after cold ms / q / db ms | before warm ms / q | after warm ms / q |
|---|---|---|---|---|---|
| dashboard: dashboard page shell | 500 | 884 / 17 / 22 | 511 / 17 / 18 | 16 / 12 | 6 / 12 |
| dashboard: dashboard page shell | 1000 | 554 / 17 / 17 | 570 / 17 / 14 | 7 / 12 | 6 / 12 |
| dashboard: dashboard page shell | 2000 | 517 / 17 / 6 | 508 / 17 / 13 | 8 / 12 | 12 / 12 |
| dashboard: dashboard page shell | 3000 | 544 / 17 / 17 | 546 / 17 / 12 | 8 / 12 | 7 / 12 |
| dashboard: api/stats (headline counts) | 500 | 373 / 38 / 116 | 220 / 38 / 85 | 14 / 12 | 6 / 12 |
| dashboard: api/stats (headline counts) | 2000 | 240 / 37 / 139 | 254 / 37 / 159 | 7 / 12 | 8 / 12 |
| dashboard: api/stats (headline counts) | 3000 | 342 / 37 / 196 | 365 / 37 / 204 | 7 / 12 | 7 / 12 |
| dashboard: api/graph (attack-surface map) | 500 | 1018 / 780 / 364 | 225 / 33 / 58 | 6 / 7 | 5 / 7 |
| dashboard: api/graph (attack-surface map) | 1000 | 816 / 1253 / 206 | 402 / 34 / 99 | 8 / 7 | 10 / 7 |
| dashboard: api/graph (attack-surface map) | 2000 | 1228 / 1939 / 314 | 542 / 34 / 154 | 14 / 7 | 6 / 7 |
| dashboard: api/graph (attack-surface map) | 3000 | 1084 / 1916 / 293 | 513 / 34 / 181 | 5 / 7 | 5 / 7 |
| dashboard: api/discovery | 2000 | 375 / 15 / 341 | 58 / 15 / 36 | 8 / 12 | 8 / 12 |
| dashboard: api/discovery | 3000 | 871 / 15 / 835 | 83 / 15 / 53 | 4 / 12 | 6 / 12 |
| dashboard: coverage (search page_size=1) | 500 | 754 / 71 / 201 | 475 / 74 / 127 | 749 / 71 | 74 / 48 |
| dashboard: coverage (search page_size=1) | 1000 | 830 / 71 / 176 | 793 / 74 / 166 | 812 / 71 | 86 / 48 |
| dashboard: coverage (search page_size=1) | 2000 | 1563 / 71 / 271 | 1315 / 74 / 272 | 1527 / 71 | 131 / 48 |
| dashboard: coverage (search page_size=1) | 3000 | 2056 / 71 / 376 | 1933 / 74 / 362 | 2045 / 71 | 155 / 48 |
| hosts: search page 1 (50 rows, facets) | 500 | 932 / 82 / 194 | 540 / 85 / 128 | 760 / 82 | 134 / 59 |
| hosts: search page 1 (50 rows, facets) | 1000 | 849 / 82 / 170 | 918 / 85 / 167 | 920 / 82 | 156 / 59 |
| hosts: search page 1 (50 rows, facets) | 2000 | 1842 / 82 / 292 | 1462 / 85 / 277 | 1772 / 82 | 190 / 59 |
| hosts: search page 1 (50 rows, facets) | 3000 | 2136 / 82 / 350 | 2115 / 85 / 350 | 2424 / 82 | 209 / 59 |
| hosts: search q=nginx | 500 | 370 / 157 / 185 | 254 / 59 / 157 | 372 / 157 | 268 / 59 |
| hosts: search q=nginx | 1000 | 632 / 157 / 285 | 495 / 59 / 304 | 384 / 157 | 361 / 59 |
| hosts: search q=nginx | 2000 | 583 / 157 / 442 | 568 / 59 / 460 | 613 / 157 | 550 / 59 |
| hosts: search q=nginx | 3000 | 814 / 157 / 661 | 739 / 59 / 645 | 799 / 157 | 741 / 59 |
| hosts: hosts list (50 rows) | 2000 | 263 / 56 / 84 | 305 / 57 / 96 | 148 / 56 | 168 / 57 |
| hosts: hosts list (50 rows) | 3000 | 271 / 56 / 96 | 173 / 57 / 83 | 163 / 56 | 162 / 57 |
| hosts: hosts list page 40 | 3000 | 277 / 56 / 89 | 270 / 57 / 103 | 198 / 56 | 159 / 57 |
| polling: system/status | 500 | 5513 / 132 / 118 | 5379 / 132 / 92 | 5106 / 98 | 5211 / 98 |
| polling: system/status | 1000 | 5345 / 132 / 109 | 5372 / 130 / 138 | 5194 / 96 | 5122 / 96 |
| polling: system/status | 2000 | 5498 / 130 / 182 | 5371 / 130 / 183 | 5203 / 96 | 5126 / 98 |
| polling: system/status | 3000 | 5511 / 130 / 198 | 5485 / 130 / 235 | 5102 / 98 | 5124 / 98 |
| queue: reap_stuck_jobs | 500 | 27562 / 22 / 1 | 27387 / 22 / 3 |  |  |
| queue: reap_stuck_jobs | 1000 | 27250 / 22 / 6 | 27652 / 22 / 7 |  |  |
| queue: reap_stuck_jobs | 2000 | 27518 / 22 / 1 | 27412 / 22 / 3 |  |  |
| queue: reap_stuck_jobs | 3000 | 27357 / 22 / 3 | 27470 / 22 / 1 |  |  |
| queue: background_full_scan | 3000 | 439 / 6 / 430 | 426 / 6 / 413 |  |  |
| queue: top_up_host_assessments | 500 | 1049 / 2116 / 321 | 759 / 2116 / 111 |  |  |
| queue: top_up_host_assessments | 1000 | 1074 / 2118 / 355 | 1068 / 2116 / 348 |  |  |
| queue: top_up_host_assessments | 2000 | 1112 / 2116 / 449 | 1035 / 2116 / 283 |  |  |
| queue: top_up_host_assessments | 3000 | 1561 / 2116 / 745 | 1227 / 2116 / 585 |  |  |
| queue: queue_hot_validations | 500 | 3456 / 2454 / 1801 | 3068 / 2454 / 1573 |  |  |
| queue: queue_hot_validations | 1000 | 3602 / 2421 / 1900 | 3664 / 2420 / 1984 |  |  |
| queue: queue_hot_validations | 2000 | 3456 / 2447 / 1810 | 3352 / 2447 / 1773 |  |  |
| queue: queue_hot_validations | 3000 | 4253 / 2480 / 2262 | 4003 / 2480 / 2160 |  |  |
| queue: reconcile_invalid_correlations | 1000 | 533 / 659 / 160 | 416 / 659 / 52 |  |  |
| queue: reconcile_invalid_correlations | 2000 | 492 / 587 / 167 | 604 / 587 / 258 |  |  |
| queue: reconcile_invalid_correlations | 3000 | 505 / 597 / 162 | 522 / 597 / 135 |  |  |
| queue: report_resources | 500 | 2045 / 7 / 0 | 2070 / 7 / 0 |  |  |
| queue: report_resources | 1000 | 2094 / 7 / 0 | 2094 / 7 / 1 |  |  |
| queue: report_resources | 2000 | 2024 / 7 / 4 | 2038 / 7 / 2 |  |  |
| queue: report_resources | 3000 | 2112 / 7 / 11 | 2034 / 7 / 1 |  |  |
| daily: rescore_all_hosts | 500 | 740 / 22 / 89 | 781 / 22 / 87 |  |  |
| daily: rescore_all_hosts | 1000 | 1555 / 40 / 200 | 0 / 2 / 0 |  |  |
| daily: triage_sweep | 500 | 2155 / 541 / 307 | 1783 / 541 / 249 |  |  |
| daily: triage_sweep | 1000 | 2465 / 545 / 345 | 0 / 2 / 0 |  |  |
| report: collect (project) | 500 | 2081 / 1592 / 593 | 1787 / 1596 / 473 |  |  |
| report: collect (project) | 1000 | 1545 / 375 / 624 | 1296 / 380 / 424 |  |  |
| report: collect (project) | 2000 | 1601 / 353 / 644 | 1726 / 358 / 698 |  |  |
| report: collect (project) | 3000 | 1975 / 477 / 869 | 1744 / 482 / 827 |  |  |
| report: collect (one host) | 3000 | 249 / 63 / 138 | 310 / 64 / 124 |  |  |
| report: collect (project, include closed) | 500 | 1561 / 651 / 494 | 1338 / 656 / 406 |  |  |
| report: collect (project, include closed) | 1000 | 1595 / 389 / 580 | 1341 / 394 / 474 |  |  |
| report: collect (project, include closed) | 2000 | 1819 / 367 / 841 | 1650 / 372 / 761 |  |  |
| report: collect (project, include closed) | 3000 | 1854 / 496 / 818 | 1751 / 501 / 828 |  |  |
| report: render_pdf (child process) | 500 | 42863 / 0 / 0 | 23037 / 0 / 0 |  |  |
| report: render_pdf (child process) | 1000 | 38984 / 0 / 0 | 21406 / 0 / 0 |  |  |
| report: render_pdf (child process) | 2000 | 38946 / 0 / 0 | 22645 / 0 / 0 |  |  |
| report: render_pdf (child process) | 3000 | 39606 / 0 / 0 | 22646 / 0 / 0 |  |  |

## Pull requests

| PR | branch | what | regression test |
|---|---|---|---|
| #490 | claude/scale-srv | fixture + matrix; host search whole-match counts (heat chips, unscannable split, facets) served from `snapshot_cache` for `max(15 s, 10 x what the walk cost)` up to 120 s, dropped by a revision bump; `graph_payload` N+1 (match and triage columns it read after `only()`) | tests/test_scale_search_facets.py (fixed warm cost, scoping, revision bump, freshness, graph query count: 44 vs 19 without the fix) |
| #492 | claude/scale-2-srv | report PDF layout | tests/test_scale_report_render.py (no grid, `anywhere` only in table cells, sanity render) |
| #493 | claude/scale-3-srv | live ticker counts, 3 nested window queries -> 1 walk + 2 id queries | tests/test_scale_discovery_counts.py |
| #495 | claude/scale-4-srv | host search page: route/archive/nuclei lookups per page instead of per row | tests/test_scale_search_matched.py |

## What remains slow at 3000 hosts (evidence)

1. **Host search / coverage tile, cold: 2.1 s** (warm 0.15-0.2 s, cached for 15-120 s). `_heat_facets` walks every matching host with 12 prefetches:
   cProfile 3.4 s of 4.5 s inside it, 30,800 queryset evaluations and 64,500 model instances hydrated for 3000 hosts (22 per host); ORM
   hydration, not SQL (db 0.35 s). Fixing it means computing heat in SQL or caching it per host, a design change, not an N+1.
2. **The one-row-per-host collapse (`_one_per_host`, `cveFeed.counts.host_reps`)** is a window query with correlated subqueries per
   subdomain row: 70-300 ms each at 9,000 rows, run twice by a search (count + page: 608 of 675 ms of `q=nginx`), twice by `api/stats`
   (166 of 280 ms), once by graph and discovery. `q=nginx` still 0.74 s, `api/stats` cold 0.37 s.
3. **PDF 23 s** for a capped 460-page report, in a child process (no worker stall). Levers are the existing caps
   (`CVENGINE_REPORT_MAX_FINDINGS` 1000, `_HOSTS` 500) or a lower default.
4. **report `collect` 1.7-2 s, 480 statements**: 50 "how to confirm" guides (`confirm_guide.match_guide`) each run 4-5 small queries
   (CVEDetection, IpAddress, ports, probes, routes). Bounded by the 500/1000 caps, not by host count.
5. **Background tasks:** `queue_hot_validations` 4.0 s / 2,480 statements, `top_up_host_assessments` 1.2 s / 2,116, `reconcile_invalid_correlations`
   0.5 s / 597 (queries grow 159 -> 659 -> 597 with hosts), `background_full_scan` 0.43 s (linear, 413 ms in one statement).
6. `system/status` 5.4 s and `reap_stuck_jobs` 27 s are inspect timeouts without workers (see above); unmeasured with workers.
7. Missing indexes: none found. The 500-host EXPLAIN shows sequential scans only on tables of under 100 rows; not re-run with EXPLAIN at 3000.
