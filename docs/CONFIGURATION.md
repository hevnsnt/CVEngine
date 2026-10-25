# Configuration

Every value in `.env` reaches the `web`, `celery`, and `celery-beat` containers. To change a setting, add a line such as `CVENGINE_TTL_NUCLEI=48` to `.env` and run `make up`. This needs Docker Compose 2.24 or newer. A few values are set by the compose files on purpose and cannot be overridden: the broker URLs, `DEBUG`, and the `POSTGRES_*` values. Avoid `#` and `$` in passwords, because `make` and Compose both parse `.env`.

## Basics

| Variable | Purpose |
| --- | --- |
| `DOMAIN_NAME` | A bare hostname such as `scanner.example.com`. It is the certificate name and the host in notification links. |
| `CVENGINE_ALLOWED_HOSTS` | Optional comma-separated additional hostnames accepted by Django, for example a second public name behind a trusted proxy. The configured `DOMAIN_NAME` and loopback health checks are accepted automatically; any other name or IP address gets 400 Bad Request (see [UPGRADE.md](UPGRADE.md#accepted-host-names)). Do not use `*` on an Internet-facing installation. |
| `CVENGINE_HSTS_SECONDS` | HTTPS browser policy lifetime in seconds (default 3600 in production, 0 in development). Increase it only after confirming every public route reliably uses HTTPS; no subdomain or preload policy is set automatically. |
| `POSTGRES_PASSWORD` | Database password. Set it before the first start. |
| `AUTHORITY_PASSWORD` | Passed to the certificate authority step of `make certs`. The key is stored in `secrets/certs/`, so protect that directory. |
| `DJANGO_SUPERUSER_USERNAME`, `_EMAIL`, `_PASSWORD` | Used by `make username isNonInteractive=true` and `sudo ./install.sh -n`. A plain `make username` asks instead. |
| `COMPOSE_PROJECT_NAME`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_HOST`, `POSTGRES_PORT` | Name the Docker volumes and the database. Change them only before the first start. |
| `AUTHORITY_NAME`, `COMPANY`, `COUNTRY_CODE`, `STATE`, `CITY` | Subject of the certificates `make certs` creates. |

## Memory and workers

| Variable | Default | Purpose |
| --- | --- | --- |
| `CELERY_MEM_LIMIT` | `4g` | Memory limit for the scan workers. About 55% of the machine's RAM works well. |
| `WEB_MEM_LIMIT`, `BEAT_MEM_LIMIT` | `1g`, `512m` | Limits for the web container and the scheduler. |
| `DISCOVERY_CONCURRENCY` | `3` | Most discovery tasks at once. Lower it on small machines. |
| `CLASSIC_CONCURRENCY` | `20` | Most tasks at once across all other queues. The CVE feed worker is fixed at 4. |
| `HEAVY_MEMORY_BUDGET_MB` | 75% of the limit | Memory the job queue can hand out at once. |
| `HEAVY_HEADROOM_MB` | larger of 256 and 5% | Free memory kept in reserve. |
| `HEAVY_COST_SCALE` | `1` | Multiplies the estimated memory cost of every job kind. |
| `HEAVY_COST_<KIND>_MB` | none | Sets the cost of one job kind, replacing the built-in and learned estimates. |
| `HEAVY_MAX_<KIND>` | 1 to 3 | How many jobs of a kind run at once. 1 for nuclei, naabu, and bbot deep. 2 for nmap, bbot standard, and bbot passive. 3 for template tests. |
| `HEAVY_TUNE_MIN_<KIND>`, `HEAVY_TUNE_MAX_<KIND>` | `1`, the `HEAVY_MAX` value | The range the three-hour AI review may move a kind's concurrency within. Raise the maximum to let it scale up. |
| `HEAVY_WAIT_SECONDS` | `86400` | How long a job waits for its turn. |
| `CELERY_VISIBILITY_TIMEOUT` | `43200` | Seconds before an unacknowledged job goes to another worker. |

`<KIND>` is the job kind in capitals with `-` written as `_`: `BBOT_DEEP`, `BBOT_STANDARD`, `BBOT_PASSIVE`, `NUCLEI`, `NUCLEI_LIGHT`, `NMAP`, `NAABU`, `TEMPLATE_TEST`. Each estimate starts at a built-in guess and then follows the peak a job actually reached on your server, plus 20%. **Settings, Resources** shows the current figures.

## Scanner windows and limits

A scanner skips a host it covered inside its window. Hours unless noted.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_TTL_NMAP_FAST` | `168` | nmap fingerprint of an IP. |
| `CVENGINE_BOUNTY_CATALOGUE` | `1` | Set to `0` to stop CVEngine from fetching the public bug bounty program data (and to disable the page's load button). Nothing is fetched until someone loads the catalogue once. |
| `CVENGINE_CVE_COVERAGE_DAYS` | `14` | How many days of the cve.now feed the hourly coverage task keeps stored. `0` turns it off. |
| `CVENGINE_INTEL` | `1` | `0` turns off the threat-intelligence sources (CISA KEV, ENISA EUVD, EPSS, Exploit-DB, Metasploit). See [PIPELINE.md](PIPELINE.md#cve-intelligence). |
| `CVENGINE_INTEL_SOURCES` | all | Comma-separated subset of `cisa_kev,euvd,vulncheck_kev,epss,exploit_db,metasploit`. |
| `CVENGINE_VULNCHECK_API_KEY` | none | A free VulnCheck community key adds VulnCheck KEV (about 80% more exploited CVEs than CISA). |
| `CVENGINE_INTEL_IMPORT`, `CVENGINE_INTEL_IMPORT_PER_RUN` | `kev,metasploit,epss,exploit_db`, `2000` | Which groups of missing CVEs are imported from the CVE List, in that order, and how many per hourly run (`0` imports none and only updates the signals of stored CVEs). |
| `CVENGINE_INTEL_DIR` | `/usr/src/scan_results/.threat-intel` | Where the downloaded source files are cached between runs. |
| `CVENGINE_CVE_WATCH_TECHS` | `php` | Technology slugs whose cve.now feed the coverage task reads, comma separated. |
| `CVENGINE_TTL_BBOT`, `CVENGINE_TTL_BBOT_DEEP` | `168` | Discovery of a target, and deep discovery of an apex domain. |
| `CVENGINE_TTL_NUCLEI`, `_NUCLEI_LIGHT`, `_NUCLEI_CVE` | `24` | Full, light, and CVE template runs per host. |
| `CVENGINE_TTL_NUCLEI_DEEP_HOST`, `_NUCLEI_DEEP_TARGET` | `168` | Successful paced deep Nuclei host and individual target coverage, in hours. |
| `CVENGINE_TTL_ROUTE_AUTH` | `168` | Web route auth check. |
| `CVENGINE_TTL_CT_WATCH`, `CVENGINE_TTL_HYGIENE` | `24` | Certificate watch and hygiene sweep. |
| `CVENGINE_TTL_VALIDATE` | `24` | A validation check for a finding. |
| `CVENGINE_DEEP_SWEEP_MAX` | `50` | Apex domains the daily sweep queues per run. |
| `CVENGINE_FULLSCAN` | `1` | Set to `0` to turn off the background full port scan. |
| `CVENGINE_FULLSCAN_INTERVAL_MIN`, `_BATCH`, `_INVESTIGATE_MAX` | `10`, `1`, `50` | Minutes between sweeps (read when the schedule is created), IPs per sweep, and new ports fingerprinted per sweep. |
| `CVENGINE_NAABU` | `0` | Set to `1` to run a naabu full-port discovery before nmap. |
| `CVENGINE_NAABU_BIN`, `CVENGINE_NAABU_RATE`, `CVENGINE_TTL_NAABU` | `naabu`, `1000`, `168` | The binary, packets per second (100 to 5000), and how long an IP's result stays fresh. |
| `CVENGINE_HYGIENE_RDAP` | `1` | Set to `0` to skip the registry (RDAP) lookups that check whether SPF includes and DMARC report domains are registered. |
| `CVENGINE_TRIAGE_MAX_PER_RUN`, `_PER_PROJECT_DAY`, `_PER_DAY` | `100`, `500`, `2000` | AI triage questions per run, per project per day, and per day. One question serves every finding with the same evidence. |
| `CVENGINE_VALIDATE_MAX_PER_RUN`, `_PER_PROJECT_DAY`, `_PER_DAY` | `50`, `300`, `1500` | Validation checks per task, per project per day, and per day. |
| `CVENGINE_TEMPLATE_GEN_MAX_PER_DAY`, `CVENGINE_TEMPLATE_GEN_CVE_DAYS` | `10`, `7` | AI-written nuclei checks: at most this many attempts in any 24 hours across all projects, and one attempt per CVE in this many days, whatever its outcome. |
| `CVENGINE_RETEST_MAX_HOSTS` | `25` | Hosts re-tested in one batch. A batch serves the project whose re-tests were dispatched longest ago, hottest hosts first, so one large discovery cannot starve the other projects. The rest wait for the five-minute sweep. |
| `CVENGINE_CHANGES_RETENTION_DAYS` | `90` | Days the Changes log is kept. |
| `CVENGINE_ACTIVITY_RETENTION_DAYS`, `CVENGINE_TRIAGE_CALL_RETENTION_DAYS`, `CVENGINE_AI_USAGE_RETENTION_DAYS` | `30`, `90`, `400` | Days the AI activity feed, the AI call leases and the AI usage ledger are kept. Every Sunday at 03:23 UTC the older rows are written to `cvengine-logs-<time>.tar.gz` (one JSON object per line per table) and only then deleted. The run is logged in the activity feed, and nothing is deleted if the archive cannot be written. |
| `CVENGINE_LOG_ARCHIVE_DIR`, `CVENGINE_LOG_ARCHIVE_DAYS` | `/usr/src/scan_results/.log-archives`, `365` | Where those archives go (on the scan results volume; only a superuser can download them), and how long they are kept. |
| `CVENGINE_ASSESSMENT_QUEUED_HOURS`, `CVENGINE_ASSESSMENT_RUNNING_HOURS`, `CVENGINE_VALIDATION_QUEUED_HOURS`, `CVENGINE_VALIDATION_RUNNING_HOURS` | `12`, `6`, `6`, `2` | After this long a host assessment or validation job still queued or running is marked failed ("expired"), freeing its slot and its share of the caps. The check runs every 15 minutes. A validation job with attempts left becomes due again at once. Queued jobs are left alone while scanning is paused. |
| `CVENGINE_SHOT_THRESHOLD` | `12` | Bits (of 64) by which screenshot hashes must differ to count as a changed front page. |

## Updates

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_COMPOSE_FILES` | `docker-compose.yml` | Compose files `scripts/update.sh` uses, comma separated. See [custom Compose layouts](UPDATES.md#custom-compose-layouts). |
| `CVENGINE_COMPOSE_ENV_FILE`, `CVENGINE_COMPOSE_PROJECT` | none | The Compose `--env-file` and project name, when your install uses them. |
| `CVENGINE_UPDATE_DRAIN_SECONDS` | `10800` | Longest wait for active tasks before an update gives up without stopping them. |
| `CVENGINE_UPDATE_READY_SECONDS` | `600` | Longest wait for the site, workers, and scheduler after an update. |
| `CVENGINE_UPDATE_STOP_SCANS` | `0` | Set to `1` to make every update stop scans and queue them again, as `--stop-scans` does. |
| `CVENGINE_AUTO_DEPLOY_BACKUPS` | `7` | Database backups automatic deployment keeps. `0` skips the backup. |
| `CVENGINE_AUTO_DEPLOY_RETRY_SECONDS` | `3600` | Wait before automatic deployment retries a commit that failed. |
| `CVENGINE_AUTO_DEPLOY_DRAIN_SECONDS` | `1800` | Longest wait for active tasks during an automatic deployment. |
| `CVENGINE_AUTO_DEPLOY_INTERVAL` | `3min` | How often the timer checks `master`, set when running `scripts/install-auto-deploy.sh`. |

## Web server

The production `web` container runs gunicorn. The development compose file keeps Django's auto-reloading server.

| Variable | Default | Purpose |
| --- | --- | --- |
| `GUNICORN_WORKERS` | `2` | Worker processes. The production compose file pins this value. Lockout counters live in the shared Redis cache, so extra workers do not add attempts. |
| `GUNICORN_THREADS` | `8` | Threads per worker. |
| `GUNICORN_TIMEOUT` | `300` | Seconds before a stuck request is stopped. Matches the proxy read timeout. |
| `CACHE_URL` | broker URL, next database | Redis URL of the shared cache. Keep it apart from the Celery broker's database, because a factory reset clears it. |

## Templates and secrets

| Variable | Default | Purpose |
| --- | --- | --- |
| `NUCLEI_TEMPLATES_DIR` | `/root/nuclei-templates` | nuclei's installed templates. |
| `CVENGINE_GENERATED_TEMPLATES_DIR` | `/root/cvengine-generated-templates` | Where validated AI-written templates live. It must sit outside `NUCLEI_TEMPLATES_DIR`, and the app says so at startup if it does not. In the shipped compose files it is the `generated_templates` volume, so validated templates survive an update, and a worker rewrites any validated template whose file is missing from the copy kept in the database when it starts. |

The AI key, API vault, update token, webhook URLs, and Telegram bot token are encrypted in the database with a key derived from `SECRET_KEY`. Keep the secret file when you restore a backup. With another key the stored secrets read as empty and must be entered again.

## Network and access

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_ALLOW_PRIVATE_TARGETS` | `0` | Set to `1` to allow private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7`). Loopback, link-local, multicast, `0.0.0.0/8`, and cloud metadata addresses are always refused. |
| `CVENGINE_BLOCKED_CIDRS` | none | Extra networks that are never scanned. |
| `CVENGINE_MAX_TARGETS_PER_ADD` | `10000` | Most addresses one CIDR, range, or bulk add may expand to. |
| `CVENGINE_TRUSTED_PROXIES` | `172.16.0.0/12` | The addresses the web container sees connecting to it whose `X-Forwarded-For` is believed, for the IP allowlist and the input guard. The default covers Docker's networks, so the bundled proxy, or your own proxy on the Docker host, works with no setting. Add to it, never replace it with your proxy's own network, or every request appears to come from the Docker gateway. See [Deployment](DEPLOYMENT.md#https). The default applies to the production compose file. |
| `CVENGINE_CSRF_TRUSTED_ORIGINS` | none | Your public https address when you use your own proxy or CDN, such as `https://scanner.example.com`. |
| `CVENGINE_GUARD_STRIKES` | `3` | Points within 15 minutes before the input guard disables the account, revokes its tokens, and blocks a public client address for 24 hours. A command injection attempt is worth 3. Superusers are only logged. |

## Settings in the app

Superusers set the rest under **Settings**: AI model, API vault, notifications, scan engines, IP allowlist, proxy, reports, resources, updates, and factory reset. On the AI model tab, tick **Use this model to confirm CVE matches** and press **Save**.

Notification channels (Slack, Discord, Telegram, Lark) receive at most one message per scan or feed sync for new fire-tier CVE matches and confirmed template-test hits (the **New vulnerabilities** switch). A match is announced only with evidence that the vulnerability exists: the host's version in the affected range, a template hit, or the distribution tracker calling it vulnerable. A match the AI is unsure of, or calls a likely false positive, stays open and is tested but is not announced until a test proves it. A one-line summary is also sent when a discovery scan finishes (**Scan status**). A message names up to five matches and counts the rest. Channels are shared by the instance, and a failed send never fails a scan.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [PIPELINE.md](PIPELINE.md), [documentation index](README.md).
