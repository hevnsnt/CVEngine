# Configuration

Every value in `.env` reaches the `web`, `celery`, and `celery-beat` containers. To change a setting, add a line such as `CVENGINE_TTL_NUCLEI=48` to `.env` and run `make up`. This needs Docker Compose 2.24 or newer. Compose fixes a few values and ignores them in `.env`: the broker URLs, `DEBUG`, and `GUNICORN_WORKERS`. Avoid `#` and `$` in passwords, because `make` and Compose both parse `.env`.

## Basics

| Variable | Purpose |
| --- | --- |
| `DOMAIN_NAME` | A hostname such as `scanner.example.com`, or an IPv4 address. It is the certificate name and the host in notification links. The installer sets it to this machine's detected address (or `--domain`); change it in `.env` and run `make certs up` to use a name. The certificate also covers `localhost` and `127.0.0.1`, and any names in `CERT_EXTRA_SANS` (comma separated). |
| `CVENGINE_ALLOWED_HOSTS` | Extra hostnames Django accepts, comma separated. Any other name or IP gets 400 ([UPGRADE.md](UPGRADE.md#accepted-host-names)). Never use `*` on an Internet-facing install. |
| `CVENGINE_HSTS_SECONDS` | HTTPS policy lifetime in seconds (3600 in production, 0 in development). Raise it only once every public route reliably uses HTTPS. |
| `POSTGRES_PASSWORD` | Database password. Set it before the first start, because changing it later does not update the existing database. |
| `AUTHORITY_PASSWORD` | Passed to the certificate authority step of `make certs`. The key is stored in `secrets/certs/`, so protect that directory. |
| `DJANGO_SUPERUSER_USERNAME`, `_EMAIL`, `_PASSWORD` | Used by `make admin` and `sudo ./install.sh`. Leave the password empty and `make admin` generates one and prints it once (you choose your own at first sign-in); set it to choose the first one yourself. `make admin-password` generates a new one for a lost password. A plain `make username` asks instead. |
| `COMPOSE_PROJECT_NAME`, `POSTGRES_DB`, `POSTGRES_USER` | Name the Docker volumes and the database. Change them only before the first start. Leave `POSTGRES_HOST=db` and `POSTGRES_PORT=5432` as they are. |
| `AUTHORITY_NAME`, `COMPANY`, `COUNTRY_CODE`, `STATE`, `CITY` | Subject of the certificates `make certs` creates. |

`make certs` and `install.sh` refuse to run while the database or certificate password still says `change-me`; `./scripts/init-env.sh` (which both run for you) fills them with random values and never touches one that is already set.

## Memory and workers

| Variable | Default | Purpose |
| --- | --- | --- |
| `CELERY_MEM_LIMIT` | `4g` | Memory limit for the scan workers. About 55% of the machine's RAM works well. |
| `WEB_MEM_LIMIT`, `BEAT_MEM_LIMIT` | `1g`, `512m` | Limits for the web container and the scheduler. |
| `DISCOVERY_CONCURRENCY` | `3` | Most discovery tasks at once. Lower it on small machines. |
| `CLASSIC_CONCURRENCY` | `20` | Most tasks at once across all other queues. The CVE feed worker is fixed at 4 and the validation lane at 1. |
| `HEAVY_MEMORY_BUDGET_MB` | 75% of the limit | Memory the job queue can hand out at once. |
| `HEAVY_HEADROOM_MB` | larger of 256 and 5% | Free memory kept in reserve. |
| `HEAVY_COST_SCALE`, `HEAVY_COST_<KIND>_MB` | `1`, none | Scale every estimated job cost, or set one kind's cost outright. |
| `HEAVY_MAX_<KIND>` | 1 to 3 | Jobs of a kind running at once. 1 for the nuclei kinds, naabu, `nmap-full-bg`, and bbot deep. 2 for nmap, bbot standard, bbot passive, and route probes. 3 for template tests. |
| `HEAVY_TUNE_MIN_<KIND>`, `HEAVY_TUNE_MAX_<KIND>` | `1`, the `HEAVY_MAX` value | The range the three-hour AI review may move a kind's concurrency within. Raise the maximum to let it scale up. Only `nmap`, `bbot-standard`, `bbot-passive`, `nuclei`, `template-test`, and `route-probe` are tuned. |
| `HEAVY_WAIT_SECONDS`, `CELERY_VISIBILITY_TIMEOUT` | `86400`, `43200` | How long a job waits for its turn, and how long before an unacknowledged job goes to another worker. |

`<KIND>` is the kind in capitals with `-` as `_`: `BBOT_DEEP`, `BBOT_STANDARD`, `BBOT_PASSIVE`, `NUCLEI`, `NUCLEI_LIGHT`, `NMAP`, `NMAP_FULL_BG`, `NAABU`, `TEMPLATE_TEST`, `ROUTE_PROBE`. Estimates adjust to the peak each kind actually reaches, plus 20%. **Settings, Resources** shows them.

## Scanning

Windows are hours. Every window is `CVENGINE_TTL_<SERVICE>` and a scanner skips a host it covered inside its window.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_TTL_NMAP_FAST`, `_BBOT`, `_BBOT_DEEP`, `_ROUTE_AUTH`, `_NAABU`, `_NUCLEI_DEEP_HOST`, `_NUCLEI_DEEP_TARGET` | `168` | nmap fingerprint, discovery, deep discovery of an apex, route checks, naabu, and deep nuclei. |
| `CVENGINE_TTL_NUCLEI`, `_NUCLEI_LIGHT`, `_NUCLEI_CVE`, `_CT_WATCH`, `_HYGIENE`, `_VALIDATE`, `_RETEST` | `24` | Nuclei runs, certificate watch, hygiene, validation checks, and re-tests, per host. |
| `CVENGINE_DEEP_SWEEP_MAX` | `50` | Apex domains the daily sweep queues for deep discovery. |
| `CVENGINE_FULLSCAN` | `1` | `0` turns off the background full port scan. |
| `CVENGINE_FULLSCAN_INTERVAL_MIN`, `_BATCH`, `_INVESTIGATE_MAX` | `10`, `1`, `50` | Minutes between sweeps (1 to 1440, read when the schedule is created), IPs per sweep (1 to 20), and new ports fingerprinted per sweep (1 to 1000). |
| `CVENGINE_NAABU` | `1` | `0` turns off the naabu full-port discovery that runs ahead of nmap by default (see [Pipeline](PIPELINE.md)). |
| `CVENGINE_NAABU_BIN`, `CVENGINE_NAABU_RATE` | `naabu`, `1000` | The binary and packets per second (100 to 5000). |
| `CVENGINE_HYGIENE_RDAP` | `1` | `0` skips the registry lookups that check whether SPF includes and DMARC report domains are registered. |
| `CVENGINE_SHOT_THRESHOLD` | `12` | Bits (of 64) by which screenshot hashes must differ to count as a changed front page. |
| `CVENGINE_RETEST_MAX_HOSTS` | `25` | Hosts re-tested per source scan. The rest wait for the five-minute sweep. |
| `CVENGINE_WPSCAN_MAX_SITES`, `CVENGINE_WPSCAN_TIMEOUT`, `CVENGINE_TTL_WPSCAN` | `10`, `900`, `24` | WordPress sites WPScan checks per scan, seconds allowed per site, and hours a site's result stays fresh (`168` for weekly). The token is an API key, not a variable: see below. |
| `CVENGINE_ARCHIVE_LOOKUP` | `1` | Set to `0` to stop asking the Internet Archive which URLs it saved for a target (passive, nothing is sent to the target). |
| `CVENGINE_TTL_ARCHIVE_URLS` | `168` | Hours before a target's archived URLs are read again. |
| `CVENGINE_RDP_SHOT` | `1` | Set to `0` to turn off RDP login-screen screenshots entirely. |
| `CVENGINE_TTL_RDP_SHOT` | `24` | Hours before a host's RDP screenshot is captured again. |
| `CVENGINE_RDP_SHOT_MAX_HOSTS` | `10` | RDP servers screenshotted per scan; a live RDP session plus an AI call costs more than most checks. |
| `CVENGINE_NODE2SHELL` | `0` | Set to `1` to check hosts fingerprinted as Node.js or Express for CVE-2026-111497. Off by default: alongside a few small requests it uploads about 23 MB to every host it checks, a much larger footprint than any other check here. |
| `CVENGINE_NODE2SHELL_TIMEOUT`, `CVENGINE_NODE2SHELL_MAX_HOSTS`, `CVENGINE_TTL_NODE2SHELL` | `90`, `5`, `24` | Seconds allowed per host, hosts checked per scan, and hours before a host is checked again. |

## AI limits

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_TRIAGE_MAX_PER_RUN`, `_PER_PROJECT_DAY`, `_PER_DAY` | `100`, `500`, `2000` | AI triage questions per run, per project per day, and per day. One question serves every finding with the same evidence. |
| `CVENGINE_VALIDATE_MAX_PER_RUN`, `_PER_PROJECT_DAY`, `_PER_DAY` | `50`, `300`, `1500` | Validation checks per task, per project per day, and per day. |
| `CVENGINE_AUTO_VALIDATE_ALL_MATCHES` | `1` | Queue every CVE match for automatic validation, hottest first. Set to `0` to validate only fire and smoke matches automatically. |
| `CVENGINE_TEMPLATE_GEN_MAX_PER_DAY`, `CVENGINE_TEMPLATE_GEN_CVE_DAYS` | `10`, `7` | AI template drafts per day across all projects, and one attempt per CVE per this many days. |

## CVE feeds and bug bounty data

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_CVE_COVERAGE_DAYS` | `14` | Days of the cve.now feed the hourly coverage task keeps stored. `0` turns it off. |
| `CVENGINE_CVE_WATCH_TECHS` | `php` | Technology slugs whose cve.now feed the coverage task also reads. |
| `CVENGINE_INTEL` | `1` | `0` turns off the exploitation sources ([PIPELINE.md](PIPELINE.md#cve-intelligence)). |
| `CVENGINE_INTEL_SOURCES` | all | A subset of `cisa_kev,euvd,vulncheck_kev,epss,exploit_db,metasploit`. |
| `CVENGINE_VULNCHECK_API_KEY` | none | A free VulnCheck community key adds VulnCheck KEV. |
| `CVENGINE_INTEL_IMPORT`, `_IMPORT_PER_RUN` | `kev,metasploit,epss,exploit_db`, `2000` | Which missing CVEs are imported from the CVE List, in order, and how many per hourly run (`0` imports none). |
| `CVENGINE_INTEL_DIR` | `/usr/src/scan_results/.threat-intel` | Where downloaded source files are cached. |
| `CVENGINE_BOUNTY_CATALOGUE` | `1` | `0` stops all fetching of public bug bounty program data. |

To fill the CVE store faster on a fresh install or after a factory reset: `docker compose exec celery python3 manage.py sync_cve_now --max-new 3000 --catch-up-after 500`.

## Retention and cleanup

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_CHANGES_RETENTION_DAYS` | `90` | Days the Changes log is kept. |
| `CVENGINE_ACTIVITY_RETENTION_DAYS`, `_TRIAGE_CALL_RETENTION_DAYS`, `_AI_USAGE_RETENTION_DAYS` | `30`, `90`, `400` | Days the activity feed, AI call leases, and AI usage ledger are kept. Each Sunday older rows are archived to `cvengine-logs-<time>.tar.gz` before deletion, and nothing is deleted if the archive cannot be written. |
| `CVENGINE_LOG_ARCHIVE_DIR`, `CVENGINE_LOG_ARCHIVE_DAYS` | `/usr/src/scan_results/.log-archives`, `365` | Where archives go (superusers can download them) and how long they are kept. |
| `CVENGINE_ASSESSMENT_QUEUED_HOURS`, `_ASSESSMENT_RUNNING_HOURS`, `_VALIDATION_QUEUED_HOURS`, `_VALIDATION_RUNNING_HOURS` | `12`, `6`, `6`, `2` | After this long a host assessment or validation job still queued or running is marked failed, checked every 15 minutes. Queued jobs wait while scanning is paused. |

## Updates

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_COMPOSE_FILES`, `_COMPOSE_ENV_FILE`, `_COMPOSE_PROJECT` | `docker-compose.yml`, none, none | The Compose layout `scripts/update.sh` and automatic deployment use ([UPDATES.md](UPDATES.md#custom-compose-layouts)). |
| `CVENGINE_UPDATE_DRAIN_SECONDS` | `10800` | Longest wait for active tasks, 1 to 10800. |
| `CVENGINE_UPDATE_READY_SECONDS` | `600` | Longest wait for the site, workers, and scheduler after an update, 1 to 900. |
| `CVENGINE_UPDATE_MISSING_POLLS` | `12` | Drain checks in a row a worker may miss before it counts as gone. |
| `CVENGINE_UPDATE_STOP_SCANS` | `0` | `1` makes every update stop scans and queue them again. |
| `CVENGINE_AUTO_DEPLOY_BACKUPS`, `_RETRY_SECONDS`, `_DRAIN_SECONDS` | `7`, `3600`, `1800` | Backups kept (`0` skips the backup), wait before retrying a failed commit, and the drain limit during automatic deployment. Whole numbers only. |
| `CVENGINE_AUTO_DEPLOY_INTERVAL` | `3min` | How often the timer checks `master`, such as `90s`, `3min`, or `1h`. Set when running `scripts/install-auto-deploy.sh`. |

## Web server

Production runs Gunicorn; the development compose file keeps Django's auto-reloading server.

| Variable | Default | Purpose |
| --- | --- | --- |
| `GUNICORN_THREADS`, `GUNICORN_TIMEOUT` | `8`, `300` | Threads per worker, and seconds before a stuck request is stopped (matches the proxy read timeout). |
| `CACHE_URL` | broker URL, next database | Redis URL of the shared cache. Keep it apart from the Celery broker's database, because a factory reset clears it. |

## Templates and secrets

| Variable | Default | Purpose |
| --- | --- | --- |
| `NUCLEI_TEMPLATES_DIR` | `/root/nuclei-templates` | nuclei's installed templates. |
| `CVENGINE_GENERATED_TEMPLATES_DIR` | `/root/cvengine-generated-templates` | Where validated AI-written templates live. It must sit outside `NUCLEI_TEMPLATES_DIR`, and the app says so at startup if it does not. In the shipped compose files it is the `generated_templates` volume, so validated templates survive an update, and a worker rewrites any validated template whose file is missing from the copy kept in the database when it starts. |
| `RENGINE_SECRET_KEY` | the key in `web/secret` | Provide the Django secret key from the environment instead of the file. |

The AI key, API vault, update token, webhook URLs, and Telegram bot token are encrypted in the database with a key derived from the secret key. Keep `web/secret` when you restore a backup. With another key the stored secrets read as empty and must be entered again.

## Network and access

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_ALLOW_PRIVATE_TARGETS` | `0` | `1` allows private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7`). Loopback, link-local, multicast, `0.0.0.0/8`, and cloud metadata addresses are always refused. |
| `CVENGINE_BLOCKED_CIDRS` | none | Extra networks that are never scanned. |
| `CVENGINE_MAX_TARGETS_PER_ADD` | `10000` | Most addresses one CIDR, range, or bulk add may expand to. |
| `CVENGINE_TRUSTED_PROXIES` | `172.16.0.0/12` | The addresses the web container sees connecting to it whose `X-Forwarded-For` is believed, for the IP allowlist and the input guard. The default covers Docker's networks, so the bundled proxy, or your own proxy on the Docker host, works with no setting. Add to it, never replace it with your proxy's own network, or every request appears to come from the Docker gateway. See [Deployment](DEPLOYMENT.md#https). The default applies to the production compose file. |
| `CVENGINE_CSRF_TRUSTED_ORIGINS` | none | Your public https address when you use your own proxy or CDN, such as `https://scanner.example.com`. |
| `CVENGINE_GUARD_STRIKES` | `3` | Points within 15 minutes before the input guard disables the account, revokes its tokens, and blocks a public client address for 24 hours. A command injection attempt is worth 3. Superusers are only logged. |

## Settings in the app

**RDP screenshots.** When nmap shows an RDP server accepts a connection without Network Level Authentication (the same finding as "RDP does not require Network Level Authentication"), cvENGINE captures its pre-authentication login screen with no credentials sent, stores the image, and asks the configured AI model whether it shows an account already signed in and what it is called. A server that requires NLA is never attempted: there is nothing to see before authentication, and nothing is guessed. The username, when the screen shows one, is not a secret; anyone who can reach the port already sees it. Needs the configured AI model to support image input; without one, the screenshot is still taken and stored, just not read.

**Database metadata.** nmap's own scripts read each database's pre-authentication greeting (MySQL, Microsoft SQL Server, MongoDB, Redis, Memcached, and CouchDB) and cvENGINE parses it into the version, role, and, for MySQL and Microsoft SQL Server, the Windows identity its NTLM negotiation discloses. This fills in `Port.version` and `Port.product` only when nmap's own probe came back empty, and is shown on the host page next to the port. It never sends a credential and answering says nothing about whether one is required. That question is answered separately: alongside the existing Redis, Memcached, PostgreSQL, Elasticsearch, and CouchDB checks, cvENGINE makes one read-only, no-credential attempt against MySQL (`root` with no password) and MongoDB (an unauthenticated `listDatabases`), and a server that lets it straight through is a critical finding, the same as the others.

**WPScan.** When a scan fingerprints a host as WordPress, cvENGINE runs [WPScan](https://wpscan.com/) on it at most once a day (set `CVENGINE_TTL_WPSCAN=168` for weekly): the version, plugins, themes, config backups, database exports, and the first author names, with no password guessing. Its vulnerability data comes from the wpscan.com API. Add the token under **Settings, API keys, WPScan** (per organization or project; a project's own token wins). The free plan allows 25 requests a day, and each site costs one request for the core plus one per plugin and theme, so a busy install needs a paid plan; when the token runs out the remaining sites wait for the next scan. Without a token WPScan still reports versions and exposures. Findings appear in Findings with the source `wpscan`, CVE ids included. The token is given to WPScan in its environment, never on a command line or in a log. WPScan's licence is free for testing your own systems and for penetration testing, and a commercial licence is needed to use it in a managed or hosted service, so check it before offering cvENGINE to others as a service.

Superusers set the rest under **Settings**: AI model, API vault, notifications, scan engines, IP allowlist, proxy, reports, resources, updates, and factory reset.

**node2shell (CVE-2026-111497).** Off by default (`CVENGINE_NODE2SHELL=0`): see above for why. When on, it runs [Assetnote's own read-only detector](https://github.com/assetnote/node2shell-scanner) against hosts already fingerprinted as Node.js or Express. It never executes a command and never sends a credential; a host is reported vulnerable only when the detector's own controls establish a real, stable signal first.

Notification channels (Slack, Discord, Telegram, Lark) get at most one message per feed sync, scan, or automatic template-test run, naming up to five matches. A match is announced only with evidence it exists: a version in the affected range, a template hit, or the distribution tracker calling it vulnerable.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [PIPELINE.md](PIPELINE.md), [documentation index](README.md).
