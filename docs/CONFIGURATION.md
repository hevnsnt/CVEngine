# Configuration

Every value in `.env` reaches the `web`, `celery`, and `celery-beat` containers. To change a setting, add a line such as `CVENGINE_TTL_NUCLEI=48` to `.env` and run `make up`. This needs Docker Compose 2.24 or newer. Compose fixes a few values and ignores them in `.env`: the broker URLs, `DEBUG`, and `GUNICORN_WORKERS`. Avoid `#` and `$` in passwords, because `make` and Compose both parse `.env`.

## Basics

| Variable | Purpose |
| --- | --- |
| `DOMAIN_NAME` | A hostname such as `scanner.example.com`, or an IPv4 address. It is the certificate name and the host in notification links. The installer sets it to this machine's detected address (or `--domain`); change it in `.env` and run `make certs up` to use a name. The certificate also covers `localhost` and `127.0.0.1`, and any names in `CERT_EXTRA_SANS` (comma separated). |
| `CVENGINE_ALLOWED_HOSTS` | Extra hostnames Django accepts, comma separated. Any other name or IP gets 400 ([UPGRADE.md](UPGRADE.md#accepted-host-names)). Never use `*` on an Internet-facing install. |
| `CVENGINE_HSTS_SECONDS` | HTTPS policy lifetime in seconds (3600 in production, 0 in development). Raise it only once every public route reliably uses HTTPS. |
| `POSTGRES_PASSWORD` | Database password. Set it before the first start, because changing it later does not update the existing database. |
| `AUTHORITY_PASSWORD` | Passed to the certificate step of `make certs`. `secrets/certs/ca.key` is not encrypted with it, so protect the directory. |
| `DJANGO_SUPERUSER_USERNAME`, `_EMAIL`, `_PASSWORD` | Used by `make admin` and `sudo ./install.sh`. Leave the password empty and `make admin` generates one and prints it once (you choose your own at first sign-in); set it to choose the first one yourself. `make admin-password` resets only the account named by `DJANGO_SUPERUSER_USERNAME` (`admin` by default), ignores `DJANGO_SUPERUSER_PASSWORD`, and always makes that account choose a new password at its next sign-in. For another user run `docker compose exec -T web python3 manage.py create_admin --reset --username NAME` or `make changepassword`. A plain `make username` asks instead. |
| `COMPOSE_PROJECT_NAME`, `POSTGRES_DB`, `POSTGRES_USER` | Name the Docker volumes and the database. Change them only before the first start. Leave `POSTGRES_HOST=db` and `POSTGRES_PORT=5432` as they are. |
| `AUTHORITY_NAME`, `COMPANY`, `COUNTRY_CODE`, `STATE`, `CITY` | Subject of the certificates `make certs` creates. |

`make certs` and `make username` refuse to run while the database or certificate password still says `change-me`. `./scripts/init-env.sh` (which `install.sh` and `make` run for you when `.env` is missing) fills those two with random values and leaves any other value alone. `STATE` and `CITY` stay `change-me`, which only affects the certificate subject. **Do not run `init-env.sh` or `install.sh` on an install made from an older `.env.example` that still has `change-me` as the database password:** it would replace that password, and PostgreSQL reads it only when the database is first created. Set the password you actually use in `.env` first.

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

| `CVENGINE_WORK_DEPTH`, `CVENGINE_WORK_MIN_GAP_HOURS` | `3`, `2` | The work conductor keeps this many discovery scans running or queued, starting the targets that have waited longest, and never rescans a target inside the minimum gap. `0` for the depth turns it off. See [PIPELINE.md](PIPELINE.md#the-work-conductor). |
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
| `CVENGINE_WPSCAN_MAX_SITES`, `CVENGINE_WPSCAN_TIMEOUT`, `CVENGINE_WPSCAN_STAGE_SECONDS` | `20`, `900`, `3600` | The quick pass: WordPress sites WPScan checks per scan, seconds allowed per site, and seconds the whole stage may use (candidates beyond either limit are recorded as waiting and go first next time, longest-waiting first). |
| `CVENGINE_WPSCAN_THOROUGH_TIMEOUT`, `CVENGINE_WPSCAN_TIMTHUMBS` | `43200`, off | The thorough pass: seconds allowed per site (at least 600; WPScan writes a partial report 30 seconds before then). `CVENGINE_WPSCAN_TIMTHUMBS=1` adds the 2,568-request timthumb check to the quick pass too. |
| `CVENGINE_TTL_WPSCAN`, `CVENGINE_TTL_WPSCAN_PARTIAL`, `CVENGINE_TTL_WP_PROBE`, `CVENGINE_TTL_WPSCAN_THOROUGH` | `168`, `24`, `24`, `720` | Hours a clean WPScan run stays fresh, hours before a run that could not check vulnerability data (the API token ran out) is repeated, and hours a WordPress probe result stays fresh, and hours a finished thorough pass stays fresh (a stopped one is repeated after a day). A failed run is retried at the next scan. |
| `CVENGINE_WP_PROBE_MAX_HOSTS` | `100` | Web hosts per scan the WordPress detection probe is run on (candidates and grouped names first). |
| `CVENGINE_PROBE_MAX_HOSTS`, `CVENGINE_TTL_PROBE` | `60`, `72` | Hosts per scan the version and identity probes run on, and hours their results stay fresh (see [Pipeline](PIPELINE.md#version-and-identity-probes)). |
| `CVENGINE_RUNZERO_SYNC_HOURS`, `CVENGINE_RUNZERO_IMPORT_MAX` | `6`, `500` | Hours between runZero syncs of each project that has a token (1 to 336; an hourly beat task starts the ones that are due), and the most new targets one sync may import when import is on (1 to 5000). See [runZero](#runzero). |
| `CVENGINE_ARCHIVE_LOOKUP` | `1` | Set to `0` to stop asking the Internet Archive which URLs it saved for a target (passive, nothing is sent to the target). |
| `CVENGINE_TTL_ARCHIVE_URLS` | `168` | Hours before a target's archived URLs are read again. |
| `CVENGINE_RDP_SHOT` | `1` | Set to `0` to turn off RDP login-screen screenshots entirely. |
| `CVENGINE_TTL_RDP_SHOT` | `24` | Hours before a host's RDP screenshot is captured again. |
| `CVENGINE_RDP_SHOT_MAX_HOSTS` | `10` | RDP servers screenshotted per scan; a live RDP session plus an AI call costs more than most checks. |
| `CVENGINE_WAFW00F` | `1` | Set to `0` to stop naming the firewall in front of each web host with [wafw00f](https://github.com/EnableSecurity/wafw00f) (a few requests per host, some with an attack-looking string, so a WAF may log them). The product it names is stored as a technology of the host. |
| `CVENGINE_WAFW00F_TIMEOUT`, `CVENGINE_WAFW00F_MAX_HOSTS`, `CVENGINE_TTL_WAFW00F` | `60`, `25`, `168` | Seconds allowed per host, hosts fingerprinted per scan, and hours before a host is fingerprinted again. |
| `CVENGINE_NODE2SHELL` | `0` | Set to `1` to check hosts fingerprinted as Node.js or Express for CVE-2026-111497. Off by default: alongside a few small requests it uploads about 23 MB to every host it checks, a much larger footprint than any other check here. |
| `CVENGINE_NODE2SHELL_SCOPE` | `runtimes` | `runtimes` checks hosts a fingerprint names as Node.js (and its frameworks), Bun or Envoy. `all` checks every web host the scan found, for what a name cannot show: a Python service using Brotli, a container base image, a sidecar that hides what it is. Still limited by `CVENGINE_NODE2SHELL_MAX_HOSTS`. |
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
| `CVENGINE_COMPOSE_FILES`, `_COMPOSE_ENV_FILE`, `_COMPOSE_PROJECT` | `docker-compose.yml`, none, none | The Compose layout `scripts/update.sh` and automatic deployment use (the approval updater reads only `CVENGINE_COMPOSE_FILE`) ([UPDATES.md](UPDATES.md#custom-compose-layouts)). |
| `CVENGINE_UPDATE_DRAIN_SECONDS` | `10800` | Longest wait for active tasks, 1 to 10800. |
| `CVENGINE_UPDATE_READY_SECONDS` | `600` | Longest wait for the site, workers, and scheduler after an update, 1 to 900. |
| `CVENGINE_UPDATE_MISSING_POLLS` | `12` | Drain checks in a row a worker may miss before it counts as gone. |
| `CVENGINE_UPDATE_STOP_SCANS` | `0` | `1` makes `scripts/update.sh` behave as if `--stop-scans` was given. The approval updater never stops scans. |
| `CVENGINE_AUTO_DEPLOY_BACKUPS`, `_RETRY_SECONDS`, `_DRAIN_SECONDS` | `7`, `3600`, `1800` | Backups kept (`0` skips the backup), wait before retrying a failed commit, and the drain limit during automatic deployment. Use whole numbers: anything else silently falls back to the default. |
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
| `CVENGINE_CVE_SEED` | `1` | Load the published CVE catalog on first start (`off` to skip). `CVENGINE_CVE_SEED_URL` points it at another https location. See [PIPELINE.md](PIPELINE.md#seeding-the-catalog). |
| `CVENGINE_DETECTION_AI_PER_DAY` | `25` | How many CVEs the AI is asked to write detection checks for in 24 hours (rules-written checks have no limit). |
| `REDIS_PASSWORD` | generated into `.env` on a first start | Password of the Redis broker (queues, caches, lockout counters). Empty means no password, as on installations that predate it: `make redis-auth` generates one and recreates Redis and the services that use it (run it while scans are idle; the updater never recreates Redis, so the change cannot happen by itself). Letters and digits only: it is part of a connection URL. |
| `CVENGINE_FIELD_KEY` | generated into `.env` | The key that encrypts stored secrets. `CVENGINE_FIELD_KEY_PREVIOUS` (comma separated) lists older keys that only decrypt, and `CVENGINE_FIELD_KEY_FILE` reads the key from a file. |
| `RENGINE_SECRET_KEY` | the key in `web/secret` | Provide the Django secret key from the environment instead of the file. |

The AI key, API vault, update token, webhook URLs, Telegram bot token and the two-step sign-in seeds are encrypted in the database. New installs get a dedicated key, `CVENGINE_FIELD_KEY` in `.env`, separate from the Django secret in `web/secret` (which signs sessions) and outside the `web/` directory every container mounts. An installation that predates it keeps reading its old values with the key derived from `web/secret`, and `make rotate-field-key` moves everything under a dedicated key: it writes a new key to `.env`, keeps the old one in `CVENGINE_FIELD_KEY_PREVIOUS` (which only decrypts), recreates the services and re-encrypts every stored secret. Back up `.env` and `web/secret` too, but not beside the database dumps: a restored database needs the same keys (with another key the stored secrets read as empty and must be entered again), and a dump stored together with its key is readable by anyone who can read the backup. To keep the key in a Docker secret instead, point `CVENGINE_FIELD_KEY_FILE` at the mounted file.

What this protects: a database dump, a backup, or SQL injection reads only ciphertext, and a file read in `web/` no longer includes the key. What it does not: code execution inside a container that decrypts the secrets (the web service or a worker) can use the key that container holds. The settings API never returns a secret, only whether one is set.

## Network and access

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_ALLOW_PRIVATE_TARGETS` | `0` | `1` allows private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7`). Loopback, link-local, multicast, `0.0.0.0/8`, and cloud metadata addresses are always refused. A connected Tailscale tailnet does not need this: its imported devices' addresses are allowed on their own ([Tailscale](TAILSCALE.md#which-addresses-may-be-scanned)). |
| `CVENGINE_BLOCKED_CIDRS` | none | Extra networks that are never scanned. |
| `COMPOSE_PROFILES` | none | Set to `tailscale` to run the optional Tailscale node that lets scans reach a tailnet. Its auth key goes in `.env.tailscale`, not here. `TAILSCALE_HOSTNAME`, `TAILSCALE_EXTRA_ARGS` (added to the always-on `--shields-up`) and `TAILSCALE_IMAGE` (pinned to a version by default) tune it. See [Tailscale](TAILSCALE.md). |
| `CVENGINE_TAILSCALE_STATUS_FILE` | `/var/run/tailscale-status/status.json` | The status file the Tailscale sidecar publishes and the worker reads (the compose volume, mounted read-only in celery only). Change it only if you mount it elsewhere. |
| `CVENGINE_MAX_TARGETS_PER_ADD` | `10000` | Most addresses one CIDR, range, or bulk add may expand to. |
| `CVENGINE_TRUSTED_PROXIES` | `172.16.0.0/12` | The addresses the web container sees connecting to it whose `X-Forwarded-For` is believed, for the IP allowlist and the input guard. The default covers Docker's networks, so the bundled proxy, or your own proxy on the Docker host, works with no setting. Add to it, never replace it with your proxy's own network, or every request appears to come from the Docker gateway. See [Deployment](DEPLOYMENT.md#https). The default applies to the production compose file. |
| `CVENGINE_CSRF_TRUSTED_ORIGINS` | none | Your public https address when you use your own proxy or CDN, such as `https://scanner.example.com`. |
| `CVENGINE_GUARD_STRIKES` | `3` | Points within 15 minutes before the input guard disables the account, revokes its tokens, and blocks a public client address for 24 hours. A command injection attempt is worth 3. Superusers are only logged. |

## Settings in the app

**API keys for outside services.** Add them under **API keys** (per organization; a project's own key wins, field by field, and a project that sets only part of a pair keeps the rest from its organization). A key is stored encrypted and never shown again. During discovery cvENGINE writes the keys of the project into a private preset file (mode 0600, deleted when the scan ends) that bbot merges with its own presets, so a key never appears on a command line. The services and what each key switches on:

| Service | What uses the key | Notes |
| --- | --- | --- |
| Shodan | bbot `shodan_dns` | `shodan_idb` (InternetDB) needs no key and always runs. |
| Censys | bbot `censys_dns` | bbot uses the legacy Search API, so enter the **API ID and secret** of a legacy account. A new account that has only a personal access token cannot be used by bbot. **Censys has announced the end of the legacy Search API** ([legacy search deprecation](https://censys.com/blog/legacy-search-deprecation)) and bbot 3.0.2, the newest release, has no module for the replacement platform API, so this key may stop working: if Censys results disappear, that is why. cvENGINE will switch as soon as bbot supports the new API. |
| VirusTotal, SecurityTrails, FullHunt, LeakIX, Hunter.io, Chaos, AlienVault OTX, C99, BeVigil, BuiltWith, BufferOver.run | the bbot module of the same name | Chaos also accepts one install-wide key in Settings, API vault, used when no organization or project has its own. |
| GitHub | bbot `github_codesearch` and `github_org` (and the other GitHub modules in a deep scan) | A personal access token. |
| WPScan | cvENGINE itself, against WordPress hosts | See WPScan below. |
| runZero | cvENGINE's own scheduled sync, not bbot | See runZero below. |
| BinaryEdge | retired | Nothing reads a stored key. See below. |

A module whose key the service refuses is skipped by bbot and the scan carries on. cvENGINE now reports it: an activity entry names the service ("VirusTotal: the key was not accepted") with the reason bbot gave. Settings, API vault holds only the keys of the older lookups: Netlas (WHOIS), Chaos (install-wide) and HackerOne (bounty submissions).

**RDP screenshots.** When nmap shows an RDP server accepts a connection without Network Level Authentication (the same finding as "RDP does not require Network Level Authentication"), cvENGINE captures its pre-authentication login screen with no credentials sent, stores the image, and asks the configured AI model whether it shows an account already signed in and what it is called. A server that requires NLA is never attempted: there is nothing to see before authentication, and nothing is guessed. The username, when the screen shows one, is not a secret; anyone who can reach the port already sees it. Needs the configured AI model to support image input; without one, the screenshot is still taken and stored, just not read.

**Database metadata.** nmap's own scripts read each database's pre-authentication greeting (MySQL, Microsoft SQL Server, MongoDB, Redis, Memcached, and CouchDB) and cvENGINE parses it into the version, role, and, for MySQL and Microsoft SQL Server, the Windows identity its NTLM negotiation discloses. This fills in `Port.version` and `Port.product` only when nmap's own probe came back empty, and is shown on the host page next to the port. It never sends a credential and answering says nothing about whether one is required. That question is answered separately: alongside the existing Redis, Memcached, PostgreSQL, Elasticsearch, and CouchDB checks, cvENGINE makes one read-only, no-credential attempt against MySQL (`root` with no password) and MongoDB (an unauthenticated `listDatabases`), and a server that lets it straight through is a critical finding, the same as the others.

**WPScan.** WPScan is the primary WordPress assessment. cvENGINE runs [WPScan](https://wpscan.com/) on every host that shows any sign of WordPress (a technology tag, a header or page signature, the login page, the REST API, plugin paths in crawled URLs, a title, the web archive's memory of the host, or an earlier probe) and on every name of a grouped host that a read-only probe finds to be WordPress, positive probes first, and every candidate ends in a recorded state (scanned, detected, blocked by the edge, failed with its reason, waiting, not WordPress) shown on the host page and counted in the system status. It works in two passes. The **quick pass** runs in the scan: the core version, the plugins and themes the site's own pages reference (passive detection, with versions, no token needed), config backups, database exports and the first author ids (`--enumerate ap,at,cb,dbe,u1-10 --plugins-detection passive --themes-detection passive`; WPScan 4 no longer enumerates plugins by default, `vp`/`vt` only report vulnerable ones and need the API), with a random user agent and a 100 ms throttle, and it finishes in minutes with a report. The **thorough pass** then asks the site for every plugin and theme WPScan knows (mixed detection, plus timthumbs: about 170,000 requests, hours per site), as a separate background task on its own queue (`wpscan_queue`), one site at a time and one pass per project at a time, with its own timeout (12 hours by default) and a partial report if it is cut short. It never blocks the scan, correlation or triage, stops while scanning is paused (the host stays waiting), is repeated every 30 days, and its state (queued, running, finished, stopped early, blocked, failed) is on the host page and in the system status. No password guessing. Plugin and theme versions need no token. Vulnerability data comes from the wpscan.com API: add the token under **Settings, API keys, WPScan** (per organization or project; a project's own token wins). The free plan allows 25 requests a day and each site costs one request for the core plus one per plugin and theme: when the budget is spent WPScan still runs on the remaining sites without the token, and each says "not checked: API token budget exhausted" and is repeated after a day (`CVENGINE_TTL_WPSCAN_PARTIAL`); a clean run is repeated after a week (`CVENGINE_TTL_WPSCAN`, 168 hours), a failed run at the next scan. If an edge (Cloudflare, Akamai, Sucuri, Imperva) answers WPScan or the probe with a challenge or a block, the host says "the edge challenged the scanner" and what to allow (the scanner's address or user agent in the WAF or bot rules); cvENGINE never tries to solve a challenge or get past a WAF. Findings appear in Findings with the source `wpscan`: CVE ids, the fixed version, remediation text, exposed backups, usernames, XML-RPC and outdated components. The core, plugin and theme versions are also versioned sightings: a CVE for a plugin matches only when the plugin (by its slug, or the title in its readme) is the product the advisory names and its version is inside the advisory's bounded range. The token is given to WPScan in its environment, never on a command line or in a log. WPScan's exit codes are 0 (clean), 5 (vulnerabilities found), 4 (the scan did not finish: not WordPress, blocked, unreachable; the report says which), 1 (bad option), 2 (interrupted), 3 (unexpected error). WPScan's licence is free for testing your own systems and for penetration testing, and a commercial licence is needed to use it in a managed or hosted service, so check it before offering cvENGINE to others as a service.

## API keys

Keys for outside services are saved under **Settings, API keys**, for an organization (its projects inherit it) or for one project (which overrides the organization's). Secrets are encrypted at rest, write-only (the app only says whether one is set) and never put on a command line or in a log.

| Service | What reads the key |
| --- | --- |
| Shodan, Censys, VirusTotal, SecurityTrails, FullHunt, LeakIX, Hunter.io, Chaos, GitHub, OTX, C99, BeVigil, BuiltWith, BufferOver.run | The matching bbot module during discovery. A service without a key is skipped or runs without one. |
| WPScan | The WPScan stage of a scan (see below). |
| runZero | The scheduled runZero sync (see below), not a scan. |
| BinaryEdge | Nothing. Retired: see below. |

**BinaryEdge is retired.** Coalition shut BinaryEdge down as a standalone service on 31 March 2025 (accounts closed that day, as Coalition's [transition FAQ](https://help.coalitioninc.com/hc/en-us/articles/34383910057371-BinaryEdge-Transition-FAQ) says; the old API host no longer serves API answers), and bbot has no BinaryEdge module, so there is nothing to connect a key to. New BinaryEdge keys are refused (`410`), the page and the API mark it `retired` with that reason and `used_in_scans: false`, and a key someone saved earlier is kept, shown as retired and can be removed, but is never used.

### runZero

[runZero](https://www.runzero.com/) is an asset inventory: it knows devices, operating systems and hardware that an outside scan cannot see. cvENGINE reads it, read-only, with the project's **runZero Export API token** (an `ET...` or `XT...` token from runZero's Account, Organization or Export token pages; organization and account tokens also work). It talks only to runZero's hosted console, `https://console.runzero.com/api/v1.0`, over HTTPS with the token in the `Authorization: Bearer` header; the address is fixed so it cannot be pointed at another host, and **self-hosted runZero consoles are not supported yet**.

A sync runs every `CVENGINE_RUNZERO_SYNC_HOURS` hours (default 6) for each project that has a token, and on **Sync now** (the runZero card on the API keys page, `POST projects/{slug}/runzero/sync`, or the `run_runzero_sync` tool). Each project syncs on its own: an organization token shared by several projects is read once per project, which is a few API calls each, against runZero's daily limit of calls per licensed asset and its limit per source address (a 429 is waited out, then reported; when runZero's `X-API-Usage-Remaining` header says the day's quota is nearly spent, the sync stops early, says `quota_low` and carries on at the next one). It does two things:

1. **Enrichment (always on once a token exists).** For every runZero asset whose address is an IP cvENGINE already holds for the project (an address of the same organization that one of the project's own hosts resolves to; another organization's row for the same address is never touched), runZero's OS and version, hardware, type, tags, site, names and last seen are stored on the address. The OS also fills the address's OS guess when nmap has none. They appear on the host page (Overview and Services) and in the host's `ips[].runzero` in the API. runZero's own CVE reports for those hosts (`vulnerabilities.json`: CVE, service address, port, severity, CVSS 3) are listed there as **runZero reports**. They are additional evidence only: a CVE match cvENGINE already found for the same host and port gets its confidence raised by 0.1 (once, capped at 1.0, never for a match the AI ruled out or a distribution patched), which orders it higher, and the boost is taken back when the report or the asset disappears from runZero (an asset that left the inventory stops describing the host, too); a report never creates a match, never sets an AI verdict, and never confirms a finding.
2. **Import (off until you turn it on per project).** With **Add runZero addresses cvENGINE does not know as targets** on, addresses runZero lists that are not yet targets of the organization are added through the same code as Add targets, so organization exclusions, `CVENGINE_ALLOW_PRIVATE_TARGETS`, `CVENGINE_BLOCKED_CIDRS` and organization-wide uniqueness all apply, and each new target is queued for discovery. The **runZero search** (runZero inventory search syntax, default `alive:true`) limits which assets are imported; enrichment always reads the whole inventory. A sync imports at most `CVENGINE_RUNZERO_IMPORT_MAX` new targets (default 500; the rest wait for the next sync). A runZero name is imported only when it sits under a domain the organization already has: names on a network are chosen by whoever runs the device, so they are never accepted as a scope decision. **A public address is imported only inside a network the organization already has as a target** (a CIDR block or an address): an inventory search such as `alive:true` can hold third-party addresses (a partner's range, a cloud address a device talked to) that nobody authorized scanning, so those are skipped as `not_owned`. The result lists what was skipped and why: already known, blocked (loopback, link-local, or private without the setting), not owned, excluded, a name out of scope, over the cap.

The API keys page shows the last sync, its counts and any error; `get_system_status` lists each project's runZero state for an App Admin and reports a failing sync as a problem; every sync writes an activity entry. A rejected token (401 or 403), a rate limit (429), an unreachable console, malformed JSON and an oversized reply (more than 32 MB, or more than 50,000 records per call) are each reported in plain words, the next scheduled sync tries again, and none of them stops the worker. Managing the sync (status, settings, Sync now) needs the organization admin or App Admin role. Needs migration 0087 (`RunZeroSync`) and the beat entry it creates, `cvengine-runzero-sync`.

Superusers set the rest under **Settings**: AI model, API vault, Tailscale, notifications, scan engines, IP allowlist, proxy, reports, resources, updates, and factory reset.

**node2shell (CVE-2026-111497).** Off by default (`CVENGINE_NODE2SHELL=0`): see above for why. When on, it runs [Assetnote's own read-only detector](https://github.com/assetnote/node2shell-scanner) against hosts already fingerprinted as Node.js or Express. It never executes a command and never sends a credential; a host is reported vulnerable only when the detector's own controls establish a real, stable signal first.

Notification channels (Slack, Discord, Telegram, Lark) get at most one message per feed sync, scan, or automatic template-test run, naming up to five matches. A match is announced only with evidence it exists: a version in the affected range, a template hit, or the distribution tracker calling it vulnerable. A [saved search](SEARCH.md#saved-searches-and-alerts) gets at most one message per search per check (up to five new hosts named), under the "Interesting findings" switch.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [PIPELINE.md](PIPELINE.md), [documentation index](README.md).
