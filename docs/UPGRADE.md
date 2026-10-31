# Upgrading from an older install

Older installs (reNgine and pre-release cvENGINE builds) ran PostgreSQL 12. The current release runs PostgreSQL 18, which cannot open a version 12 data directory, so the data is dumped and loaded into a new volume. The old volume is not converted or deleted. A fresh install needs none of this.

1. Back up the database, then `git pull`. Do not use the in-app updater or automatic deployment until the move is done.
2. `make up`. It moves the database to PostgreSQL 18, keeps a dump in `backups/`, then rebuilds and starts everything. The first build takes a while on an arm64 machine because nmap is compiled there (an x86-64 build installs the official nmap binary instead). For a development install, run `scripts/upgrade-postgres.sh --dev` and then `docker compose -f docker-compose.dev.yml up -d --build`.
3. When you have checked the data, remove the old volume: `docker volume rm <project>_postgres_data` (the project is `COMPOSE_PROJECT_NAME` in `.env`, default `rengine`).

To roll back, check out the previous commit and start it. It still uses the untouched old volume, without anything written since the upgrade.

## Upgrading to 1.3

Update from 1.2.x the way you always do: the in-app updater, `scripts/update.sh`, or automatic deployment ([UPDATES.md](UPDATES.md)). Nothing in 1.3 needs a manual step to start working, and a fresh install needs none of this. The update takes a database dump just before it migrates (`scripts/db-backup.sh`, the last 3 are kept; see [UPDATES.md](UPDATES.md)) and a migration is never rolled back, so that dump is the way back, in particular from the migrations that drop legacy tables (below). The dump stays on the same disk as the database, so copy it elsewhere too, and back the database up yourself first if you can.

**Before you start**

- **Free disk space.** The update rebuilds the image (a few gigabytes) and pulls the current `nginx:alpine` for the proxy. The 1.3 safeguards below do not apply to this one update, because an update is applied by the scripts of the version being replaced ([UPDATES.md](UPDATES.md#branches-and-releases)): make sure at least 6 GB are free where Docker keeps its images.
- **The update into 1.3 is applied by the scripts you have now.** The approval updater of 1.2.1 waits for running scans with no time limit (use **Stop all** on the **Scans** page of each project, or `scripts/update.sh --stop-scans`, to shorten that), visitors see an error page while the services restart, the replaced image stays on disk (`docker image prune` removes it), and success is judged by Docker saying the services run. The database dump is the exception: it is taken by `scripts/update-deploy.sh` (or by `update.sh` itself, which runs the fetched copy of itself), which the update reads after merging, so this update has it. From the update after this one, 1.3's other scripts apply: a disk check, the maintenance page, a check that the web service answers, image cleanup, and a 5-minute drain limit for the approval updater.
- A server installed before v1.2.0 still needs its one manual update first ([Upgrading to 1.2](#upgrading-to-12)).

**What changes in the database.** The migrations add, apart from a few that drop legacy schema (see [Dropped legacy tables and columns](#dropped-legacy-tables-and-columns)): a new app (`agentapi`, migrations 0001 to 0007: agents, Sentinels, their tasks and settings), `dashboard` 0026 to 0030, `startScan` 0021 to 0023, `scanEngine` 0005 and 0006, `recon_note` 0002, `targetApp` 0005, and `cveFeed` 0082 to 0117 (there is no 0101). They add tables for saved searches, runZero, Tailscale, host inventory, probe observations, stored sign-ins for authenticated checks, PDF report exports, OpenVAS, suppliers and internal ranges, plus new columns and indexes, and scheduled-task entries for the new sweeps. Besides schema, four things are written:

- `dashboard` 0030 switches the **Nuclei templates** policy on for an install where nobody ever changed it (the audit log records every change): see below.
- `cveFeed` 0092 rewrites the stored reason of old "invalid product correlation" closures to "different product".
- Every existing API token gets the full scope, except the token of a Sentinel enrolled earlier: `agentapi` 0006 narrows it to the `sentinel` scope. The new reporter tokens are separate.
- `agentapi` 0007 gives every Sentinel a network (`external`, or `internal` when it had declared `network:internal`), because the server, not the Sentinel, now decides that.
- `scanEngine` 0006 encrypts the stored proxy list.
- The new schedules are created enabled, except the OpenVAS sweep, which is created **disabled** and only the OpenVAS switch turns on.

**What starts, and what does not.**

- The stack is the same six services (`db`, `redis`, `web`, `celery`, `celery-beat`, `proxy`) on the same ports (443, 8082, and `127.0.0.1` for 8000 and 5432). `docker compose config --services` on a plain 1.3 install lists exactly those six.
- **Tailscale and OpenVAS are off by default.** They are Compose profiles (`tailscale` and `openvas`, 1 and 15 services). Without `COMPOSE_PROFILES` in `.env`, an update neither creates nor starts them, and `make up` and the updaters never start a profile service. OpenVAS also has no scheduled work while it is off. Turn them on only if you want them ([TAILSCALE.md](TAILSCALE.md), [OPENVAS.md](OPENVAS.md)).
- Two empty volumes are created for the celery container even with both off: `tailscale_status` and `openvas_gvmd_socket_vol`, mounted read-only. The proxy now also mounts the maintenance page and `config/nginx/state`, and pulls its image on every `up`.
- Sentinels, internal ranges, authenticated checks, suppliers, runZero, saved searches and reporter tokens do nothing until someone sets them up. A project with no Sentinel pays nothing for the dispatch code.

**Defaults that change behavior**

- **The whole Nuclei template library is now the default scan scope.** Before, scans ran only the templates that make plain GET, HEAD or OPTIONS requests. The migration turns the new default on for an install where no App Admin ever changed **Settings, Scan policy, Nuclei templates**; an install where one did keeps its choice. Validation uses the same switch, so automatic and on-demand validation can send requests other than plain reads. Denial-of-service templates stay excluded and AI-written templates stay read-only. To keep the old behavior, turn the switch off after the update (it was under **Scan engines** in 1.2; that tab is now **Scan policy**, and an old `#engines` link opens it).
- **Matches need hard evidence, and old name-only matches close themselves.** A CVE match is made only when the product is the same one the advisory names and its version is inside a bounded range (or a template hit, a distribution verdict, a host inventory report or runZero backs it). A product seen without a version is listed as an **Unverified product** on the host instead. After the update, within about half an hour (the next run of the 30-minute guidance task or the next correlation), the open matches that rest on a name alone, an operating-system fingerprint, a different product, or a local-only CVE are closed with a stored reason ("Closed automatically: no version evidence"), the affected hosts are rescored and the counts drop. A match is never closed if anyone worked it (a status other than open, an assignee, a comment, a manual validation request, an AI "affected" verdict) or if it has a template hit, a distribution "vulnerable" verdict, a runZero report or a host report. Version probes then look for the missing versions, and matches return where a version proves them.
- **The UDP scan is on by default** (`CVENGINE_UDPSCAN=1`): 18 ports, 20 packets a second, one address at a time, each address once a week, riding the background full port scan's schedule. Set `CVENGINE_UDPSCAN=0` to turn it off. It needs the worker to open raw sockets; if it cannot, it says so in the activity feed and does not scan.
- **New background sweeps are on by default**, each slow, polite, paused by the global pause, and skipped for a project whose bug bounty engagement has not confirmed automated testing: the TLS audit (testssl.sh; no environment switch, `CVENGINE_TESTSSL_MAX_TARGETS` caps it), other sites on an address (`CVENGINE_VHOST`), applications under subdirectories (`CVENGINE_SUBDIR_APPS`), cloud storage exposure (`CVENGINE_BUCKETS`), and third-party suppliers (`CVENGINE_SUPPLIERS`, nothing to do until a supplier is listed). The version and identity probes run inside each scan on up to `CVENGINE_PROBE_MAX_HOSTS` hosts. Expect more findings and a little more traffic to your own hosts. The background full port scan and the UDP scan are deferred, instance-wide, while any project still has a host missing its first pass.
- **Sentinel tokens expire.** A Sentinel's token has the scope `sentinel` (the Sentinel routes only, not the rest of the API or MCP) and lasts 90 days; a heartbeat renews the same token in place when under 60 days are left. A Sentinel that was off for more than 90 days is enrolled again. `network:internal` is granted by the server (Where it runs, at provisioning or in the Sentinel's settings), never by what a Sentinel declares. A Sentinel client older than this release keeps working but cannot enforce the template policy: update it from the Sentinels page.
- **Stored sign-ins need a verified certificate.** The in-process route check verifies TLS on its credential-bearing connection. Nuclei cannot verify TLS on that connection, so its signed-in HTTPS pass is withheld unless the owner explicitly enables **Trust this certificate anyway** for that credential. Anonymous Nuclei checks still run. A signed-in Nuclei pass never runs on a Sentinel.
- **The proxy under Settings now applies to scans.** The web probes, nuclei, bbot, WPScan, testssl.sh and wafw00f on this server leave through it; nmap, naabu and the UDP sweeps stay direct, and private, link-local and tailnet addresses skip it unless `CVENGINE_PROXY_PRIVATE=1`.
- **A CVE with no version range is a review item.** It makes a *version unknown* match: Needs validation, lowest heat, a small capped share of the host score, never announced as a new Fire match and never sent to the model.
- **The bug bounty gate works per host** and covers the full port sweep, UDP, the weekly deep nuclei lane, the thorough WPScan pass and OpenVAS ([BUG-BOUNTY.md](BUG-BOUNTY.md#the-scan-gate)).
- **Local models get a reply limit (a later 1.3.x release).** `CVENGINE_AI_MAX_TOKENS` now applies to Anthropic too, and a self-hosted server (vLLM, LM Studio, Ollama) is sent 2048 tokens by default, 400 for a finding triage, where it was sent none. A reasoning model that thinks before it answers can end at that limit with no answer: raise `CVENGINE_AI_MAX_TOKENS` or turn its reasoning off ([Local models](DEPLOYMENT.md#local-models)). The same release adds one additive migration (`cveFeed` 0129).
- **Smaller changes.** A host that crashes OpenVAS three times in a row is set aside for three days. Project API keys can be set and deleted by project administrators only. One paste of exclusions is capped at 100 lines. A host inventory report matches a scanned host by its name alone (`CVENGINE_INVENTORY_STRICT=1` brings the address check back). The per-project counts in the system status are reused for `CVENGINE_STATUS_CACHE_SECONDS` (60 by default).
- **Hosts that never resolve to a scannable address are archived** after `CVENGINE_TTL_UNRESOLVED_HOST` hours (default 72, which is 3 days) of an unbroken streak, and restored automatically if they come back. A name that resolves only into a private network counts like any other name that cannot be scanned from this server; it is archived too and looked at again daily. The streak starts counting after the update.
- **AI guidance for CVEs.** Settings, AI model has a new daily budget, "CVE guidance written by the model per day", 25 by default. With an AI model configured, that is up to 25 paid requests a day; set it to 0 to turn it off. The rule-written guidance for every CVE has no AI cost and finishes on its own after the update.
- **Tools are pinned** (nuclei, naabu, bbot, testssl.sh, python-gvm and others), and on x86-64 the image installs the nmap project's own release binary instead of compiling nmap. The build is minutes faster on x86-64 and the same on arm64, where nmap is still compiled. New worker queues (`wpscan_queue`, `testssl_queue`, `bucketscan_queue`, `vhost_queue`, `udp_queue`, `openvas_queue`, `supplier_queue`, `ctwatch_queue`) are consumed by the existing classic worker, which `CLASSIC_CONCURRENCY` sizes.
- **Settings changed.** There is no API vault tab (the instance-wide Chaos key is a line on the API keys page; the Netlas and HackerOne keys keep working but have no page), BinaryEdge is retired (a saved key is kept, shown as retired and never used), and **Settings, Reports** only sets report branding.

**Manual steps.** None are required. These are choices:

- To keep scans read-only as in 1.2, turn off **Settings, Scan policy, Nuclei templates**.
- To turn a new sweep off, set its variable in `.env` ([CONFIGURATION.md](CONFIGURATION.md#scanning)) and run `make up`.
- If you want a Tailscale node or OpenVAS, follow their guides. Neither is started for you.
- If the approval updater needs a longer drain limit than 5 minutes, put `CVENGINE_UPDATE_DRAIN_SECONDS` in `.env` ([CONFIGURATION.md](CONFIGURATION.md#updates)).
- Sentinels run from their own repository and are enrolled from the Sentinels page, which also needs the new 1.3 server.

**Check afterwards**

1. **Settings, Updates** shows the new commit as installed and no problem, and `docker compose ps` shows the six services running and no `openvas-*` or `tailscale` container.
2. `docker compose exec web python3 manage.py migrate --check` exits without complaint.
3. **Settings, Scan policy** shows the Nuclei switch the way you want it.
4. After half an hour, the open CVE count has fallen and closed matches say "Closed automatically" with a reason. Open a few hosts: technologies without a version appear as **Unverified products**.
5. **Activity** shows the new sweeps starting over the next day, and the system status (`GET /api/v1/system/status`, or the MCP tool `get_system_status`) has no new problem. If it says the worker cannot open raw sockets, the UDP scan is not running.
6. **Settings, Resources** shows the memory budget keeps up; raise `CELERY_MEM_LIMIT` if new work waits for memory.

## Upgrading to 1.2

An update takes a database dump, applies the migrations (a migration is never rolled back; when one fails the update says what state the database is in and keeps the dump, see [UPDATES.md](UPDATES.md)) and ends every session once, so everyone signs in again. Three protections are new-install only, because an update cannot switch them on without recreating services:

- **Redis password.** New installs generate `REDIS_PASSWORD` and every service uses it. On an older install Redis stays open to the Docker network until you run `make redis-auth` when scanning is idle. It recreates Redis, web, the workers, and the proxy, and queued tasks are lost.
- **Secret-encryption key.** New installs generate `CVENGINE_FIELD_KEY` in `.env`. An older install keeps reading its stored secrets with the key derived from `web/secret` until you run `make rotate-field-key`, which re-encrypts them under a new key and keeps the old one as `CVENGINE_FIELD_KEY_PREVIOUS` until you have a backup taken after the rotation. Back up `.env` and keep it apart from database dumps.
- **Web interface certificate.** A 10-year certificate made by an earlier installer is replaced once by the first automatic renewal check after the update, with a 397-day one (same key, same authority, same names); from then on it renews itself 30 days before it ends ([Deployment](DEPLOYMENT.md#https)). Nothing has to be copied to browsers again.
- **Certificate authority key.** An authority made by an older version keeps an unencrypted `ca.key`. To replace it, delete `ca.key` and `ca.crt` in `secrets/certs` and run `make certs`. Browsers then need the new `ca.crt`.

The in-app updater of a server installed before v1.2.0 has no watcher, so Approve does nothing there until you run `cd /opt/cvengine && git pull --ff-only && sudo scripts/install-updater.sh` once ([UPDATES.md](UPDATES.md)). On an install with its own Compose overlay, update with `scripts/update.sh` or the in-app updater, never `make up`.

## Accepted host names

The current release accepts only the host of `DOMAIN_NAME`, loopback (for health checks), and the names in `CVENGINE_ALLOWED_HOSTS`. Any other name gets **400 Bad Request** on every page. Before you update:

- Reached by the name in `DOMAIN_NAME`: nothing to do.
- Reached by another name or an IP address: add each to `.env`, comma separated, and run `make up`: `CVENGINE_ALLOWED_HOSTS=scanner.internal.example,192.0.2.10`.
- `DOMAIN_NAME` unset or still an example value: set it to the server's public name.

`python3 manage.py check` prints warning `cvengine.W001` when `DOMAIN_NAME` would leave only loopback accepted. Do not use `*` on an Internet-facing installation.

## Shared provider domains

An earlier build promoted a tenant such as `acme.jfrog.com` to `jfrog.com` in the weekly deep-discovery sweep. The update's migration deletes targets that sweep created on the shared-domain list, with their scans, hosts, and findings, because that data was outside your scope. A shared domain you added yourself is kept and set to `host` scope. Deleted targets do not come back on rollback, so back up first if you want that data.

## Dropped legacy tables and columns

The update's migrations delete schema that nothing writes or reads any more, since the old classic screens and the legacy `/api` routes are gone. The data in them is deleted with them and is not restored by a rollback of the code, so the database backup the update script takes before migrating is the way back:

- Tables: the old per-target **Organization** (`targetApp_organization`, not the organization/project tenancy), the classic **To-do notes** (`recon_note_todonote`), **Wordlist**, **Configuration** and the interesting-keyword lookup (`scanEngine_wordlist`, `scanEngine_configuration`, `scanEngine_interestinglookupmodel`), the old GPT vulnerability reports and **S3 bucket** results (`startScan_gptvulnerabilityreport`, `startScan_s3bucket`) with their link tables.
- Columns: `startScan_scanhistory.cfg_out_of_scope_subdomains`, `cfg_starting_point_path`, `cfg_excluded_paths` and `cfg_imported_subdomains`, and `cveFeed_cveentry.raw` (the cve.now entry stored a second time; the modelled columns already hold what is used).
- The scan report no longer has an "Interesting subdomains" section: its keyword list could only be filled in through the Django admin.

Scans, targets, hosts, findings and CVE data are untouched. A tool of your own that read one of these tables or columns needs the backup, or its data taken before the update.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
