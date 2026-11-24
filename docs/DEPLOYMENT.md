# Deployment

cvENGINE is one Docker Compose deployment: `db`, `redis`, `web`, `celery`, `celery-beat`, `proxy`, the AI reviewer (`reviewer`, [AI-REVIEWER.md](AI-REVIEWER.md)) and the built-in scanner (`scanner`, [BUILTIN-SCANNER.md](BUILTIN-SCANNER.md)), which runs the scan tools ([ARCHITECTURE.md](ARCHITECTURE.md)). Two optional parts ship in the same file as Compose profiles and are **off by default**: a `tailscale` service ([TAILSCALE.md](TAILSCALE.md)) and the old in-stack OpenVAS containers, 15 Greenbone services the application no longer uses (OpenVAS runs on a Sentinel, [OPENVAS.md](OPENVAS.md)). Until you switch one on, none of its containers exist, run, publish a port or use memory. Sentinels, the scanner agents you run on other machines, are not part of this stack: each runs from its own repository and calls this server over HTTPS on 443. The [install steps](#install) are below. Size the server for your scans: 4 GB of RAM is the least (the installer warns below that) and 8 GB is comfortable with the built-in scanner, and heavy jobs queue by memory use ([Memory](#memory), [CONFIGURATION.md](CONFIGURATION.md#memory-and-workers)). Images build for amd64 and arm64.

## Small hosts (1 to 2 GB)

The defaults below were measured on a 3000-target stack (3000 hosts, 18,000 findings, 1,500 secrets, 300,000 Sentinel task rows, 50 Sentinels polling every 3 seconds and 10 dashboard tabs) with every container limited as listed. Peak resident memory seen under that load: `web` 560 MB, `celery` 900 MB (four worker pools, idle plus discovery), `celery-beat` 134 MB, `db` 460 MB (of which the shared buffers), `redis` 10 MB. A report PDF of the whole 3000-host project peaks at 350 MB in a child of the worker (it was 2.9 GB before the renderer cut the report into chunks).

| Setting (`.env`) | Default | Small host (2 GB) | Why |
| --- | --- | --- | --- |
| `POSTGRES_SHARED_BUFFERS` | `256MB` | `256MB` (`128MB` at 1 GB) | The working set of the dashboard, hosts and Sentinel queries was 100% cache hits (`pg_stat_database`: 65% at the PostgreSQL default of 128 MB before the new indexes, 100% after). |
| `POSTGRES_EFFECTIVE_CACHE_SIZE` | `768MB` | `768MB` | What the planner assumes the operating system caches; no memory is reserved. |
| `POSTGRES_MAINTENANCE_WORK_MEM` | `64MB` | `64MB` | Index builds (an update builds its new indexes concurrently) and autovacuum. |
| `POSTGRES_RANDOM_PAGE_COST` | `1.1` | `1.1` | The data directory is on an SSD; the PostgreSQL default of 4 favours sequential scans of the 300,000-row task table. Use `4` on a spinning disk. |
| `POSTGRES_MAX_CONNECTIONS` | `300` | `100` | The web container holds at most 16 persistent connections, the workers about 30 at their busiest, beat one. Lower it only if you also keep the worker pools small. |
| `CVENGINE_DB_CONN_MAX_AGE` | `60` (web only) | `60` | A request that opened a connection spent 3.8 ms of a 5 to 60 ms answer on it, and the database forked a backend each time. `0` brings the old behaviour back. |
| `WEB_MEM_LIMIT`, `CELERY_MEM_LIMIT`, `BEAT_MEM_LIMIT` | `1g`, `4g`, `512m` | `1g`, `2g`, `256m` | Container ceilings. Report PDFs, discovery and feed workers share the celery ceiling; lower `DISCOVERY_CONCURRENCY` (default 8) to 4 on a 2 GB host. |
| `CVENGINE_AGENT_TASK_RETENTION_DAYS` | `30` | `7` to `14` | A Sentinel task row is about a kilobyte: a week of scanning 3000 targets was 300,000 rows (300 MB with indexes). Also on Settings, configMaxxing, **Data retention**. |
| `CVENGINE_REPORT_MAX_HOSTS`, `CVENGINE_REPORT_MAX_WRITEUPS` | `500`, `50` | defaults | Bound the PDF: the hosts report's table, and the issues written up in full in a findings report (findings are grouped into issues across hosts). They keep a report readable and quick to build. |

Changing a `POSTGRES_*` value recreates the `db` container once on the next update or `docker compose up -d` (a few seconds of downtime, no data change).

## Sizing the database

The `db` service starts with the values above whatever the host has, so a bigger host leaves memory unused and sorts spill to disk. Every value is a line in `.env`. An update sizes the first four for the host by itself (the host review's postgres rule, below): it raises only a value that is not set or still the default, never lowers one, and keeps them inside the database's container ceiling. A value you set is yours and is left. For a host with 12 GB of RAM that runs the whole stack:

| Setting (`.env`) | Default | 12 GB host | Note |
| --- | --- | --- | --- |
| `POSTGRES_SHARED_BUFFERS` | `256MB` | `1GB` | PostgreSQL's own cache, reserved when the database starts. |
| `POSTGRES_EFFECTIVE_CACHE_SIZE` | `768MB` | `4GB` | What the planner assumes the operating system caches; reserves nothing. |
| `POSTGRES_WORK_MEM` | `4MB` | `16MB` | Per sort or hash step, per connection, not per query or per server: the web server alone has 2 workers of 8 threads (16 connections) and the workers add their own, so the busiest moment can use it many times over. Raise it when `pg_stat_database` shows many temporary files. |
| `POSTGRES_MAINTENANCE_WORK_MEM` | `64MB` | `256MB` | Index builds and autovacuum. |
| `DB_MEM_LIMIT` | none in `docker-compose.yml` | `4g` | The `db` container's ceiling, where an overlay compose file sets one (`mem_limit: "${DB_MEM_LIMIT:-...}"` for `db`); it must stay above the shared buffers plus the work memory in use. |
| `POSTGRES_SHARED_PRELOAD_LIBRARIES` | empty | `pg_stat_statements` (optional) | Per query statistics. Run `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;` once in the cvENGINE database after the restart. |

Scale the first four with the memory the host can give the database.

**What the update writes.** The host review (`scripts/host-review.py`, the postgres rule) reads the memory the database can really use: its container ceiling (`DB_MEM_LIMIT` or a `mem_limit` in an overlay, after the limits rule raised one below its floor), else its share of the host after the other containers' ceilings. From that:

| Setting | Written |
| --- | --- |
| `POSTGRES_SHARED_BUFFERS` | a quarter of that memory rounded down to 128MB, at most `2GB`, never below `256MB` |
| `POSTGRES_EFFECTIVE_CACHE_SIZE` | the host's memory after the other containers' ceilings, at least what the database may use, at most 55 percent of the host |
| `POSTGRES_WORK_MEM` | `16MB` from 3 GB, `8MB` from 1.5 GB, else left at `4MB` |
| `POSTGRES_MAINTENANCE_WORK_MEM` | `256MB` from 3 GB, `128MB` from 1.5 GB, else left at `64MB` |

Before it writes, it checks that shared buffers, plus work memory for 4 sort steps on each of 24 busy connections (the web server's 16 threads and the workers), plus one maintenance job fit in 90 percent of that memory, and takes smaller values until they do: the kernel kills a database that reaches its ceiling. If your own values do not fit, it says so and changes nothing. The production host this was written for (12 GB, the database held to `2g`) gets `512MB`, `3328MB`, `8MB` and `128MB`; `DB_MEM_LIMIT=4g` gets `1GB`, `16MB` and `256MB`. Each value goes into the env file Compose reads, with a comment line, after a backup (`<file>.cvengine-review-<time>`), and the update log says *Postgres settings changed, the database restarts once during this update*: the update's `docker compose up -d --no-deps db` recreates the container because its command line changed. A second run changes nothing. **Settings, Sentinels, Which scanners run** does not restart the database, so it leaves the values for the next update. The review never writes `DB_MEM_LIMIT` for this; raise the ceiling yourself and the next update sizes up a value it wrote. A changed value takes effect only when the database restarts: run `docker compose up -d db` (with the same `-f` files and `--env-file` as your other compose commands), which recreates the `db` container in a few seconds and keeps the data. These command line values take precedence over a value set with `ALTER SYSTEM` or in `postgresql.conf`, so move such a setting to `.env`.

## Finding slow queries

Three `.env` values help find the statements that cost the database the most. All are off by default and the update never sets them: they are diagnostics, so turn them on while you look and back off when you are done. Each takes a restart of the database: `docker compose up -d db` (with the same `-f` files and `--env-file` as your other compose commands) recreates the `db` container in a few seconds and keeps the data.

| Setting (`.env`) | Default | To diagnose | What it does |
| --- | --- | --- | --- |
| `POSTGRES_SHARED_PRELOAD_LIBRARIES` | empty | `pg_stat_statements` | Loads the per query statistics. |
| `POSTGRES_TRACK_IO_TIMING` | `off` | `on` | Records how long each statement waited on disk reads. |
| `POSTGRES_LOG_MIN_DURATION_STATEMENT` | `-1` (no log) | `1000` | Writes every statement that ran for 1000 ms or more to the database log, with its duration. |

1. Set the values in `.env`, then run `docker compose up -d db`.
2. Once, in the cvENGINE database (`docker compose exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"`), create the extension:

   ```sql
   CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
   ```

3. After the server has done a few hours of its usual work, rank the statements by the total time they took:

   ```sql
   SELECT round(total_exec_time) AS total_ms, calls, round(mean_exec_time::numeric, 1) AS mean_ms,
          round((shared_blk_read_time + shared_blk_write_time)::numeric) AS io_ms, rows, left(query, 120) AS query
   FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20;
   ```

   `io_ms` stays 0 unless `POSTGRES_TRACK_IO_TIMING` is `on`. `SELECT pg_stat_statements_reset();` starts the counts again.
4. The slow log: `docker compose logs db | grep 'duration:'` lists each statement of 1000 ms or more with its time.

To turn them off, remove the lines from `.env` (or set `off` and `-1`) and run `docker compose up -d db` again. `pg_stat_statements` costs little and may stay loaded.

Two more diagnostics are on by default, because the evidence they keep is needed after the fact: `POSTGRES_LOG_LOCK_WAITS` (`log_lock_waits`: a statement that waits longer than a second for a lock is logged with the process that holds it; `docker compose logs db | grep 'still waiting'`) and `POSTGRES_TRACK_WAL_IO_TIMING` (`track_wal_io_timing`: the time spent writing and flushing the write-ahead log, in `pg_stat_io` where `object = 'wal'`). Together they tell a slow single row `UPDATE` that waited on another transaction's lock from one that waited on its commit's flush to a busy disk. The host review says whether they are on ([CONFIGURATION.md](CONFIGURATION.md)).

## Ports

| Port | Bound to | Service |
| --- | --- | --- |
| 443 | all interfaces | `proxy`, the HTTPS front door |
| 8082 | all interfaces | `proxy`, redirects to HTTPS |
| 8000 | not published | `web`. Opt in on `127.0.0.1` with `docker-compose.webport.yml` (your own reverse proxy) or `docker-compose.hostnet.yml` (which publishes it for the scanner) |
| 5432 | `127.0.0.1` | `db` |

Firewall 443 and 8082 to the people who need them. The development stack has no proxy and publishes 8000 and 5432 on `127.0.0.1` only. The optional `tailscale` and `openvas` profiles publish no ports at all.

## Install

On a Linux server (Debian or Ubuntu is easiest; 4 GB of RAM at the least and 8 GB for comfort, and 20 GB of free disk for a fresh install; `install.sh` warns below about 15 GB. Updating an install needs its own free space, about 14 GB for the first update to 1.4, see [UPDATES.md](UPDATES.md#small-hosts-disk-memory-and-stuck-scans)):

```bash
git clone https://github.com/hevnsnt/CVEngine.git
cd CVEngine
sudo ./install.sh
```

It is a thin bootstrap: setup itself happens in the browser. It checks the machine, installs what is missing, generates every secret, detects the address to use, creates the HTTPS certificate, builds and starts cvENGINE (the first build takes several minutes), waits until it answers, creates the admin account and prints the address, your username and a generated password (shown once; a re-run says the account exists and points to `make admin-password`). Open the address: the setup wizard continues there. If you lose the password, `make admin-password` prints a new one for the `admin` account (use `sudo` if the installer ran as root). To use a name instead of the detected address, run `sudo ./install.sh --domain scanner.example.com`.

Which scanners this server uses can be given ahead of time for automation: `--sentinels=internal` (the default: the built-in scanner only), `--sentinels=both` (plus external Sentinels you add in the browser) or `--sentinels=external` (nothing scans here; the built-in scanner's 5 GB image is never downloaded). On a terminal, one optional question offers the same three answers (Enter takes the default); `-n`/`--non-interactive`, `CI` set, no terminal, or an existing `.env` skip it. OpenVAS is installed and started by none of them: it runs on a Sentinel and costs about 4 GB of RAM and 60 GB of disk there ([OPENVAS.md](OPENVAS.md)). Running it again is safe: it keeps `.env`, the certificate and the earlier choice, and a flag changes the choice. When another program holds port 443, set `CVENGINE_HTTPS_PORT` (and `CVENGINE_HTTP_PORT` for 8082) in `.env` before installing; the address then ends in `:PORT`.

**First sign-in.** Open the printed address. Browsers warn about the private certificate authority until you trust `secrets/certs/ca.crt` (copy it from the server to the computer whose browser you use). After you choose your own password, the setup wizard (superusers only) creates your organization and project, offers an optional AI model (paste an Anthropic, OpenAI, or OpenRouter key; set up Ollama or vLLM later in Settings), adds your first target if you confirm you are authorized to test it (discovery starts the moment you add it), and offers optional Shodan, VirusTotal, and SecurityTrails keys. The CVE feed starts loading about a minute after the workers come up.

**Step by step.** To run the steps yourself (any Linux with [Docker Engine](https://docs.docker.com/engine/install/), the Compose plugin, `git`, `make`, and `python3`, in a `git clone`, not a release archive):

```bash
./scripts/init-env.sh    # creates .env: generates its passwords and sets DOMAIN_NAME to this machine's address
make certs               # HTTPS certificate for the built-in proxy
make up                  # build and start
# wait until https://<your address>/ answers (follow it with: make logs), then:
make admin               # create your admin account: its password is generated and printed once
```

To choose the password yourself instead, put it in `DJANGO_SUPERUSER_PASSWORD` in `.env` before `make up`, or run `make username`. To serve it on the Internet under a real name with a trusted certificate, see [HOSTING-ONLINE.md](HOSTING-ONLINE.md).

## Linux, Mac, and Windows

`install.sh` checks that this is Linux, that it is root (it re-runs itself through `sudo`), the architecture, memory (it warns below about 3.5 GB), free disk on the checkout's filesystem (it warns below about 14 GiB), that ports 443 and 8082 (or the ones set in `.env`) are free (it stops if not), and whether Docker's registry and GitHub answer (it only warns). On Debian and Ubuntu it installs curl, make, python3, git, openssl, and the Compose plugin with `apt`. Docker comes from `get.docker.com` on any distribution that script supports. On other Linux it stops at the first missing one of those tools and names it, so install them and run it again, or follow the README steps. It needs Compose 2.24 or newer and stops, naming the requirement, when the installed one is older. When a step fails it prints the last 25 log lines of `web`, `proxy`, and `db`. It also installs the update watcher into root's crontab, so the Approve button works straight away (it only warns when `crontab` is missing, and skips it when automatic deployment is installed).

Running it again keeps `.env`, the certificate (unless the address changed), and your data, then rebuilds and restarts from the code in your checkout. It does not fetch new code or wait for scans ([UPDATES.md](UPDATES.md)). `make admin` then says the account already exists and changes nothing.

On macOS or Windows, install Docker Desktop (with the WSL 2 backend on Windows), clone the repository, and run the README steps from a shell where `make` works, such as the macOS terminal or a WSL 2 distribution. Without `make`, the commands are plain Compose calls:

```bash
./scripts/init-env.sh
docker compose -f docker-compose.setup.yml run --rm certs
docker compose up -d --build   # runs the one-off migrate service first (migrations, the database role check), then the rest
docker compose run --rm -T migrate python3 manage.py create_admin
```

`.env` must exist first, because the database will not start with an empty password. A plain `docker compose up` does not record the installed commit for the updater, so the in-app update check shows it as unknown (`make up` records it). It also does not install the update watcher: run `sudo scripts/install-updater.sh` once so the Approve button works.

Give Docker Desktop at least the memory recommended above.

Docker Desktop is fine for trying cvENGINE and for scanning the public internet, with one limit: nmap's operating system detection cannot work from it. See [Operating system detection and the scan path](#operating-system-detection-and-the-scan-path) below.

## Operating system detection and the scan path

nmap finds a host's operating system from how it answers sixteen crafted probes, some malformed on purpose (a segment with FIN, PSH and URG set, a segment to a closed port with an odd option layout). That only works if the probes arrive as sent and the answers return as sent. nmap's own guide says so: "NAT gateways, firewalls, and especially port forwarding can confuse OS detection", and the cure it gives is to scan "from the same network segment" as the target. The scan tools run in the built-in `scanner` container, which shares the `celery` container's network namespace, so what matters is the network path that container has. Two paths damage it.

**Docker's default bridge network (Linux).** Every connection is translated with iptables and conntrack. A probe with an impossible flag combination is marked `INVALID` by conntrack, is not translated, leaves with the container's private address, and its answer has nowhere to go. Measured here with real Docker (Engine 29.9.2, nmap 7.94, one Linux target, the same scan from each path):

| Path of the scanning container | Top guess | `T7` probe (FIN+PSH+URG) | Distance |
| --- | --- | --- | --- |
| Default bridge network | Linux 5.3 - 5.4 (94%), then HP P2000 G3 NAS device (93%) | lost | 2 hops |
| `network_mode: host` | Linux 5.3 - 5.4 (97%) | answered | 1 hop |
| macvlan (its own address on the LAN) | Linux 5.3 - 5.4 (97%) | answered | 1 hop |

The guess is only a little worse on a good day, and wrong on a bad one (the NAS ranked first in other runs). The same loss breaks nmap's `-sN`, `-sF` and `-sX` scans.

**Docker Desktop (macOS, Windows).** The container's traffic never reaches the target: Docker's user-space stack (`vpnkit`, now `com.docker.backend`) creates a virtual TCP/IP stack for each remote address, sees the SYN, makes the real connection from the host, and answers the container itself ("How Docker Desktop Networking Works Under the Hood"). Open ports, services and banners are right, because the real connection is made. Every operating system guess describes that stack: one install saw "Google Fuchsia" on an Ubuntu server and a NAS, and an Apple OS X release on a Dell iDRAC. No Docker network setting changes this. Docker's documentation says macvlan "is not supported on Docker Desktop for Mac or Windows", and that Desktop's host networking "works on layer 4": protocols below TCP and UDP are not supported.

### What cvENGINE does about it

- It **measures the path**. Once a day, from the scanning container, `check_os_path` sends a plain SYN and the FIN+PSH+URG probe to a closed port of up to eight hosts the scans already reach (each on a different /16, using the closed port nmap itself found), and notes whether each drew a reset. A path that answers the plain probe and loses the odd one on most hosts is a translating path. Run in the three containers above it said `interfering` on the default bridge and `direct` on host networking and on macvlan. It sends two packets to a host nmap already sends the same probe to. It needs at least three hosts on three different /16 networks that the scans fingerprinted lately, so a lab that is one LAN never gets a verdict and detection fails open: guesses are believed unless the VM kernel is recognised.
- It **recognises Docker Desktop** from the VM kernel (`linuxkit` on macOS, `microsoft-standard-WSL2` on Windows, OrbStack; also `moby` and `boot2docker`, the kernels of the early Docker for Mac and of docker-machine), which no probe can tell apart. A VM that runs an ordinary distribution kernel (Colima, Podman machine, Rancher Desktop on macOS) has no name to recognise; there only the daily measurement can tell, or `CVENGINE_OS_DETECTION=distrust`.
- When either is true, a packet-based guess made by this server's scanner is **not stored and not given to the AI**, and guesses stored earlier are removed. A guess a Sentinel measured on its own network (stored with `os_source` set to `sentinel`) is kept and given to the AI: it did not cross this path. A Sentinel guess stored by an earlier version has no such mark until the host's next Sentinel scan, and is treated as a local one until then. The host still gets an operating system from what survives any path, because a full TCP connection does cross it: the distribution in an SSH or HTTP banner, the operating system CPE and `ostype` from service detection, and the Windows build from SMB and RDP. It is marked as service detection and not as a packet measurement. A host whose services say nothing about the system has none.
- `get_system_status` (and the status page) report it under `os_detection`: whether guesses are believed, why not, the measurement, and what to do.
- `CVENGINE_OS_DETECTION` overrides everything: `trust` believes the guesses anyway, `distrust` never does.

### Getting packet-based detection back

Take the translation out of the scanner's path.

- **Linux host or VPS (the usual install):** use one of the two overlays. Both were run for real, with the results above.
  Both move only the built-in scanner, where every scan runs: the server's containers (celery included) stay on the compose network and carry no scan traffic. An install that used one of them when they moved celery needs no step: the update recreates celery on the compose network and the scanner with the overlay.
  - `docker-compose.hostnet.yml` puts the built-in `scanner` container on the host's network (`docker compose -f docker-compose.yml -f docker-compose.hostnet.yml up -d`). It reaches the server on the host's loopback, where web is published (`127.0.0.1:8000`, `CVENGINE_WEB_HOST_PORT` moves it), and the server writes that address into its enrollment (`CVENGINE_SCANNER_SERVER_URL`). Do not combine it with the `tailscale` profile, which joins the scanner's network namespace: run Tailscale on the host instead. Needs Docker Compose 2.24 or later.
  - `docker-compose.macvlan.yml` gives the `scanner` container its own address on your LAN, with its bridge network (`scanner_network`) kept to reach the server (set `CVENGINE_SCANNER_IP`, `CVENGINE_SCANNER_SUBNET`, `CVENGINE_SCANNER_GATEWAY` and `CVENGINE_SCANNER_PARENT` in `.env`). Needs Docker Engine 28 or later (`gw_priority`). The switch port must accept more than one MAC address; Wi-Fi access points usually do not, so use `ipvlan` in layer 2 mode there. A macvlan container cannot reach the Docker host itself (a kernel restriction).
  - Rootless Docker and Podman use a user-space network stack and behave like Docker Desktop.
- **macOS and Windows:** Docker Desktop cannot send these probes at any setting. The options that hold up are a [Sentinel](SENTINELS.md) on a Linux machine or VM on the network to be measured (it runs with host networking, and a Sentinel on Docker Desktop reports `os_reliable: false`), or running the whole stack on a Linux machine. A Linux VM with a bridged network adapter running Docker Engine should work (Lima's `socket_vmnet` bridged mode gives the VM an address from the LAN's own DHCP server; Colima has a bridged mode too), but that was not run here, and a Wi-Fi interface is a poor bridge target because access points refuse extra MAC addresses: use Ethernet.
- Commercial scanners say the same: Tenable "does not recommend deploying Tenable Nessus behind a NAT device unless it is scanning the internal network", and runZero asks for host networking and a native explorer.

## HTTPS

`make certs` creates a private certificate authority and a certificate in `secrets/certs/` for `DOMAIN_NAME` (a hostname or an IP address), `localhost`, `127.0.0.1`, and anything in `CERT_EXTRA_SANS`. `install.sh` runs it only when the certificate is missing or does not match the address. Run it before `make up`, and again after changing `DOMAIN_NAME` or `CERT_EXTRA_SANS`. It is safe to run again at any time: it issues a certificate only when one is needed (none yet, the names changed, fewer than 30 days left, or an older 10-year one), and `CERT_FORCE=1 make certs` issues one regardless. The built-in proxy serves HTTPS (TLS 1.2 and 1.3, HTTP/2) on 443 and redirects plain HTTP on 8082 to it. It accepts request bodies up to 4 MB. Browsers warn until you trust `secrets/certs/ca.crt`, which you copy from the server.

The files in `secrets/certs/` are `ca.crt`, `ca.key`, `ca.srl`, `rengine.pem`, `rengine_chain.pem`, and `rengine_rsa.key`. Both certificates use RSA 4096. The authority is valid for 3,650 days; the server certificate for **397 days** (browsers refuse a longer one). A new authority's key is encrypted with `AUTHORITY_PASSWORD`. A new server certificate reuses the server key, the authority and the names, so browsers that trust `ca.crt` keep trusting it and nothing has to be copied again. An authority made by an older version keeps an unencrypted key until you delete `ca.key` and `ca.crt` and run `make certs` again, after which browsers need the new `ca.crt`.

**Renewal is automatic.** `scripts/renew-certs.sh` runs the same certs service twice a day and issues a new certificate when fewer than 30 days remain, so there is no expiry day and no browser warning window. It is started by the update watcher (`scripts/install-updater.sh`, which `install.sh` sets up: a cron entry that runs every minute, and the script does nothing until its next check is due), by the automatic-deployment timer, and just before an update recreates the proxy, so any of them is enough. A new certificate is written over the old files in place, and the proxy is told to reload (`nginx -s reload`: no restart, no dropped connection; if the reload fails it recreates the proxy once). The authority and its password are never touched. A certificate someone else issued (Let's Encrypt, a Cloudflare origin certificate, see [HOSTING-ONLINE.md](HOSTING-ONLINE.md)) is never replaced by this: it is reported as not renewed here, and renewing it stays with its issuer.

An install made before this release holds a 10-year server certificate: it is replaced once, by the first check after the update (same key, same authority, same names), with 397 days. The first check runs within minutes of the watcher's next cron tick.

**Seeing it.** **Settings > Updates** shows how many days the certificate has left and turns into a warning when a renewal failed, fewer than 30 days remain, it has expired, or no check has run for days. `get_system_status` (`GET system/status`, App Admin) reports the same under `system.certificate` (`not_after`, `days_left`, `state`, when it was last checked and renewed, the last error) and adds a line to `problems` when something needs attention. Nothing is shown on an install that does not report (no cron and no update): run `scripts/renew-certs.sh` yourself to check and publish once. The script's log is `cert.log` in `.git/cvengine-update` (and `.git/cvengine-auto-deploy` for the timer). `CVENGINE_CERT_CHECK_SECONDS` (default 43200) and `CVENGINE_CERT_RETRY_SECONDS` (default 3600, the wait after a failure) change the schedule.

For a public site with a browser-trusted certificate (Let's Encrypt, Cloudflare), follow [HOSTING-ONLINE.md](HOSTING-ONLINE.md). For a server with no inbound port, published through a Cloudflare Tunnel, see [Through a Cloudflare Tunnel](HOSTING-ONLINE.md#c-through-a-cloudflare-tunnel-no-inbound-port): the tunnel needs the bundled proxy told to believe it (`config/nginx/trusted-upstreams.conf`), which is the one thing that differs from the proxy of your own below.

**Client addresses.** The IP allowlist, the abuse guard, the sign-in lockout and the audit log need the real client address. The web service reads it from `X-Forwarded-For`, but only when the peer connecting to it is listed in `CVENGINE_TRUSTED_PROXIES`, and by default that is the bundled proxy alone: the proxy has a fixed address (`172.16.238.10`, `CVENGINE_PROXY_ADDRESS`) on `proxy_network`, a network only it and `web` are on, and it reaches `web` there and nowhere else. The built-in scanner, the AI reviewer and anything on the host reach `web` from other addresses, so the header they send is ignored and they cannot choose the address the server records or bans. The bundled proxy in turn replaces any `X-Forwarded-For` it receives with the address that connected to it, except in two cases, where it passes the chain on unchanged (the application takes its right-most address):

- the request came in on the tunnel listener (container port 8443, not published by default) from a peer listed in the file mounted at `/etc/nginx/trusted-upstreams.conf` (empty by default; [Through a Cloudflare Tunnel](HOSTING-ONLINE.md#c-through-a-cloudflare-tunnel-no-inbound-port));
- the request came in on port 443 with this install's upstream secret in `X-CVEngine-Upstream` ([Client addresses behind a host proxy](#client-addresses-behind-a-host-proxy)). The proxy removes that header before the request reaches the application.

Port 443 never believes the peer alone: Docker's port publishing shows an outside client (every IPv6 client, for one) to the proxy as the same gateway address a host nginx has. Run `scripts/client-address-check.sh` to see which address the server takes for a request through your public name; every update runs it and writes the answer to its log. Its last line is the server's verdict (`web/cveFeed/client_address.py`), made from where the proxy's port 443 is published (`docker compose port proxy 443`) and a label the proxy puts on the probe request only (`X-CVEngine-Probe-Forwarded`: `believed`, `ignored`, `wrong-secret`, `tunnel` or `none`, what it did with the forwarding headers that came with it; the label changes nothing the proxy believes). Published on the host's port 443 with no forwarding header: nothing is in front, nothing to do. A host proxy in front whose address is not believed yet, one that sends an old secret, or one that passes on Cloudflare's address: App Admins get a notice in the status strip, Settings, Updates and the system status with the lines to install, a Copy button and Check again, and it clears itself when the check passes (also re-checked hourly while open). The lines are served to App Admins in the web interface only (`GET /cve/api/settings/client_address/snippet`, no-store, audited as `client_address.snippet_shown`, refused to an agent).

### Client addresses behind a host proxy

When a web server on the host terminates TLS and forwards to the bundled proxy (for example Cloudflare, then the host's nginx, then `127.0.0.1:18443`, which a Compose overlay publishes for the proxy's port 443), the proxy sees the Docker gateway connect, so without this step every visitor is one address: five wrong passwords from anyone lock the account out for everyone, and a ban or the IP allowlist acts on everybody at once.

1. The install has a secret: `CVENGINE_UPSTREAM_SECRET` in `.env` (and in the Compose env file, such as `.env.vps`). `make up`, the installer and every update generate it when it is missing, and recreate the proxy, which loads it.
2. Print the lines for the host nginx with the secret filled in, into a file only root can read:

   ```bash
   (umask 077; scripts/client-address-check.sh --snippet | sudo tee /etc/nginx/snippets/cvengine-client-address.conf >/dev/null)
   ```

   The shipped file is `config/nginx/host-proxy-client-address.conf`. It holds exactly two lines, `proxy_set_header X-Forwarded-For $remote_addr;` (the address this nginx saw, replacing anything the client sent) and `proxy_set_header X-CVEngine-Upstream "<secret>";`.
3. Include it in the `location` that holds the `proxy_pass` to the bundled proxy (`include snippets/cvengine-client-address.conf;`), next to the other `proxy_set_header` lines, and remove any other `X-Forwarded-For` line there. Behind Cloudflare, `$remote_addr` must already be the visitor: `real_ip_header CF-Connecting-IP;` and one `set_real_ip_from` line per Cloudflare range (https://www.cloudflare.com/ips/).
4. `sudo nginx -t && sudo systemctl reload nginx`, then `scripts/client-address-check.sh`. `ok: a request through https://... arrived as <address>, the address Cloudflare saw` means it works; `PROBLEM` names what is still missing.

Without the snippet, or with an empty secret, the proxy behaves as before (it believes no header on 443): nothing breaks, the addresses are just all the gateway. A new secret (remove the line from `.env` and update) must be put into the host snippet again. Anyone who holds the secret and can reach the proxy's port 443 directly can choose the address the server records, so keep the snippet root-only and the proxy's port on loopback where a host proxy fronts it.

A Compose overlay for such a host (for example `docker-compose.vps.yml`) may move the proxy's published ports, but it must not: set `CVENGINE_TRUSTED_PROXIES` to a range, publish `web`'s port 8000 again (use `docker-compose.webport.yml` only for your own reverse proxy), replace the proxy's `networks` (its fixed address on `proxy_network`), its `environment` (`CVENGINE_UPSTREAM_SECRET`) or the `./config/nginx/templates` mount, or move `web`'s `rengine` alias off `proxy_network`. Each of these either lets other containers choose the client address again or stops the secret from loading (the check script reports the second).

### Your own reverse proxy

To use your own proxy in place of the bundled one, publish the web service with `docker-compose.webport.yml` (`127.0.0.1:8000`, `CVENGINE_WEB_HOST_PORT` moves it; add it to `CVENGINE_COMPOSE_FILES`), point the proxy at it, and have it set `X-Forwarded-Proto` and `X-Forwarded-For`, replacing any values from the client. The web container sees your proxy connect from a Docker gateway address (`docker compose exec web python3 manage.py client_address_probe trusted` prints what it trusts; your proxy's address is in the web container's logs, or `docker network inspect`), so add that one address to `CVENGINE_TRUSTED_PROXIES` beside the default (`CVENGINE_TRUSTED_PROXIES=172.16.238.10,<gateway>`). Anything else on the host that can reach `127.0.0.1:8000` can then choose its client address too. Then add `CVENGINE_CSRF_TRUSTED_ORIGINS` (your https address) to `.env` and run `make up`.

Django sends an HSTS header with a one-hour lifetime by default and does not include subdomains or ask for preloading. Raise `CVENGINE_HSTS_SECONDS` only once your public TLS path is reliable.

## AI models

cvENGINE runs no model itself. In **Settings, AI model**, choose Anthropic, OpenAI, OpenRouter, [Ollama](https://github.com/ollama/ollama), [vLLM](https://github.com/vllm-project/vllm), or [LM Studio](https://lmstudio.ai). For Ollama, vLLM and LM Studio enter your server's **Base URL** (the list of models loads by itself; **Refresh list** asks again), choose a model for each job in **Which model does which job** (a name the list cannot know goes under **Other**), tick **Use this model to confirm CVE matches**, and **Save**.

**Base URL for every provider.** Anthropic and OpenAI have one too, optional and empty by default (the vendor's own address): set it for a gateway or proxy such as LiteLLM, which then receives the key you type. For Anthropic a bare address (`https://gateway.example`, or one ending in `/v1`) is the server and the messages endpoint is under it; an address with any other path is used as written. A key is stored for one provider at one host: changing the provider or the host (the vendor's own address counts as a host) clears the stored key, and you type it again for the new service. **A key is never guessed onto a vendor.** On first-run setup a key is recognised only by a prefix that names one vendor (`sk-ant-` Anthropic, `sk-or-` OpenRouter, `sk-proj-` OpenAI); a bare `sk-...` key is issued by several vendors (DeepSeek and others), so you choose the provider and nothing is sent until you do.

**Request settings.** In **Settings, AI model, Request settings** (also through the API below) the timeouts, the reply limit, the context window, structured output, reasoning and Ollama's keep-alive are settings of the AI model, saved in the database and applied to every request and every stage (`GET` and `PUT /cve/api/settings/ai`; App Admins only). A value there replaces the environment variable of the same name ([Configuration](CONFIGURATION.md#ai-requests)); an empty one follows the variable and then the provider's default. A connection test that fails says what to change: a refused key, a rate limit, a timeout (and the seconds that were waited), an unreachable server or a connect timeout, an address that is not an AI API, a reply cut off at the limit or one with no text. The test waits at most 240 seconds even if the Request timeout is longer (it runs inside a web request, which ends at 300 seconds), and says so. Anthropic requests are not streamed, so a very large reply limit or high reasoning on a slow generation can time out on this side while the provider still bills it: raise the Request timeout with them, and note that older Claude models refuse very large reply limits with a 400.

**Reasoning.** `CVENGINE_AI_REASONING` (or the `reasoning` setting, where `default` sends nothing even when the variable is set) (`off`, `low`, `medium`, `high`, `max`; unset sends nothing) turns on a model's reasoning in the way its provider takes it: `reasoning_effort` for OpenAI's o-series and gpt-5 models, adaptive thinking and an effort for Claude 4.6 and later (`budget_tokens` for Claude 3.7 to 4.5), `think` for Ollama. It is not sent to vLLM, LM Studio or OpenRouter: set reasoning on the server. See [Configuration](CONFIGURATION.md#ai-requests) for each mapping, and raise `CVENGINE_AI_MAX_TOKENS` with it, because thinking is paid from the reply limit.

- **A remote machine**, the usual case on a VPS: use any address the server can reach, such as a Tailscale `100.x` address (`http://100.64.0.5:11434`). MagicDNS names do not resolve inside containers. Keep the port on your tailnet or behind a firewall, since Ollama has no authentication.
- **The same machine**: enter `http://localhost:11434`. cvENGINE maps `localhost`, `127.0.0.1`, and `::1` to the Docker host. Ollama must then listen beyond 127.0.0.1 (for example `OLLAMA_HOST=0.0.0.0`) while staying firewalled.
- **vLLM** works the same way with its `/v1` URL, such as `http://100.64.0.5:8000/v1`. An API key is optional.
- **LM Studio** serves an OpenAI-compatible API on port 1234: use `http://100.64.0.5:1234/v1` (or `http://localhost:1234/v1` on the same machine). Start the server in LM Studio's Developer tab, or headless with `lms server start` (or the `llmster` daemon). LM Studio listens on localhost only until you switch on serving on the local network in its server settings, and a server reached over a tailnet or network should have authentication on: LM Studio 0.4 and later can require an API token (Server Settings, Manage Tokens), which you enter here as the **API key**. Leave the key blank when authentication is off. With just-in-time loading on (the default), the model list shows every model you have downloaded, embedding models excluded, and the first request for a model loads it, which can take a minute or more for a large one (cvENGINE waits up to five minutes). With it off, only models you have already loaded are listed. Screenshot reading needs a vision model.

### Local models

Everything below is what the code does with a model on your own server (Ollama, vLLM, LM Studio); for any other OpenAI-compatible server (llama.cpp's `llama-server`, LiteLLM, a gateway) choose **vLLM, llama.cpp or another OpenAI-compatible server** (stored as `vllm`) and give its address. Only Ollama, vLLM and LM Studio are treated as self-hosted: they get the default reply limit, and a triage gets temperature 0, a fixed seed and a JSON Schema. The **OpenAI** provider with another Base URL is sent only what the operator set, because a proxy in front of OpenAI may front a hosted reasoning model that refuses a temperature.

- **Context size.** A finding triage sends about 7,000 characters of instructions and evidence (roughly 2,000 tokens, counted at four characters to a token) and asks for at most 400 back, so 4096 tokens of context is the least that works and 8192 is comfortable. The other stages (CVE detection records, template writing, the validation plan, Nuclei targeting with up to 150 offered tags) send longer prompts that were not measured here: give them 16k or more. Ollama sizes its window by the machine's memory (4k tokens under 24 GiB) and cuts a longer prompt at its start without an error: set the `context_tokens` setting (or `CVENGINE_OLLAMA_NUM_CTX`), and cvENGINE logs a warning when a prompt used 95% of it. vLLM takes `--max-model-len`, LM Studio the model's context length setting.
- **Reasoning off.** cvENGINE sends no switch for reasoning unless you set `CVENGINE_AI_REASONING`, and then only to Ollama (`think`, for qwen3, deepseek-r1, gpt-oss and magistral models); vLLM and LM Studio never get one: turn reasoning off in the server or the model's settings, or pick a model without it. A reasoning model spends its reply limit thinking (its `<think>` block is dropped before the answer is read, but it counts against the limit), and a limit of 400 or 2048 ends before the answer. If you want to keep it, raise `CVENGINE_AI_MAX_TOKENS` (the value replaces the defaults, the triage's too).
- **JSON output.** A triage request carries the triage's JSON Schema (`response_format` to vLLM and LM Studio, `format` to Ollama), and the reply is validated whatever the server did. A server that refuses the schema is asked in JSON mode and then plainly, and remembered for an hour (`CVENGINE_AI_STRUCTURED=off` never sends it). The other stages ask for JSON in the prompt and take the last object in the reply.
- **Limits.** The reply limit (`CVENGINE_AI_MAX_TOKENS`; default: the stage's own answer room, 2048 or more, 400 for a triage), `CVENGINE_AI_TIMEOUT` (default 120 seconds, 300 for LM Studio, which may load a model on the first request), `CVENGINE_AI_CONNECT_TIMEOUT` (10 seconds), `CVENGINE_OLLAMA_NUM_CTX`, `CVENGINE_AI_STRUCTURED`, each also a setting. Ollama's `keep_alive` keeps the model loaded between the scheduled stages (the server unloads it after five minutes by default). See [Configuration](CONFIGURATION.md).
- **When a reply is cut off.** Every stage whose reply hit its limit (the server said `length`) is asked once more with twice the limit plus the thinking room (a triage: 800, or twice yours, up to 32768). If that is cut off too, the call fails with the category `output_truncated`, the finding is not triaged by that attempt, and the failure is recorded with the AI usage of that stage. A reply with no text at all is `empty_response`. The Nuclei tag choice asks once more with four times the reply limit (at most 8192) when an Anthropic answer was cut off before any text (a reasoning model that used the limit thinking), never after a refusal, and when it still fails the scan uses the standard templates, says why in its activity, and does not ask the same question again for 5 minutes, then 10, up to an hour; its calls are capped by `CVENGINE_NUCLEI_AI_MAX_PER_DAY`. The other stages do not retry: the call fails and the stage carries on as it does for any model error.

## Scan more targets at once

cvENGINE scans as much as the machine can hold without running out of memory, and by default that is not much: a handful of scanners at a time, and a few discovery scans in flight. On a small machine that is right. On a bigger one, or when you watch the queue and only one or two targets move at a time, you can allow more.

**Where.** Sign in as an App Admin, open **Settings**, then **configMaxxing** (collapsed in the left column until you click it; the address is `/cve/settings/#configmaxxing`), then **Scan concurrency**. Each number shows its default, the environment variable behind it if you set one, and who changed it and when; **Reset to default** puts one back, and **Reset all configMaxxing settings to defaults** puts everything back. No restart is needed for the scanner limits and the discovery scans kept running; they apply within seconds. The number of hosts assessed at once is the ceiling of the discovery worker's autoscaler: the page resizes the running worker and shows the ceiling the worker reports (the worker grows toward it one slot a second while work is waiting and never runs more), and if the worker does not confirm the change it says so and the number takes effect after the next restart or update.

**What the numbers mean.**

- **Hosts assessed at once** (`DISCOVERY_CONCURRENCY`): how many discovery tasks and host assessments run together. Each assessment works through one host from start to finish, so this is the number of hosts being assessed at one time. Most of an assessment is waiting on a Sentinel, so this can be higher than the number of CPUs. 16 to 24 keeps the Sentinels fed. Every running task holds a database connection; the shipped `POSTGRES_MAX_CONNECTIONS` (300) covers the maximum of 32 with the other workers and the web server.
- **Hosts per assessment batch** (`CVENGINE_ASSESS_BATCH`): how many hosts of one target are carried through one assessment run together, so a Sentinel is handed a batch instead of one host at a time. It only matters where a Sentinel covers the project; leave it at 8 unless a Sentinel sits idle with hosts waiting.
- **Discovery scans kept running** (`CVENGINE_WORK_DEPTH`): how many scans of whole targets the work conductor keeps going or queued. Raise it when you have many targets and the scanners are not busy; `0` stops cvENGINE from starting scans on its own.

**No scanner runs here.** Every scan runs on a Sentinel, and each Sentinel sets how much it runs at once (its slots, on the Sentinels page). These numbers only set how much the server itself does at once, so the way to scan more is another Sentinel, not higher numbers here.

**Safe starting values.** Change a few numbers, watch **Settings, Resources** for a day (the memory each worker container uses), then go on. Auto-tuning (on by default, Settings, configMaxxing, Auto-tuning) sizes the numbers you did not save for this machine, starts there and backs off on trouble; a number you save, or set in `.env` to anything other than its default, is pinned and never moved. Choose Off there to tune everything by hand, and use the table below as your starting point.

| Machine | `CELERY_MEM_LIMIT` | nmap | nuclei, nuclei light | bbot standard, passive | bbot deep | hosts assessed at once | discovery scans kept running |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 4 vCPU, 8 GB | `4g` (the default) | 2 (default) to 3 | 1 | 2 | 1 | 8 (default) | 3 (default) to 4 |
| 8 vCPU, 16 GB | `8g` | 4 | 2 | 3 | 1 | 12 | 6 |
| 16 vCPU, 32 GB | `16g` | 6 | 3 | 4 | 2 | 16 | 10 |

Leave the other scanner kinds at their defaults unless a particular queue is the one that is slow. The slow background sweeps (`nmap-full-bg`, `nmap-udp-bg`) are meant to wait behind everything else, and a higher number sends more probes at the same address.

**More concurrency sends more traffic to your targets.** Ten nmap scans at once are ten times the packets. Check that the networks and the devices you scan can take it (small routers and printers often cannot), and that your scope allows it.

**The best way to scale is a second machine.** A Sentinel scans from its own machine with its own CPU, memory and network path, takes work from this server and reports back, so it adds capacity instead of squeezing more out of one container. Add one before you push the numbers on a single server far above the table ([Sentinels](SENTINELS.md)).

## Memory

Each container has a memory ceiling of its own, set in `.env` and applied by `make up` or the next update:

| Container | Variable | Default | What it holds |
| --- | --- | --- | --- |
| `celery` | `CELERY_MEM_LIMIT` | `4g` | the workers: scan planning, the stages that wait for a Sentinel, the AI jobs, the CVE feed and the storing and judging of results. No scan tool runs here |
| `scanner` | `SCANNER_MEM_LIMIT` | `3g` | the built-in scanner: nmap, naabu, nuclei, testssl.sh, WPScan, wafw00f, bbot, Kingfisher, sshamble and the screenshot browser, as many at once as fit (below) |
| `web` | `WEB_MEM_LIMIT` | `1g` | the web server |
| `celery-beat` | `BEAT_MEM_LIMIT` | `512m` | the scheduler |
| `reviewer` | `REVIEWER_MEM_LIMIT` | `256m` | the AI reviewer |

With PostgreSQL, Redis and the proxy that comes to about 8 GB, which is why 8 GB is comfortable. On a smaller host the installer gives the
scanner 1 GB (`SCANNER_MEM_LIMIT=1g`, written when the host has less than about 7 GB) and warns. Below 4 GB lower `CELERY_MEM_LIMIT` too (the
no scan tool runs in celery, so it needs less than before 1.4). The scanner does not run into its ceiling: it reads its own container limit and weighs every kind of work against it
before it takes the work (`client/admission.py` in the Sentinel). Measured peaks, one run each, against a local lab server: **nuclei 500 MB** (720-735 MB
before it was started with a soft Go memory limit; it loads the whole template set whatever its tags), **the screenshot browser 224 MB** for two pages (a page can
use more; the browser is stopped at 1500 MB), **nmap `-p-` 68 MB**, bbot 66 MB for a one-host run (weighed at 250 MB because a real discovery grows), Kingfisher
about 150 MB. At 2 GB the scanner runs two nuclei and a browser together; at the default 3 GB it runs three nuclei and a browser, which is the mix that was
once killed at 2 GB (one deep nuclei, several light ones and Chromium). A kind that does not fit waits (the server holds the task for the scanner, nothing fails); a run the
kernel kills anyway reports *out of memory, retry later* and the work stays due. To run fewer tools at once, lower how many tasks the scanner runs at once on its
card on the Sentinels page (**Settings**), or lower `SCANNER_MEM_LIMIT`.

**The host-size rule** is one function (`scripts/host-fit.sh`), used by `install.sh` and by every update (the Update button, `scripts/update.sh`, automatic updates):

| Host memory | `SCANNER_MEM_LIMIT` |
| --- | --- |
| under 7 GB (7,000,000 kB) | `1g`, written to `.env` once, with a comment saying why |
| 7 GB or more | nothing written (the default, `3g`) |

A `SCANNER_MEM_LIMIT` you set, or any `CVENGINE_BUILTIN_SCANNER`, is never changed, and running the update again changes nothing more. The update prints one line when it writes (*This host has 4.5 GB of memory, so SCANNER_MEM_LIMIT=1g was written to .env ...*). `CVENGINE_HOST_MEM_MB` replaces the memory it reads; only the tests and rehearsals set it.

**Updating on a small host.** The same under-7-GB rule decides one more thing about the Update button: the cold build of the server image needs about 2 GB and the workers keep the memory they grew to, so on such a host the updater stops `celery` and the built-in `scanner` for the build and starts them again right after it (`web`, `db`, `redis` and `proxy` stay up; `CVENGINE_UPDATE_STOP_CELERY=0` turns it off). It also checks the disk first (about 14 GB free for the first update to 1.4; `CVENGINE_UPDATE_MIN_FREE_MB` replaces the figure) and closes scans that are stuck "running" with no worker instead of waiting for them. All three are automatic and need no terminal: [UPDATES.md](UPDATES.md#small-hosts-disk-memory-and-stuck-scans). If you update by hand with `scripts/update.sh`, none of them applies: check `df -h "$(docker info -f '{{.DockerRootDir}}')"`, and on a small host run `docker compose stop celery scanner` before `docker compose build` and `docker compose start celery scanner` after it.

**The host review** runs before anything is stopped, on every way of updating (`scripts/host-review.py`, called by `cvengine_fit_review` in `scripts/host-fit.sh`): a leftover `DISCOVERY_CONCURRENCY` pin below 4 is removed, a database or web ceiling below what it needs on this host is raised, and the database's memory settings still at their small defaults are sized for the memory it can use ([Sizing the database](#sizing-the-database); the database then restarts once during the update), each with a backup and a line in the update log. It also says whether the database logs lock waits and times its WAL writes (`log_lock_waits`, `track_wal_io_timing`), and warns when the compose files leave them off; it never changes them. See [UPGRADE.md](UPGRADE.md). Run it by hand with `python3 scripts/host-review.py` (report only) or `--apply`.

**The budget check** runs at the end of every update, after the containers started. It adds up the memory limits of the project's running containers and compares the sum with the host: under 90 percent it prints one line, over it prints *Memory warning* with the sum, the largest container and the setting that lowers it (`CELERY_MEM_LIMIT`, `SCANNER_MEM_LIMIT`, `WEB_MEM_LIMIT`, `BEAT_MEM_LIMIT`, `REVIEWER_MEM_LIMIT`, `DB_MEM_LIMIT`). Limits are ceilings, so a sum over the host is a risk, not a failure, and the update does not fail on it. On a 4.5 GB host with the defaults the workers' 4 GB is the largest: lower `CELERY_MEM_LIMIT` (look at what the workers really use with `docker stats` first), or choose **Use my own Sentinels only** to free the scanner's.

**From the command line.**

Almost everyone uses the buttons above. Everything they do can be done from a terminal, and an update run by hand, by cron or by systemd never asks a question and never waits for an answer.

The three choices are keys in `.env` (the same ones `install.sh` writes):

| Choice | `.env` |
| --- | --- |
| Use the built-in scanner only | nothing, or `CVENGINE_SENTINEL_PLAN=internal` (and `CVENGINE_BUILTIN_SCANNER=1` if it was off) |
| Use both | `CVENGINE_SENTINEL_PLAN=both` (and `CVENGINE_BUILTIN_SCANNER=1` if it was off) |
| Use my own Sentinels only | `CVENGINE_BUILTIN_SCANNER=0` and `CVENGINE_SENTINEL_PLAN=external`; the next update removes the `scanner` container |

`SCANNER_MEM_LIMIT` is the built-in scanner's memory ceiling (`1g`, `2g`, ...). To answer the question in a script, pass it to the updater: `scripts/update.sh --sentinels external` (or `internal`, `both`), or set `CVENGINE_INSTALL_SENTINELS=external` in the environment. Either writes the keys above exactly as the dialog would, before anything is stopped. Anything else is refused before the update starts.

**An update with no answer** (cron, `scripts/update.sh` with no flag, an automatic update, an update approved by a server too old to ask) applies the safe default: a host under 7 GB gets `SCANNER_MEM_LIMIT=1g` unless you set one, and a scanner is never removed. When it finds two or more Sentinels of your own live and nobody has chosen, it keeps the scanner, prints the finding and the exact flag (`scripts/update.sh --sentinels external`), and leaves a notice in `web/.update-notice.json` that Settings > Updates and Settings > Sentinels show until somebody chooses. The count of live Sentinels is read from the server's database by a one-off container of the new web image (the running container, still on the old image, cannot start the new code, and a 1.3 server has no such command). When it cannot be read (the database is not reachable), the updater prints that and changes nothing about which scanners run.

Read the state from a terminal: `scripts/update.sh --check` prints the memory the updater sees, whether it will write `SCANNER_MEM_LIMIT`, and how many Sentinels of your own are live when the running server can say (it changes nothing); `grep -E '^(CVENGINE_BUILTIN_SCANNER|CVENGINE_SENTINEL_PLAN|SCANNER_MEM_LIMIT)=' .env` shows the choice; `docker compose run --rm --no-deps -T --entrypoint python3 web manage.py external_sentinels` prints `EXTERNAL_SENTINELS_LIVE n` (read only). The memory budget line (see [DEPLOYMENT.md](DEPLOYMENT.md#memory)) is in the update's output (`scripts/update.sh`) or in the update log under Settings > Updates (`.git/cvengine-update/update.log` on the host).


## Screenshots and AppArmor

The screenshot browser (Chromium, in the built-in scanner container) is sandboxed with user namespaces. Docker's seccomp profile refuses them, which is why `docker-compose.yml` gives the scanner Playwright's seccomp profile (`config/seccomp/playwright-chromium.json`). On a host whose **AppArmor** also restricts unprivileged user namespaces (Ubuntu 24.04 and later, recent Debian and Kali) Docker's own `docker-default` AppArmor profile refuses them as well, and the browser dies at launch: Chromium prints `FATAL credentials.cc ... Check failed: Permission denied (13)`. The seccomp profile alone is not enough there.

What you see: **Settings, System status** and the Sentinels page say *the host's AppArmor profile blocks Chromium's sandbox*, and the scanner stops taking `web_screenshot` work (it no longer declares it), so the pages stay queued instead of failing one by one. Everything else is unaffected. Once the host is fixed, the scanner proves its sandbox again within ten minutes (or at its next restart) and takes screenshots again.

Fix it with a profile that is `docker-default` plus one line, `userns,` (`config/apparmor/cvengine-scanner`). It needs AppArmor 4.0 or newer, which is also the version that introduced the restriction:

```bash
sudo apparmor_parser -r -W config/apparmor/cvengine-scanner     # load it (until the host reboots)
```

Then run the scanner under it with the overlay `docker-compose.apparmor.yml` (it adds `apparmor=cvengine-scanner` to the scanner's `security_opt`; the commented line under `security_opt` in `docker-compose.yml` shows the same). Name the overlay in `.env` so `make up` and the updater keep using it:

```bash
echo 'CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.apparmor.yml' >> .env
docker compose -f docker-compose.yml -f docker-compose.apparmor.yml up -d scanner
```

To keep it across reboots, copy the file to `/etc/apparmor.d/cvengine-scanner` and `sudo systemctl reload apparmor`. The profile changes nothing else about the container.

The fallback is `apparmor=unconfined` in place of `apparmor=cvengine-scanner` in the overlay. It works, and the trade-off is real: the scanner container, which runs scan tools against the internet, then has no AppArmor confinement at all (its capabilities, user and seccomp limits still apply). Use it only to prove the diagnosis, and move to the profile.

## Database roles, networks and logs

The server runs as the least privilege database role `cvengine_app`, not as `POSTGRES_USER` (the owner, used for migrations and backups only); every update and `make up` set it up by themselves, and nothing has to be done by hand ([CONFIGURATION.md](CONFIGURATION.md#database-roles-and-logs), [UPGRADE.md](UPGRADE.md#database-roles-the-server-no-longer-runs-as-the-database-owner)). `docker compose exec web python3 manage.py db_app_role status` says which role a container runs as.

The owner's password (`POSTGRES_PASSWORD`) is in one container only: the one-off `migrate` service, which runs the migrations and checks the app role, then exits. `web`, `celery` and `celery-beat` do not have it, and do not start when the app role cannot log in, unless `CVENGINE_DB_ALLOW_OWNER_FALLBACK=1` is in `.env` ([UPGRADE.md](UPGRADE.md#the-owner-password-leaves-the-application-containers)). Owner commands therefore run in that service or in the `db` container, never with `docker compose exec web`:

| To | Run |
| --- | --- |
| apply migrations (and check the app role) | `make migrate`, or `docker compose run --rm migrate` |
| create an admin account | `make admin` or `make username` (`docker compose run --rm migrate python3 manage.py createsuperuser`) |
| any other owner command | `docker compose run --rm migrate python3 manage.py <command>` |
| a psql prompt as the owner | `make dbshell` (`docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'`) |
| a backup | `scripts/db-backup.sh` and the updaters run `pg_dump` inside the `db` container with `docker exec` |

An install that starts the stack with its own `docker compose up` gets the `migrate` service first through `depends_on`; when its check fails, `docker compose up` reports `service "migrate" didn't complete successfully` and `docker compose logs migrate` shows the `Fix:` line. An overlay must not list `POSTGRES_PASSWORD` under `web`, `celery` or `celery-beat`: Compose would merge it back in, and the updaters refuse such a layout. The database and Redis sit on `data_network` with `web`, `celery` and `celery-beat` only. PostgreSQL logs every connection and disconnection (`log_connections`, `log_disconnections`), and every container's Docker log rotates at 5 files of 50 MB (`CVENGINE_LOG_MAX_FILE`, `CVENGINE_LOG_MAX_SIZE`).

## Who the containers run as

| Service | User | Capabilities | `./web` | Static volume |
| --- | --- | --- | --- | --- |
| `web` | 10002 | none, `no-new-privileges` | at `/var/lib/cvengine/web`, writable (the update requests of Settings, Updates) | read-only |
| `celery` | 10002 | none, `no-new-privileges` | at `/var/lib/cvengine/web`, writable (the watchdog's and the scanner's requests) | **writable** (`collectstatic`) |
| `celery-beat` | 10002 | none, `no-new-privileges` | at `/var/lib/cvengine/web`, read-only (the Django secret) | not mounted; every volume read-only |
| `migrate` (one-off) | 10002 | none, `no-new-privileges` | at `/var/lib/cvengine/web`, read-only (the Django secret) | not mounted |
| `ownership` (one-off) | root | CHOWN, FOWNER, DAC_OVERRIDE only; no network | at `/var/lib/cvengine/web`, writable | writable (hands it over) |
| `proxy` | the nginx image's | the image's | `static/cve/maintenance.html` and `config/nginx`, read-only | read-only |

The application runs the copy of the source its image was built with (`/usr/src/app`, root's and read-only to uid 10002): nothing it can write is ever imported.
uid 10002 owns only what it must write: its home (`/home/cvengine`: `~/.config` with the CVE seed folder, a volume, and `~/logs`, `CVENGINE_LOG_DIR`), the generated
templates, the scan results (with group 101, the proxy's nginx group, mode 0750) and, in celery, the static files. The server listens on 8000 and runs no scan tool,
so it needs no capability at all, not even `NET_BIND_SERVICE` or `NET_RAW`. The host's `web/` folder has group 10002 and mode `1775`: the containers create their
update requests there, and the sticky bit keeps them from changing, renaming or removing anything they did not create (the source, `.version`, what the host
writes). The image is built from an allow list of `web/` (`web/.dockerignore`), so a file the application creates there is never built into the next image.
The built-in scanner's enrollment folder (the `scanner_bootstrap` volume) is 10002's with group 10002 and mode `2750`, and celery writes the blob in it mode
0640: the scanner service keeps its image's own user and is given group 10002 (`group_add`), so it reads the blob and no other account does. celery never
falls back to a blob readable by others; it logs `built-in scanner: no enrollment written` instead ([BUILTIN-SCANNER.md](BUILTIN-SCANNER.md)).
The one-off `ownership` service (`web/ownership.sh`) sets all of this up; every update and `make up` run it after the build and before the migrations, and it
changes nothing the second time. File modes of the secret and the field key: [CONFIGURATION.md](CONFIGURATION.md#the-account-the-server-runs-as).

A command you run in a container runs as uid 10002 too (`docker compose exec web ...`); add `-u 0` only for a one-off look as root. To run a management command
that writes a file for you, write it below `/var/lib/cvengine/web` (that is `web/` on the host), as `make export-cve-seed` does.

## Backups

Back up the database, `.env` and the secret file, but keep the keys apart from the dump. The dump holds the database only: scan result files (screenshots and raw output) live in the `scan_results` Docker volume, and the optional add-ons keep their state in volumes of their own (`tailscale_state` and the `openvas_*` volumes), so none of those are in it. `web/secret` also keys the hashes of the session table and the recovery codes, so a restore without it signs everyone out and breaks new recovery codes. Stored secrets are encrypted with `CVENGINE_FIELD_KEY` from `.env` (older values with a key derived from `web/secret`), so a restored database needs the same keys. A dump stored in the same archive, bucket or folder as those keys gives away every stored API key, webhook URL and two-step seed to anyone who can read that place, which is exactly what the encryption is there to prevent: put `.env` and `web/secret` in a password manager or another store with different access, and the database dumps wherever backups normally go. Keep every copy private (mode 0600).

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > cvengine-$(date +%F).sql.gz
cp web/secret cvengine-secret.bak
```

To restore, put the original `.env` (with `CVENGINE_FIELD_KEY`) and `web/secret` in place, start only the database (`docker compose up -d db`), load the dump, then start everything with `make up`:

```bash
gunzip -c cvengine-2026-01-01.sql.gz | docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
```

Load it as the owner (`POSTGRES_USER`), as above. Into a brand new database the dump's grants to `cvengine_app` fail with "role does not exist" (everything else loads); `make up` then migrates, which creates the role and grants it again.

Every updater takes a database dump just before it migrates (`scripts/update.sh` and the in-app updater keep the last 3 in `.git/cvengine-update/backups`, mode 0700, and stop the update when a dump fails; `CVENGINE_UPDATE_BACKUPS=0` in `.env` turns that off; automatic deployment makes its own in `.git/cvengine-auto-deploy/backups`, [UPDATES.md](UPDATES.md#automatic-deployment)). These dumps stay on the same disk as the database: copy them elsewhere if the disk is what you are protecting against.

### Nightly dump

The update dumps exist only when an update runs. For a dump every night, run `make db-backup-schedule` once (`scripts/install-db-backup.sh`, as a user that may run Docker; root on most hosts). It adds one line, marked `# cvengine-db-backup`, to that user's crontab: at 03:17 host time it runs `scripts/db-backup-daily.sh`, which

- dumps the database with `pg_dump -Fc` (PostgreSQL's custom format: compressed, and `pg_restore` can restore it whole or table by table) as the owner role, inside the `db` container;
- writes it to `backups/db/cvengine-<time>.dump` (`CVENGINE_DB_BACKUP_DIR`), the folder mode 0700 and the file 0600, and checks it with `pg_restore --list` before keeping it;
- then removes dumps older than `CVENGINE_DB_BACKUP_DAYS` days (default 7). A dump that fails removes nothing, so a run of failed nights never empties the folder. `CVENGINE_DB_BACKUP_DAYS=0` turns the nightly dump off.

The folder holds dumps only: `.env` and `web/secret` are never written there, so it can be copied to your normal backup store while the keys go to another one, as above. Its log is `backups/db/backup.log`. `make db-backup` takes one now. `scripts/install-db-backup.sh --remove` takes the crontab line away and keeps the dumps. `make rotate-secrets` puts its dump before a rotation in the same folder (`cvengine-<time>-before-rotation.dump`), where the nightly run removes it after the same number of days. Each dump is about the size of the database compressed, so keep an eye on free disk when you raise the days kept.

Restore a custom format dump the way the plain one above is restored, with `pg_restore` instead of `psql`:

```bash
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' < backups/db/cvengine-20261123T091700Z.dump
```

### Checking that a dump restores

`make restore-check` (`scripts/restore-check.sh`) proves the newest dump can be restored, without touching the live database: it creates a throwaway database, `cvengine_restore_check_<number>`, in the same PostgreSQL, restores the newest nightly dump into it (or, with none, the newest update dump; `scripts/restore-check.sh FILE` takes a given `.dump` or `.sql.gz`), prints the row counts of a few tables (migrations, users, projects, targets, hosts, findings, CVEs) next to the live counts, and drops it again, also when the restore fails or you interrupt it. It fails when a table is missing or the migrations or users table is empty in the copy. It needs free disk for one more copy of the database for a few minutes and loads the database server while it runs, so run it in a quiet hour, for example once a week after the nightly dump.

## Make targets

`make help` lists them. They all use `docker-compose.yml` alone, and the ones that name services (`stop`, `restart`, `rm`, `logs`, `images`, `build`, `up`) act on the six core services only.

| Target | What it does |
| --- | --- |
| `make up` | Creates `.env` if it is missing, clears a leftover maintenance flag, moves a PostgreSQL 12 database to 18 ([UPGRADE.md](UPGRADE.md)), records the installed commit, then builds the image, hands the application's files to its account (the one-off `ownership` service, [Who the containers run as](#who-the-containers-run-as)), runs the migrations and starts the core services, and fetches the built-in scanner image this release pins and starts it on its own network, with the Tailscale sidecar in its namespace when that profile is on ([BUILTIN-SCANNER.md](BUILTIN-SCANNER.md)). |
| `make build` | Records the installed commit and builds the images. |
| `make certs` | Creates the HTTPS certificate ([HTTPS](#https)). Refuses while the database or certificate password still says `change-me`. |
| `make admin`, `make admin-password` | Create the admin account with a generated password, or reset that account's password and print a new one (in the one-off `migrate` service). |
| `make username`, `make changepassword` | Create an admin account of your own choosing (`createsuperuser`, in the `migrate` service), or change a user's password. |
| `make migrate` | Applies migrations and checks the database role the server runs as, in the one-off `migrate` service, the only container with the owner's password ([Database roles](#database-roles-networks-and-logs)). |
| `make dbshell` | A `psql` prompt as the database owner, inside the `db` container (`docker exec`); no password leaves it. |
| `make down`, `make stop`, `make restart`, `make rm` | Take the stack down, stop, restart or remove its containers. Volumes stay. |
| `make logs`, `make images` | Follow the logs (last 1000 lines), or show the images. |
| `make test` | Runs the test suite in a one-off `migrate` container (the test runner creates its database as the owner). |
| `make redis-auth`, `make rotate-field-key` | One-time hardening of an older install ([CONFIGURATION.md](CONFIGURATION.md#templates-and-secrets), [UPGRADE.md](UPGRADE.md#upgrading-to-12)). |
| `make rotate-secrets` | Rotates the database passwords, the Redis password, the field key and the Django secret, then verifies the site; `ARGS=--dry-run` prints the plan ([CONFIGURATION.md](CONFIGURATION.md#rotating-secrets)). |
| `make db-backup`, `make db-backup-schedule`, `make restore-check` | Dump the database now, dump it every night, or prove the newest dump restores ([Backups](#nightly-dump)). |
| `make export-cve-seed` | Writes this instance's CVE catalog to `web/cve-seed.jsonl.gz` ([PIPELINE.md](PIPELINE.md#seeding-the-catalog)). |
| `make scanner-update` | The Scanner update: pull the scanner image this release pins (a no-op when it already runs), start it, keep it only once it has checked in with a contract version the server accepts, else put the previous image back ([BUILTIN-SCANNER.md](BUILTIN-SCANNER.md#keeping-it-current-the-scanner-update)). Run it from cron on a host without the updater timer. |
| `make scanner-build`, `make scanner-logs` | Build the built-in scanner's image from the known-good floor commit `scanner.lock.json` names (the offline fallback when the published image cannot be pulled), or follow its log ([BUILTIN-SCANNER.md](BUILTIN-SCANNER.md)). |
| `make inventory-sync` | Copies the host inventory reporter scripts to the copies the server hands out (a development task). |

## SETUP-WIZARD

The first sign-in of the first App Admin opens a setup wizard at `/cve/welcome/`; most installs are set up there and never need the command line. It asks for what the first run needs and starts it as soon as step 1 is saved, so the dashboard already has something to show when it opens. Steps 1 to 4 and the strip above them say only that things are being set up ("We will set things up while you answer a few questions.", "Setting up your workspace"): they never say what is running underneath, never show counts, and never use the words scan, discovery, queued, found or Sentinel (the word scanner appears only on the plan step's three option cards). A test enforces this.

| Step | What it asks | What it does |
| --- | --- | --- |
| 1. Let us get you set up (button **Continue**) | Organization, project and **one** seed domain (plus a tick that you are authorized to test it) | Creates the organization, project and target, using the same domain rules as Targets (an address, range, URL path, or a name that resolves to a loopback, link-local or internal address is refused), and queues a bbot discovery (`bbot_discovery`) for it. With no Sentinel live yet it is queued and starts as soon as one connects; the worker is asked to enrol the built-in scanner now rather than at its next five-minute beat. |
| 2. Where should it run? | The built-in scanner only, the built-in scanner plus external scanners, or external scanners only | For external scanners it makes the real one-time enrollment command (the same enrollment as Sentinels > Add) under "Connect another machine" and shows the connection status live. External only turns the built-in scanner off through the existing instance setting once the wizard finishes; it still completes the first discovery. The page shows no status line for the built-in scanner. |
| 3. What runs | Check families (Names and addresses, Websites, Open ports and services, Certificates and email, SSH, Exposed secrets, Screenshots, WordPress, Known-issue templates), each a per-kind toggle | Writes the instance defaults of the Sentinel settings (`builtin_kinds` for the built-in scanner, `external_kinds` for every other Sentinel). A small host, one with under 6 GB of memory (`SMALL_MEMORY_GB` in `web/cveFeed/setup_flow.py`, the only place the number is set; memory that cannot be read counts as small), starts with the kinds marked HEAVY (full port and UDP sweeps, deep nuclei, thorough WordPress, screenshots) unticked, each with the reason "heavy: off by default on this machine; turn on if you have the capacity". A host with 6 GB or more starts with everything ticked. Either way every box can be changed, and the choice is stored and applied exactly as any other (`off_kinds`); every other family starts on. **OpenVAS is its own group, off by default**; it needs about 4 GB of memory, 2 CPUs and 60 GB of disk and an hours-long feed download, and can be turned on for the built-in scanner, for external Sentinels (which must run the Full profile), or both. |
| 4. Optional extras (opens with "Almost there.") | AI model key, Slack or Discord webhook, time zone, your own password | Each can be skipped and is stored in the same place as in Settings. A key or webhook is never shown again. |
| 5. Getting ready | Nothing | A calm screen ("Getting everything ready") that covers a first minute with nothing to show. It says in plain words what is happening (a first look at the domain you gave), how long that usually takes and what comes next (hosts appear on the dashboard as they are found, and it opens by itself, then "Opening your dashboard"). It shows no counts or names. When the time is up with no host found, the dashboard opens with a note that the first look is still under way, how long it usually takes and an **Add targets** button; the note goes away as soon as the first host is found. It is **not shown at all** when one or more hosts have been found by the time the step is reached or finished (the dashboard opens at once, and its live discovery panel carries on). With none found it stays for at most `CVENGINE_SETUP_DWELL_SECONDS` seconds (default 60, 0 to 900; set in `.env`; `0` never shows it), counted from the first time the screen asked, so a reload does not restart the clock and a reload after the time is up goes to the dashboard. It leaves the moment the first host appears. A visible **Open the dashboard now** button is always there. |

Everything is stored on the server (`dashboard.SetupWizard`), so the wizard resumes in any browser, every step can be sent again without duplicating anything (the same values change nothing and start no second discovery; other names rename the organization and project), and "Skip the rest and open the dashboard" leaves it at any point (`/cve/?skip=1` also leaves it). An install that already has targets (an upgrade, or one set up by hand) is never redirected to it, but it can be opened from `/cve/welcome/` by an App Admin. Only an App Admin can read or write it, writes need the CSRF token and are rate limited per account, and the only secret it ever shows is a Sentinel enrollment command, once.

## Development stack

A single-machine stack on `http://localhost:8000` with Django's auto-reloading server:

```bash
./scripts/init-env.sh
docker compose -f docker-compose.dev.yml build web celery celery-beat
docker compose -f docker-compose.dev.yml up -d db redis web celery celery-beat   # the migrate service runs first
docker compose -f docker-compose.dev.yml run --rm migrate python3 manage.py createsuperuser
```

`make admin` only targets the production file, so use `createsuperuser` here. The development file mounts `./web` writable over the image's source (edit and reload) and therefore runs web, celery, celery-beat and migrate as root (`user: "0:0"`): the bind-mounted files belong to your account, not to uid 10002. It is for a development machine only; production runs as described in [Who the containers run as](#who-the-containers-run-as).

## The watchdog

The host process that picks up approved updates (`scripts/update-watch.sh`, started by cron every minute) also runs the **watchdog** every 30 seconds: a pass of `manage.py watchdog_tick` in the `web` container that restarts a worker lane that has gone quiet, lifts a discovery pool that `.env` holds too low, and tells you on **Administration, Watchdog** and in the notice strip what it did or could not fix. It needs nothing installed beyond the updater (`scripts/install-updater.sh`), stands aside while an update runs, and is switched off with `CVENGINE_WATCHDOG=0`. See [WATCHDOG.md](WATCHDOG.md).

## Updating

Three options, all of which keep the database and broker running: automatic deployment, approval in the app, or `scripts/update.sh` by hand. Manual updates wait for active tasks (or stop scans with `--stop-scans`), automatic deployment stops and requeues scans, and an approved update waits for running scans for 5 minutes by default and then interrupts what is left. The optional `tailscale` and `openvas` services are neither started nor stopped by an update. See [UPDATES.md](UPDATES.md). `make up` always uses `docker-compose.yml` alone, so on an install with its own overlay use `scripts/update.sh` or `docker compose` with your files instead. Moving an older install across the PostgreSQL 18 change is covered in [UPGRADE.md](UPGRADE.md). Every start of the worker container adds the built-in engine rows, keywords and tool rows the install does not have yet and never overwrites one that is there (the engine rows are kept only so that existing agents keep working: no scan reads them).

## Factory reset

**Settings, Factory reset** (superusers only) returns the instance to a fresh install and restarts the setup wizard. It recreates a "Default" organization and project, ends every other session (yours stays), and records one `system.factory_reset` audit row after clearing the log. Five wrong passwords lock the button for 10 minutes. It removes every organization, project, target, host, scan, result file, other user, token (so every Sentinel is removed with its token and has to be enrolled again), and setting, plus the CVE feed, the audit log, and scheduled scans. It keeps your own account, the scan engines, and installed tools. You must type `FACTORY RESET` and your password, and it refuses while scans are running unless you tick "reset anyway". It cannot be undone, so take a backup first.

## Uninstall

`scripts/uninstall.sh` lists the containers, volumes, and networks of this install's Compose project (named by `CVENGINE_COMPOSE_PROJECT`, then `COMPOSE_PROJECT_NAME`, then the checkout directory) and, once you type yes, deletes them and their locally built images. That includes all scan results. Other applications, including other reNgine installs, are not touched. `.env`, `secrets/`, `web/secret`, and `backups/` stay, and so do the update watcher and the automatic-deployment timer: run `sudo scripts/uninstall-updater.sh` (or `sudo make uninstall-updater`) and `sudo scripts/install-auto-deploy.sh --remove` first. `install.sh` adds one line to root's crontab (it starts the watcher every minute); `uninstall-updater.sh` removes that line and nothing else in the crontab. It needs access to Docker, not necessarily `sudo`.

See also: [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
