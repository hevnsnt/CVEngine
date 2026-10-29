# OpenVAS (Greenbone)

OpenVAS is an optional second vulnerability scanner. cvENGINE runs it as a set of Greenbone Community Edition containers next to the stack, talks to its manager (gvmd) over the GMP protocol, and turns its results into findings and CVE evidence. It is **off by default and costs nothing while it is off**: no container, no memory, no queue consumer work and no scheduled task. Turning it on is one decision by an App Admin or an Org Admin: tick the organizations or projects to scan in **Administration > OpenVAS**. Everything else (starting the containers, making the scanner's login, loading the feeds) happens by itself.

OpenVAS finds what nuclei and nmap do not: it runs tens of thousands of network vulnerability tests (version checks, protocol-level checks, default credentials, weak configuration) against every port of a host. It is slow, it is heavy, and its version-based results are often wrong about backported fixes, which is why cvENGINE only treats the high-confidence ones as confirmed (see Results).

## What you need

Greenbone's container guide gives no hardware figures, so these are cvENGINE's own estimates for the add-on on top of the normal stack. Measure on your hardware.

| | Floor | Why |
| --- | --- | --- |
| Memory | about 4 GB used once loaded; the guard wants **3 GB free plus the platform's headroom** before it starts a scan | Redis holds the vulnerability-test cache, gvmd and its PostgreSQL run beside it, and the scanner adds memory per host |
| CPU | 2 vCPUs | The first feed load and a scan are CPU bound |
| Disk | about 25 GB free | Images, the feeds (vulnerability tests, SCAP and CERT data) and the database; the first synchronization needs the most |
| Time | the first synchronization takes from several minutes to hours | Greenbone says the same; no scan is possible until it ends |

**The resource guard.** The scanner runs in the sidecar, outside the celery container's job budget (`reNgine/resources.py`), so cvENGINE applies the same rules to the machine before it starts a GVM task. It **refuses to start** while any of these holds, and says which in Settings > OpenVAS:

- free memory is below `CVENGINE_OPENVAS_MIN_AVAILABLE_MB` (default 3072) plus the platform's headroom (`HEAVY_HEADROOM_MB`);
- the scanners already running have reserved so much of the job budget that a further `CVENGINE_OPENVAS_COST_MB` (default 1500) does not fit;
- other scanner jobs are waiting for memory;
- a scanner was stopped for memory in the last hour.

A task that is already running is **stopped** when free memory falls below the platform's critical floor, when scanning is paused (Pause all scanning), or after its time budget, `CVENGINE_OPENVAS_MAX_HOURS` (24) per host. A stopped task leaves its hosts due. The sweep's own step keeps running while scanning is paused, only to do this: on the next step (within 15 minutes) it stops the running local task, or expires the one a Sentinel is running (the hosts stay due), and it starts or dispatches nothing. An update's drain pause stops new work but lets a running task finish. A task that ran out of its budget keeps the results it had (a partial scan, see below); with none, it counts as failed (the hosts wait three days).

## Turn it on

An **App Admin** opens **Administration > OpenVAS** (or the Settings tab) and presses **Switch on**. Then App Admins and Org Admins tick the organizations or projects to scan. With nobody typing anything, switching it on does this:

1. **The containers start.** The web container has no Docker access, so it writes `web/.openvas-wanted`; the **host agent** (`scripts/update-watch.sh`, the same small job that applies updates, installed once with `scripts/install-updater.sh`) sees it within seconds and runs `scripts/openvas-sync.sh`, which checks the host has the free memory the scanner needs and starts the Greenbone services. The page follows it (Starting, then Loading vulnerability tests) and, if the agent is not installed, shows the install command with a Check again button.
2. **The login is made.** Greenbone's containers create the user `admin` with the password `admin`. The first check the worker runs signs in once with that default over gvmd's socket, sets a random password through GMP (so it is never on a command line, where every process can read it) and saves it encrypted in cvENGINE. Nobody sees or types it. If the default password was already changed by hand, the page says so and you save the one in use with `manage.py openvas_credentials` (below).
3. **The feeds load.** The first start downloads and loads the vulnerability tests, SCAP and CERT data, which takes from several minutes to hours. The page says "Getting ready" and why. **No scan starts while the feed is not ready**, and scans then begin by themselves.

Who can do what: only an **App Admin** switches the add-on on or off for the instance (the choices are kept when it is off). While it is off nobody can choose anything, and an Org Admin is told an App Admin has to switch it on first. Once it is on, an App Admin sees every organization and an **Org Admin** sees only the organizations they administer and those organizations' projects. Members and auditors cannot use it. Every choice is in the audit log. The add-on is deliberately not part of the agent REST API or MCP. Ticking an organization covers all its projects, including ones added later; ticking single projects covers just those. A project of a ticked organization can still be left out: untick it on the page (an explicit exclusion that wins over the organization, shown as "left out of the organization's scan"; tick it again to put it back under the organization). The page and the check coverage show what the sweep really does.

Stop it with the **Switch off** button (App Admin) or `make openvas-down`; the data volumes stay. By hand, the old way still works: `make openvas-up`, `make openvas-user`, then `COMPOSE_PROFILES=openvas` in `.env` keeps the containers across `docker compose` runs on a host that does not use the watcher. The switch in the app must still be on, or nothing is scheduled. The Settings API (`PUT openvas` in Settings) refuses to switch the add-on on until a GMP login is saved; the Administration page switches it on and makes the login by itself.

## What gets scanned

OpenVAS is slow (about 4% an hour on one host with the safest settings, so one host takes between half a day and a day) and intrusive, so it is spent **only where it matters**, and only in the projects someone opted in (a project, or a whole organization):

- **Fire or Smoke only.** A host is scanned only while its heat is Fire or Smoke (the color on the host card: a CVE match rated hot, or an open finding rated medium or above). Clean, Ice and Unscanned hosts are never scanned. The order is Fire before Smoke, then the host with the most fire reasons, then the most smoke reasons, then the one that has waited longest.
- **Automatic.** Nobody has to list anything: a host that turns Fire or Smoke becomes due by itself, and one that cools to Clean leaves the queue. The old "every name the project's scans found" fallback (`CVENGINE_OPENVAS_AUTO_HOSTS`) is gone.
- **Listed and forced.** `hosts` on `openvas/projects/{id}` still adds hosts someone named, but the heat gate still applies to them. `forced_hosts` (a subset the administrator marks) lifts only the heat gate, for a host to be scanned whatever its color. Forcing never lifts the ownership refusals below.
- **One host per task**, with a time budget per host (`CVENGINE_OPENVAS_MAX_HOURS`, 24). When the budget runs out the task is stopped and **what it found so far is kept** (a partial scan: the findings are stored, nothing an earlier scan found is closed by it, and the host counts as scanned). A task that found nothing before the budget ran out is a failure like any other.
- **Why a host is or is not due is shown**: `GET openvas/projects/{id}/queue` (Settings), the Sentinels page (`openvas` in `GET sentinels/live`: the run, the hosts due next in order, and the hosts that are not due with the reason) and the host's check coverage say, in plain words, "not Fire or Smoke (clean)", "a CDN edge", "a third-party platform (Atlassian Cloud) shared with other customers", "a documentation address range", "this cvENGINE server", "scanned 3 days ago", and so on.

Every host, chosen or not, is vetted at every sweep:

- each name must be a host of that project (another project's host is never scanned);
- hosts excluded for the organization or archived are dropped (`cveFeed.exclusions`), as is any name that resolves to an address a scanner may not be pointed at (`scannable_hosts`, `pinned_transport.resolve`);
- GVM is given the **numeric address** that was vetted, never a name, so a name re-pointed after it was stored cannot redirect the scan;
- **tailnet addresses (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) are never given to OpenVAS**, even for a project with a connected tailnet. The scanner containers have no Tailscale interface, so the packets would leave by the Docker host's default route.
- **shared infrastructure is never given to OpenVAS**: a name or address recorded as a CDN edge or a vendor's shared front (Microsoft 365 autodiscover and device enrolment, Google Workspace, a PaaS such as Netlify or Heroku, `cveFeed.hosting`), and any other name recorded on such an address. These are other customers' machines, not the project's to test;
- **documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and this instance's own address are refused**: its own address is what `DOMAIN_NAME` resolves to, plus `CVENGINE_OWN_ADDRESSES` (comma separated, for an instance behind NAT or a load balancer);
- a task that fails for want of a working scanner (a Sentinel that stopped answering, gvmd not reachable or not answering, its feed still syncing, a login or scan configuration problem, a task gvmd reports as Interrupted because it or its scanner restarted) **marks no host failed** at first: the hosts are tried again at the next tick. A host whose tasks are Interrupted three times in a row (`CVENGINE_OPENVAS_MAX_INTERRUPTS`) is the likely cause, so on the third it is marked failed like any scan that failed and waits three days (its reason reads "OpenVAS was interrupted 3 times scanning this host; asked again after three days", as does the run's error); a finished run, even an inconclusive one, or any other outcome in between restarts the count, and so does the retry after the three days. A gvmd that fails to answer about a running task is asked again for a few steps before the run is given up (the task is told to stop, and no second task starts meanwhile); only a task gvmd says it no longer has, a scan that ran and failed, or one that ran out of its budget with no result makes a host wait three days;
- **one host, many names**: GVM scans the address, so when a host is scanned every other name of the project that has that address is counted as scanned too, and is not scanned again at the next step;
- **a result set cut at the cap** (`MAX_RESULTS`, 5000, highest severity first) is imported as a partial scan: what it found is kept and nothing earlier is closed by it;
- a task gvmd reports as Done whose report names **no scanned host** is **inconclusive**, not a scan: no host is stamped as scanned, the run says "OpenVAS ran but reported no scanned host", the host's reason says the same, and it is asked again after three days;
- the global pause is honored, projects take turns (the one scanned longest ago goes first), and the project's hosts are visited once a week each (`CVENGINE_TTL_OPENVAS`, hours; a host that failed waits three days, `CVENGINE_TTL_OPENVAS_FAILED`).

The sweep runs on its own queue (`openvas_queue`), every 15 minutes. Each step is small: poll the running task, or start the next due batch of at most `CVENGINE_OPENVAS_MAX_HOSTS` hosts (default 1) as **one task for one project**. **One GVM task runs at a time**, enforced by a database constraint (`OpenvasRun`), so two workers or a restart cannot start a second. The task is throttled (`max_checks` from `CVENGINE_OPENVAS_MAX_CHECKS`, default 4, and `max_hosts` 1: that many tests at a time against one host at a time) and its target reuses the project's last target while the set of addresses is unchanged. A finished task is removed from GVM after its results are imported. Where the batch runs is decided first: see Where a due batch runs.

**Egress.** The scanner (`openvas-ospd`) needs raw sockets, so it has `NET_ADMIN` and `NET_RAW` and the unconfined seccomp and AppArmor profiles Greenbone's own compose file uses; it is the only add-on container with extra privileges, and no container in the stack runs privileged. Its scans leave the Docker host directly, not through the celery container, and the add-on is on its own network (`openvas_network`), publishes no ports and reads no `.env`. Only the celery container mounts gvmd's socket (read-only; a socket still connects), and gvmd still needs the login.

## The scan configuration, and what it leaves out

The task uses a configuration cvENGINE builds in GVM, **"cvENGINE safe scan"**: a copy of the built-in "Full and fast" without two NVT families and with the scanner preference `safe_checks` on.

- **Denial of Service**: tests that crash or hang the service they probe. A vulnerability scan that takes a customer's service down is an incident, not a finding.
- **Brute force attacks**: password guessing, which locks accounts out and is a different act from checking for a known vulnerability.

Every other family is "Full and fast"'s. `safe_checks` additionally makes the scanner skip any remaining test whose category is destructive, denial, kill-host or flood. The configuration is **read back and verified every time it is used** (no excluded family selected, `safe_checks` is yes); a configuration that does not pass makes the sweep refuse to run, with the reason, and cvENGINE never alters the built-in. New families are not added to it automatically.

## Results

Only results that name a CVE are imported. For each result cvENGINE keeps its host, port, NVT OID, name, CVSS score, threat, quality of detection, the NVT's summary, impact and solution, its reference URLs and the result text.

| | |
| --- | --- |
| **Dedupe key** | host, port and NVT OID: one `ProbeObservation` (probe `openvas`), one Vulnerability row and one match per key, however many scans report it |
| **Finding** | a Vulnerability, source `openvas`, template id `openvas:<OID>`, CVE ids, references, solution as remediation, the result text as extracted result. Severity from the CVSS score: 9.0 and up critical, 7.0 high, 4.0 medium, above 0 low |
| **Evidence** | a `CVEMatch` (source `openvas`) for each CVE the catalog knows (not rejected, not local only), with the OID, QoD and result text |
| **Hard evidence** | only a result whose **QoD is 80 or more** (the level of the active remote checks and authenticated package checks): `template_result` is `vulnerable`, version in range, confidence 0.95. A lower one ("version possibly affected", a banner that a backport may defeat) is stored with its QoD, tagged `qod-unconfirmed`, with no template result, an unknown version range and confidence at most 0.5, so it can never confirm a finding |
| **Resolved** | a result that a later **complete** scan of the host no longer reports is resolved: the Vulnerability is closed, the match is marked no longer matched and, unless a person already works it, not affected. A host the scan could not reach (no result, not in the report's host list) resolves nothing and is asked again in three days |
| **New scans** | a scan stores hosts again, so after correlation the findings are carried onto the new host row from the stored observations, newest 21 days; a decision a person made on an earlier copy follows it |
| **Not imported** | results with no CVE reference (default credentials, weak ciphers, exposed services) are counted ("n results without a CVE not imported") but not stored; results for an address that was not in the batch are ignored |

An NVT's text is third-party text. It is stripped of control characters, clipped (the result at 2,000 characters, the summary, insight, impact and solution at 1,500 each, the description built from them at 6,000) and stored as plain text. Nothing marks it safe for HTML; the pages and reports escape it, and the settings page builds its DOM with `textContent`.

## Where a due batch runs

Each step of the sweep looks for a place to run a due batch in this order:

1. **A Sentinel that declares the `openvas` capability** for the project (a Sentinel declares it only while its own GVM stack can scan; a light-profile Sentinel never does). cvENGINE hands it one task with the vetted host set (numeric addresses), this instance's own excluded-family list (so a Sentinel never uses a copy that is out of date), the time budget and the throttling preferences, and records an `OpenvasRun` that only tracks it. The next step polls the task, then imports its results through the same code a local run uses. A Sentinel that went away or whose own GVM stack was not ready (no login, feed still syncing, no scan configuration, gvmd not reachable) marks no host failed; a scan that ran and failed does.
2. **The projects' declared internal networks.** A target inside a network a project declared internal is a batch of its own, never mixed with the external one, and only a Sentinel inside that network (capability `network:internal`) can take it. This server never scans such an address, with or without Sentinel only.
3. **This server's own `gvmd`**, the sidecar described above, unless **Sentinel only** is on.

Only one GVM task, local or on a Sentinel, runs at a time. See [AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents) and [ARCHITECTURE.md](ARCHITECTURE.md#sentinels).

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_OPENVAS_MIN_AVAILABLE_MB` | `3072` | Free memory required, beside the platform's headroom, to start a scan |
| `CVENGINE_OPENVAS_COST_MB` | `1500` | What a GVM scan is counted as against the job budget |
| `CVENGINE_OPENVAS_MAX_HOSTS` | `1` | Hosts in one GVM task |
| `CVENGINE_OPENVAS_MAX_HOURS` | `24` | The time budget per host (a task of n hosts gets n times this). A task running longer is stopped and keeps what it found |
| `CVENGINE_OPENVAS_MAX_CHECKS` | `4` | NVTs run at a time against a host (1 to 10; Greenbone's default is 4). At 2 a host takes about a day, at 4 about half that; lower is gentler on the target |
| `CVENGINE_OWN_ADDRESSES` | none | Addresses of this instance OpenVAS must never scan, besides what `DOMAIN_NAME` resolves to |
| `CVENGINE_OPENVAS_SOCKET` | `/run/gvmd/gvmd.sock` | gvmd's unix socket in the celery container |
| `CVENGINE_OPENVAS_HOST`, `_PORT`, `_CA`, `_CERT`, `_KEY`, `_TLS_NAME` | none, `9390` | Reach a gvmd on another machine by TLS instead of the local socket (an external GVM; not exercised here). The link is always verified: `_CA` (the CA file that signed the server certificate) is required, and cvENGINE refuses to connect, and so never sends the GMP login, without it. The certificate must name the host (a subject alternative name), or set `_TLS_NAME` to the name it carries. `_CERT` and `_KEY` add a client certificate when gvmd asks for one. The default, the unix socket the sidecar publishes in a volume, is a local file and uses no TLS |
| `CVENGINE_TTL_OPENVAS`, `CVENGINE_TTL_OPENVAS_FAILED` | `168`, `72` hours | How long a scanned host, and a failed one, stays fresh |

**Sentinel only.** Settings > OpenVAS and Administration > OpenVAS (App Admin only) have a **Sentinel only** switch, off by default. Without it, a Sentinel that can take the batch gets it first and this server's own `gvmd` is the fallback (see Where a due batch runs). On, a due batch with no eligible Sentinel registered for the `openvas` capability right now is simply left due (tried again at the next tick), never scanned by this server's own `gvmd` sidecar. This is how an install offloads OpenVAS's GVM workload entirely to remote Sentinel machines: with it on and at least one Sentinel registered, `gvmd` on the main server never has to run a scan at all. The add-on still needs to be switched on (the Sentinel-only choice only decides where a due scan runs, not whether one is due), but switching it on, or pressing Try again, does not ask the host agent to start the Greenbone containers on this server, and the sweep opens no GMP session to it, so they need not exist here at all. Turning it on does not stop a scan already running locally; that one finishes normally. With it on, Settings > OpenVAS does not show the local engine's state (a stale "gvmd could not be reached" from before the switch says nothing): it lists each Sentinel with whether it is ready to scan or why not (still syncing its feeds, no scan configuration, a light profile, not checking in), the run in progress and the last result. A Sentinel reports its GVM readiness in its heartbeat (`info.openvas: {ready, reason}`). When no Sentinel is ready nothing is run locally and nothing is marked failed: the hosts simply stay due. A Sentinel that stops a scan at its time budget reports `partial: true` with the results it had, and they are kept.

## Images, pins and updating

**Some of these images float, on purpose.** The program images (the manager, the scanner, its database and cache) are pinned by digest. The **feed data images are not**: they follow Greenbone's moving `community` tag so the vulnerability definitions keep updating. The cost is that what they contain changes without a cvENGINE release and cannot be reproduced from a cvENGINE version; the software bill of materials (`scripts/generate_sbom.py`) lists them as unpinned and says why. If you need a frozen set, pin those digests yourself and accept that the definitions then go stale.

**What a cvENGINE update does to the add-on.** An update rebuilds the cvENGINE images, which installs the pinned `python-gvm` with no manual step, and recreates only `web`, `celery`, `celery-beat` and `proxy`. It does not start, stop, pull or recreate any `openvas-*` service: with `COMPOSE_PROFILES=openvas` in `.env` the add-on keeps running as it was, without it nothing of the add-on exists. Greenbone's images are changed only by you (see To update below).

Greenbone publishes **no version tags**: the registry lists only the moving tags `stable`, `community`, `latest` and `edge` (read 2026-10-27), so the program images are pinned by `tag@digest` in `docker-compose.yml`, which is what runs. The feed data images (`vulnerability-tests`, `notus-data`, `scap-data`, `cert-bund-data`, `dfn-cert-data`, `data-objects`, `report-formats`) follow `:community` on purpose: they are data that Greenbone refreshes daily and that is checked against its GPG signing keys, and a pinned feed would be a stale one. The set is the minimal one that exposes GMP, from Greenbone's own compose file (greenbone.github.io/docs, Greenbone Community Containers, `FEED_RELEASE` 24.10): without the web interface (`gsa`, `gsad`, `nginx`), the certificate generator and the `gvm-tools` shell. There is **no MQTT broker** in Greenbone's current compose file (older layouts ran a mosquitto broker for a separate notus-scanner); notus is served by `openvasd` in `OPENVASD_MODE=service_notus`.

Digests read from `registry.community.greenbone.net` on 2026-10-27 (multi-architecture index digests). The `stable` rows are what `docker-compose.yml` pins; the `community` rows are for reference only, since the compose file follows that tag:

| Image | Tag | Digest |
| --- | --- | --- |
| `gvmd` | `stable` | `sha256:e59a6a684b112ea77fe4ddd7e5ca35e6a07d36bf854f1b411d11d12f9b0c608a` |
| `pg-gvm` | `stable` | `sha256:a18d9e2f0cbba7839e65547a2331ce8f984500e8c4fbe91d08f9a48036d03fa2` |
| `pg-gvm-migrator` | `stable` | `sha256:8fc1cc11cac0481674527e01ec7610a8195110cf117d700bd47fe3af7012b34d` |
| `redis-server` | `stable` | `sha256:83227e34b276bf7c7453a91bbfc070341af58f7ff40eb707ed6724965fe3846c` |
| `ospd-openvas` | `stable` | `sha256:31a85272abc77521c98451ce6834ed7d2f887e98ff1b26ff3fd94f00d000b169` |
| `openvas-scanner` | `stable` | `sha256:5067aa68bdb63038180cbdbb5cdc199c1908ec6b7d55997a41b6a51b14c12eee` |
| `gpg-data` | `stable` | `sha256:c18618252f7d874cd1fe09413b043cfc40b57e6464d8c5973d4a93b074d5d91a` |
| `vulnerability-tests` | `community` | `sha256:d0a8df253c177321c03c24ca5be051ca22da547756f684a96a2153c2ff0c9bd7` |
| `notus-data` | `community` | `sha256:f84397aede60d158e47ac199e0fe5108f707ed75657406e4e9aad37b92cb0c9a` |
| `scap-data` | `community` | `sha256:fff27d3994c6a559241719547be5dc8992bd50b1c6bf44de48588adcf2e7a567` |
| `cert-bund-data` | `community` | `sha256:b3dc178aca3c874c48529ca1ba877900b8069fd715a5831c4c3539642c57ec8a` |
| `dfn-cert-data` | `community` | `sha256:f0c2f33101616bf956ccb605c89449b8fcd85c47226347fc8961eb5661b7f8c6` |
| `data-objects` | `community` | `sha256:192188bcf92ac440a45556731243a6ab7255a52aff94bd78901ceed452b608da` |
| `report-formats` | `community` | `sha256:5a74234489215f4d7e26d9b481293cc51ab7efcebb683de8bc5dfe06cd68e549` |

To update: read the new digest (`docker buildx imagetools inspect registry.community.greenbone.net/community/gvmd:stable`), change it in `docker-compose.yml`, read [Greenbone's release notes](https://greenbone.github.io/docs/latest/) for the manager and scanner first, and `docker compose --profile openvas up -d`. Update `python-gvm` (pinned in `web/requirements.txt`) with it: a gvmd that speaks a GMP version newer than the client knows (22.8 and later) makes python-gvm warn. `scripts/check_tool_versions.py` watches python-gvm; it cannot watch the Greenbone images, which have no version to compare.

## Licenses

The add-on runs Greenbone's software as separate containers and talks to it over a socket; nothing is linked into cvENGINE except the client library. gvmd and ospd-openvas are AGPL-3.0-or-later, openvas-scanner GPL-2.0 (its Rust parts GPL-2.0-or-later), pg-gvm GPL-3.0. [python-gvm](https://github.com/greenbone/python-gvm) is GPL-3.0-or-later, which fits cvENGINE's GPL-3.0; it brings `paramiko` (LGPL-2.1), `PyNaCl` and `bcrypt` (Apache-2.0), `invoke` (BSD) and `h2`, `hpack` and `hyperframe` (MIT) as dependencies. The feed content has its own terms, which the data containers print when they start; read them before offering cvENGINE to others as a service. See THIRD-PARTY.md.

## Not verified against a real GVM

cvENGINE's tests run python-gvm unmodified against a fake gvmd that speaks GMP in the documented XML formats (`web/tests/fake_gvmd.py`). **No Greenbone container was started when this was written** (no container runtime was available), so these are unconfirmed until someone runs them against a real gvmd:

- the exact shape of `get_feeds`, `get_configs` (family `nvt_count`, the `safe_checks` preference), `get_results` and `get_reports` on gvmd 22.x, and whether `currently_syncing` is present while a feed loads;
- that rebuilding the configuration with `modify_config` family selection leaves exactly the families intended and that the scanner skips the right NVTs under `safe_checks` (the verification after the build is the safeguard: it fails closed);
- the built-in ids (`daba56c8-...` Full and fast, `08b69003-...` OpenVAS Default, `33d0cd82-...` All IANA assigned TCP) and the task preferences `max_checks` and `max_hosts`;
- the `levels=chmlg` result filter and the report's host list, which decide which hosts count as scanned;
- that `modify_user` with only a password keeps the user's role (`make openvas-user`); if it does not, set the password in GVM and use `openvas_credentials`;
- the memory and disk figures above, the length of the first feed synchronization, and the TLS transport;
- that a read-only mount of the socket volume connects on every Docker storage driver.

`docker compose config` accepts the file with and without the profile; that is all that was checked of the compose wiring.

## Troubleshooting

| Settings says | Meaning |
| --- | --- |
| Not connected: gvmd could not be reached | The containers are not running yet (the page says Starting for the first minutes), or celery was not recreated to mount the socket volume |
| Nothing on the host can start it | The updater watcher is not installed or not running: run `make openvas-up` once, or `scripts/install-updater.sh` |
| The scanner could not be started | The host refused or failed (usually too little free memory); the reason is on the page and in `web/.openvas-log`. Fix it and press Try again |
| gvmd refused the GMP login | The saved password is not the one gvmd has; run `make openvas-user` or save the right one |
| No scan can start yet: the vulnerability tests are not loaded | The feed is still loading; wait |
| Resource guard: memory is short | See What you need; free memory or lower `CVENGINE_OPENVAS_MIN_AVAILABLE_MB` knowingly |
| the scan configuration is not safe | Someone edited "cvENGINE safe scan" in GVM: delete it there and cvENGINE rebuilds it |
