# OpenVAS (Greenbone)

OpenVAS is an optional second vulnerability scanner. cvENGINE runs it as a set of Greenbone Community Edition containers next to the stack, talks to its manager (gvmd) over the GMP protocol, and turns its results into findings and CVE evidence. It is **off by default and costs nothing while it is off**: no container, no memory, no queue consumer work and no scheduled task. Turning it on is two decisions by an App Admin: start the compose profile, and switch it on in **Settings > OpenVAS**, then opt each project's hosts in by name.

OpenVAS finds what nuclei and nmap do not: it runs tens of thousands of network vulnerability tests (version checks, protocol-level checks, default credentials, weak configuration) against every port of a host. It is slow, it is heavy, and its version-based results are often wrong about backported fixes, which is why cvENGINE only treats the high-confidence ones as confirmed (see Results).

## What you need

Greenbone's container guide gives no hardware figures, so these are cvENGINE's own estimates for the add-on on top of the normal stack. Measure on your hardware.

| | Floor | Why |
| --- | --- | --- |
| Memory | about 4 GB used once loaded; the guard wants **3 GB free plus the platform's headroom** before it starts a scan | Redis holds the vulnerability-test cache, gvmd and its PostgreSQL run beside it, and the scanner adds memory per host |
| CPU | 2 vCPUs | The first feed load and a scan are CPU bound |
| Disk | about 25 GB free | Images, the feeds (vulnerability tests, SCAP and CERT data) and the database; the first synchronisation needs the most |
| Time | the first synchronisation takes from several minutes to hours | Greenbone says the same; no scan is possible until it ends |

**The resource guard.** The scanner runs in the sidecar, outside the celery container's job budget (`reNgine/resources.py`), so cvENGINE applies the same rules to the machine before it starts a GVM task. It **refuses to start** while any of these holds, and says which in Settings > OpenVAS:

- free memory is below `CVENGINE_OPENVAS_MIN_AVAILABLE_MB` (default 3072) plus the platform's headroom (`HEAVY_HEADROOM_MB`);
- the scanners already running have reserved so much of the job budget that a further `CVENGINE_OPENVAS_COST_MB` (default 1500) does not fit;
- other scanner jobs are waiting for memory;
- a scanner was stopped for memory in the last hour.

A task that is already running is **stopped** when free memory falls below the platform's critical floor, when scanning is paused (Pause all scanning), or after `CVENGINE_OPENVAS_MAX_HOURS` (12). A stopped task leaves its hosts due, and a task that ran too long counts as failed (the hosts wait three days).

## Turn it on

1. Add `COMPOSE_PROFILES=openvas` to `.env` (with Tailscale too: `COMPOSE_PROFILES=tailscale,openvas`) so updates keep it, and start it: `make openvas-up` (or `docker compose --profile openvas up -d openvas-gvmd openvas-ospd openvas-openvasd`; Compose starts what they depend on). Recreate the celery container once (`make up`) so it mounts gvmd's socket.
2. Wait for the feeds. The first start downloads and loads the vulnerability tests, SCAP and CERT data. Settings > OpenVAS shows the state and, until it is ready, the reason: "the NVT feed is synchronising", "the vulnerability tests are not loaded yet (0 in Full and fast)". **No scan starts while the feed is not ready.**
3. `make openvas-user`. Greenbone's containers create the user `admin` with the password `admin`. This signs in once with that default over gvmd's socket, sets a random password through GMP (so it is never on a command line, where every process can read it), saves it encrypted in cvENGINE and prints only the user name. If you already changed the password, save it with `printf '%s' "$PASSWORD" | docker compose exec -T web python3 manage.py openvas_credentials --username admin` (standard input, never an argument). Do not leave the default password in place.
4. Settings > OpenVAS: press **Test connection** (it asks a worker, the only container that can reach the socket, and reads the saved login), then switch the add-on on. Switching it on enables the sweep's beat entry (`cvengine-openvas-sweep`, created disabled by migration); switching it off disables it again.
5. **Opt a project in** and list its hosts. A project scans nothing until it is opted in and has hosts listed.

Stop it with `make openvas-down` (the data volumes stay). Nothing else in the stack changes whether it is on or off.

## What gets scanned

Only hosts an App Admin listed for an opted-in project. The list is checked twice, at save time and at every sweep:

- each entry must already be a host of that project (an unknown or another project's host is refused);
- hosts excluded for the organization or archived are dropped (`cveFeed.exclusions`), as is any name that resolves to an address a scanner may not be pointed at (`scannable_hosts`, `pinned_transport.resolve`);
- GVM is given the **numeric address** that was vetted, never a name, so a name re-pointed after it was stored cannot redirect the scan;
- **tailnet addresses (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) are never given to OpenVAS**, even for a project with a connected tailnet. The scanner containers have no Tailscale interface, so the packets would leave by the Docker host's default route.
- the global pause is honoured, and the project's hosts are visited once a week each (`CVENGINE_TTL_OPENVAS`, hours; a host that failed waits three days, `CVENGINE_TTL_OPENVAS_FAILED`).

The sweep runs on its own queue (`openvas_queue`), every 15 minutes. Each step is small: poll the running task, or start the next due batch of at most `CVENGINE_OPENVAS_MAX_HOSTS` hosts (default 4) as **one task for one project**. **One GVM task runs at a time**, enforced by a database constraint (`OpenvasRun`), so two workers or a restart cannot start a second. The task is throttled (`max_checks` 2, `max_hosts` 1: two tests at a time against one host at a time) and its target reuses the project's last target while the set of addresses is unchanged. A finished task is removed from GVM after its results are imported.

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
| **Evidence** | a `CVEMatch` (source `openvas`) for each CVE the catalogue knows (not rejected, not local only), with the OID, QoD and result text |
| **Hard evidence** | only a result whose **QoD is 80 or more** (the level of the active remote checks and authenticated package checks): `template_result` is `vulnerable`, version in range, confidence 0.95. A lower one ("version possibly affected", a banner that a backport may defeat) is stored with its QoD, tagged `qod-unconfirmed`, with no template result, an unknown version range and confidence at most 0.5, so it can never confirm a finding |
| **Resolved** | a result that a later **complete** scan of the host no longer reports is resolved: the Vulnerability is closed, the match is marked no longer matched and, unless a person already works it, not affected. A host the scan could not reach (no result, not in the report's host list) resolves nothing and is asked again in three days |
| **New scans** | a scan stores hosts again, so after correlation the findings are carried onto the new host row from the stored observations, newest 21 days; a decision a person made on an earlier copy follows it |
| **Not imported** | results with no CVE reference (default credentials, weak ciphers, exposed services) are counted ("n results without a CVE not imported") but not stored; results for an address that was not in the batch are ignored |

An NVT's text is third-party text. It is stripped of control characters, clipped (summary and result at 2,000 characters, the description at 6,000) and stored as plain text. Nothing marks it safe for HTML; the pages and reports escape it, and the settings page builds its DOM with `textContent`.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_OPENVAS_MIN_AVAILABLE_MB` | `3072` | Free memory required, beside the platform's headroom, to start a scan |
| `CVENGINE_OPENVAS_COST_MB` | `1500` | What a GVM scan is counted as against the job budget |
| `CVENGINE_OPENVAS_MAX_HOSTS` | `4` | Hosts in one GVM task |
| `CVENGINE_OPENVAS_MAX_HOURS` | `12` | A task running longer is stopped |
| `CVENGINE_OPENVAS_SOCKET` | `/run/gvmd/gvmd.sock` | gvmd's unix socket in the celery container |
| `CVENGINE_OPENVAS_HOST`, `_PORT`, `_CA`, `_CERT`, `_KEY` | none, `9390` | Reach a gvmd by TLS instead of the socket (an external GVM; not exercised here) |
| `CVENGINE_TTL_OPENVAS`, `CVENGINE_TTL_OPENVAS_FAILED` | `168`, `72` hours | How long a scanned host, and a failed one, stays fresh |

## Images, pins and updating

**Some of these images float, on purpose.** The program images (the manager, the scanner, its database and cache) are pinned by digest. The **feed data images are not**: they follow Greenbone's moving `community` tag so the vulnerability definitions keep updating. The cost is that what they contain changes without a cvENGINE release and cannot be reproduced from a cvENGINE version; the software bill of materials (`scripts/generate_sbom.py`) lists them as unpinned and says why. If you need a frozen set, pin those digests yourself and accept that the definitions then go stale.

**What a cvENGINE update does to the add-on.** An update rebuilds the cvENGINE images, which installs the pinned `python-gvm` with no manual step, and recreates only `web`, `celery`, `celery-beat` and `proxy`. It does not start, stop, pull or recreate any `openvas-*` service: with `COMPOSE_PROFILES=openvas` in `.env` the add-on keeps running as it was, without it nothing of the add-on exists. Greenbone's images are changed only by you (see To update below).

Greenbone publishes **no version tags**: the registry lists only the moving tags `stable`, `community`, `latest` and `edge` (read 2026-10-27), so the program images are pinned by `tag@digest` in `docker-compose.yml`, which is what runs. The feed data images (`vulnerability-tests`, `notus-data`, `scap-data`, `cert-bund-data`, `dfn-cert-data`, `data-objects`, `report-formats`) follow `:community` on purpose: they are data that Greenbone refreshes daily and that is checked against its GPG signing keys, and a pinned feed would be a stale one. The set is the minimal one that exposes GMP, from Greenbone's own compose file (greenbone.github.io/docs, Greenbone Community Containers, `FEED_RELEASE` 24.10): without the web interface (`gsa`, `gsad`, `nginx`), the certificate generator and the `gvm-tools` shell. There is **no MQTT broker** in Greenbone's current compose file (older layouts ran a mosquitto broker for a separate notus-scanner); notus is served by `openvasd` in `OPENVASD_MODE=service_notus`.

Digests read from `registry.community.greenbone.net` on 2026-10-27 (multi-architecture index digests):

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

## Licences

The add-on runs Greenbone's software as separate containers and talks to it over a socket; nothing is linked into cvENGINE except the client library. gvmd and ospd-openvas are AGPL-3.0-or-later, openvas-scanner GPL-2.0 (its Rust parts GPL-2.0-or-later), pg-gvm GPL-3.0. [python-gvm](https://github.com/greenbone/python-gvm) is GPL-3.0-or-later, which fits cvENGINE's GPL-3.0; it brings `paramiko` (LGPL-2.1), `PyNaCl` and `bcrypt` (Apache-2.0), `invoke` (BSD) and `h2`, `hpack` and `hyperframe` (MIT) as dependencies. The feed content has its own terms, which the data containers print when they start; read them before offering cvENGINE to others as a service. See THIRD-PARTY.md.

## Not verified against a real GVM

cvENGINE's tests run python-gvm unmodified against a fake gvmd that speaks GMP in the documented XML formats (`web/tests/fake_gvmd.py`). **No Greenbone container was started when this was written** (no container runtime was available), so these are unconfirmed until someone runs them against a real gvmd:

- the exact shape of `get_feeds`, `get_configs` (family `nvt_count`, the `safe_checks` preference), `get_results` and `get_reports` on gvmd 22.x, and whether `currently_syncing` is present while a feed loads;
- that rebuilding the configuration with `modify_config` family selection leaves exactly the families intended and that the scanner skips the right NVTs under `safe_checks` (the verification after the build is the safeguard: it fails closed);
- the built-in ids (`daba56c8-...` Full and fast, `08b69003-...` OpenVAS Default, `33d0cd82-...` All IANA assigned TCP) and the task preferences `max_checks` and `max_hosts`;
- the `levels=chmlg` result filter and the report's host list, which decide which hosts count as scanned;
- that `modify_user` with only a password keeps the user's role (`make openvas-user`); if it does not, set the password in GVM and use `openvas_credentials`;
- the memory and disk figures above, the length of the first feed synchronisation, and the TLS transport;
- that a read-only mount of the socket volume connects on every Docker storage driver.

`docker compose config` accepts the file with and without the profile; that is all that was checked of the compose wiring.

## Troubleshooting

| Settings says | Meaning |
| --- | --- |
| Not connected: gvmd could not be reached | The profile is not running, or celery was not recreated to mount the socket volume |
| gvmd refused the GMP login | The saved password is not the one gvmd has; run `make openvas-user` or save the right one |
| No scan can start yet: the vulnerability tests are not loaded | The feed is still loading; wait |
| Resource guard: memory is short | See What you need; free memory or lower `CVENGINE_OPENVAS_MIN_AVAILABLE_MB` knowingly |
| the scan configuration is not safe | Someone edited "cvENGINE safe scan" in GVM: delete it there and cvENGINE rebuilds it |
