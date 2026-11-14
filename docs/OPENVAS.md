# OpenVAS (Greenbone)

OpenVAS is an optional second vulnerability scanner. **A Sentinel runs it** (kind `openvas`, `sentinel_dispatch.NEVER_LOCAL`): the Sentinel's own Greenbone Community Edition stack scans, and cvENGINE hands it a task and imports what it reports back, as findings and CVE evidence. **This server never talks GMP to gvmd and never runs a scan**; there is no local path and `CVENGINE_LOCAL_FALLBACK` cannot bring one back. It is **off by default and costs nothing while it is off**: no scheduled work and no task. Turning it on is one decision for the whole instance (an App Admin), and then the organizations choose what is scanned. The `openvas` compose profile in `docker-compose.yml` and the host scripts that start it (`make openvas-up`, `scripts/openvas-sync.sh`) are no longer used by the application: the web container no longer asks the host to start them.

OpenVAS finds what nuclei and nmap do not: it runs tens of thousands of network vulnerability tests (version checks, protocol-level checks, default credentials, weak configuration) against every port of a host. It is slow, it is heavy, and its version-based results are often wrong about backported fixes, which is why cvENGINE only treats the high-confidence ones as confirmed (see Results).

## What you need

The Sentinel that runs it needs the Greenbone stack (gvmd, its PostgreSQL, Redis, the scanner and the feed data) and declares the `openvas` capability only while that stack can scan (the Sentinel repo's README and `client/openvas.py` say how: the feed must be loaded, its login made, the scan configuration verified). Greenbone's container guide gives no hardware figures; the Sentinel host needs roughly 4 GB of memory once loaded, 2 vCPUs, about 60 GB of disk for the first synchronization, and hours for that first synchronization. This server holds no GMP login and keeps no memory or disk floor for it.

## Turn it on

An **App Admin** opens **Administration > OpenVAS** (or the Settings tab) and presses **Switch on**. That enables the sweep's beat entry; nothing is started on this host. Then App Admins and Org Admins tick the organizations or projects to scan. Hosts are handed to a Sentinel that declares `openvas` for the project (the page lists each Sentinel as ready, or says why not). With no such Sentinel the hosts simply stay due.

Who can do what: only an **App Admin** switches the add-on on or off for the instance (the choices are kept when it is off). While it is off nobody can choose anything, and an Org Admin is told an App Admin has to switch it on first. Once it is on, an App Admin sees every organization and an **Org Admin** sees only the organizations they administer and those organizations' projects. Members and auditors see nothing. Every choice is in the audit log.

A run an earlier version started against this server's own gvmd (no Sentinel task) is closed as failed at the next step and marks no host failed: the hosts stay due and go to a Sentinel. Retire the old stack by hand when convenient (`make openvas-down`; the data volumes stay).

## What gets scanned

OpenVAS is slow (about 4% an hour on one host with the safest settings, so one host takes between half a day and a day) and intrusive, so it is spent **only where it matters**, and only in the projects someone opted in (a project, or a whole organization):

- **Fire or Smoke only.** A host is scanned only while its heat is Fire or Smoke (the color on the host card: a CVE match rated hot, or an open finding rated medium or above). Clean, Ice and Unscanned hosts are never scanned. The order is Fire before Smoke, then the host with the most fire reasons, then the most smoke reasons, then the one that has waited longest. OpenVAS is a confirmer, so a CVE match counts here at the heat it would have once proven (`threat.validation_heat`): a host whose only reason is a known-exploited CVE whose version is not proven shows Smoke on its card but is Fire for OpenVAS. Under the KEV heat policy (the default, `CVENGINE_HEAT_POLICY=kev`) a CVE that is neither on the KEV nor exploited is ice however high its CVSS or EPSS, so **a host whose only CVEs are ice no longer qualifies** (before the policy, a high or critical CVSS was enough), whether they are CVE matches or scanner findings that name the CVE (a scanner finding with CVE ids follows the CVE rule: hot is Fire here, not hot is Ice); an open scanner finding that names no CVE, rated medium or above, still makes a host qualify. `CVENGINE_HEAT_POLICY=legacy` restores the old selection (see [Fire, smoke, and ice](FIRE-SMOKE-ICE.md#from-the-feed-to-your-hosts)). The heat the queue and the host's Checks line name is that one.
- **Automatic.** Nobody has to list anything: a host that turns Fire or Smoke becomes due by itself, and one that cools to Clean leaves the queue. The old "every name the project's scans found" fallback (`CVENGINE_OPENVAS_AUTO_HOSTS`) is gone.
- **Listed and forced.** `hosts` on `openvas/projects/{id}` still adds hosts someone named, but the heat gate still applies to them. `forced_hosts` (a subset the administrator marks) lifts only the heat gate, for a host to be scanned whatever its color. Forcing never lifts the ownership refusals below.
- **One host per task**, with a time budget per host (`CVENGINE_OPENVAS_MAX_HOURS`, 24). When the budget runs out the task is stopped and **what it found so far is kept** (a partial scan: the findings are stored, nothing an earlier scan found is closed by it, and the host counts as scanned). A task that found nothing before the budget ran out is a failure like any other.
- **Why a host is or is not due is shown**: `GET openvas/projects/{id}/queue` (Settings), the Sentinels page (`openvas` in `GET sentinels/live`: the run, the hosts due next in order, and the hosts that are not due with the reason) and the host's check coverage say, in plain words, "not Fire or Smoke (clean)", "a CDN edge", "a third-party platform (Atlassian Cloud) shared with other customers", "a documentation address range", "this cvENGINE server", "scanned 3 days ago", and so on. Above the collapsed **Not due** list the Sentinels page shows one summary line such as `33 not due: 20 not Fire or Smoke, 8 scanned this week, 5 on shared platforms`. The server groups the per-host reasons into fixed categories (`QUEUE_REASONS` in `cveFeed/openvas_scan.py`; a reason it does not know is counted as `for other reasons`) and counts every host, not only the rows the list shows (`not_due_summary` and `not_due_groups` in `openvas`; `counts` are exact too). The per-host list is unchanged.

Every host, chosen or not, is vetted at every sweep:

- each name must be a host of that project (another project's host is never scanned);
- hosts excluded for the organization or archived are dropped (`cveFeed.exclusions`), as is any name that resolves to an address a scanner may not be pointed at (`scannable_hosts`, `pinned_transport.resolve`);
- GVM is given the **numeric address** that was vetted, never a name, so a name re-pointed after it was stored cannot redirect the scan;
- **tailnet addresses (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) are never given to OpenVAS**, even for a project with a connected tailnet. The scanner containers have no Tailscale interface, so the packets would leave by the Docker host's default route.
- **shared infrastructure is never given to OpenVAS**: a name or address recorded as a CDN edge or a vendor's shared front (Microsoft 365 autodiscover and device enrolment, Google Workspace, a PaaS such as Netlify or Heroku, `cveFeed.hosting`), and any other name recorded on such an address. These are other customers' machines, not the project's to test;
- **documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and this instance's own address are refused**: its own address is what `DOMAIN_NAME` resolves to, plus `CVENGINE_OWN_ADDRESSES` (comma separated, for an instance behind NAT or a load balancer);
- a task that fails for want of a working scanner (a Sentinel that stopped answering, its gvmd not reachable or not answering, its feed still syncing, a login or scan configuration problem) **marks no host failed** at first: the hosts are tried again at the next step. A task that fails after the scan ran marks its hosts failed, and they are asked again after three days;
- **one host, many names**: GVM scans the address, so when a host is scanned every other name of the project that has that address is counted as scanned too, and is not scanned again at the next step;
- **a result set cut at the cap** (5000 results, highest severity first) is imported as a partial scan: what it found is kept and nothing earlier is closed by it;
- a task whose report names **no scanned host** is **inconclusive**, not a scan: no host is stamped as scanned, the run says "OpenVAS ran but reported no scanned host", the host's reason says the same, and it is asked again after three days;
- the global pause is honored, projects take turns (the one scanned longest ago goes first), and the project's hosts are visited once a week each (`CVENGINE_TTL_OPENVAS`, hours; a host that failed waits three days, `CVENGINE_TTL_OPENVAS_FAILED`).

The sweep runs on its own queue (`openvas_queue`), every 15 minutes. Each step is small: import the running task's report, or hand the next due batch of at most `CVENGINE_OPENVAS_MAX_HOSTS` hosts (default 1, at most 16) to a Sentinel as **one task for one project**. **One GVM task runs at a time**, enforced by a database constraint (`OpenvasRun`). While scanning is paused the step starts nothing, and when an App Admin pauses everything it expires the running Sentinel task (an expired task marks no host failed).

**How results are read.** The Sentinel reads its gvmd's report (`client/openvas.py`) and sends back the results, the addresses gvmd scanned and the counts. The server cleans and bounds every field (`sentinel_broker`), then imports it: a result for an address the task did not name is ignored, and results gvmd left without their CVE references (a stale NVT cache, greenbone/gvmd#3220) make the run partial, so nothing earlier is closed and the hosts are asked again after three days.

**The activity feed.** A run shows as one line from start to end, "OpenVAS run 12 on www.example.com (Sentinel task 7)", which ends "finished after 1 h 23 min" (or failed, and why); the import adds a line with what it found under the same name.


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
| **Hard evidence** | only a result of a **hard type** (`remote_active`, `remote_vul`, `remote_app`, `exploit`, `package`, `registry`: the check ran against the service or read the installed package; QoD 95 or more when gvmd gives no type). QoD 80 is `remote_banner` or `executable_version`, a version read from a banner or a binary, and a backport defeats it, so it is not hard evidence: `template_result` is `vulnerable`, version in range, confidence 0.95. A lower one ("version possibly affected", a banner that a backport may defeat) is stored with its QoD, tagged `qod-unconfirmed`, with no template result, an unknown version range and confidence at most 0.5, so it can never confirm a finding |
| **Resolved** | a result that a later **complete** scan of the host no longer reports is resolved: the Vulnerability is closed, the match is marked no longer matched and, unless a person already works it, not affected. A host the scan could not reach (no result, not in the report's host list) resolves nothing and is asked again in three days |
| **New scans** | a scan stores hosts again, so after correlation the findings are carried onto the new host row from the stored observations, newest 21 days; a decision a person made on an earlier copy follows it |
| **Not imported** | results with no CVE reference (default credentials, weak ciphers, exposed services) are counted ("n results without a CVE not imported") but not stored; results for an address that was not in the batch are ignored |

An NVT's text is third-party text. It is stripped of control characters, clipped (the result at 2,000 characters, the summary, insight, impact and solution at 1,500 each, the description built from them at 6,000) and stored as plain text. Nothing marks it safe for HTML; the pages and reports escape it, and the settings page builds its DOM with `textContent`.

## Where a due batch runs

A due batch runs on **a Sentinel that declares the `openvas` capability** for the project (a Sentinel declares it only while its own GVM stack can scan; a light-profile Sentinel never does). cvENGINE hands it one task with the vetted host set (numeric addresses), this instance's own excluded-family list (so a Sentinel never uses a copy that is out of date) and its preferences. A target inside a network a project declared internal is a batch of its own, never mixed with the external one, and only a Sentinel inside that network (capability `network:internal`) can take it. With no eligible Sentinel the batch stays due; the page says why (`disabled`, `offline`, `withheld`, `inactive`, `never`). This server never runs OpenVAS itself, with or without `CVENGINE_LOCAL_FALLBACK`.

Only one GVM task runs at a time. See [AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents) and [ARCHITECTURE.md](ARCHITECTURE.md#sentinels).

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVENGINE_OPENVAS_MAX_HOSTS` | `1` | Hosts in one task (1 to 16). A larger value is held to 16 with a warning in the log: a Sentinel refuses an OpenVAS task of more hosts |
| `CVENGINE_OPENVAS_MAX_HOURS` | `24` | The time budget per host (a task of n hosts gets n times this). A task running longer is stopped and keeps what it found |
| `CVENGINE_OPENVAS_MAX_CHECKS` | `4` | NVTs run at a time against a host (1 to 10; Greenbone's default is 4). At 2 a host takes about a day, at 4 about half that; lower is gentler on the target |
| `CVENGINE_OWN_ADDRESSES` | none | Addresses of this instance OpenVAS must never scan, besides what `DOMAIN_NAME` resolves to |
| `CVENGINE_TTL_OPENVAS`, `CVENGINE_TTL_OPENVAS_FAILED` | `168`, `72` hours | How long a scanned host, and a failed one, stays fresh |

**Sentinel only.** The old **Sentinel only** switch is gone from the pages and is no longer read: OpenVAS always runs on a Sentinel.

## Images, pins and updating

**Which stack scans.** The Greenbone stack that scans is the one in the **Sentinel repository's** `docker-compose.yml` (the `openvas` profile of a Full Sentinel: `COMPOSE_PROFILES=openvas` in the Sentinel's `.env`). This repository's `docker-compose.yml` still carries the same 15 `openvas-*` services under the `openvas` profile, but the application no longer uses them (`make openvas-up` starts them by hand); they are off unless you ask. The digests below are this repository's. The two files pin the same images, `openvas-scanner` included (`sha256:5b2043df…` since 11/10, when Greenbone removed both earlier digests from its registry). Greenbone publishes no version tags and replaces the images behind `stable`, so a pin can disappear: the Sentinel's `scripts/greenbone-digests.sh` checks every pin and prints the current digest. Read the Sentinel's file for what actually scans. Software list with versions and licenses: the About page and THIRD-PARTY.md.

**Some of these images float, on purpose.** The program images (the manager, the scanner, its database and cache) are pinned by digest. The **feed data images are not**: they follow Greenbone's moving `community` tag so the vulnerability definitions keep updating. The cost is that what they contain changes without a cvENGINE release and cannot be reproduced from a cvENGINE version; the software bill of materials (`scripts/generate_sbom.py`) lists them as unpinned and says why. If you need a frozen set, pin those digests yourself and accept that the definitions then go stale.

**What a cvENGINE update does to the add-on.** An update rebuilds the cvENGINE images and recreates only `web`, `celery`, `celery-beat` and `proxy`. It does not start, stop, pull or recreate any `openvas-*` service: with `COMPOSE_PROFILES=openvas` in `.env` the old in-stack Greenbone containers keep running as they were (this server no longer uses them: a Sentinel scans, so they only cost memory and disk and can be stopped with `make openvas-down`), without it nothing of them exists. Greenbone's images on this host are changed only by you (see To update below).

Greenbone publishes **no version tags**: the registry lists only the moving tags `stable`, `community`, `latest` and `edge` (read 2026-10-27), so the program images are pinned by `tag@digest` in `docker-compose.yml`, which is what runs. The feed data images (`vulnerability-tests`, `notus-data`, `scap-data`, `cert-bund-data`, `dfn-cert-data`, `data-objects`, `report-formats`) follow `:community` on purpose: they are data that Greenbone refreshes daily and that is checked against its GPG signing keys, and a pinned feed would be a stale one. The set is the minimal one that exposes GMP, from Greenbone's own compose file (greenbone.github.io/docs, Greenbone Community Containers, `FEED_RELEASE` 24.10): without the web interface (`gsa`, `gsad`, `nginx`), the certificate generator and the `gvm-tools` shell. There is **no MQTT broker** in Greenbone's current compose file (older layouts ran a mosquitto broker for a separate notus-scanner); notus is served by `openvasd` in `OPENVASD_MODE=service_notus`.

Digests read from `registry.community.greenbone.net` on 2026-10-27 (multi-architecture index digests), `openvas-scanner` again on 2026-11-02: Greenbone removed the digest pinned before (`sha256:5067aa68...`, which the registry now answers with 404), so a fresh pull failed. The `stable` rows are what `docker-compose.yml` pins; the `community` rows are for reference only, since the compose file follows that tag:

| Image | Tag | Digest |
| --- | --- | --- |
| `gvmd` | `stable` | `sha256:e59a6a684b112ea77fe4ddd7e5ca35e6a07d36bf854f1b411d11d12f9b0c608a` |
| `pg-gvm` | `stable` | `sha256:a18d9e2f0cbba7839e65547a2331ce8f984500e8c4fbe91d08f9a48036d03fa2` |
| `pg-gvm-migrator` | `stable` | `sha256:8fc1cc11cac0481674527e01ec7610a8195110cf117d700bd47fe3af7012b34d` |
| `redis-server` | `stable` | `sha256:83227e34b276bf7c7453a91bbfc070341af58f7ff40eb707ed6724965fe3846c` |
| `ospd-openvas` | `stable` | `sha256:31a85272abc77521c98451ce6834ed7d2f887e98ff1b26ff3fd94f00d000b169` |
| `openvas-scanner` | `stable` | `sha256:5b2043df8abed6acff7cd4c08636ea87c57f73b95cd406c88dc2adcec24426dd` |
| `gpg-data` | `stable` | `sha256:c18618252f7d874cd1fe09413b043cfc40b57e6464d8c5973d4a93b074d5d91a` |
| `vulnerability-tests` | `community` | `sha256:d0a8df253c177321c03c24ca5be051ca22da547756f684a96a2153c2ff0c9bd7` |
| `notus-data` | `community` | `sha256:f84397aede60d158e47ac199e0fe5108f707ed75657406e4e9aad37b92cb0c9a` |
| `scap-data` | `community` | `sha256:fff27d3994c6a559241719547be5dc8992bd50b1c6bf44de48588adcf2e7a567` |
| `cert-bund-data` | `community` | `sha256:b3dc178aca3c874c48529ca1ba877900b8069fd715a5831c4c3539642c57ec8a` |
| `dfn-cert-data` | `community` | `sha256:f0c2f33101616bf956ccb605c89449b8fcd85c47226347fc8961eb5661b7f8c6` |
| `data-objects` | `community` | `sha256:192188bcf92ac440a45556731243a6ab7255a52aff94bd78901ceed452b608da` |
| `report-formats` | `community` | `sha256:5a74234489215f4d7e26d9b481293cc51ab7efcebb683de8bc5dfe06cd68e549` |

To update: read the new digest (`docker buildx imagetools inspect registry.community.greenbone.net/community/gvmd:stable`), change it in `docker-compose.yml`, read [Greenbone's release notes](https://greenbone.github.io/docs/latest/) for the manager and scanner first, and `docker compose --profile openvas up -d` (on the Sentinel, in its own checkout, for the stack that scans). Update `python-gvm` (pinned in `web/requirements.txt` here and in the Sentinel's `requirements.txt`) with it: a gvmd that speaks a GMP version newer than the client knows (22.8 and later) makes python-gvm warn. `scripts/check_tool_versions.py` watches python-gvm; it cannot watch the Greenbone images, which have no version to compare.

## Licenses

The add-on runs Greenbone's software as separate containers and talks to it over a socket; nothing is linked into cvENGINE except the client library. gvmd and ospd-openvas are AGPL-3.0-or-later, openvas-scanner GPL-2.0 (its Rust parts GPL-2.0-or-later), pg-gvm GPL-3.0. [python-gvm](https://github.com/greenbone/python-gvm) is GPL-3.0-or-later, which fits cvENGINE's GPL-3.0; it brings `paramiko` (LGPL-2.1), `PyNaCl` and `bcrypt` (Apache-2.0), `invoke` (BSD) and `h2`, `hpack` and `hyperframe` (MIT) as dependencies. The feed content has its own terms, which the data containers print when they start; read them before offering cvENGINE to others as a service. See THIRD-PARTY.md.

## Not verified against a real GVM

The GMP client (the scan configuration, the target and task, the report reading) is the Sentinel's (`client/openvas.py`), and its tests (`client/tests/test_openvas.py` and `test_openvas_gmp.py` in the Sentinel repo) run against a scripted gvmd that speaks GMP in the documented XML formats. **No Greenbone container was started when this was written** (no container runtime was available), so these are unconfirmed until someone runs them against a real gvmd:

- the exact shape of `get_feeds` and `get_configs` (family `nvt_count`, the `safe_checks` preference) on gvmd 22.x, and whether `currently_syncing` is present while a feed loads. The shapes of `get_results`, `get_reports` (with and without `details`, `result_hosts_only`, `first` and `rows`) and `modify_user`'s refusal were read from gvmd's source (v22.7.0 and v26.43.0, which speaks GMP 22.7) after issue #394, and the fake gvmd answers in them. `get_tasks`' `last_report` differs between the two: v22.7.0 (like every gvmd 22.4 to 24.x) counts results as `hole`, `info`, `log`, `warning` and `false_positive` only, and `critical`, `high`, `medium` and `low` first appear in v25.0.0, with the old names kept as deprecated duplicates. The fake gvmd prints the v22.7.0 names by default and the v25 shape when a test asks for it; they are still not checked against a running gvmd;
- that rebuilding the configuration with `modify_config` family selection leaves exactly the families intended and that the scanner skips the right NVTs under `safe_checks` (the verification after the build is the safeguard: it fails closed);
- the built-in ids (`daba56c8-...` Full and fast, `08b69003-...` OpenVAS Default, `33d0cd82-...` All IANA assigned TCP) and the task preferences `max_checks` and `max_hosts`;
- that a report host gvmd finished always has an end time (a host with a start and no end does not count as scanned);
- that a read-only mount of the socket volume connects on every Docker storage driver.

`docker compose config` accepts the file with and without the profile; that is all that was checked of the compose wiring.

## Troubleshooting

| Settings says | Meaning |
| --- | --- |
| No scan can start yet: the vulnerability tests are not loaded | The feed is still loading; wait |
| OpenVAS ran but reported no scanned host | The Sentinel's gvmd finished a task that names no scanned host. Nothing is marked scanned; the hosts are asked again after three days. Read the task and its report on the Sentinel's own GVM stack |
| gvmd sent N result(s) without their CVE references: its NVT cache is out of date | gvmd 26.35 and later reload the NVT cache that GMP answers are built from only in their periodic-jobs process, so after the first feed load (and for NVTs a later feed sync adds) results come with their CERT-Bund and DFN-CERT references but none of their CVEs, until gvmd restarts ([greenbone/gvmd#3220](https://github.com/greenbone/gvmd/issues/3220)). cvENGINE imports such a run as partial (nothing an earlier scan found is closed), keeps the GVM task, asks for the hosts again in three days and asks the host's watcher to restart `openvas-gvmd` (at most once in six hours; `web/.openvas-log` says when). Without the watcher (Docker Desktop, `make openvas-up` by hand) run `docker compose restart openvas-gvmd` yourself. A Sentinel's run says "the Sentinel's gvmd": restart `openvas-gvmd` on the Sentinel's host |
| the scan configuration is not safe | Someone edited "cvENGINE safe scan" in GVM: delete it there and cvENGINE rebuilds it |
