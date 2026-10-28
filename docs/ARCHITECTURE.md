# Architecture

cvENGINE is one Docker Compose deployment. The scanners run inside the worker image, so nothing is split across machines.

## Services

| Service | Role |
| --- | --- |
| `web` | Django app: the interface, the REST API, and the MCP server (Gunicorn) |
| `celery` | Four gevent workers: discovery, CVE feed, a one-at-a-time validation lane, and everything else |
| `celery-beat` | The schedules: feeds, certificate watch, hygiene, sweeps, AI reviews, and housekeeping (see [PIPELINE.md](PIPELINE.md#schedules)) |
| `db` | PostgreSQL 18 |
| `redis` | Job broker, locks, cache, and the memory queue |
| `proxy` | nginx, terminates TLS on 443 and redirects 8082 to HTTPS |
| `tailscale` | Optional (`COMPOSE_PROFILES=tailscale`): a `tailscaled` sidecar in the celery container's network namespace, so scans reach a tailnet (see [TAILSCALE.md](TAILSCALE.md)) |

The worker image holds the scanners: [bbot](https://github.com/blacklanternsecurity/bbot), [nmap](https://nmap.org), [nuclei](https://github.com/projectdiscovery/nuclei), [naabu](https://github.com/projectdiscovery/naabu), [wafw00f](https://github.com/EnableSecurity/wafw00f) to name firewalls, and [WPScan](https://wpscan.com/) for WordPress sites. [aardwolf](https://github.com/skelsec/aardwolf) reads RDP login screens. naabu and nuclei install at their latest release when the image is built, nmap 7.992 is built from source, and WPScan is pinned. The old reNgine scan engine and the Go tools it used (httpx, subfinder, katana, and others) are gone. bbot downloads [gowitness](https://github.com/sensepost/gowitness) for deep-mode screenshots. See [THIRD-PARTY.md](../THIRD-PARTY.md).

## Stack

Ubuntu 26.04, Python 3.14, Django 5.2 LTS, PostgreSQL 18, nmap 7.993, and Go 1.27 for building the scanners.

## Main data

| Model | Holds |
| --- | --- |
| `Org`, `Project` | The tenancy hierarchy ([TENANCY.md](TENANCY.md)) |
| `Domain` | A target: a domain, IP, or URL host. It belongs to an organization, which can track a name that another organization also tracks |
| `Subdomain`, `IpAddress`, `Port` | The inventory: hosts, addresses (one row per address in an organization), and services with product and version |
| `CVEDetection` | One shared detection strategy and validation profile per CVE, the same for every organization |
| `RouteAuth`, `HygieneFinding`, `TlsCertificate` | Web route auth states, email and domain findings, and certificates |
| `Vulnerability` | Scanner findings: nuclei, the exposure checks, nmap (RDP without NLA, anonymous FTP), WPScan, and node2shell |
| `AuthCredential` | Encrypted request headers and a cookie an owner stored for a target, for authenticated checks ([PIPELINE.md](PIPELINE.md#authenticated-checks)) |
| `RdpScreenshot`, `HostArchive` | RDP login-screen captures, and archived-URL evidence of what a host once ran |
| `CVEEntry`, `CVEMatch` | The CVE store, and which CVEs apply to which hosts |
| `Triage`, `TriageVerdict` | One triage per finding, and the AI answer shared by findings with the same evidence |
| `GeneratedTemplate`, `AutoFireRun` | AI-drafted nuclei templates and auto-fire runs |
| `HostState`, `AssetChange` | Each host's snapshot, and the change log built from comparing snapshots |
| `HostProfile`, `HostLabel`, `HostExclusion`, `HostAssessment` | Owner and criticality, detection chips, exclusions, and rescans |
| `HostInventory`, `HostInventoryReport` | What a host reported about itself with the reporter script, one row per machine, and its summarised report history ([HOST-INVENTORY.md](HOST-INVENTORY.md)) |
| `ServiceRun` | The last finished run of each scanner on each asset |
| `ReportExport` | One requested PDF report: who asked, for what, its state and the random file name, until it expires ([FRONTEND.md](FRONTEND.md#pdf-reports)) |
| `AgentActivity`, `AIUsage` | The activity feed, and the AI call ledger ([AI-USAGE.md](AI-USAGE.md)) |
| `Agent`, `AgentTask` | A registered agent (an API token that identified itself, including a Sentinel: `kind='scanner'`) and remediation/validation work leased to one |
| `SentinelTask`, `SentinelEnrollment` | Scan-stage work (nmap, naabu, a nuclei pass) leased to a Sentinel, and a one-time secret for a Sentinel's first registration ([AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents)) |

## Sentinels

A Sentinel is a scanner a person runs on their own network: it registers itself as an `Agent` (`kind='scanner'`), pulls scan-stage work off a project's queue, runs it, and reports typed, clipped results back. It is exactly as untrusted as any other agent (see [TENANCY.md](TENANCY.md) and [AGENT-API.md](AGENT-API.md#agents-and-assigned-work)): nothing it reports is ever executed or built into a command.

**Phase 1 (foundation)** covered identity, registration, enrollment, task queueing and leasing, the dispatch point in the scan pipeline, and the admin UI, for three tools: nmap, naabu, and the two nuclei passes (`nuclei_light`, `nuclei_targeted`). bbot, testssl, bucket/vhost/UDP sweeps and WPScan are untouched and keep running locally; wiring them for dispatch is a further follow-up.

**Phase 3 extends dispatch past the per-scan pipeline to the weekly deep Nuclei pass.** `weekly_deep_nuclei` (`cveFeed/tasks.py`) is a standalone Celery-beat task, not a stage inside `discovery.py`'s `_run_stages`: it paces one host at a time through the broad, unrestricted template set, independent of any particular scan. It now builds its nuclei `stream` the same way the per-scan passes do, `agentapi.sentinel_dispatch.wrap_nuclei_stream(scan, 'nuclei_deep')` — the function needed no change, since it was already generic over `kind`; only `SentinelTask.KINDS` gained the new name and `sentinel_broker._CLEANERS` gained the matching result cleaner (the same one `nuclei_light`/`nuclei_targeted` already use, since a deep-pass finding has the identical shape).

**Phase 5 covers the testssl.sh TLS audit.** Unlike the per-scan stages, testssl's sweep (`cveFeed.testssl_scan.sweep`) tests one `host:port` at a time, never a chunk, so `agentapi.sentinel_dispatch.try_testssl` dispatches a single target per `SentinelTask` (kind `testssl`). A Sentinel's report is testssl.sh's own raw finding items (`id`, `severity`, `finding`, `cve` - the four fields `evaluate()` reads), typed and clipped by a dedicated result cleaner, so no detection logic (CVE extraction, "proven" vs "may apply") is duplicated client-side: `evaluate()` reads a Sentinel's report exactly as it reads a local run's.

**Phase 6 covers the UDP exposure sweep.** Unlike every other dispatched kind, a Sentinel's `nmap -sU` report travels as nmap's own raw XML text (`SentinelTask` kind `nmap_udp`), not pre-parsed JSON: UDP's state vocabulary (`open|filtered`, extraports summarisation) and the NSE script output the sweep's own product identification reads are read correctly only by `cveFeed.nmap_scan.parse_xml`, so that one function - local or dispatched - is the sole place either kind of run's XML is ever turned into a record. Because this function now also reads XML a remote agent reported, it refuses a custom ENTITY declaration outright before parsing (real nmap output never declares one) on top of `xmltodict`'s own default entity handling, which already blocks an external DTD/entity fetch - no new dependency, and it protects a local run's own XML parsing too, at no behavioural cost for a well-formed report.

Each remaining stage (bbot, buckets, vhost/subdirectory) is a further follow-up, one at a time. The Sentinel's own GVM stack and GMP client, in the external `cvengine-sentinel` repository, is also still outstanding: OpenVAS dispatch below is this server's half of the contract, ready for that client once it exists.

Every dispatch attempt is now visible in the AI activity feed, not just inferable from the Sentinels page's task counts: `agentapi.sentinel_dispatch.dispatch_or_none` logs one `run_check` activity line per `SentinelTask` ("Handed `kind` work for `host` to a Sentinel"), running while the wait is in progress and settled once it ends — naming the Sentinel and its outcome on success or a reported failure, or saying plainly that no Sentinel checked in and the stage ran locally on a timeout. This reuses the exact `kind`/`status` shape every other scan-stage line already uses (`cveFeed.activity.log`/`settle`), so it needs no change to the Live page or the Activity page: both already render any `run_check` line the same way.

A Sentinel's scope widens past one project: an organization-wide enrollment (`orgs/{slug}/sentinels/enroll`, an admin of that organization or an App Admin) covers every project of that organization, present and future, and an instance-wide one (`sentinels/enroll` with no project or org, App Admin only) covers the whole server. Both reuse the existing `scope: {orgs, projects, hosts}` shape unchanged for the first case (`agentapi.agent_scope.project_slugs_in_scope` already resolved `scope.orgs` dynamically at claim time, so this needed no new resolution logic) plus one new `instance: bool` flag for the second, checked only where scope is authorised (`agentapi.agent_scope.authorise`) and resolved (`project_slugs_in_scope`); nothing about task leasing, dispatch, or the Sentinel client changed.

**Phase 2 ships the actual downloadable client, in its own repository.** There is no per-OS package: the Sentinel client is a small, standalone Docker Compose service at [hevnsnt/cvengine-sentinel](https://github.com/hevnsnt/cvengine-sentinel) (its own Dockerfile, `docker-compose.yml` and `client/` package, kept separate from this codebase so provisioning a Sentinel never needs a clone of the full CVEngine source), and it runs identically on Linux, macOS and Windows hosts with nothing OS-specific to build or ship. Provisioning is one copy-pasteable blob rather than typing separate fields into a Sentinel's config: the Sentinels page's **Provision** button (or `?format=blob` on `sentinels/enroll`) base64-encodes `generate_enrollment`'s own payload (`agentapi.sentinel_broker.encode_enrollment_blob`; no new crypto, no custom framing, still a plain bearer token over HTTPS) into `CVENGINE_SENTINEL_BLOB`, which the client decodes once, trades for its own token at `sentinels/bootstrap`, and persists (0600, in a named Docker volume) so a restart never needs the blob again. The client's own main loop (`client/daemon.py` in the Sentinel repository) long-polls `sentinel/tasks/next`, accepts, runs the matching tool against only the task's own typed `target` (a fixed argv list built from a defensively validated address/host list, never a shell command: see that repository's `client/tools.py`), parses the tool's own output (nmap XML, naabu JSON lines, nuclei `-jsonl`) into the exact typed shapes `clean_result` expects, and reports back; a concurrent heartbeat thread matches `agent_broker.HEARTBEAT_SECONDS`, and SIGTERM finishes or releases in-flight tasks rather than abandoning them. The Sentinel image's own Dockerfile pins nmap, naabu and nuclei to the same versions `web/Dockerfile` pins here (checksum-verified nmap, the same Go module versions for naabu and nuclei), kept in sync by hand across the two repositories since the version-freshness tooling in this repository (`scripts/check_tool_versions.py`, `scripts/generate_sbom.py`) only covers files in this repository.

**Dispatch or local**, the one design decision that matters: before a scan stage (nmap's fingerprint pass, naabu's port sweep, a nuclei pass) runs its tool, it asks `agentapi.sentinel_dispatch` whether a live, eligible, in-scope Sentinel exists for the project with free capacity and the right capability. A project with none gets a single cheap existence check and otherwise runs exactly as it did before Sentinels existed, which is the property a dedicated regression test enforces (`tests.test_sentinel_dispatch`). When one exists, the stage creates a `SentinelTask` and waits under two budgets: a short `CVENGINE_SENTINEL_CLAIM_TIMEOUT` (default 8s) for any Sentinel to claim it at all, and only once claimed, a `CVENGINE_SENTINEL_DISPATCH_TIMEOUT` (default 90s) for it to finish and report - so a quiet, offline or saturated Sentinel costs a scan stage single-digit seconds, not the full completion budget, while a Sentinel that did pick the work up keeps the full budget to actually run it. On success the stage parses the typed result into the exact shape the local tool's own output already takes, handing it to the exact same persistence function local execution uses (`cveFeed.nmap_scan.persist_inventory`, `cveFeed.naabu_scan.persist_open_ports`, or, for nuclei, a reconstructed result line run through the stage's own untouched per-line loop). On timeout, failure, or no Sentinel, the stage falls back to running the tool locally: the subprocess-invoking code itself (`run_nmap_xml`, `run_naabu`, `stream_nuclei`) is never modified, only called from a different place depending on this one branch.

**WPScan dispatch keeps classification server-side, not tool-shaped like nmap/naabu/nuclei.** A Sentinel runs WPScan and reports its raw, unclassified outcome - `{report, returncode, stderr_tail}`, the process's own JSON report and exit code, nothing pre-interpreted - because WPScan's own exit codes and `scan_aborted` text ARE the answer (not WordPress, blocked by an edge, a scan cut short but still useful), not a retry-worthy transient failure the way a dropped nmap probe is. `cveFeed.wpscan_scan._classify`, extracted from the function a local run already used, is the one place - local or dispatched - that turns an outcome into a report or a classified `NotWordPress`/`Blocked`/`RuntimeError`, so a dispatched site is classified exactly as a local one would be. The project's WPScan API token travels in the `SentinelTask.target` for this one dispatch - the same blast radius it already has today, since it already leaves this process into a local subprocess's environment - and `agentapi.sentinel_dispatch.dispatch_or_none` gained a generic `redact_target` parameter for it: once the task reaches a terminal state, the token is scrubbed from the stored row (`{'token': '***'}`) so it does not sit in the plaintext `target` `JSONField` for the rest of the task's retention window. The weekly thorough pass (`run_thorough`, up to a 12-hour timeout) is not dispatched: `dispatch_or_none`'s bounded wait fits a per-scan stage, not a pass that may legitimately run for hours.

**OpenVAS dispatch does not use `dispatch_or_none` at all**, because a GVM task can legitimately run for up to twelve hours (`max_hours()`) - far past any bounded wait a scan stage can afford. Instead, `cveFeed.openvas_scan.tick` (the same beat step that already polls a local `gvmd` task over many 15-minute ticks) tries every due, opted-in project (`sweep_links()`/`next_batch()`, the same host selection and resolve/IP-exists guard a local run already uses) against `agentapi.sentinel_dispatch.any_scanner_for(project, 'openvas')` before ever opening a local GMP session; a project with no eligible Sentinel pays for nothing beyond that one query. When a Sentinel is eligible, `dispatch_to_sentinel` creates a `SentinelTask` (kind `openvas`) and an `OpenvasRun` that only tracks it (`OpenvasRun.sentinel_task`), under the exact same one-task-at-a-time constraint a local run already enforces; later ticks call `poll_sentinel` instead of the local `poll`, which asks the `SentinelTask`'s own status and, once `done`, imports its reported results through `_apply_import` - the one storage path both a local run's own `import_results` and a Sentinel's report feed into, so neither is any richer or poorer a record than the other. `OpenvasSettings.sentinel_only` (Settings > OpenVAS and Administration > OpenVAS, App Admin only) refuses the local fallback entirely: with it on, a due batch with no eligible Sentinel right now is simply left due - tried again next tick, never scanned on this server - rather than ever opening a local GMP session; off by default, so an install that never sets it behaves exactly as before this toggle existed. A local run already in progress when the toggle is turned on is left to finish, not abandoned mid-scan.

## Where the AI is used

- Triaging findings into confirmed, likely, needs validation, likely false positive, or not applicable. Fixed rules keep hard evidence from being dismissed. A reply the validator rejects is sent back to the model once with the reason.
- Confirming CVE matches when auto-fire is on, planning **Validate now** checks, and re-triaging their evidence.
- Choosing nuclei template tags and severities from those the installed templates use.
- Drafting a nuclei template when none exists for a CVE.
- Writing detection checks for the CVEs attackers use, from feed text only, within a daily budget.
- The three-hour coverage review and scanner capacity tuning.
- Reading RDP login-screen screenshots, and suggesting local checks for matches no external check can settle.
- Report text on the bug bounty page.

The AI never writes severity, CVSS, KEV, or EPSS data. It can suggest a one-step severity change, which is shown but not applied. Set the provider as described in [DEPLOYMENT.md](DEPLOYMENT.md#ai-models).

## Code layout

| Path | Contents |
| --- | --- |
| `web/cveFeed/` | CVE feeds, discovery pipeline, nmap, nuclei, hygiene, correlation, triage, validation, bug bounty |
| `web/agentapi/` | The REST API and MCP server |
| `web/tenancy/` | Roles, two-step sign-in, and per-project data isolation |
| `web/reNgine/` | Shared code: the bbot wrapper, AI providers, the memory queue |
| `web/startScan/`, `web/targetApp/`, `web/dashboard/`, `web/scanEngine/` | Inventory, target, settings, and scan engine models inherited from reNgine |
| `web/static/cve/` | The front end ([FRONTEND.md](FRONTEND.md)) |
| `scripts/`, `config/` | Update and deploy scripts, and the nginx config |

cvENGINE is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x. The code under `web/reNgine/` keeps that name.

See also: [PIPELINE.md](PIPELINE.md), [DEPLOYMENT.md](DEPLOYMENT.md), [documentation index](README.md).
