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

**Phase 2 (this phase) ships the actual downloadable client.** There is no per-OS package: the Sentinel client lives in this repository, under `sentinel/`, as its own Docker Compose service (`sentinel/docker-compose.yml`, `sentinel/Dockerfile`, `sentinel/client/`), so it runs identically on Linux, macOS and Windows hosts with nothing OS-specific to build or ship. Provisioning is one copy-pasteable blob rather than typing separate fields into a Sentinel's config: the Sentinels page's **Provision** button (or `?format=blob` on `sentinels/enroll`) base64-encodes `generate_enrollment`'s own payload (`agentapi.sentinel_broker.encode_enrollment_blob`; no new crypto, no custom framing, still a plain bearer token over HTTPS) into `CVENGINE_SENTINEL_BLOB`, which the client decodes once, trades for its own token at `sentinels/bootstrap`, and persists (0600, in a named Docker volume) so a restart never needs the blob again. The client's own main loop (`sentinel/client/daemon.py`) long-polls `sentinel/tasks/next`, accepts, runs the matching tool against only the task's own typed `target` (a fixed argv list built from a defensively validated address/host list, never a shell command: see `sentinel/client/tools.py`), parses the tool's own output (nmap XML, naabu JSON lines, nuclei `-jsonl`) into the exact typed shapes `clean_result` expects, and reports back; a concurrent heartbeat thread matches `agent_broker.HEARTBEAT_SECONDS`, and SIGTERM finishes or releases in-flight tasks rather than abandoning them. `sentinel/Dockerfile` pins nmap, naabu and nuclei to the *exact same* versions `web/Dockerfile` pins (checksum-verified nmap, the same Go module versions for naabu and nuclei); `scripts/check_tool_versions.py` checks both files' pins for freshness and for parity with each other, and `scripts/generate_sbom.py` lists the Sentinel image's pins as their own SBOM components.

**Dispatch or local**, the one design decision that matters: before a scan stage (nmap's fingerprint pass, naabu's port sweep, a nuclei pass) runs its tool, it asks `agentapi.sentinel_dispatch` whether a live, eligible, in-scope Sentinel exists for the project with free capacity and the right capability. A project with none gets a single cheap existence check and otherwise runs exactly as it did before Sentinels existed, which is the property a dedicated regression test enforces (`tests.test_sentinel_dispatch`). When one exists, the stage creates a `SentinelTask`, waits bounded (`CVENGINE_SENTINEL_DISPATCH_TIMEOUT`, default 90s) for it to be claimed and reported, and on success parses the typed result into the exact shape the local tool's own output already takes, handing it to the exact same persistence function local execution uses (`cveFeed.nmap_scan.persist_inventory`, `cveFeed.naabu_scan.persist_open_ports`, or, for nuclei, a reconstructed result line run through the stage's own untouched per-line loop). On timeout, failure, or no Sentinel, the stage falls back to running the tool locally: the subprocess-invoking code itself (`run_nmap_xml`, `run_naabu`, `stream_nuclei`) is never modified, only called from a different place depending on this one branch.

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
