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
