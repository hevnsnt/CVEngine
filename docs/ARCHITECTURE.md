# Architecture

CVEngine is one Docker Compose deployment. The scanners run inside the worker image, so nothing is split across machines.

## Services

| Service | Role |
| --- | --- |
| `web` | Django app: the interface, the REST API, and the MCP server |
| `celery` | Three gevent workers: discovery, CVE feed, and everything else |
| `celery-beat` | Schedules: CVE sync, certificate watch, hygiene, deep apex sweep, template update, update check, resource report |
| `db` | PostgreSQL 18 |
| `redis` | Job broker, locks, and the memory queue |
| `proxy` | nginx, terminates TLS |

The worker image contains the scanners: bbot, nmap, nuclei, and httpx, plus other Go tools inherited from reNgine. bbot fetches gowitness for screenshots on first use.

## Stack

Ubuntu 26.04, Python 3.14, Django 5.2 LTS, PostgreSQL 18, nmap 7.992, and Go 1.27 for building the scanners.

## Main data

| Model | Holds |
| --- | --- |
| `Org`, `Project` | The tenancy hierarchy. See [TENANCY.md](TENANCY.md). |
| `Domain` | A target: a domain, IP, or URL host |
| `Subdomain`, `IpAddress`, `Port` | The inventory: hosts, addresses, and services with product and version |
| `Vulnerability` | Findings from nuclei, bbot, and the exposure check |
| `CVEEntry`, `CVEMatch` | The CVE feed, and which CVEs apply to which hosts, with the AI verdict |
| `ServiceRun` | The last finished run of each scanner on each asset. See [PIPELINE.md](PIPELINE.md). |
| `GeneratedTemplate`, `AutoFireRun`, `MatchVerdict` | AI-written nuclei templates, auto-fire runs, and the AI verdict shared by matches of the same kind |
| `Triage`, `TriageVerdict` | One triage per finding, and the AI answer shared by findings with the same evidence |
| `HostState`, `AssetChange` | Each host's snapshot, and the change log built from comparing snapshots |
| `AgentActivity` | The activity feed shown on the dashboard |

## Where the AI is used

- Triaging findings into confirmed, likely, needs validation, or likely false positive. Fixed rules keep hard evidence from being dismissed.
- Confirming CVE matches as affected, not affected, or uncertain when auto-fire is on.
- Choosing nuclei template tags from the tags the installed templates use, based on the technologies found on a host.
- Writing a nuclei template when none exists for a CVE.

The AI never changes severity, CVSS, KEV, or EPSS data. Those come from the feed. See [CONFIGURATION.md](CONFIGURATION.md) to set the provider.

## Code layout

| Path | Contents |
| --- | --- |
| `web/cveFeed/` | CVE feed, discovery pipeline, nmap, nuclei, hygiene, correlation, AI auto-fire |
| `web/agentapi/` | The REST API and MCP server |
| `web/tenancy/` | Roles and per-project data isolation |
| `web/reNgine/` | Shared code: the bbot wrapper, AI providers, the memory queue |
| `web/startScan/`, `web/targetApp/`, `web/dashboard/` | Inventory, target, and tenancy models inherited from reNgine |
| `web/static/cve/` | The front end. See [FRONTEND.md](FRONTEND.md). |

CVEngine is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x. The code under `web/reNgine/` keeps that name.

See also: [PIPELINE.md](PIPELINE.md), [DEPLOYMENT.md](DEPLOYMENT.md), [documentation index](README.md).
