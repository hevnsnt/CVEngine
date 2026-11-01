# Documentation

Start with the [project README](../README.md) for what cvENGINE is and how to install it.

## Using cvENGINE

| Document                               | What it covers                                                                                                                                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [FRONTEND.md](FRONTEND.md)             | The interface: design system, every page and route, the Live dashboard, Hosts, Findings, Suppliers, Sentinels, Settings, PDF reports, the rebuilding page, themes, and keyboard shortcuts |
| [SEARCH.md](SEARCH.md)                 | Shodan-style search over your inventory: filters, examples, the Shodan equivalents, and saved searches with alerts                                                                        |
| [FIRE-SMOKE-ICE.md](FIRE-SMOKE-ICE.md) | How cvENGINE rates every CVE and why                                                                                                                                                      |
| [BUG-BOUNTY.md](BUG-BOUNTY.md)         | The bug bounty page: who may use it, program scope, reports, and submission                                                                                                               |
| [AI-USAGE.md](AI-USAGE.md)             | AI model usage, tokens, and cost estimates                                                                                                                                                |

## How it works

| Document                           | What it covers                                                                                     |
| ---------------------------------- | -------------------------------------------------------------------------------------------------- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Services, stack, main models, Sentinels, where AI is used, and the code layout                     |
| [PIPELINE.md](PIPELINE.md)         | How a target becomes findings: stages, triage, changes, CVE intelligence, schedules                |
| [CVE-INTAKE.md](CVE-INTAKE.md)     | How a new CVE becomes guidance, which CVEs an outside scan can decide, and what is never a finding |

## Scanning from your own networks, and more sources

| Document                               | What it covers                                                                                                                                                                                                         |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [SENTINELS.md](SENTINELS.md)           | Sentinels: running scanners on your own network, internal networks included                                                                                                                                            |
| [BUILTIN-SCANNER.md](BUILTIN-SCANNER.md) | Trying the optional built-in scanner (1.4): what moves to it and what stays on the server, and a test recipe from build to rollback                                                                                    |
| [SECRETS-PLAN.md](SECRETS-PLAN.md) | The 1.4 plan for exposed secrets: a project secrets inventory built on the Kingfisher detector, run by the Sentinel, with severity rules, gated read-only validation and the PR breakdown (planning, not built) |
| [OPENVAS.md](OPENVAS.md)               | The optional OpenVAS (Greenbone) scanner: the compose profile, the hardware floor and resource guard, which hosts it scans and how, the safe scan configuration, how results become findings, and what is not verified |
| [TAILSCALE.md](TAILSCALE.md)           | Attaching a tailnet: the scanner's node, device import and auto-scan, the Tailscale checks, and how tailnet addresses are allowed                                                                                      |
| [HOST-INVENTORY.md](HOST-INVENTORY.md) | Hosts reporting about themselves: the Linux, macOS and Windows scripts, what they collect, the report format, how it finds its host, and the local CVEs it makes decidable                                             |

## Installing and running

| Document                               | What it covers                                                                                                         |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| [DEPLOYMENT.md](DEPLOYMENT.md)         | Ports, HTTPS, proxies, AI models, backups and restore, dev stack, factory reset, uninstall                             |
| [HOSTING-ONLINE.md](HOSTING-ONLINE.md) | Putting an install on the Internet under a real name: DNS, Let's Encrypt, Cloudflare, your own proxy                   |
| [CONFIGURATION.md](CONFIGURATION.md)   | Every environment variable: memory, workers, scan windows, Sentinels, AI limits, feeds, retention, PDF reports, access |
| [UPDATES.md](UPDATES.md)               | Automatic deployment, in-app approval, and the manual updater                                                          |
| [UPGRADE.md](UPGRADE.md)               | Moving an older install to the current release                                                                         |

## Access and integration

| Document                     | What it covers                                                                          |
| ---------------------------- | --------------------------------------------------------------------------------------- |
| [TENANCY.md](TENANCY.md)     | Organizations, projects, roles, and two-step sign-in                                    |
| [AGENT-API.md](AGENT-API.md) | REST and MCP interface for agents, including Sentinels, saved searches, and PDF reports |

## Comparison and project

| Document                                 | What it covers                                                                               |
| ---------------------------------------- | -------------------------------------------------------------------------------------------- |
| [COMPARISON.md](COMPARISON.md)           | cvENGINE and ProjectDiscovery, feature by feature, including where ProjectDiscovery is ahead |
| [../CHANGELOG.md](../CHANGELOG.md)       | What changed                                                                                 |
| [../CONTRIBUTORS.md](../CONTRIBUTORS.md) | Credits, including the reNgine contributors                                                  |
| [../THIRD-PARTY.md](../THIRD-PARTY.md)   | Third-party software and licenses                                                            |
