# cvENGINE and ProjectDiscovery

[ProjectDiscovery](https://projectdiscovery.io) makes [Nuclei](https://github.com/projectdiscovery/nuclei) and [naabu](https://github.com/projectdiscovery/naabu), and cvENGINE runs both. They also sell a hosted platform. This page compares the two honestly, feature by feature, and says where ProjectDiscovery is ahead.

**How this was compared.** cvENGINE's column comes from its own code and docs. ProjectDiscovery's column comes from its public pages as read on 2026-10-26 ([pricing](https://projectdiscovery.io/pricing), [asset discovery](https://docs.projectdiscovery.io/cloud/assets/overview), [scanning](https://docs.projectdiscovery.io/cloud/scanning/overview), [vulnerability management](https://projectdiscovery.io/vulnerability-management), [quick start](https://docs.projectdiscovery.io/quickstart)). Where a page says nothing, the table says "not stated", which is not proof the feature is missing. The "Edge" column marks who is ahead on that row.

## The short version

- **Choose cvENGINE** to run a free, self-hosted tool that tells you which of today's exploited CVEs are live on assets you own, with evidence, and keeps everything on your own server.
- **Choose ProjectDiscovery** for a managed platform with a pre-indexed asset dataset, cloud account discovery, internal scanning, SSO, Jira, support, and a vendor behind it.
- **Use both** if you like. cvENGINE already runs their open source tools.

## Cost, hosting, and trust

| Area | cvENGINE | ProjectDiscovery | Edge |
| --- | --- | --- | --- |
| Price | Free and open source (GPL-3.0), with no seat, asset, or usage limits beyond your hardware | A free tier with limits (one seat and a one-time allowance on Neo, a capped domain count on the cloud platform), $200 per seat per month pay as you go, and custom enterprise pricing | cvENGINE |
| Hosting | Self-hosted only, on one Docker Compose stack | Managed cloud, dedicated VPC, or on-prem (enterprise) | ProjectDiscovery |
| Your data | Stays on your server. Nothing is sent to the authors. | Managed service. It states SOC 2 Type II and zero data retention. | Different |
| AI models | Bring your own: Anthropic, OpenAI, OpenRouter, or a local Ollama or vLLM, on every install | Standard and frontier models. Bring your own key is enterprise only. | cvENGINE |
| Support | Community, through GitHub | Vendor support | ProjectDiscovery |
| Maturity | New: v1.2, written in days and tested far less | Years in production | ProjectDiscovery |

## Discovery

| Area | cvENGINE | ProjectDiscovery | Edge |
| --- | --- | --- | --- |
| Subdomains and assets | [bbot](https://github.com/blacklanternsecurity/bbot) in passive, standard, or deep mode, a certificate transparency watch, and a weekly deep sweep of every apex domain | A pre-indexed Chaos dataset for instant results, plus DNS brute forcing, permutations, and certificate transparency | ProjectDiscovery |
| Related assets | Whatever bbot finds from your domains | ASN mapping, Shodan, Censys, and FOFA data, subsidiaries, and associated domains | ProjectDiscovery |
| Cloud accounts | Not supported | AWS, Azure, and GCP through Cloudlist | ProjectDiscovery |
| Open ports | naabu by default (all 65,535 ports), a background full sweep, then nmap | naabu | Even |
| Service detail | nmap at version intensity 7 with 18 reviewed scripts: versions, CPEs, banners, SSH and TLS facts, database greetings, RDP and SMB facts | HTTP probing, technology fingerprinting, and certificate evaluation. Port and version depth not stated. | cvENGINE |
| Screenshots | Deep-mode screenshots, side-by-side diffs when a front page changes, and RDP login screens | Screenshots and visualization | Even |
| Exclusions | Per-organization host exclusions, private ranges off by default, and shared platform addresses never port-scanned | Exclusions by subdomain, IP, or wildcard | Even |
| Labels | Detection labels (such as a WAF), owner, criticality, and saved views | AI-generated and custom labels, with bulk labeling | ProjectDiscovery |

## Scanning and validation

| Area | cvENGINE | ProjectDiscovery | Edge |
| --- | --- | --- | --- |
| Template library | By default only templates that pass a read-only check (about half the community set at last count). An App Admin can switch on every installed template; denial-of-service templates stay excluded. | The full Nuclei library, stated as over 9,000 community templates | ProjectDiscovery |
| Custom templates | The AI drafts one when none exists. It never runs until a person approves it with reviewed fixtures. | Private custom checks and AI-assisted generation | Even |
| Protocols | HTTP, plus network service checks through nmap and the exposure checks | HTTP(S), TCP, DNS, SMB, and more | ProjectDiscovery |
| Extra scanners | wafw00f to name the firewall in front of a host, WPScan, a read-only node2shell check (off by default), unauthenticated-database checks (Redis, Memcached, PostgreSQL, MySQL, MongoDB, Elasticsearch, CouchDB), web route auth and sensitive-data checks, and email and DNS hygiene | Not stated | cvENGINE |
| Internal scanning | Possible only if you allow private ranges and the server can reach them. There is no tunnel or agent. | Internal scanning, with a tunnel (beta) | ProjectDiscovery |
| Authenticated testing | Not supported. Routes are checked anonymously. | Stated for Neo, with SSO and TOTP | ProjectDiscovery |
| Re-testing | Re-test on change, and **Validate now** on any CVE match | One-click retesting and regression monitoring | Even |
| Pentesting, code review, cloud posture | Not supported | Neo: autonomous app and API pentesting, PR review, cloud security, and mobile (beta) | ProjectDiscovery |

## Prioritization and triage

| Area | cvENGINE | ProjectDiscovery | Edge |
| --- | --- | --- | --- |
| Exploitation ranking | Fire, smoke, or ice from CISA KEV, ENISA EUVD, VulnCheck KEV, EPSS, Exploit-DB, Metasploit, and CVSS ([how it works](FIRE-SMOKE-ICE.md)) | Severity and a score. EPSS and KEV are not mentioned on the page read. | cvENGINE |
| Host score | A 0 to 100 score per host, with reasons | Not stated | cvENGINE |
| AI triage | Every finding is classified, with fixed rules so the model cannot dismiss hard evidence | Neo triages and validates | Even |
| Validation | Read-only reproduction, with the exact command recorded | Findings replay against the live target and arrive with proof | Even |
| Remediation | Statuses (open, in progress, fixed, accepted risk), notes, an assignee, comments, and an audit trail, set by people or agents | Triaging, Validated, Fixed, and Retesting states, an assignee, and a pull request with the fix and a regression test | ProjectDiscovery |
| Change tracking | A timeline of new hosts, ports, versions, technologies, certificates, and screenshots | Continuous monitoring. A change-diff feature is not described. | cvENGINE |

## Search, API, and teams

| Area | cvENGINE | ProjectDiscovery | Edge |
| --- | --- | --- | --- |
| Search | [Shodan-style filters](SEARCH.md) over your whole inventory | A search-like experience with filtering and grouping | cvENGINE |
| API and agents | REST API and an MCP server ([details](AGENT-API.md)) | REST APIs | Even |
| Access control | Organizations, projects, roles (admin, user, audit), TOTP two-step sign-in, an IP allowlist, and an audit log | Team enrollment, SSO (SAML and OIDC), and scoped runs | ProjectDiscovery |
| Notifications | Slack, Discord, Telegram, and Lark | Slack, Teams, email, and webhooks | Even |
| Ticketing | Not supported | Jira | ProjectDiscovery |
| Compliance | None | SOC 2 Type II stated | ProjectDiscovery |
| Bug bounty | A built-in workbench ([details](BUG-BOUNTY.md)) | Not stated | cvENGINE |

## Where cvENGINE is going to lose

If you need a vendor to call, a compliance report to hand an auditor, SSO for a large team, cloud account discovery, scans from inside the network, or a pentest agent, ProjectDiscovery is the better choice today. cvENGINE's bet is narrower: the most useful free answer to "of everything exploited this week, what do I have exposed?", running on your own hardware, built on the same open source tools. Corrections are welcome: open an issue if a row here is out of date.
