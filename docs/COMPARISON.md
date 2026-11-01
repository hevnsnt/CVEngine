# cvENGINE and ProjectDiscovery

[ProjectDiscovery](https://projectdiscovery.io) makes [Nuclei](https://github.com/projectdiscovery/nuclei) and [naabu](https://github.com/projectdiscovery/naabu), and cvENGINE runs both. They also sell a hosted platform. This page compares the two honestly, feature by feature, and says where ProjectDiscovery is ahead.

**How this was compared.** cvENGINE's column comes from its own code and docs. ProjectDiscovery's column comes from its public pages as read on 2026-10-26 ([pricing](https://projectdiscovery.io/pricing), [asset discovery](https://docs.projectdiscovery.io/cloud/assets/overview), [scanning](https://docs.projectdiscovery.io/cloud/scanning/overview), [vulnerability management](https://projectdiscovery.io/vulnerability-management), [quick start](https://docs.projectdiscovery.io/quickstart)). Where a page says nothing, the table says "not stated", which is not proof the feature is missing. The "Edge" column marks who is ahead on that row.

## The short version

- **Choose cvENGINE** to run a free, self-hosted tool that tells you which of today's exploited CVEs are live on assets you own, with evidence, and keeps everything on your own server. Scanner agents you run on your own networks (Sentinels) cover internal networks too.
- **Choose ProjectDiscovery** for a managed platform with a pre-indexed asset dataset, cloud account discovery, a managed route into internal networks, SSO, Jira, support, and a vendor behind it.
- **Use both** if you like. cvENGINE already runs their open source tools.

## Cost, hosting, and trust

| Area | cvENGINE | ProjectDiscovery | Edge |
| --- | --- | --- | --- |
| Price | Free and open source (GPL-3.0), with no seat, asset, or usage limits beyond your hardware | A free tier with limits (one seat and a one-time allowance on Neo, a capped domain count on the cloud platform), $200 per seat per month pay as you go, and custom enterprise pricing | cvENGINE |
| Hosting | Self-hosted only: one Docker Compose stack, plus optional [Sentinels](ARCHITECTURE.md#sentinels) (a small Docker Compose client you run on another network) | Managed cloud, dedicated VPC, or on-prem (enterprise) | ProjectDiscovery |
| Your data | Stays on your server. Nothing is sent to the authors. | Managed service. It states SOC 2 Type II and zero data retention. | Different |
| AI models | Bring your own: Anthropic, OpenAI, OpenRouter, or a local Ollama, vLLM or LM Studio, on every install | Standard and frontier models. Bring your own key is enterprise only. | cvENGINE |
| Support | Community, through GitHub | Vendor support | ProjectDiscovery |
| Maturity | New: v1.3, written in days and tested far less | Years in production | ProjectDiscovery |

## Discovery

| Area | cvENGINE | ProjectDiscovery | Edge |
| --- | --- | --- | --- |
| Subdomains and assets | [bbot](https://github.com/blacklanternsecurity/bbot) in passive, standard, or deep mode, a certificate transparency watch, and a weekly deep sweep of every apex domain | A pre-indexed Chaos dataset for instant results, plus DNS brute forcing, permutations, and certificate transparency | ProjectDiscovery |
| Other sites on an address | The project's own known names (hosts, certificate names, certificate transparency) are asked once a week at each web address with a Host header, and a distinct site is added as an alias of the host or a host of its own, in scope only. No name guessing. | Virtual host discovery is not described on the pages read | cvENGINE |
| Applications under subdirectories | About 40 well-known mount paths (Jira, Grafana, phpMyAdmin, OWA and others) asked with one GET each, read into a product and version that CVE matching uses. Not a content wordlist. | Technology fingerprinting and directory brute forcing are described; the depth is not stated | Different |
| Third-party suppliers | A per-project list of critical vendors, kept apart from owned assets: a host card per supplier domain (headers, certificate, technology stack with versions), a technology search across them, and weekly passive posture checks (TLS, email authentication, headers, well-known login pages). No scanning of them | Not compared here (not checked against their public pages) | Not compared |
| Related assets | Whatever bbot finds from your domains, plus devices imported from a [Tailscale](TAILSCALE.md) tailnet and from a runZero inventory (matching addresses are enriched with runZero's facts, and new ones are imported only when you turn it on, and only inside scope you already own) | ASN mapping, Shodan, Censys, and FOFA data, subsidiaries, and associated domains | ProjectDiscovery |
| Cloud accounts | Not supported. A Tailscale tailnet or a runZero inventory can be attached, which is not cloud account discovery. | AWS, Azure, and GCP through Cloudlist | ProjectDiscovery |
| Open ports | naabu by default (all 65,535 ports), a background full sweep, then nmap | naabu | Even |
| UDP exposure | A slow background scan of 18 UDP ports that matter (DNS, NTP, SNMP, IKE, IPMI, SSDP, memcached and the like), once a week per address, with findings for memcached, public SNMP, NTP control queries, SSDP and IPMI; a port counts only when it answered | naabu scans UDP only when asked, and nuclei has network templates for individual UDP services. No scheduled UDP sweep or stored UDP inventory stated. | cvENGINE |
| Service detail | nmap at version intensity 7 with 18 reviewed scripts: versions, CPEs, banners, SSH and TLS facts, database greetings, RDP and SMB facts | HTTP probing, technology fingerprinting, and certificate evaluation. Port and version depth not stated. | cvENGINE |
| Screenshots | Screenshots from standard and deep discovery, side-by-side diffs when a front page changes, and RDP login screens | Screenshots and visualization | Even |
| Exclusions | Per-organization host exclusions, private ranges off by default, and shared platform addresses never port-scanned | Exclusions by subdomain, IP, or wildcard | Even |
| Labels | Detection labels (such as a WAF), owner, criticality, and saved views | AI-generated and custom labels, with bulk labeling | ProjectDiscovery |

## Scanning and validation

| Area | cvENGINE | ProjectDiscovery | Edge |
| --- | --- | --- | --- |
| Template library | The whole installed Nuclei library by default (denial-of-service templates stay excluded). An App Admin can limit scans to templates that pass a read-only check, about half the community set at last count. | The full Nuclei library, stated as over 9,000 community templates | Even |
| Custom templates | The AI drafts one when none exists. It never runs until a person approves it with reviewed fixtures. | Private custom checks and AI-assisted generation | Even |
| Protocols | HTTP, plus network service checks through nmap and the exposure checks, and, with the optional off-by-default [OpenVAS (Greenbone) add-on](OPENVAS.md), its network-level vulnerability tests for the hosts you list (slow, version-based results are not treated as confirmed) | HTTP(S), TCP, DNS, SMB, and more | ProjectDiscovery |
| Extra scanners | wafw00f to name the firewall in front of a host, WPScan, testssl.sh for the TLS configuration and the named TLS vulnerabilities, cloud storage bucket exposure checks (public and dangling S3, GCS and Azure Blob storage), a read-only node2shell check (off by default), unauthenticated-database checks (Redis, Memcached, PostgreSQL, MySQL, MongoDB, Elasticsearch, CouchDB), web route auth and sensitive-data checks, and email and DNS hygiene | Not stated | cvENGINE |
| Internal scanning | A project declares a private network internal, and only a [Sentinel](ARCHITECTURE.md#sentinels) you deploy inside it scans it (this server never does, and there is no fallback). A Sentinel sweeps the range for live hosts, then runs nmap, a TLS audit, two Nuclei passes and WPScan, and OpenVAS where that is switched on. It is a client you run and keep updated, not a managed tunnel, and the server-side checks (route checks, probes, hygiene, database exposure, screenshots) do not run on internal hosts. | Internal scanning, with a tunnel (beta) | Different |
| Distributed scanning | Sentinels are not only for internal networks: nmap, naabu, Nuclei, testssl.sh, UDP, WPScan and OpenVAS work is handed to a Sentinel scoped to a project, an organization, or the whole instance, and runs on this server when none is live. Discovery (bbot), the cloud storage checks, and the virtual host and subdirectory sweeps always run on this server. | Not compared here (not checked against their public pages) | Not compared |
| Host-reported inventory | Linux, macOS and Windows scripts report a host's operating system build, packages and patches, so local-only CVEs and backported fixes become decidable ([details](HOST-INVENTORY.md)) | Not compared here (not checked against their public pages) | Not compared |
| Authenticated testing | Supported with headers and a cookie you store for a target (an API token or a session cookie of a test account; encrypted, write-only, host- and origin-scoped, with an expiry). Nuclei and the web route check then also see the signed-in application. Nothing logs in for you: no SSO, TOTP or login flow. | Stated for Neo, with SSO and TOTP | ProjectDiscovery |
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
| Search | [Shodan-style filters](SEARCH.md) over your whole inventory, and saved searches that alert on new matches | A search-like experience with filtering and grouping | cvENGINE |
| API and agents | REST API and an MCP server ([details](AGENT-API.md)) | REST APIs | Even |
| Access control | Organizations, projects, roles (admin, user, audit), TOTP two-step sign-in, an IP allowlist, and an audit log | Team enrollment, SSO (SAML and OIDC), and scoped runs | ProjectDiscovery |
| Notifications | Slack, Discord, Telegram, and Lark | Slack, Teams, email, and webhooks | Even |
| Ticketing | Not supported | Jira | ProjectDiscovery |
| Reports | A one-click PDF of a project or a host (PDF only): summary by fire, smoke and ice, hosts, one section per finding with its evidence, the exact check and fix status, TLS and email hygiene, and the method and its limits ([details](FRONTEND.md#pdf-reports)). Not a compliance or audit-framework report. | Per-scan export as JSONL, CSV, and PDF, from a [January 2024 changelog entry](https://projectdiscovery.featurebase.app/en/changelog/v056-export-early-templates-and-new-teams-tier). The current pricing and docs pages read for this page do not describe reports, so what a report holds today is not verified. | Not compared |
| Compliance | None | SOC 2 Type II stated | ProjectDiscovery |
| Bug bounty | A built-in workbench ([details](BUG-BOUNTY.md)) | Not stated | cvENGINE |

## Where cvENGINE is going to lose

If you need a vendor to call, a compliance report to hand an auditor, SSO for a large team, cloud account discovery, a managed route into private networks (cvENGINE's Sentinels scan inside a network, but you run and update them), or a pentest agent, ProjectDiscovery is the better choice today. cvENGINE's bet is narrower: the most useful free answer to "of everything exploited this week, what do I have exposed?", running on your own hardware, built on the same open source tools. Corrections are welcome: open an issue if a row here is out of date.
