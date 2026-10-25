# Changelog

cvENGINE is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x. The history of reNgine up to the fork is in [its changelog](https://github.com/yogeshojha/rengine/blob/master/CHANGELOG.md).

## Unreleased

Nothing yet.

## v1.0 (2026-10-25)

The most advanced external attack surface assessment you can get for free. cvENGINE continuously discovers your internet-facing assets, fingerprints their services, and tells you which of today's CVEs are actually exploitable on them, with evidence.

### Highlights

- **Continuous discovery.** Subdomains, certificates, IPs, and open ports with [bbot](https://github.com/blacklanternsecurity/bbot), scheduled re-discovery, and a change log.
- **Service and OS fingerprinting.** One host inventory built from [nmap](https://github.com/nmap/nmap), optional [naabu](https://github.com/projectdiscovery/naabu), and bbot.
- **Fire, smoke, and ice.** Every CVE rated by real-world exploitation from CISA KEV, ENISA EUVD, VulnCheck KEV, EPSS, Exploit-DB, and Metasploit, so hosts are matched against historically exploited CVEs, not just the last two weeks.
- **Evidence-based validation.** Each finding is reproduced with a read-only check (a vetted [nuclei](https://github.com/projectdiscovery/nuclei) template, nmap, an HTTP probe, or a database banner). The AI triages it and drafts a template when none exists; a person reviews drafts before they run.
- **One findings view.** CVE matches, scanner findings, and email and DNS hygiene together, hottest first.
- **Exposure checks.** Unauthenticated Redis, PostgreSQL, Elasticsearch, Memcached, and CouchDB, plus a full email-security review (SPF, DKIM, DMARC, MTA-STS, and more).
- **Bug bounty workbench.** Public program scope, a vulnerability rating per finding, and report drafts ([BUG-BOUNTY.md](docs/BUG-BOUNTY.md)).
- **Built for teams and agents.** Organizations and projects with data isolation and roles, a REST API and an MCP server, and Shodan-style host search.
- **Operations.** A pause-all control, scheduler and worker health, an activity and AI-cost log, two-step sign-in, an IP allowlist, an audit log, and automatic deployment of new releases.

### Platform

Python 3.14, Django 5.2 LTS, PostgreSQL 18, nmap 7.992, Go 1.27, and Ubuntu 26.04 LTS. GPL-3.0. See [docs/](docs/), and [docs/UPGRADE.md](docs/UPGRADE.md) to move an older install.

### Security

Hardened against prompt injection and server-side request forgery, with tenant-isolated media, encrypted secrets, bounded scan and probe time, and a static safety gate on AI-generated templates.
