# Changelog

cvENGINE is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x. The history of reNgine up to the fork is in [its changelog](https://github.com/yogeshojha/rengine/blob/master/CHANGELOG.md).

## v1.0.1 (2026-10-25)

A security patch for v1.0. Update with `make up` or the in-app updater.

### Security

- **Two-step sign-in could be skipped at `/admin/login/`.** Django's own admin login signed a staff user in with the password alone and made a normal session for the whole app. `/admin/login/` now only forwards to the app's `/login/`, which enforces the second step.

### Fixed

- **AI-written templates survived no update.** Their directory was not on a Docker volume, so each deploy deleted them and they had to be regenerated and reviewed again. It is now the `generated_templates` volume in all three services that share it, and a worker restores any validated template whose file is missing from the database copy, through the same safety check, when it starts.
- **`scripts/uninstall.sh` removed anything with `rengine` in its name,** including another reNgine install on the host. It now removes only this install's Docker Compose project, selected by its exact label, and lists what it will remove before asking.
- **Proxy documentation.** It told operators to set `CVENGINE_TRUSTED_PROXIES` to their proxy's network, which replaces the Docker default and makes the IP allowlist and abuse guard see the Docker gateway for every request. The docs now say to leave the default or add to it.

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
