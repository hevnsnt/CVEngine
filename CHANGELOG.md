# Changelog

CVEngine is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x, taken in November 2025. The history of reNgine up to that point is in [its changelog](https://github.com/yogeshojha/rengine/blob/master/CHANGELOG.md).

## Unreleased

Nothing yet.

## v1.0 (2026-10-25)

CVEngine is an AI-first external attack surface scanner: it continuously
discovers your internet-facing assets, fingerprints their services, and tells
you which of today's CVEs are actually exploitable on them — with evidence.

### Highlights

- **Continuous attack surface discovery** — subdomains, certificates, IPs and
  open ports, with scheduled re-discovery and change tracking.
- **Service and OS fingerprinting** — one consistent host inventory built from
  nmap, naabu and bbot.
- **Exploitability-ranked CVEs (fire / smoke / ice)** — every CVE scored by
  real-world exploitation, fed by CISA KEV, ENISA EUVD, EPSS, Exploit-DB and
  Metasploit so hosts are matched against historically exploited CVEs, not just
  the last two weeks.
- **Evidence-based validation** — each finding is reproduced with a read-only
  check (a vetted nuclei template, nmap, an HTTP probe, a database banner); the
  AI triages it and drafts a template when none exists. No raw guessing.
- **One findings view** — CVE matches, scanner findings and email/DNS hygiene
  together, hottest first.
- **Exposure checks** — unauthenticated Redis, PostgreSQL, Elasticsearch,
  Memcached and CouchDB, plus a full email-security review (SPF, DKIM, DMARC,
  MTA-STS and more).
- **Built for teams and agents** — organizations and projects with data
  isolation and roles, a REST API and an MCP server, and Shodan-style host
  search.
- **Operations** — pause-all control, scheduler and worker health, an activity
  and AI-cost log, two-step sign-in, an IP allowlist and an audit log.

### Platform

Python 3.14, Django 5.2 LTS, PostgreSQL 18, nmap 7.9, Go 1.27 and Ubuntu 26.04
LTS. GPL-3.0; a fork of reNgine 2.x. See [docs/](docs/), and
[docs/UPGRADE.md](docs/UPGRADE.md) to move an older install.

### Security

Hardened against prompt injection and server-side request forgery, with
tenant-isolated media, encrypted secrets, bounded scan and probe time, and a
static safety gate on AI-generated templates.

Also includes an optional bug-bounty workbench.
