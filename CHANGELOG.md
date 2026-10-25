# Changelog

CVEngine is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x, taken in November 2025. The history of reNgine up to that point is in [its changelog](https://github.com/yogeshojha/rengine/blob/master/CHANGELOG.md).

## Unreleased

### Security

- **Two-step sign-in could be skipped at `/admin/login/`.** Django's own admin login signed a staff user in with the password alone and made a normal session for the whole app. `/admin/login/` now only forwards to the app's `/login/`, which enforces the second step. Found by the API, tenancy and front-end review.

### Changed

- **Every CVE match is validated automatically.** Before, only fire and smoke matches were queued for AI validation and the rest waited for someone to press Validate now. Now a match of any confidence or score is queued by itself, hottest first (fire, smoke, then ice at the lowest priority, using the capacity the hot ones leave), except one the AI ruled out or the distribution patched. Ice stops at five active jobs per project so it cannot crowd out hot findings, and the daily validation caps still apply. `CVENGINE_AUTO_VALIDATE_ALL_MATCHES=0` restores fire and smoke only.
- **More nuclei templates run.** Installed templates that follow redirects on the same host (`host-redirects`, at most three hops) now pass the read-only policy, about 1,250 more (6,531 of 13,903 in the current community set, up from 5,280), among them the technology detection template, so hosts get fingerprinted again. A template that merely recognizes an interactsh server by its header is no longer taken for an out-of-band check. Redirects to other hosts stay refused, and AI-written templates still follow none.

### Fixed

- **AI-written templates survived no update.** Their directory was not on a Docker volume, so each deploy deleted them and they had to be regenerated and reviewed again. It is now the `generated_templates` volume in all three services that share it, and a worker restores any validated template whose file is missing from the database copy, through the same safety check, when it starts.
- **`scripts/uninstall.sh` removed anything with `rengine` in its name,** including another reNgine install on the host. It now removes only this install's Docker Compose project, selected by its exact label, and lists what it will remove before asking.
- **Proxy documentation.** It told operators to set `CVENGINE_TRUSTED_PROXIES` to their proxy's network, which replaces the Docker default and makes the IP allowlist and abuse guard see the Docker gateway for every request. The docs now say to leave the default or add to it.
- **Search.** A bare word and `tech:` find a host wherever its software was seen (web server and `X-Powered-By` headers, cookie names, banners, NSE output, route fingerprints, port product and version), not only in the technology list, and `banner:` searches service banners. `php` now finds every host running PHP.
- **Test suite.** `tests.test_nmap` (a placeholder with fixtures that never existed) now tests the vulners and vulscan parsers, and `tests.test_hard_lockout` calls the current lockout helpers.

## v1.0 (2026-10-25)

CVEngine is an AI-first external attack surface scanner: it continuously
discovers your internet-facing assets, fingerprints their services, and tells
you which of today's CVEs are actually exploitable on them, with evidence.

### Highlights

- **Continuous attack surface discovery**: subdomains, certificates, IPs and
  open ports, with scheduled re-discovery and change tracking.
- **Service and OS fingerprinting**: one consistent host inventory built from
  nmap, naabu and bbot.
- **Exploitability-ranked CVEs (fire / smoke / ice)**: every CVE scored by
  real-world exploitation, fed by CISA KEV, ENISA EUVD, EPSS, Exploit-DB and
  Metasploit so hosts are matched against historically exploited CVEs, not just
  the last two weeks.
- **Evidence-based validation**: each finding is reproduced with a read-only
  check (a vetted nuclei template, nmap, an HTTP probe, a database banner); the
  AI triages it and drafts a template when none exists. No raw guessing.
- **One findings view**: CVE matches, scanner findings and email/DNS hygiene
  together, hottest first.
- **Exposure checks**: unauthenticated Redis, PostgreSQL, Elasticsearch,
  Memcached and CouchDB, plus a full email-security review (SPF, DKIM, DMARC,
  MTA-STS and more).
- **Built for teams and agents**: organizations and projects with data
  isolation and roles, a REST API and an MCP server, and Shodan-style host
  search.
- **Operations**: pause-all control, scheduler and worker health, an activity
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
