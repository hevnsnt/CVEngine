# Changelog

CVEngine is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x, taken in November 2025. The history of reNgine up to that point is in [its changelog](https://github.com/yogeshojha/rengine/blob/master/CHANGELOG.md).

CVEngine has not made a numbered release yet. Everything below is on `master`.

## Unreleased

### Added

- **One Findings list.** The Findings page (formerly Scanner findings) lists CVE matches, scanner findings and hygiene findings together, hottest first, filtered by type, severity and status (actionable by default). Its heat follows the host card. The API and MCP offer the same list (`GET projects/{slug}/findings`, `list_findings`). The CVE matches and Hygiene pages stay for focused work. See [docs/FRONTEND.md](docs/FRONTEND.md).
- **Weekly log maintenance.** AI activity, AI call and AI usage rows past their retention (30, 90 and 400 days) are archived to a tar.gz on the scan results volume, then deleted. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md).
- **Stuck-job expiry.** Host assessments and validation jobs that a restarted worker left queued or running are expired every 15 minutes, freeing their slots.
- **MailFail email checks.** The hygiene scan now runs the email-security checks of [MailFail](https://github.com/ACK-J/MailFail) by Black Hills Information Security (domain takeover of SPF includes and DMARC report addresses, DMARC report authorization, MTA-STS, TLS reporting, DANE, DNSSEC strength, Microsoft 365 Direct Send, BIMI, ARC, ADSP, MailChannels and record-format checks), credited in the AI activity feed while they run. See [docs/PIPELINE.md](docs/PIPELINE.md).
- **Accuracy and security hardening.** CVE matching by product rather than vendor (aliases, CPE first, no-bound ranges are unknown, epochs and pre-releases), stale matches closed, one scan's copy of each host, distro backports labelled "patched by distro" from a daily Debian and OSV sync, findings that show template-test hits and dedupe on what and where, per-IP ports with closed ports recorded, an optional naabu full-port stage, a stricter AI template gate validated before it is saved, scannable-host filtering on every stored host list, encrypted secret columns, bbot keys in a private temporary file, lockout counters in shared Redis, one notification per auto-fire run. Details in [docs/PIPELINE.md](docs/PIPELINE.md) and [docs/CONFIGURATION.md](docs/CONFIGURATION.md).
- **CVE intelligence.** A [cve.now](https://cve.now) feed sync, fire, smoke, and ice threat tiers, and matching of CVEs to the host inventory by product and version.
- **AI.** A model-agnostic layer for Anthropic, OpenAI, OpenRouter, Ollama, and vLLM. It gives a verdict on each CVE match, picks nuclei templates by each host's technologies, and writes and validates a nuclei template when none exists for a CVE.
- **Auto-fire.** An optional step that tests confirmed fire and smoke matches on their hosts.
- **Discovery.** bbot for subdomain discovery in standard (default), deep, and passive modes, a daily sweep that queues a deep discovery for each apex domain that has had none in 7 days, a certificate transparency watch, and gowitness screenshots.
- **Inventory.** One nmap pass per IP (`-O -sV --top-ports 1000`) that fills the host, port, service, product, and version records. A slow background task sweeps all TCP ports of one in-scope IP at a time, oldest sweep first, and investigates new ports; it replaces `CVENGINE_NMAP_FULL`.
- **Exposure checks.** Read-only checks for Redis, Memcached, PostgreSQL, Elasticsearch, and CouchDB servers that accept connections without a login.
- **Hygiene.** TLS certificate, SPF, DKIM, DMARC, and CAA checks.
- **Scheduling.** One pipeline per target, one scanner run per host with a re-scan window, three worker types, and a memory-aware queue with a watchdog for heavy jobs.
- **Scan control.** A first in, first out queue with queue positions, stop for one scan or all running and queued scans, and a re-scan of chosen hosts without a new bbot run.
- **Search.** Shodan-style host search (`tech:`, `port:`, `ip:`, `cve:`, `sev:`, and more) in the UI, the API, and MCP.
- **Targets.** Domains, IPs, CIDR blocks, ranges, and URLs, bulk add with `##Organization` and `#Project` headers, and bulk delete.
- **Multi-tenancy.** Organizations and projects, the roles admin, user, audit, and pentester, and project isolation at the data layer. An **All projects** option in the project switcher (the reserved slug `_all`, also accepted by the list endpoints of the API and MCP) shows one combined, read-only list across every project the user can see, each row tagged with its project.
- **Access control.** Two-step sign-in with TOTP and recovery codes, a perimeter IP allowlist, an input guard that bans repeat offenders, and an audit log.
- **Agent interface.** A REST API at `/api/v1/` and an MCP server at `/mcp/`, with API tokens that follow user roles and a remediation workflow.
- **Updates.** A GitHub update check with administrator approval and a host script that applies the update.
- **Administration.** First-run wizard, an Administration page where organization admins manage their members and projects, API keys for OSINT services (instance-wide, and per organization or project), and a factory reset.
- **AI review every three hours.** The AI picks the due triage, validation, discovery, or host assessment for each project, and tunes scanner concurrency within bounds you set.
- **Faster validation.** A dedicated validation worker checks fire and smoke findings first, **Validate now** runs an AI-planned check on any CVE match, and AI-drafted templates run only after a reviewed positive test.
- **Host control.** Rescan a single host with a full assessment, archive or pin hosts, and let daily rediscovery bring archived hosts back when they reappear.
- **Coverage.** Paced deep nuclei runs over the whole inventory each week, and CVE details refresh when the feed updates them.
- **Operations.** Pause all scanning with one switch, scheduler and worker health, an activity and error log for administrators, AI model usage with cost estimates, and an update script that drains running work before restarting.
- **User interface.** A new mobile-first interface with a live dashboard, an attack-surface map, a live asset graph, a hosts page, and a command palette.

### Changed

- **Accepted host names.** Only `DOMAIN_NAME`, loopback and `CVENGINE_ALLOWED_HOSTS` are accepted; a server reached by another name or by IP answers 400 until that name is listed. `manage.py check` warns (`cvengine.W001`) when `DOMAIN_NAME` is unset or a placeholder. See [docs/UPGRADE.md](docs/UPGRADE.md#accepted-host-names).
- **Pause scope.** Pausing scanning holds work that touches targets or spends AI budget, and lets the CVE feed, notifications, pruning and the update check run. A validation run stops before its next check.
- **AI budget and triage.** AI-written nuclei checks are limited to one attempt per CVE per week and 10 a day. A CVE feed refresh or a new decision scheme re-reviews a finding without discarding its verdict or validation proof.
- **Fairness and resilience.** Re-tests serve projects in turn and hottest hosts first. The global host-assessment caps count every project. The background full-port sweep backs off from IPs that keep failing. The three-hour AI review no longer skips a cycle under queue latency.
- **Archives.** A host a person archived stays archived until restored; rediscovery and scans no longer lift it. A failed rediscovery enqueue puts the archive back.
- **Errors.** Stored and displayed job errors carry a diagnostic id instead of exception text. Nuclei failures say why, and the template policy reports what it excludes, including the technology detection template. Impossible dates in filters return 400.
- **Dashboard.** The Attack surface map shows the 100 highest-scoring hosts.

- Python 3.14, Django 5.2 LTS, PostgreSQL 18, Go 1.27, nmap 7.992, and Ubuntu 26.04 LTS. See [docs/UPGRADE.md](docs/UPGRADE.md) for moving an older install.
- Database indexes on the tables that grow with every scan, and batched writes in the feed sync and scanner passes.
- Branding and installer are CVEngine's.
- `.env` is no longer tracked. Copy `.env.example` to `.env`.
- **My account.** Two-step sign-in is set up and turned off on My account (QR code, confirmation code and recovery codes in place), so the separate two-step page and its menu item are gone; `/mfa/setup/` and `/mfa/disable/` forward to My account. The page lays out in two independent columns.
- **About page.** A new About page in the account menu credits FieldCraft Cyber, Bill Swearingen, reNgine and the scanners and libraries CVEngine uses, and links to the GitHub repository.
- **Scope of tenant domains.** The weekly apex sweep no longer promotes a tenant on a shared provider domain (`acme.jfrog.com`, `acme.atlassian.net`) to the provider's apex (`jfrog.com`, `atlassian.net`) and deep-scans all of it. A curated shared-domain list marks such targets host scoped: bbot runs with `--strict-scope` for them, the sweep skips them, and certificate transparency never queries a bare provider domain. Each target has a scope mode (`auto`, `host`, `parent`) in the Targets page, the API and MCP. On migrate, provider apexes that the sweep created earlier are deleted (with their scans and findings), and a shared domain you added yourself is kept and switched to `host`. See [docs/PIPELINE.md](docs/PIPELINE.md).

### Removed

- The reNgine web interface. Old addresses forward to the matching CVEngine page.
- amass, geckodriver, Selenium, and Firefox. bbot covers subdomain discovery.
- The OpenAI and LangChain libraries, plotly, and `pycvesearch`.

### Security

- **Detection gaps found on a live host.** A Netlify site tagged `datocms` matched Craft CMS advisories, and neither PHP2Shell CVE (CVE-2026-109618, CVE-2026-109619) was in the scanner. Name matching now requires whole words (`cms` is not in `datocms`, `php` is not `phpMyAdmin`); an advisory that lists only fixed branches leaves older branches *unknown*, not cleared; the feed gets an hourly coverage task, `sync_cve_now --backfill-days/--tech/--ids`, and retry with backoff; and the host record shows the web server, technologies with versions and categories, hosting, and shared-IP flags. nmap and the full-port sweep no longer scan addresses that belong to a shared platform.
- Closed a command injection hole and a cross-organization account takeover.
- Tenant-scoped media, a filter for internal addresses in outbound requests, and shell commands replaced with contained file operations.
- Hardened the AI features against prompt injection, and added a static safety check for generated templates.
- Source audit repairs: project write authority and the requester's current authorization are rechecked at legacy API and queued validation boundaries; MFA state is bound to current credentials; probes and TLS checks connect only to the addresses they vetted; PDF reports fetch no external resources; update state moved out of paths the containers can write; MCP requests, batches and responses are bounded, including JSON nesting depth.
- `/api/listIps/` and `/api/listTargets/` are scoped to the caller's projects on every request; changing your password revokes your API tokens; the HackerOne report route needs the bug bounty permission; discovery refuses a name that resolves to a loopback, link-local or internal address; a probe of a slow host stops after 20 seconds; the sensitive-data scan no longer spends tens of seconds on a hostile response body; `install.sh` and `make certs` / `make username` refuse to run while `.env` still holds the example `change-me` passwords.
