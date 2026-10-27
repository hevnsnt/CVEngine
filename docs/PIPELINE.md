# Pipeline

Add a target and cvENGINE runs one pipeline for it. Stages run in order and each records its own result, so you can see exactly what was covered. If discovery fails, the scan fails. If a later stage fails, that stage is named in the scan's error and the scan still completes, so the hosts it found stay in the inventory.

## Targets

A target is a domain, an IP address, a CIDR range (`10.0.0.0/24`), a dashed range (`192.168.1.1-192.168.1.20`), or a URL, which is reduced to its host. Every host is validated before it is stored. Targets queue first in, first out.

## Stages

1. **Discovery.** [bbot](https://github.com/blacklanternsecurity/bbot) finds domains, subdomains, and IPs and streams them into the inventory as it runs. *Standard* mode, the default, enumerates subdomains and fingerprints web hosts with safe modules. *Deep* mode runs everything bbot has, including brute forcing, spidering, and [gowitness](https://github.com/sensepost/gowitness) screenshots, and takes hours. *Passive* keeps discovery to public sources (later stages still connect to the hosts it finds). A bare IP skips bbot and gets a reverse-DNS lookup and a read of its certificate.
2. **Inventory.** [nmap](https://nmap.org) fingerprints each IP once per window (`-sV -O`) on the top 1,000 ports plus about 40 high-risk ones that nmap's ranking leaves out, such as Redis, MongoDB, the Docker and Kubernetes APIs, and etcd. It records ports, services, products, versions, CPEs, the distribution read from the banner, and the OS. Only open ports are correlated, and a port that closes is marked closed. By default, [naabu](https://github.com/projectdiscovery/naabu) finds every open port of each address first (a full 65,535-port SYN sweep at a polite rate), and nmap fingerprints just those instead of guessing from its own top-1,000 list; `CVENGINE_NAABU=0` turns this off and falls back to nmap's own top-1,000 guess alone. Its scripts also read banners and SSH, TLS, HTTP, SMB, and RDP details, plus each database's own pre-authentication greeting (MySQL, Microsoft SQL Server, MongoDB, Redis, Memcached, and CouchDB), which fills in a version or product nmap's own probe missed. They name the Windows build, computer, and domain from RDP, SMB, and Microsoft SQL Server's own NTLM negotiation, and they raise two findings: an FTP server that accepts anonymous sign-in (with its listing as evidence) and an RDP server that does not require Network Level Authentication.
3. **RDP screenshot.** A server the inventory stage showed accepts a connection without Network Level Authentication gets one pre-authentication login-screen capture, with no credentials sent, stored and read by the AI model for a signed-in account (see [Configuration](CONFIGURATION.md#settings-in-the-app)). A server that requires NLA is never attempted.
4. **Exposure checks.** One connection with no credentials to Redis, Memcached, PostgreSQL, MySQL, MongoDB, Elasticsearch, and CouchDB ports (an empty password for the default `postgres` and `root` accounts, never a password list). A server that answers is reported as a critical finding.
5. **nuclei, technology pass.** [nuclei](https://github.com/projectdiscovery/nuclei) HTTP and technology templates fingerprint each host.
6. **Web route checks.** For each web host, cvENGINE sends one plain anonymous GET to a handful of common routes (`/`, `/login`, `/admin`, `/api`, and paths bbot found) and labels each `open`, `login`, `session_required`, `sso`, or `redirect`. The response is scanned in memory for sensitive data such as cloud keys, personal data, and internal identifiers. Only the type, a count, and a masked sample are stored. The page's headers, generator tag, and script names, plus the comment banners of up to four scripts the host serves itself, name the technologies and libraries it runs (jQuery, Bootstrap, AngularJS, and others) with versions, so an old library is correlated like any other technology.
7. **WAF fingerprint.** On by default (`CVENGINE_WAFW00F=0` turns it off). [wafw00f](https://github.com/EnableSecurity/wafw00f) names the web application firewall in front of each web host with a few requests, and the product is stored as a technology of the host (a product, never a version). A generic block that names no product, and a host with nothing in front of it, store nothing.
7. **WPScan.** Hosts the earlier stages fingerprinted as WordPress are scanned with [WPScan](https://wpscan.com/) (see [Configuration](CONFIGURATION.md#settings-in-the-app)).
8. **node2shell.** Off by default (`CVENGINE_NODE2SHELL=1` turns it on). Hosts fingerprinted as Node.js (or a framework on it), Bun or Envoy are checked for CVE-2026-111497 (`CVENGINE_NODE2SHELL_SCOPE=all` checks every web host) with [Assetnote's own read-only detector](https://github.com/assetnote/node2shell-scanner) (see [Configuration](CONFIGURATION.md#settings-in-the-app)).
9. **CVE correlation.** The inventory is matched against the CVE store.
10. **nuclei, AI-targeted pass.** Your AI model sees the technology names found on each host and picks nuclei tags from those the installed templates use. A built-in technology map always adds its tags. Hosts with the same choice are scanned together, and each host's fire and smoke CVE matches get a template test.
11. **Triage, validation, and changes.** See below.

The daily hygiene task also asks the Internet Archive, once a week per target, for the URLs it saved. A `.php` page or a `/wp-content/` path says a host ran PHP or WordPress at some point. That is kept as historical evidence only: search finds the host and labels it *seen in web archive*, and it is never treated as a current technology.

**Hygiene** runs as its own task when the scan finishes: TLS certificates (expiry, trust chain, hostname, self-signed, legacy protocols), SPF, DKIM, DMARC, and CAA, plus the checks of [MailFail](https://github.com/ACK-J/MailFail) re-implemented server side: records receivers ignore, report addresses on domains anyone can register, unauthorized DMARC reports, weak DKIM and ARC keys, Microsoft 365 Direct Send exposure, MTA-STS, TLS reporting, DANE, DNSSEC, BIMI, and MailChannels lockdown. None sends mail. `CVENGINE_HYGIENE_RDAP=0` turns off the registry lookups.

Every nuclei run uses a snapshot of the installed templates that passed read-only and destination checks: plain GET, HEAD or OPTIONS requests to the scanned host only, no payloads, bodies, code or out-of-band (interactsh) checks. A template may follow redirects on the same host, up to three (nuclei's `host-redirects`, which the technology detection template uses); one that follows redirects to other hosts is left out. The AI-written templates may not follow redirects at all.

### runZero between scans

A project with a runZero token is also synced from [runZero](CONFIGURATION.md#runzero), outside any scan. The sync stores runZero's OS, hardware, tags and CVE reports on the addresses cvENGINE already holds and, if the project turned import on, adds runZero addresses it does not know as targets through the Add targets path (exclusions, private-range policy and organization uniqueness included). runZero's CVE reports only raise the confidence of a match this pipeline already made; they never create or confirm one.

### Inventory details

- **Port discovery.** By default [naabu](https://github.com/projectdiscovery/naabu) sweeps all 65,535 TCP ports of each address (SYN, 1,000 packets a second) and nmap fingerprints only the open ports it found plus ports already known open. If naabu is off (`CVENGINE_NAABU=0`), missing, fails, or sees more than 500 open ports on one address, nmap falls back to the top 1,000 ports plus 37 high-risk ones.
- **Scripts.** nmap runs at version intensity 7 with 18 reviewed scripts: banner, SSH host key and algorithms, TLS certificate, HTTP headers and title, anonymous FTP, RDP NTLM and encryption, SMB OS discovery, NetBIOS, and the MySQL, SQL Server, MongoDB, Redis, Memcached, and CouchDB greetings. nmap's `-sV` also runs its own version scripts. Their output is dropped before storage, because only the reviewed scripts are trusted to be read-only.
- **The background port sweep** fingerprints what it finds with `-sV` only: no scripts and no OS guess until the next regular scan.
- **What queues for memory.** bbot, nuclei, nmap, naabu, route checks, and template tests wait in the memory-aware queue. WPScan, RDP screenshots, node2shell, and the database checks do not.
- **Per-host limits.** At most 10 CVE template tests per host. Route checks make up to 20 requests per host, 1,500 per scan, 0.2 seconds apart.

## Triage and validation

CVE matches, scanner findings, open databases, open admin routes, routes exposing credentials, and hygiene findings of medium severity or worse are queued for triage, within daily caps. Each finding carries a classification (`confirmed`, `likely`, `needs_validation`, `likely_false_positive`, `not_applicable`), why it matters, how to fix it, when it was first and last seen, and every check that ran. Nothing is deleted or hidden: a likely false positive sorts last. Without an AI provider, findings read "not triaged" and validation still runs.

**Fixed rules keep the model honest.** Hard evidence sets a floor the model cannot go below. A template hit, a database that answered, a distribution tracker that lists the package as vulnerable, a scanner finding whose template matcher fired at medium severity or higher, and a route serving a credential are `confirmed`. A version inside a CVE's affected range is at least `needs_validation`. An open admin route is at least `likely`. The model alone can never confirm a finding. A failed or malformed reply is retried, and meanwhile the finding shows a diagnostic you can copy.

**One question per kind of evidence.** The model sees cleaned, structured evidence (product, version, advisory range, template id, counts) with hostnames redacted. Findings with the same evidence share one saved answer.

**Validation runs by itself.** cvENGINE reproduces a finding with one of four read-only checks and records the exact command and result: a vetted nuclei template, `nmap -sV` on the one port, a HEAD request for the version banner, or the credential-less database check. A hit confirms the finding. A check that does not reproduce it never lowers it, because templates can miss behind a WAF or on another virtual host. A banner that only shows a version is recorded as `observed`. Every five minutes a dedicated worker queues up to 20 findings: fire first, then smoke, then every other CVE match (`CVENGINE_AUTO_VALIDATE_ALL_MATCHES=0` leaves those out). A project has at most 10 active jobs, 5 of them cold. Checks are not repeated within 24 hours.

**Validate now.** Matches are validated automatically, so this is for jumping the queue: on any CVE match, **Validate now** (or the API) has the AI plan the checks, runs them, and has the AI review the evidence. The plan can only choose checks the scope and template policy already allow. When a CVE cannot be answered from outside, such as a local kernel flaw, the match records that no external check applies.

**When nothing can be checked from outside**, cvENGINE asks the AI once for at most three short, read-only commands a person with shell access to the host could run themselves, such as checking for a package, a process, or a config path named in the advisory, with what the output would mean. It is suggestion only, unverified by this tool, shown under **Confirm it yourself** beside the usual "no check exists" message, never a classification or evidence of anything. The model is told never to suggest a command that changes the host or needs a credential, and to say so plainly when it is not confident of the exact way to detect a given product rather than invent one.

A daily sweep (triage 04:41 UTC, validation 05:17 UTC) catches whatever is left.

## AI review every three hours

With an AI model connected, cvENGINE reviews each project's inventory, matched CVEs, findings, scans, and recent activity every three hours and queues the most useful due action: triage, validation, a discovery on a stored target, or an assessment of a host missing a core stage. One action per project per run, at most 100 model calls and 20 actions per review. The server rechecks scope, exclusions, active scans, the pause switch, and queue caps first, and the model never supplies a target or a command.

The same review right-sizes scanner concurrency. With two hours of memory samples and enough completed scans, a controller proposes one step up or down and the AI must confirm that exact step. The result stays inside the `HEAVY_TUNE_MIN_<KIND>` and `HEAVY_TUNE_MAX_<KIND>` bounds you set ([CONFIGURATION.md](CONFIGURATION.md)), with a six-hour cooldown and an automatic step back after memory pressure. The **Scheduler health** tab shows each run and its decisions.

## Changes

Each host keeps a snapshot of its IPs, open ports, services, versions, and technologies. When a scan finishes, hosts are compared with their snapshots and the differences go into the Changes log, which the Changes page, the API (`list_changes`), and the host score read. A target's first scan only records a baseline, so the log starts quiet.

| Kind | Meaning |
| --- | --- |
| `host_new`, `host_returned`, `host_retired` | A host appeared, came back, or was retired |
| `port_opened`, `port_closed` | An open port appeared or went away |
| `service_changed` | The product or version of a port changed |
| `tech_added`, `tech_removed`, `tech_version_changed` | The host's technologies changed |
| `cert_changed` | The host presents a different certificate |
| `auth_changed`, `sensitive_found` | A route's anonymous answer changed, or it started serving a type of sensitive data |
| `screenshot_changed` | The front page visibly changed. The Changes page shows both screenshots side by side. |
| `zombie_host`, `zombie_cleared`, `zombie_route`, `route_retired` | See below |

**Zombie and retired hosts.** A host that stops resolving and whose last web address no longer answers is retired. If that address still answers a plain request with the old name, it is flagged as a zombie instead and scores higher until its name resolves again. A route that answered and now returns 404 or 410 is retired, and one that answers again is a zombie route.

**Re-test on change.** A new host, a new port, a changed service or technology, a route whose auth changed, or a zombie host queues a re-test with the CVE checks forced, up to 25 hosts per scan (`CVENGINE_RETEST_MAX_HOSTS`). A five-minute sweep drains the rest.

**Archive and rediscovery.** A person can archive a host, which keeps its findings and history but leaves routine scanning, and can pin a host to protect it. A daily review also archives retired hosts that stay gone: two meaningful negative observations at least 30 days apart, with no positive one between them. DNS errors, wildcard answers, missing probes, exclusions, and paused scanning never count as absence. Every day cvENGINE rechecks the hosts it archived itself, and a name that resolves again or an IP whose known port answers again is restored and reassessed. A host a person archived stays archived until someone restores it.

## Host score

Every host has a score from 0 to 100 and the reasons behind it, shown as "Why the score is N" on the Hosts page. Hosts, search, and the attack-surface map sort highest first. The score adds capped components: CVE matches (fire 40, smoke 20, ice 5, plus 10 for an AI-confirmed fire match, up to 50), open findings (up to 25), web route auth (up to 15), sensitive data (up to 25), a public IP (10), recent change (up to 10), and zombies (up to 15). It is recomputed after each scan, when a verdict is saved, and daily.

## CVE intelligence

1. **Feed.** The [cve.now](https://cve.now) feed brings CVSS and affected version ranges. Each sync adds new CVEs and refreshes up to 10 matched ones, so a CVE that gains an exploit or a new range updates its matches. An hourly task covers the last 14 days of the feed.
2. **Exploitation sources.** An hourly task (`sync_threat_intel`) also reads sources that cover the whole history: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [ENISA EUVD](https://euvd.enisa.europa.eu/) (exploited in the wild), optionally [VulnCheck KEV](https://docs.vulncheck.com/community/vulncheck-kev/introduction) (needs `CVENGINE_VULNCHECK_API_KEY`), [FIRST EPSS](https://www.first.org/epss/) (probability of exploitation), [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) (public exploit code), and [Metasploit](https://github.com/rapid7/metasploit-framework) (weaponized modules). A source only adds evidence: a CVE missing from one never loses what another reported, and the CVE detail names each source. A CVE these sources name that is not stored is imported from its [CVE List V5](https://github.com/CVEProject/cvelistV5) record, up to 2,000 an hour, known exploited first, so the whole exploited history is in within hours.
3. **Tier** (see [Fire, smoke, and ice](FIRE-SMOKE-ICE.md)). *Fire*: known exploited, has a public exploit, has CVSS 9.0 or higher, or has EPSS of 0.1 or more with CVSS 7.0 or higher. *Smoke*: CVSS 7.0 or higher, or EPSS of 0.1 or more. *Ice*: everything else.
4. **Match.** The product (or package) a host runs must be the one the CVE names. A vendor alone is not enough, so an Apache HTTP Server host is not a Log4j host, and a generic cloud service fingerprint is never a product. Known name variants are aliased, and an nmap CPE gives product and version exactly. A shorter name matches a longer one only as whole words (`apache` in `Apache HTTP Server`, never `php` in `phpMyAdmin`). An entry with no usable version bound is *unknown* at low confidence, and so is a version older than every branch an advisory lists for a fire or smoke CVE, because end-of-life branches get no fix. A host with no version does not match an ice CVE that has ranges. A match whose version moved out of range or whose product is gone is closed. Each match stores its evidence.
5. **Distro backports.** Linux distributions fix CVEs without changing the upstream version. cvENGINE reads the distribution and package release from the banner and, for Ubuntu and Debian, compares it with the fixed version from the [Debian security tracker](https://security-tracker.debian.org) and [OSV](https://osv.dev), labeling the match *patched by distro*, *vulnerable per distro tracker*, or *version-only*. Other distributions, such as RHEL, are recognized and stay version-only. Matches are labeled, never dropped.
6. **Auto-fire (optional, off by default).** After a feed sync stores new CVEs, each new fire or smoke CVE is handled once. The AI confirms its matches, and the ones it calls affected or uncertain are tested on their hosts. The cap is set under **Settings, AI model** (default 200 hosts per CVE).
7. **Test.** An installed nuclei template for the CVE runs on matched hosts once it passes the read-only and destination checks. When none exists, the AI can draft one, and a draft stays a draft until a person reviews it. The reviewer adds an independent positive and negative HTTP response fixture in `web/cveFeed/reviewed_fixtures/CVE-YYYY-NNNN.json`, citing an HTTPS source, and runs `python manage.py review_generated_template <id>`. Only a draft that detects the positive response and rejects the negative one is installed. This covers fixed-path, read-only HTTP detectors, and fixture success proves the detector's behavior, not that a live host is affected. A hit is saved as evidence linked to the CVE, and a tool error is recorded as an error, never as a clean result.

CVE matches appear under **CVE matches** and in **Findings** with a remediation status (open, in progress, fixed, accepted risk). Agents read and update it through the [API](AGENT-API.md).

## Detection strategies

Every CVE has one detection record, shared by all organizations, that says how to tell whether a product is affected: **remote
checks** (a version in an affected range, an HTTP marker, an installed nuclei template, a reviewed nmap script, a TLS property, a
service on a port) and **local checks** on the host itself (a package older than the fixed release, a file that contains a version, a
configuration setting, a service state). Read it with `GET /api/v1/cves/{id}/detection`, the MCP tool `get_cve_detection`, or the
`detection` field of `get_cve`.

A strategy is data, never a program. Every check is one of the kinds above with parameters from an allowlist (HTTP `GET` and `HEAD`
only, nmap scripts from the reviewed list, plain package and file names with no `..`), so whatever runs a check does it with its own
primitive for that kind; nothing in a strategy is a shell command. Each record carries `safety: read_only`.

Records are written by a task every 30 minutes (`author_cve_detections`), hottest first (known exploited, public exploit, high
exploit probability, then score), so a new CVE from any feed gets one within the hour and the back catalogue fills in behind it:

1. The **rules author** reads the CVE's own affected products and ranges, and any installed nuclei template. No AI, no cost.
2. The **AI author** is asked once per CVE, for the hot ones only (known exploited, exploit probability or public exploit, or a
   critical score), and only within `CVENGINE_DETECTION_AI_PER_DAY` (default 25; 5 per run). It sees feed text only, never a project
   or an asset, and its answer is parsed against the schema: a check that does not validate is dropped on its own, and the reason is
   kept on the record. Its checks are added after the rules' checks with an `ai-` id and never replace them. A failed ask is retried
   after a week.

A `manual` record is never overwritten. When a CVE's affected data changes, the rules checks are rewritten and the AI checks kept.
`manage.py author_cve_detections [--ai]` fills the whole catalogue at once.

The policy the AI follows for each new CVE (scope first: `external`, `local_only`, `unclear`; then the record), when a record is revised, and how an administrator adds facts are in [CVE-INTAKE.md](CVE-INTAKE.md). A CVE only usable from the host itself (`local_only`) is never matched to a host.

### Validating a match

Each detection record also says how to decide a match, so nobody has to rediscover it per CVE:

- `validation.remote_determinable` is `yes` (a nuclei template, an HTTP marker or a reviewed nmap script can decide it from outside), `partial` (only the reported version or the exposed service, which a backported fix can fool) or `no` (it needs the host, or the CVSS attack vector is local). `validation.max_remote_state` is the best a remote check can reach on the triage scale: `confirmed` (validated), `likely` or `needs_validation`.
- `validation.validated_when`, `needs_validation_when`, `likely_false_positive_when` and `not_applicable_when` list what moves a match to each state, and `recommended_tools` names the tools (nuclei, nmap, curl, openssl, the package manager, grep, systemctl).
- Every remote check has a `how`: the tool, the invocation with `<TARGET>` and `<PORT>` to fill in, and how to decide from the output. Every local check has `commands`: one read-only command per platform (Debian, Red Hat, Alpine, other Linux, Windows) with the shell, whether it needs elevated rights, an `explain` sentence for a person logged in to the host, and a structured `expect` (`version_lt`, `exit_code`, `output_equals`) that a future authenticated scan can evaluate without parsing prose.

The commands are rendered by the application from the validated parameters of each check, with every value quoted; a model never writes one, and a record read from a seed or a model reply has its commands thrown away and rendered again.

### Seeding the catalog

Building the catalog from the cve.now feed takes one request per CVE, so a new install used to spend hours rebuilding what another instance already had. A **seed** is the whole catalog as one file: every CVE (fire, smoke and ice) with its scores, exploitation signals, affected ranges and references, plus its detection record. On first start (and on an older install that still has fewer than 5,000 CVEs, once a day) CVEngine downloads the published seed, checks it against its manifest (count, size, sha256), imports the CVEs it lacks and their detection records, runs the correlation if there are already hosts, and the incremental feed carries on from there. A CVE already present is never overwritten, nothing in the file is trusted (each field is typed and clipped, each strategy is validated again), and offline or a failed check only means the feed builds the catalog up gradually, as before.

- Maintainer: on an instance with the full catalog, `make export-cve-seed` writes `web/cve-seed.jsonl.gz` and its manifest (it first writes any missing detection records), and `scripts/publish-cve-seed.sh` uploads both to the `cve-seed` release.
- Anyone: `manage.py import_cve_seed [file | --url https://...]` imports a file or the published seed by hand.
- `CVENGINE_CVE_SEED=off` turns the automatic load off; `CVENGINE_CVE_SEED_URL` points it at your own mirror (https, with the `.manifest.json` beside it).

## Keeping scans fast and polite

- **One run per host.** A successful scanner run is reused inside its window: 168 hours for nmap, bbot, route checks, naabu, deep nuclei, and archived-URL lookups, 24 hours for nuclei, the certificate watch, hygiene, re-tests, WPScan, node2shell, and RDP screenshots. Failed or skipped work never counts as coverage, and a Redis claim keeps two pipelines off the same asset. Set the windows with `CVENGINE_TTL_*` ([CONFIGURATION.md](CONFIGURATION.md)).
- **Parents are reused.** A target under one already discovered (`www.example.com` after `example.com`) skips bbot when its parent finished in the last 7 days.
- **Memory aware.** Heavy jobs wait in a queue that hands out memory by estimated cost. If memory runs short, the largest job stops first and bbot, nuclei, and nmap retry lighter. Watch it under **Settings, Resources**.
- **Rescan a host.** **Rescan host** (or `assess_host`) runs a full, fresh assessment of one host: DNS, ports, exposure, nuclei, routes, correlation, AI triage, and TLS, ignoring recent results but keeping scope, exclusions, and resource limits. Progress shows stage by stage, and you can stop it.
- **New hosts between scans.** When the certificate watch sees a new hostname, a short pipeline runs on up to 200 new hosts: the same stages a scan ends with (nmap, RDP screenshot, exposure checks, technology pass, route checks, WPScan, node2shell if enabled, correlation, targeted pass, triage, and change recording). Agents can start it with `rescan_hosts`.
- **Background full port scan.** A slow task sweeps all 65,535 TCP ports of one in-scope IP at a time (10 minutes per host at most), oldest first. Ports it finds are fingerprinted and the host is re-tested. `CVENGINE_FULLSCAN=0` turns it off.
- **Paced deep nuclei.** Every 10 minutes one due host gets the approved broad template set on its name and up to 20 nonstandard ports, which covers an inventory of about 1,000 hosts each week.
- **Weekly deep discovery.** Daily, each apex domain without a deep discovery in the last 7 days gets one, up to 50 per run. If only its subdomains were targets, the apex is added. This is the one automatic rediscovery without an AI model.
- **Pause everything.** An App Admin can **Pause all scanning** from **All projects, Activity**. The pause survives restarts: work that touches targets or spends AI budget waits, running scanners stop cooperatively, and running scans are marked aborted. Bookkeeping that touches no target keeps running (the feeds, notifications, pruning, rescoring). **Resume** releases the queue.

### Shared platform addresses

A name on Netlify, Vercel, GitHub Pages, Heroku, or a CDN edge answers on addresses that belong to the platform. cvENGINE recognizes them from the name's CNAME, the `Server` header, or the CDN flag and never points nmap or the full-port sweep at them. The host record says so.

### Shared provider domains

A tenant of a multi-tenant provider owns only its own subdomain. For `acme.jfrog.com`, the registrable domain `jfrog.com` belongs to the provider and all its customers, so cvENGINE never promotes it to an apex or enumerates it. A curated list (`SHARED_DOMAINS` in `web/targetApp/shared_domains.py`) marks such domains, and a target under one is **host scoped**: bbot runs with strict scope, the apex sweep skips it, and the certificate watch asks only about that host. Each target has a **scope mode**: `auto` (the list decides), `host`, or `parent` (for a domain you control that sits on the list).

### Excluded hosts

An organization can remove a host and exclude it (**Remove & exclude**, or the API). An exclusion matches the exact host name, case-insensitively, and every stage skips an excluded host in every project of that organization. Adding it as a target is refused. The Hosts page shows names that point at the same addresses as one host, so **Remove & exclude** offers to take those other names with it (otherwise the next name would simply take its place on the page). To drop a whole domain, put `-example.com` on a line in **Add targets** (or call `exclude_host` with `include_subdomains`): the name, every name under it (`www.example.com`, `a.b.example.com`, never `notexample.com`) and every target named like them are removed in every project of the organization you can write to, their running scans are stopped, and nothing under that domain is discovered, scanned or added again. A line such as `-com` or `-co.uk` is refused. **Delete host data** removes a host from one project only and leaves it free to be found again.

## The work conductor

Scans used to start only when someone asked or when a daily or weekly sweep ran, so for most of the day nothing was running even with a thousand hosts to look after. Now a watchdog runs every minute and keeps the discovery queue topped up: when fewer than `CVENGINE_WORK_DEPTH` scans (default 3) are running or queued, it starts discovery of the targets that have gone longest without one: never scanned first, then the stalest. It starts at most one per project per round so no project starves the others, and it never picks a target scanned within `CVENGINE_WORK_MIN_GAP_HOURS` (default 2), one that already has a scan going, one an organization excluded, a project whose bug bounty engagement has not confirmed that automated testing is allowed (or is paused or finished), or anything at all while scanning is paused (an update's pause included). Each start is logged in the target's project activity. Set `CVENGINE_WORK_DEPTH=0` to turn it off. The system status (`get_system_status`, App Admin) shows its depth, the scans running and queued, and its last round, and reports a problem when targets exist, scanning is not paused and nothing is running or queued.

The other work that keeps the instance busy has its own schedule, below: validation of fire and smoke matches, re-tests of changed hosts, the paced full port scan and deep nuclei, triage, and the AI review every three hours.

## Schedules

A superuser can change CVE sync, certificate watch, the hygiene hour, and both time limits on the Administration page. The rest are fixed.

| Task | Default |
| --- | --- |
| CVE feed sync | every 30 minutes |
| Exploitation sources | hourly; each source re-read when due (6 to 24 hours) |
| Certificate watch | every 20 minutes |
| Hygiene sweep | daily at 03:17 UTC |
| Discovery time limit, per bbot run | 6 hours |
| nuclei time limit, per run | 4 hours |
| Work conductor (keeps the discovery queue fed) | every minute |
| Tailscale sync (devices, findings, scans of connected tailnets; [Tailscale](TAILSCALE.md)) | every 15 minutes |
| Fire and smoke validation, change re-tests | every 5 minutes |
| Background full port scan, paced deep nuclei | every 10 minutes, one host per run |
| AI review and capacity tuning | every 3 hours |
| Stuck job cleanup | every 15 minutes |
| runZero sync (projects with a token) | checked hourly, each project every 6 hours (`CVENGINE_RUNZERO_SYNC_HOURS`) |
| CVE feed coverage, bounty catalogue | hourly |
| Archived host rediscovery, inactive host review | daily |
| Deep discovery of apex domains | daily at 02:43 UTC |
| Distro fix sync | daily at 03:17 UTC |
| Triage and validation sweeps | daily at 04:41 and 05:17 UTC |
| nuclei template update | daily at 04:41 UTC |
| Update check | 05:23 and 17:23 UTC |
| Host rescore | daily at 05:29 UTC |
| Change log pruning (90 days) | daily at 04:11 UTC |
| Log archive and cleanup | Sundays at 03:23 UTC |

See also: [ARCHITECTURE.md](ARCHITECTURE.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
