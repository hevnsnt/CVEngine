# Pipeline

Add a target and CVEngine runs one pipeline for it. Stages run in order, and each stage records its own result, so you can see exactly what was covered. If discovery itself fails, the scan is marked failed. If a later stage fails, the stage is marked failed and named in the scan's error, and the scan still completes, so the hosts it found stay in the inventory.

## Targets

A target is a domain, an IP address, a CIDR range (`10.0.0.0/24`), a dashed range (`192.168.1.1-192.168.1.20`), or a URL, which is reduced to its host. Every host is validated before it is stored. Targets queue first in, first out.

## Stages

1. **Discovery.** bbot finds domains, subdomains, and IPs and streams them into the inventory as it runs, and screenshots capture each web host. *Standard* mode, the default, enumerates subdomains and fingerprints web hosts with safe modules. *Deep* mode runs everything bbot has, including brute forcing and spidering, and takes hours. *Passive* keeps discovery to public sources (the later stages still connect to the hosts it finds). A bare IP skips bbot and gets a reverse-DNS lookup and a read of its certificate.
2. **Inventory.** nmap fingerprints each IP once per window (`-sV -O`) on the top 1,000 ports plus about 40 high-risk ones that nmap's ranking leaves out, such as Redis, MongoDB, the Docker and Kubernetes APIs, and etcd. It records ports, services, products, versions, CPEs, the distribution read from the banner, and the OS. Only open ports are correlated and listed, and a port that closes is marked closed. With `CVENGINE_NAABU=1`, naabu finds open ports first and nmap fingerprints just those.
3. **Exposure checks.** One connection attempt, with no credentials, to Redis, Memcached, PostgreSQL, Elasticsearch, and CouchDB ports. A server that answers is reported as a critical finding.
4. **nuclei, technology pass.** HTTP and technology templates fingerprint each host.
5. **Web route checks.** For each web host, CVEngine asks a handful of common routes (`/`, `/login`, `/admin`, `/api`, and paths bbot found) one plain anonymous GET and labels each route `open`, `login`, `session_required`, `sso`, or `redirect`. The same response is scanned in memory for sensitive data such as cloud keys, personal data, and internal identifiers. Only the type, a count, and a masked sample are stored. Credentials show only their type and public prefix.
6. **CVE correlation.** The inventory is matched against the CVE feed.
7. **nuclei, AI-targeted pass.** Your AI model sees the technology names found on each host and picks nuclei tags from those the installed templates use. A built-in technology map always adds its tags. Hosts with the same choice are scanned together, and each host's fire and smoke CVE matches get a template test.
8. **Triage, validation, and changes.** See below.

Hygiene runs as its own task when the scan finishes. It checks TLS certificates (expiry, trust chain, hostname, self-signed, legacy protocols) and SPF, DKIM, DMARC, and CAA records.

The email review also runs the checks of [MailFail](https://github.com/ACK-J/MailFail) by Black Hills Information Security, re-implemented server side and credited in the AI activity feed while they run: SPF and DMARC records that receivers ignore, SPF includes and DMARC report addresses on domains anyone can register (asked of the domain's registry over RDAP), DMARC report addresses that are not authorised (RFC 7489 §7.1), malformed report addresses, DKIM keys in testing mode, SHA-1 only or unparseable, weak ARC keys, Microsoft 365 Direct Send exposure (read from MX; nothing is sent), MTA-STS (the record and the domain's own policy file, fetched only when it does not resolve to a blocked address), SMTP TLS reporting, DANE TLSA records for SMTP, DNSSEC algorithms and key sizes, BIMI records, obsolete ADSP, and MailChannels Domain Lockdown. Like MailFail, none of these sends mail or opens SMTP. `CVENGINE_HYGIENE_RDAP=0` turns the registry lookups off.

Every nuclei run uses a snapshot of the installed templates that passed source-level read-only and destination checks: plain GET, HEAD or OPTIONS requests to the scanned host only, no payloads, bodies, code or out-of-band (interactsh) checks. A template may follow redirects on the same host, up to three (nuclei's `host-redirects`, which the technology detection template uses); one that follows redirects to other hosts is left out. The AI-written templates may not follow redirects at all.

## Triage and validation

CVE matches, scanner findings, open databases, open admin routes, routes exposing credentials, and hygiene findings of medium severity or worse are queued for triage. Each finding carries a classification (`confirmed`, `likely`, `needs_validation`, `likely_false_positive`, `not_applicable`), why it matters, how to fix it, when it was first and last seen, and every check that ran. Nothing is deleted or hidden: a likely false positive sorts last. Without an AI provider, findings read "not triaged" and validation still runs.

**Fixed rules keep the model honest.** Hard evidence sets a floor the model cannot go below. A template hit, a database that answered, a distribution tracker that lists the package as vulnerable, a scanner match at medium severity or higher, and a route serving a credential are `confirmed`. A version inside a CVE's affected range is at least `needs_validation`. An open admin route is at least `likely`. The model alone can never confirm a finding. A failed or malformed reply is retried, and until it succeeds the finding shows a diagnostic you can copy.

**One question per kind of evidence.** The model sees cleaned, structured evidence (product, version, advisory range, template id, counts) with hostnames redacted. Findings with the same evidence share one saved answer, and daily caps bound the provider calls.

**Validation runs by itself.** CVEngine reproduces a finding with one of four read-only checks and records the exact command and result: a vetted nuclei template, `nmap -sV` on the one port, a HEAD request for the version banner, or the credential-less database check. A hit confirms the finding. A check that does not reproduce it never lowers it, because templates can miss behind a WAF or on another virtual host. A banner that only shows a version is recorded as `observed`. Fire and smoke findings go to a dedicated validation worker every five minutes, fire first, so the most dangerous findings are checked within minutes of being found. Checks are not repeated within 24 hours.

**Validate now.** For any CVE match, **Validate now** (or the API) asks the AI to plan the checks, runs them, and has the AI review the evidence. The plan can only choose checks the scope and template policy already allow. When a CVE cannot be answered from outside, such as a local kernel flaw, the AI says so and the match records that no external check applies.

A daily sweep (triage 04:41 UTC, validation 05:17 UTC) catches whatever is left.

## AI review every three hours

Every three hours CVEngine reviews each project's inventory, matched CVEs, findings, scans, and recent activity, and the AI picks the most useful next step for each project. It can queue due triage or validation, start a due discovery on a stored target, or assess an inventoried host that is missing a core stage. The server rechecks scope, exclusions, active scans, the pause switch, and queue caps before anything runs, and the model never supplies a target or a command. Each review makes at most 100 model calls and 20 new actions, and a large installation continues where it stopped in the next window.

The same review right-sizes scanner concurrency. With at least two hours of memory samples and enough completed scans, a controller proposes one step up or down, and the AI must confirm that exact step. The result stays inside the `HEAVY_TUNE_MIN_<KIND>` and `HEAVY_TUNE_MAX_<KIND>` bounds you set ([CONFIGURATION.md](CONFIGURATION.md)), with a six-hour cooldown and an automatic step back after memory pressure. The **Scheduler health** tab shows each run, its decisions, and any change.

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
| `zombie_host`, `zombie_route`, `route_retired` | See below |

**Zombie and retired hosts.** A host that stops resolving and whose last web address no longer answers is retired. If that address still answers a plain request with the old name, the host is flagged as a zombie instead and scores higher until its name resolves again. A route that answered and now returns 404 or 410 is retired, and one that answers again is a zombie route.

**Re-test on change.** A new port, a version change, or a route that just opened queues a re-test of that host with the CVE checks forced, up to 25 hosts per scan (`CVENGINE_RETEST_MAX_HOSTS`). The rest wait in a queue that a five-minute sweep drains.

**Archive and rediscovery.** A project user can archive a host manually; it keeps its findings and history but leaves routine scanning. A pinned host cannot be archived. A daily inactive-host review also examines retired hosts that were last seen and retired at least 30 days ago. It archives one only after two meaningful negative observations at least 30 days apart, with no positive observation between them. DNS errors, wildcard/blocked answers, missing probes, exclusions, paused scanning, and never-assessed hosts do not count as absence. A queued or running scan of the host's domain postpones the review, unless that scan is more than 3 days old and therefore stuck. Positive rediscovery queues a fresh host assessment. This conservative rule can take longer than 30 days to archive older records whose previous absence was not recorded. Every day CVEngine separately rechecks the hosts it archived itself: a name that resolves again, or an IP whose known port answers again, is restored and gets a fresh assessment (if that assessment cannot be queued, the host stays archived). A host a person archived stays archived, even when a scan finds it again, until someone restores it. **Restore** brings a host back by hand, and **Pin** prevents automatic archival. Neither action deletes history or creates an exclusion.

## Host score

Every host has a score from 0 to 100 and the reasons behind it, shown as "Why the score is N" on the Hosts page. Hosts, search, and the attack-surface map sort highest first. The score adds capped components: CVE matches (fire 40, smoke 20, ice 5, plus 10 for an AI-confirmed fire match, up to 50), open findings (up to 25), web route auth (up to 15), sensitive data (up to 25), a public IP (10), recent change (up to 10), and zombies (up to 15). It is recomputed after each scan, when a verdict is saved, and daily.

## CVE intelligence

1. **Feed.** The [cve.now](https://cve.now) feed brings CVSS, CISA KEV, EPSS, Exploit-DB, and affected version ranges. Each sync adds new CVEs and refreshes up to 10 of the matched ones, so a CVE that gains an exploit or a new version range updates its matches and their AI review. The incremental sync stops after 40 known entries in a row, so an hourly coverage task reads the last 14 days of the feed (and the per-technology feed for PHP) whenever the stored feed does not reach back that far, and does nothing once it does. `python manage.py sync_cve_now --ids CVE-2026-109618` or `--tech php` reads specific entries at once. If cve.now refuses a request (403, 429) the run stops instead of retrying.
2. **Threat intelligence.** The feed's incremental walk and 14-day coverage miss older CVEs that are exploited today, so an hourly task (`sync_threat_intel`, `cveFeed/intel.py`) also reads public sources that cover the whole history:

   | Source | What it says | Size |
   |---|---|---|
   | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | exploited in the wild | about 1,800 CVEs |
   | [ENISA EUVD](https://euvd.enisa.europa.eu/) (exploited) | exploited in the wild | about 1,800 CVEs |
   | [VulnCheck KEV](https://docs.vulncheck.com/community/vulncheck-kev/introduction) | exploited in the wild (only with `CVENGINE_VULNCHECK_API_KEY`) | about 80% more than CISA |
   | [FIRST EPSS](https://www.first.org/epss/) | probability of exploitation in 30 days | every CVE |
   | [Exploit-DB](https://www.exploit-db.com/) | public exploit code | about 25,000 CVEs |
   | [Metasploit](https://github.com/rapid7/metasploit-framework) | weaponized module | about 3,200 CVEs |

   They are reconciled into the signals the tiers read. A CVE is known exploited when cve.now or any of the exploited-in-the-wild lists says so. It has a public exploit when cve.now, Exploit-DB or Metasploit does. EPSS is elevated when today's EPSS score is 0.1 or more. A source only adds evidence: a CVE missing from one never loses what another reported, and cve.now rewriting an entry keeps it. Each CVE records which source said what, and the CVE detail names them.

   A CVE these sources name that is not stored is imported from its [CVE List V5](https://github.com/CVEProject/cvelistV5) record: the CNA's affected products and version ranges (split at each fixed release), CVSS from the CNA or CISA's ADP enrichment, and the references. Imports go in order: known exploited, then Metasploit, then EPSS, then Exploit-DB. Up to 2,000 are imported an hour, so a new install has every known-exploited CVE within the first hour and all of about 37,000 within a day. Imported CVEs are correlated against the inventory and announced like the feed's new ones. A source that fails keeps its last copy in use and is reported in the activity log.
3. **Tier** (see [Fire, smoke, and ice](FIRE-SMOKE-ICE.md)). *Fire*: known exploited (CISA KEV, ENISA EUVD, or VulnCheck KEV), has a public exploit (Exploit-DB or Metasploit), has CVSS 9.0 or higher, or has EPSS of 0.1 or more with CVSS 7.0 or higher. *Smoke*: CVSS 7.0 or higher, or EPSS of 0.1 or more. *Ice*: everything else.
4. **Match.** A match needs the product (or package) a host runs to be the one the CVE names. A vendor alone is not enough, so an Apache HTTP Server host is not a Log4j host, and a generic cloud service fingerprint is never treated as a product. Known name variants are aliased, and an nmap CPE gives product and version exactly. An entry with no usable version bound is *unknown* at low confidence. A host with no version does not match an ice CVE that has version ranges. A shorter name matches a longer one only as whole words (`apache` in `Apache HTTP Server`, never `cms` in `datocms` or `php` in `phpMyAdmin`), and a product that is one generic word (`cms`, `server`) is matched by its vendor's name instead. When an advisory lists only the branches that received a fix (PHP 8.2 to 8.5, each with its own fixed release), a version older than every listed branch is *unknown*, not "not in range": end-of-life branches get no fix, so they are not cleared. The evidence says `branch_unlisted`. A match whose version moved out of range or whose product is gone is closed. Each match stores its evidence.
5. **Distro backports.** Linux distributions fix CVEs without changing the upstream version. CVEngine reads the distribution and package release from the banner (Ubuntu, Debian, RHEL), compares it with the distribution's fixed version from the Debian security tracker and OSV, and labels the match *patched by distro*, *vulnerable per distro tracker*, or *version-only*. Matches are labeled, never dropped. The data syncs daily.
6. **Auto-fire (optional).** After a feed sync stores new CVEs, each new fire or smoke CVE is handled once. The AI confirms its matches, and the ones it calls affected or uncertain are tested on their hosts. The cap is set under **Settings, AI model** (default 200 hosts per CVE).
7. **Test.** An installed nuclei template for the CVE runs on matched hosts once it passes the read-only and destination checks. When none exists, the AI can draft one. A draft must pass static, syntax, and benign fixture checks. A maintainer can add an independent CVE-specific positive and negative HTTP response fixture in `web/cveFeed/reviewed_fixtures/CVE-YYYY-NNNN.json`, citing an HTTPS source and reviewer, then run `python manage.py review_generated_template <template-database-id>`. Only a draft that detects the positive response and rejects the negative response on loopback is installed for targeted use. This narrow harness supports fixed-path, read-only HTTP detectors; other template types remain drafts. Fixture success proves that detector behavior on those responses, not that any live host is affected. A hit is saved as evidence linked to the CVE, and a tool error is recorded as an error, never as a clean result.

Matches appear under **CVE matches** with a remediation status. Agents read and update them through the [API](AGENT-API.md).

## Excluded hosts

An organization can remove a host and exclude it (**Remove & exclude** on the Hosts page, or the API). Exclusions match the exact host name, case-insensitively, and every stage skips an excluded host in every project of that organization: discovery, the certificate watch, nmap, nuclei, web route checks, the full-port sweep, and the apex sweep. Adding it as a target is refused. **Delete host data** removes a host's data from one project only and leaves it free to be found again.

## Keeping scans fast and polite

- **One run per host.** A successful scanner run is reused within its time window (168 hours for nmap and bbot, 24 hours for nuclei, the certificate watch, and hygiene). Failed or skipped work never counts as coverage. A Redis claim keeps two pipelines off the same asset. Set the windows with `CVENGINE_TTL_*` in [CONFIGURATION.md](CONFIGURATION.md).
- **Parents are reused.** A target under one already discovered (`www.example.com` after `example.com`) skips bbot when its parent finished in the last 7 days.
- **Memory aware.** Heavy jobs wait in a queue that hands out memory by estimated cost. If memory runs short, the largest job stops first, and bbot, nuclei, and nmap retry lighter. Watch it under **Settings, Resources**.
- **Rescan a host.** **Rescan host** on the Hosts page (or `assess_host` in the API) runs a full, fresh assessment of one host: DNS, ports, exposure, nuclei, routes, correlation, AI triage, and TLS, ignoring recent results while keeping scope, exclusions, and resource limits. Progress shows stage by stage, and you can stop it.
- **New hosts between scans.** When the certificate watch finds a new host, a short pipeline runs on up to 200 new hosts: nmap, exposure checks, the technology pass, correlation, and the targeted pass. Agents can start it with `rescan_hosts`. This short pipeline (and a host rescan or re-test) adds to the target's inventory: the inventory is the latest full scan plus any later host pipelines, with the newest result for each host.
- **Background full port scan.** A slow task sweeps all 65,535 TCP ports of one in-scope IP at a time (10 minutes per host at most), oldest first. Ports it finds are fingerprinted and the host is re-tested. `CVENGINE_FULLSCAN=0` turns it off.
- **Paced deep nuclei.** Every 10 minutes one due host gets the full broad template set on its web ports and up to 20 nonstandard ports, so the whole inventory gets a deep pass each week as capacity allows.
- **Weekly deep discovery.** Once a day, each apex domain without a deep discovery in the last 7 days gets one, up to 50 per run. If only its subdomains were targets, the apex is added.
- **Pause everything.** An App Admin can **Pause all scanning** from **All projects, Activity**. The pause survives restarts: scheduled and queued work that touches targets or spends AI budget (discovery, scanners, validation, triage, reviews) waits, a validation run stops before its next check, running scanners stop cooperatively, and running scans are marked aborted. Bookkeeping that touches no target keeps running: the CVE feed, threat intelligence and distribution fixes, the update check and template download, notifications, pruning and rescoring. If the pause switch cannot be read, new work waits but running scanners are not stopped. **Resume** releases the queue.

### Shared platform addresses

A name hosted on Netlify, Vercel, GitHub Pages, Heroku or a CDN edge answers on addresses that belong to the platform, where other customers' sites answer too. CVEngine recognises them from the name's CNAME (stored, or looked up once and cached), the `Server` header, or the CDN flag, marks the address as a CDN address, and does not point nmap or the background full-port sweep at it. The host record says so (`hosting.shared_ip`).

### The host record

Each host in the API, MCP and `search_hosts` carries a Shodan-style record: `http` (status, title, web server, `X-Powered-By`, redirect, CNAME, and which stage saw it), `hosting` (provider, kind, whether the IP is shared, the cloud its addresses reverse-resolve to, and the evidence), `technology_details` (name, version, category, and where it was seen), and per address the reverse DNS, country when known, how many names of the project sit on it, and the CDN flag. The web route check keeps the root page's `Server` and `X-Powered-By` headers, the generator meta tag, and a few page markers (Next.js, WordPress, `.php` links), and records them as the host's technologies, so a PHP version in a header reaches correlation like any other detected technology. What the host row stores wins over what the route check saw.

### Shared provider domains

A tenant of a multi-tenant provider owns only its own subdomain. For `acme.jfrog.com`, the registrable domain `jfrog.com` belongs to the provider and all its customers, so CVEngine never promotes it to an apex or enumerates it. A curated list (`SHARED_DOMAINS` in `web/targetApp/shared_domains.py`, covering SaaS, cloud, CDN, source hosting, and pages providers) marks such domains. A target under one is **host scoped**: bbot runs with strict scope, the apex sweep skips it, and the certificate watch asks only about that host. Each target has a **scope mode**: `auto` (the list decides), `host`, or `parent` (treat the parent as yours, for domains you control that sit on the list).

## Schedules

A superuser can change the first five rows on the Administration page. The rest are fixed.

| Task | Default |
| --- | --- |
| CVE feed sync | every 30 minutes |
| Threat intelligence (KEV, EUVD, EPSS, Exploit-DB, Metasploit) | hourly; each source re-read when due (6 to 24 hours) |
| Certificate watch | every 20 minutes |
| Hygiene sweep | daily at 03:17 UTC (the hour can change) |
| Discovery time limit, per bbot run | 6 hours |
| nuclei time limit, per run | 4 hours |
| Fire and smoke validation, change re-tests | every 5 minutes |
| Background full port scan, paced deep nuclei | every 10 minutes, one host per run |
| AI review and capacity tuning | every 3 hours |
| Archived host rediscovery | daily |
| Inactive host archival review | daily; only repeated negative observations at least 30 days apart can archive |
| Deep discovery of apex domains | daily at 02:43 UTC |
| Distro fix sync | daily at 03:17 UTC |
| Triage and validation sweeps | daily at 04:41 and 05:17 UTC |
| nuclei template update | daily at 04:41 UTC |
| Update check | 05:23 and 17:23 UTC |
| Host rescore | daily at 05:29 UTC |
| Change log retention (90 days) | daily at 04:11 UTC |

See also: [ARCHITECTURE.md](ARCHITECTURE.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
