# Pipeline

Add a target and cvENGINE runs one pipeline for it. Stages run in order and each records its own result, so you can see exactly what was covered. If discovery fails, the scan fails. If a later stage fails, that stage is named in the scan's error and the scan still completes, so the hosts it found stay in the inventory.

## Targets

A target is a domain, an IP address, a CIDR range (`10.0.0.0/24`), a dashed range (`192.168.1.1-192.168.1.20`), or a URL, which is reduced to its host. Every host is validated before it is stored. Targets queue first in, first out.

## Stages

1. **Discovery.** [bbot](https://github.com/blacklanternsecurity/bbot) finds domains, subdomains, and IPs and streams them into the inventory as it runs. *Standard* mode, the default, enumerates subdomains and fingerprints web hosts with safe modules. *Deep* mode runs everything bbot has, including brute forcing, spidering, and [gowitness](https://github.com/sensepost/gowitness) screenshots, and takes hours. *Passive* keeps discovery to public sources (later stages still connect to the hosts it finds). A bare IP skips bbot and gets a reverse-DNS lookup and a read of its certificate.
2. **Inventory.** [nmap](https://nmap.org) fingerprints each IP once per window (`-sV -O`) on the top 1,000 ports plus 37 high-risk ones that nmap's ranking leaves out, such as Redis, MongoDB, the Docker and Kubernetes APIs, and etcd. It records ports, services, products, versions, CPEs, the distribution read from the banner, and the OS. Only open ports are correlated, and a port that closes is marked closed. By default, [naabu](https://github.com/projectdiscovery/naabu) finds every open port of each address first (a full 65,535-port SYN sweep at a polite rate), and nmap fingerprints just those instead of guessing from its own top-1,000 list; `CVENGINE_NAABU=0` turns this off and falls back to nmap's own top-1,000 guess alone. Its scripts also read banners and SSH, TLS, HTTP, SMB, and RDP details, plus each database's own pre-authentication greeting (MySQL, Microsoft SQL Server, MongoDB, Redis, Memcached, and CouchDB), which fills in a version or product nmap's own probe missed. They name the Windows build, computer, and domain from RDP, SMB, and Microsoft SQL Server's own NTLM negotiation, and they raise two findings: an FTP server that accepts anonymous sign-in (with its listing as evidence) and an RDP server that does not require Network Level Authentication.
3. **RDP screenshot.** A server the inventory stage showed accepts a connection without Network Level Authentication gets one pre-authentication login-screen capture, with no credentials sent, stored and read by the AI model for a signed-in account (see [Configuration](CONFIGURATION.md#settings-in-the-app)). A server that requires NLA is never attempted.
4. **Exposure checks.** One connection with no credentials to Redis, Memcached, PostgreSQL, MySQL, MongoDB, Elasticsearch, and CouchDB ports (an empty password for the default `postgres` and `root` accounts, never a password list). A server that answers is reported as a critical finding.
5. **nuclei, technology pass.** [nuclei](https://github.com/projectdiscovery/nuclei) HTTP and technology templates fingerprint each host.
6. **WAF fingerprint.** On by default (`CVENGINE_WAFW00F=0` turns it off). [wafw00f](https://github.com/EnableSecurity/wafw00f) names the web application firewall in front of each web host with a few requests (up to 25 hosts per scan, 60 seconds each; it runs only when a host answered over HTTP and the binary is present), and the product is stored as a technology of the host (a product, never a version). A generic block that names no product, and a host with nothing in front of it, store nothing. Some of its requests carry attack-looking strings, so a firewall may log them. bbot's own WAF events are stored the same way.
7. **Web route checks.** For each web host, cvENGINE sends one plain anonymous GET to a handful of common routes (`/`, `/login`, `/admin`, `/api`, and paths bbot found) and labels each `open`, `login`, `session_required`, `sso`, or `redirect`. The response is scanned in memory for sensitive data such as cloud keys, personal data, and internal identifiers. Only the type, a count, and a masked sample are stored. The page's headers, generator tag, and script names, plus the comment banners of up to four scripts the host serves itself, name the technologies and libraries it runs (jQuery, Bootstrap, AngularJS, and others) with versions, so an old library is correlated like any other technology.
8. **Version and identity probes.** A product the earlier stages saw without a version (nginx, Next.js, jQuery, an nmap service with no version) is a lead. cvENGINE asks the host for the missing fact with safe, read-only probes chosen by rule, with no AI: see [Version and identity probes](#version-and-identity-probes).
9. **WordPress detection and WPScan.** Every host that shows any sign of WordPress is probed and scanned with [WPScan](https://wpscan.com/), and nothing is skipped silently: see [WordPress and WPScan](#wordpress-and-wpscan).
10. **node2shell.** Off by default (`CVENGINE_NODE2SHELL=1` turns it on). Hosts fingerprinted as Node.js (or a framework on it), Bun or Envoy are checked for CVE-2026-111497 (`CVENGINE_NODE2SHELL_SCOPE=all` checks every web host) with [Assetnote's own read-only detector](https://github.com/assetnote/node2shell-scanner) (see [Configuration](CONFIGURATION.md#settings-in-the-app)).
11. **CVE correlation.** The inventory is matched against the CVE store.
12. **nuclei, AI-targeted pass.** Your AI model sees the technology names found on each host and picks nuclei tags from those the installed templates use. A built-in technology map always adds its tags. Hosts with the same choice are scanned together, and each host's fire and smoke CVE matches get a template test.
13. **Triage, validation, and changes.** See below.

The daily hygiene task also asks the Internet Archive, once a week per target, for the URLs it saved. A `.php` page or a `/wp-content/` path says a host ran PHP or WordPress at some point. That is kept as historical evidence only: search finds the host and labels it *seen in web archive*, and it is never treated as a current technology.

**Hygiene** runs as its own task when the scan finishes: TLS certificates (expiry, trust chain, hostname, self-signed, legacy protocols), SPF, DKIM, DMARC, and CAA, plus the checks of [MailFail](https://github.com/ACK-J/MailFail) re-implemented server side: records receivers ignore, report addresses on domains anyone can register, unauthorized DMARC reports, weak DKIM and ARC keys, Microsoft 365 Direct Send exposure, MTA-STS, TLS reporting, DANE, DNSSEC, BIMI, and MailChannels lockdown. None sends mail. `CVENGINE_HYGIENE_RDAP=0` turns off the registry lookups.

By default nuclei runs the whole installed template library (denial-of-service templates stay excluded, and the AI-written templates always stay read-only). An App Admin can turn that off under **Settings, Scan engines**, and then every nuclei run uses a snapshot of the installed templates that passed read-only and destination checks: plain GET, HEAD or OPTIONS requests to the scanned host only, no payloads, bodies, code or out-of-band (interactsh) checks. A template may follow redirects on the same host, up to three (nuclei's `host-redirects`, which the technology detection template uses); one that follows redirects to other hosts is left out. The AI-written templates may not follow redirects at all. A superuser can switch on **Settings, Scan engines, Nuclei templates** ([Configuration](CONFIGURATION.md#settings-in-the-app)): then every installed template runs in the broad scans and when a match is validated, except nuclei's denial-of-service templates. Out-of-band checks stay off, and AI-written templates stay read-only.

### runZero between scans

A project with a runZero token is also synced from [runZero](CONFIGURATION.md#runzero), outside any scan. The sync stores runZero's OS, hardware, tags and CVE reports on the addresses cvENGINE already holds and, if the project turned import on, adds runZero addresses it does not know as targets through the Add targets path (exclusions, private-range policy and organization uniqueness included). runZero's CVE reports only raise the confidence of a match this pipeline already made; they never create or confirm one.

### Inventory details

- **Port discovery.** By default [naabu](https://github.com/projectdiscovery/naabu) sweeps all 65,535 TCP ports of each address (SYN, 1,000 packets a second) and nmap fingerprints only the open ports it found plus ports already known open. If naabu is off (`CVENGINE_NAABU=0`), missing, fails, or sees more than 500 open ports on one address, nmap falls back to the top 1,000 ports plus 37 high-risk ones.
- **Scripts.** nmap runs at version intensity 7 with 18 reviewed scripts: banner, SSH host key and algorithms, TLS certificate, HTTP headers and title, anonymous FTP, RDP NTLM and encryption, SMB OS discovery, NetBIOS, and the MySQL, SQL Server, MongoDB, Redis, Memcached, and CouchDB greetings. nmap's `-sV` also runs its own version scripts. Their output is dropped before storage, because only the reviewed scripts are trusted to be read-only.
- **The background port sweep** fingerprints what it finds with `-sV` only: no scripts and no OS guess until the next regular scan.
- **What queues for memory.** bbot, nuclei, nmap, naabu, route checks, and template tests wait in the memory-aware queue. wafw00f, WPScan, RDP screenshots, node2shell, and the database checks do not.
- **Per-host limits.** At most 10 CVE template tests per host. Route checks make up to 20 requests per host, 1,500 per scan, 0.2 seconds apart.

## Triage and validation

CVE matches, scanner findings, open databases, open admin routes, routes exposing credentials, and hygiene findings of medium severity or worse are queued for triage, within daily caps. Each finding carries a classification (`confirmed`, `likely`, `needs_validation`, `likely_false_positive`, `not_applicable`), why it matters, how to fix it, when it was first and last seen, and every check that ran. Nothing is deleted or hidden: a likely false positive sorts last. Without an AI provider, findings read "not triaged" and validation still runs.

**Fixed rules keep the model honest.** Hard evidence sets a floor the model cannot go below. A template hit, a database that answered, a distribution tracker that lists the package as vulnerable, a scanner finding whose template matcher fired at medium severity or higher, and a route serving a credential are `confirmed`. A version inside a CVE's affected range is at least `needs_validation`. An open admin route is at least `likely`. The model alone can never confirm a finding. A reply that breaks the answer schema is sent back to the model once with the exact reason, and the second answer is used. If that is also rejected, the finding shows a diagnostic you can copy (the reason and the number of attempts, never the reply text) and a later pass retries it.

**One question per kind of evidence.** The model sees cleaned, structured evidence (product, version, advisory range, template id, counts) with hostnames redacted. Findings with the same evidence share one saved answer.

**Validation runs by itself.** cvENGINE reproduces a finding with one of five read-only checks and records the exact command and result: a vetted nuclei template, `nmap -sV` on the one port, a HEAD request for the version banner, the credential-less database check, or a version and identity probe (see [below](#version-and-identity-probes)). A hit confirms the finding. A check that does not reproduce it never lowers it, because templates can miss behind a WAF or on another virtual host. A banner that only shows a version is recorded as `observed`. Every five minutes a dedicated worker queues up to 20 findings: fire first, then smoke, then every other CVE match (`CVENGINE_AUTO_VALIDATE_ALL_MATCHES=0` leaves those out). A project has at most 10 active jobs, 5 of them cold. Checks are not repeated within 24 hours.

**Validate now.** Matches are validated automatically, so this is for jumping the queue: on any CVE match, **Validate now** (or the API) has the AI plan the checks, runs them, and has the AI review the evidence. The plan can only choose checks the scope and template policy already allow. When a CVE cannot be answered from outside, such as a local kernel flaw, the match records that no external check applies.

**When nothing can be checked from outside**, cvENGINE asks the AI once for at most three short, read-only commands a person with shell access to the host could run themselves, such as checking for a package, a process, or a config path named in the advisory, with what the output would mean. It is suggestion only, unverified by this tool, shown under **Confirm it yourself** beside the usual "no check exists" message, never a classification or evidence of anything. The model is told never to suggest a command that changes the host or needs a credential, and to say so plainly when it is not confident of the exact way to detect a given product rather than invent one.

A daily sweep (triage 04:41 UTC, validation 05:17 UTC) catches whatever is left.

### How the AI investigates a lead

A finding is judged with everything cvENGINE holds about its host (`cveFeed/host_context.py`): technologies with their versions and where each was seen, the ports with product, version, extra info, banner, HTTP and TLS facts, the front page's headers and title, CDN, WAF, hosting and CNAME hints, certificates, the operating system guess and its runners-up, what runZero and the host inventory reporter said, what probes found or found hidden, earlier check results and the host's other CVE matches. It goes to the model as a second untrusted block, cleaned and capped, with no host name or address. The model is told, in order: is the advisory's product the product the host runs (nginx is not ingress-nginx or nginx-ui), is the version inside the range and did a probe state it or only a banner, is the host behind a CDN or WAF (then the Server header, X-Powered-By and error pages describe the edge, a tag such as `cloudflare` names the edge and not an application, and the origin version is unknowable from here), and does the advisory need local state (then the host inventory reporter decides, not a network check).

**Closing a match needs concrete grounds.** A version inside an advisory's range stays a floor the model cannot clear, unless the application itself verified a ground from the host's metadata: a probe identified a look-alike product (the host's error page is plain nginx and the advisory names ingress-nginx), (and the host does not itself run the look-alike), or a CDN, WAF or hosting edge answers for the host on DNS-level evidence (its CNAME, its name, the CDN flag on an address: a response header such as `cf-ray` is the host's own say-so and counts for nothing) and the match rests on a web response (an SSH, database or mail banner is never the edge's). A match that has standing (worked by a person, a template hit, a distribution verdict, a host report) is never cleared this way. Then the model's `likely_false_positive` or `not_applicable` stands, with its reason. A banner or tag that states no version is never a reason to close a finding, and a template hit or a distribution's "vulnerable" verdict still floors it. When probes or an edge change what is known, the question is asked again without erasing the earlier validation record.

### Version and identity probes

The probe catalogue (`cveFeed/probes.py`) is data: an id, the products it helps with, the requests it makes and the patterns that read the answers. The application renders every request; no model writes one. Each probe sends only GETs (or an nmap service probe), no cookie and no credential, caps its requests, response size (256 KB) and time, goes through the same safe-address gate, exclusions, scan stop and pause as every other check, and logs to the activity feed.

| Probe | Finds |
| --- | --- |
| `headers-root` | The front page's `Server` header and the modules it lists (an Apache header names its PHP, OpenSSL and mod_wsgi versions), `X-Powered-By`, `X-AspNet-Version`, framework headers, `Via`, every generator meta tag and plugin comment, library versions in script names, and the CDN or WAF edge that answered |
| `error-page` | The footer of the server's own error page: `nginx/1.24.0`, Apache, Tomcat, Jetty, IIS Detailed Error; the Kubernetes `default backend - 404`; Express, Spring Boot and Next.js signatures |
| `nginx-variants` | nginx-ui and Nginx Proxy Manager (and its API version) as opposed to plain nginx |
| `nextjs-version` | The Next.js version a framework script states (`window.next={version:"..."}`) |
| `html-libraries` | jQuery, Bootstrap, AngularJS and other versions from script names and banners |
| `drupal-changelog`, `joomla-manifest` | Those products' version files |
| `robots-txt` | CMS hints in `robots.txt` |
| `wordpress-detect` | WordPress, by its login page, REST API (and the `Link: <.../wp-json/>; rel="https://api.w.org/"` header), generator tag, readme and core asset versions |
| `nmap-version-all` | `nmap -sV --version-all` on one port with the reviewed safe scripts for its service (`http-server-header`, `http-headers`, `http-generator`, `ssl-cert`, `banner`; `ssh2-enum-algos`, `ssh-hostkey`; `mysql-info`, `redis-info` and the like) |

**What is recorded.** Each result is a `ProbeObservation` (host, probe, product, version, identity variant, source, confidence, outcome) in the project: `found`, `hidden` (the product answers and states no version, which is a result: the AI is told the version is unknowable from outside), `edge` (only a CDN or WAF answered), `challenged` (the edge refused the scanner) or `absent`. A found version is also written as the host's technology (`nginx:1.24.0`; an nmap probe updates the Port row), the host is correlated again, and the deterministic rules then create a versioned match or none. A version is never guessed. Facts found inside the freshness window (`CVENGINE_TTL_PROBE`, 72 hours) are carried onto the next scan's host rows.

**No AI needed.** `plan_for_host` picks the probes for each lead by rule (at most five per host, one web base URL, no nmap probe where a CDN answers). In a validation request the AI may choose among the checks offered and reasons over their results, but a probe is always part of the plan when one applies, and a request ends with "no executable check" only when none does. The plan then says why: a kernel, driver or hardware advisory needs the host inventory reporter, since no network probe can read it. `CVENGINE_PROBE_MAX_HOSTS` (default 60) bounds the hosts probed per scan.

**Parsing.** Versions are read from what a service states and nothing else: `Apache-Coyote/1.1` is a connector's protocol version, not Tomcat's; `Jetty(9.4.51.v20230217)` and every `Name/version` token of an Apache `Server` header are read; a CPE technology (`cpe:/a:apache:http_server:2.4.41`, what Shodan's InternetDB gives bbot) and `Bootstrap:v3.3.7` are normalized to name and version; nmap's `tunnel="ssl"` marks a TLS web service on any port (so port 8444 is asked over HTTPS), its `ssl-cert` output fills the port's TLS facts, and a version that stops being stated (`server_tokens off`) is cleared from the port instead of kept.

### WordPress and WPScan

WPScan is the primary WordPress assessment. A host is a candidate when anything suggests WordPress: a technology tag, a front page fingerprint, a `wp-login.php` login form, a crawled `/wp-content/` URL, a page title or label, the web archive's memory of the host, or an earlier probe. A cheap read-only probe (`wordpress-detect`: `/`, `/wp-login.php`, `/wp-json/`, and `/readme.html` once positive) confirms it with browser-like request headers, follows apex and `www` redirects inside the host's group, reads a signature in the headers or the body, and is also run on every name that shares a candidate's address and on other web hosts up to `CVENGINE_WP_PROBE_MAX_HOSTS` (default 100). WPScan then runs on every candidate and every grouped name that probes positive, positive probes first.

Every candidate ends in a recorded state, shown on the host page and counted in `get_system_status` (`wordpress`: hosts, scanned, never scanned, with the reasons): `scanned` (when, findings, whether vulnerability data was checked, next scan), `detected` (not scanned yet), `candidate`, `blocked` (the edge challenged the scanner), `failed` (with the reason; retried at the next scan), `waiting` (over the per-scan limit), `unavailable` (WPScan not installed) or `not_wordpress`. When an edge answers with a challenge (`cf-mitigated`, "Just a moment", an Akamai, Sucuri or Imperva block page, or a 202, 403, 429 or 503 with no origin signature), cvENGINE does not push against it (a plain 429 or 503 is asked again once), records that the edge challenged the scanner, and tells the owner to allow the scanner's address or user agent in the WAF or bot rules. It never tries to solve a challenge or get past a WAF.

WPScan runs in two passes. The quick pass (in the scan) runs `--enumerate ap,at,cb,dbe,u1-10` with passive plugin and theme detection, a random user agent and a 100 ms throttle: the core, the plugins and themes the pages reference, config backups, database exports and author ids. In WPScan 4 plugin and theme detection fall back to the global mode unless they are set, so they are set explicitly: mixed mode with `ap` asks for every plugin slug WPScan knows. The thorough pass (`wpscan_thorough` on its own `wpscan_queue`) then runs mixed detection with timthumbs on each scanned host, one site at a time and one pass per project, for as long as it needs (`CVENGINE_WPSCAN_THOROUGH_TIMEOUT`, 12 hours; WPScan writes a partial report before the process is killed). It never blocks the scan, stops while scanning is paused and resumes, and shows `pending`, `running`, `done`, `partial`, `blocked` or `failed` on the host page and in `get_system_status`. A scan that WPScan could not finish still keeps what it read. WPScan exits 4 with `NotWordPress` only when it says so; a positive probe that WPScan could not confirm is `failed` ("WPScan could not see WordPress, the probe did"), because a WAF may serve it a decoy page. Plugin and theme versions need no API token. When the token's daily budget (25 requests on the free plan) is spent, the remaining sites are still scanned without it and say "not checked: API token budget exhausted"; such a run is repeated after a day, a clean run after a week (`CVENGINE_TTL_WPSCAN`, `CVENGINE_TTL_WPSCAN_PARTIAL`). Its findings (core, plugin and theme vulnerabilities with CVE ids and the fixed version, exposed backups and database exports, usernames, XML-RPC, outdated components) are normal findings with remediation text. The core, every plugin and every theme with a version also become sightings: a CVE for a plugin matches only when the plugin's slug or title (read from its own readme) equals the advisory's product or package name and its version is inside a bounded range (`wp-plugin` matches).

### TLS audit

[testssl.sh](https://testssl.sh) (GPLv2, run as a separate program) tests what a handshake cannot show: the protocols and cipher categories a server offers, forward secrecy, renegotiation and the TLS vulnerabilities that have names (Heartbleed, CCS injection, ROBOT, POODLE, FREAK, DROWN, Logjam, SWEET32, Ticketbleed, RC4, CRIME, Winshock, BEAST, Lucky13, BREACH). It is a slow background sweep, never part of a scan: `testssl_sweep` runs daily at 02:20 UTC on its own `testssl_queue`, tests one port at a time (about a minute each), the longest-waiting first, at most 40 per run (`CVENGINE_TESTSSL_MAX_TARGETS`), one sweep at a time, and stops while scanning is paused. A target is retested after 14 days (`CVENGINE_TTL_TESTSSL`); one that could not be tested is asked again after three days.

Targets are the TLS ports nmap found open on a host (443, 8443, 9443, 993, 995, 465, 636, and any port nmap called ssl or https), and 443 for a host with no port data. Mail and directory ports are tested with their STARTTLS dialect (SMTP on 25 and 587, IMAP, POP3, FTP, LDAP). Each target is tested at the address `cveFeed.pinned_transport` vetted (`--ip`, with `--nodns none`), so a name pointed at a prohibited address after it was stored is never contacted, and excluded and archived hosts are skipped. testssl.sh runs with a bare environment: no application secret reaches it.

What it records:

* **Configuration findings** (hygiene findings named `tlsa_*`): SSLv2 or SSLv3 offered, NULL, anonymous, export, low-strength and 3DES ciphers, no forward secrecy, missing secure renegotiation, weak Diffie-Hellman parameters, and every named vulnerability testssl.sh reports as vulnerable or potentially vulnerable, at testssl.sh's own severity. TLS 1.0 and 1.1 stay with the certificate check above (`tls_legacy_protocol`), and the certificate's own problems with `tls_*`. A finding resolves only when a later test of the same port ran and no longer reports it; a test that could not answer changes nothing.
* **Observations**: one per vulnerability test (found or absent) and one summary per port with the protocols offered, kept as `ProbeObservation` rows (kinds `tls-vuln` and `tls-audit`).
* **Hard CVE evidence.** A vulnerability testssl.sh proves is a CVE match (source `testssl`, one per CVE the test names) with the test result as evidence, and counts like a template confirmation: the AI cannot rule it out. Only results that say VULNERABLE count (Heartbleed answered with memory, a ROBOT oracle, an accepted export cipher, an accepted renegotiation); "potentially vulnerable" and mitigated results (BEAST, Lucky13, BREACH, SWEET32's 64-bit block warning) are findings, never CVE matches. A later test that finds the service no longer vulnerable closes the match unless a person already works it, and the next scan's host row gets the match back from the stored observation until then.

The x86-64 image bundles the openssl build that ships with testssl.sh, which still speaks SSLv2, SSLv3 and export ciphers. On arm64 testssl.sh uses the system openssl, which has those protocols compiled out: results for them are not reliable there.

### Other sites and applications on a host

Two slow background sweeps look for OTHER APPLICATIONS that could carry a known CVE. They are not content discovery: GET only, no body, no cookie, no credential, redirects never followed, a small curated set of questions, and a cap on what one host or address is asked. Both run on their own `vhost_queue` (a beat task each, `vhost_sweep` hourly and `subdir_apps_sweep` every 30 minutes, a few addresses or hosts per run), stop while scanning is paused, skip excluded and archived hosts and any address the scannable gate refuses, wait between requests (`CVENGINE_SLOW_WEB_GAP`, 1 second across all workers, and `CVENGINE_SLOW_WEB_HOST_GAP`, 2 seconds per host), and ask each question once per week (the service ledger: `vhost`, `subapp`). `CVENGINE_VHOST=0` and `CVENGINE_SUBDIR_APPS=0` turn them off.

**Virtual hosts** (`cveFeed/vhost_scan.py`). One address can serve several sites, told apart by the Host header (and the TLS server name). For each web address of a project (not a CDN or shared-platform address), the sweep asks `/` once with each name the project ALREADY knows that is not yet recorded as answering there: the hosts stored for the project, the names in the certificates seen on that address and the reverse names discovery recorded for it, and the names certificate transparency found. There is no wordlist and nothing is guessed. A name is asked only when it is in scope (equal to or under a domain target of the project; a host-scoped target covers its own name only): a name outside it is never asked and never added, whatever a certificate lists. At most 20 names per address and 5 addresses per run (`CVENGINE_VHOST_MAX_NAMES`, `CVENGINE_VHOST_MAX_IPS`). The answer (status, title, length, redirect target; never the body) is compared with the address's own default response and with the name's own site (its stored front-page route check, else one GET at its own address): `distinct` is another application, `default_site` (the address ignores the name) and `same_app` (the application the name already serves elsewhere) add nothing. A distinct application is recorded as a `ProbeObservation` of kind `vhost` (host the name, product the address, evidence the classification) and added to the project as a host row of its own (like the rows certificate transparency creates) linked to the address, so names that resolve to the same addresses stay one host with aliases exactly as the Hosts page already merges them; what its page states (a product and a version, in its headers and markers) becomes the host's technologies, which the correlation reads. A later answer that is no longer distinct unlinks the address and says so in the record. The host page shows "Also served here" on the host that holds the address.

**Applications under subdirectories** (`cveFeed/subdir_apps.py`). A product installed under a path (`/jira`, `/grafana`, `/owa`) is invisible to a check that reads only the front page. For each web host (and each distinct virtual host, asked at its own address with its own name) the sweep sends one GET per path of the curated list `web/cveFeed/data/subdir_apps.json`, which holds each path, the product it indicates and the signatures that confirm it, plus at most 10 directories the host's own crawled URLs, archived URLs, `robots.txt` and `sitemap.xml` already show, and three fixed requests (a path no site serves, as the baseline, `/robots.txt` and `/sitemap.xml`). At most `CVENGINE_SUBDIR_MAX_REQUESTS` requests per host per sweep (60) and `CVENGINE_SUBDIR_MAX_HOSTS` hosts per run (6). Only 200, 301, 302, 401 and 403 count as something being there, and an answer the server gives to every path (the baseline, or the front page) is not a mount. What answers is read from the response (title, a header, a marker in the body, a redirect to the product's login): a signature names the product, and a version pattern of that product reads the version when the page states one. A path that only answered is a **lead** (stored with its status, never a technology); a confirmed product that states no version is recorded as `hidden`, like a version probe does; a confirmed product AND a stated version is a Technology (`Jenkins:2.401.3`) of the host and the host is correlated again, so the CVE match rule above applies unchanged (a bare path hit is never a finding). No favicon hash is used. Results are `ProbeObservation` rows of kind `subapp` (an application that is gone at a later sweep becomes `absent`), shown on the host's Web tab as "Applications under subdirectories", and the versioned ones follow the host onto each new scan's rows. An edge that challenges or blocks a request (a Cloudflare challenge, an Akamai, Sucuri or Imperva block page) is recorded as `challenged` with what to allow and is never retried or worked around: that host or address is left alone until the next window.

The curated paths and the product each one indicates:

| Path | Product | Path | Product |
| --- | --- | --- | --- |
| `/jira/` | Jira | `/confluence/` | Confluence |
| `/bitbucket/` | Bitbucket | `/grafana/` | Grafana |
| `/wordpress/` | WordPress | `/phpmyadmin/` | phpMyAdmin |
| `/gitlab/` | GitLab | `/jenkins/` | Jenkins |
| `/owa/` | Microsoft Exchange Server | `/sonarqube/` | SonarQube |
| `/nexus/` | Nexus Repository Manager | `/artifactory/` | JFrog Artifactory |
| `/kibana/` | Kibana | `/zabbix/` | Zabbix |
| `/nagios/` | Nagios Core | `/cacti/` | Cacti |
| `/roundcube/` | Roundcube Webmail | `/squirrelmail/` | SquirrelMail |
| `/horde/` | Horde | `/joomla/` | Joomla |
| `/drupal/` | Drupal | `/moodle/` | Moodle |
| `/mediawiki/` | MediaWiki | `/redmine/` | Redmine |
| `/mantis/` | Mantis Bug Tracker | `/bugzilla/` | Bugzilla |
| `/gitea/` | Gitea | `/portainer/` | Portainer |
| `/manager/html` | Apache Tomcat | `/solr/` | Apache Solr |
| `/zimbra/` | Zimbra | `/pgadmin4/` | pgAdmin |
| `/adminer/` | Adminer | `/prometheus/` | Prometheus |
| `/airflow/` | Apache Airflow | `/superset/` | Apache Superset |
| `/metabase/` | Metabase | `/nextcloud/` | Nextcloud |
| `/owncloud/` | ownCloud | `/typo3/` | TYPO3 |
| `/umbraco/` | Umbraco | `/sitecore/` | Sitecore |
| `/graylog/` | Graylog |  | |

### Authenticated checks

By default every request is anonymous. For an application the owner may test, an App Admin or the organization's admin can store request headers and a cookie for a target (the **Sign-in** button on the Targets page or `PUT /api/v1/projects/{slug}/targets/{id}/auth-credential`; the MCP server can list and revoke them but never takes a value, so a secret does not pass through a model's context), and Nuclei and the web route check then also see the signed-in application. Use a dedicated low-privilege test account, never a person's session, and choose an expiry of 30, 90 or 120 days (or `never`, which must be chosen on purpose): a session ends, and a stored value past its expiry is simply not sent (the target shows it as expired, and the list shows the days left). Scans send read-only requests (the Nuclei template read-only policy still applies), but an application can change state on a GET, so keep the account's data disposable.

**What is stored.** A label, up to ten header name and value pairs, an optional cookie string, the `scheme:port` origins it may go to (default `https:443`; plain `http` only if named), a mandatory expiry (30, 90 or 120 days from saving, or an explicit never, in which case none is stored), and the scope it is for, always chosen explicitly: one named host of the target, or all hosts of the target (the target's own name and every subdomain of it), which the page marks with a warning that the credential will be sent to every host of the target that is in scope and on the allowed origins. A blank host never means the whole target. The values are encrypted at rest with the same field key as every other secret (`make rotate-field-key` re-encrypts them), are write-only (every read returns the header and cookie names, never a value; sending a blank value for a name already stored keeps it), and are never logged: the audit log records the label, the header names and the origins. A value must be 6 to 2,000 characters on one line, because a shorter one could not be told apart from ordinary text when it is removed from stored evidence.

**Scope.** A credential is attached to a request only when its destination host is exactly the host it was stored for (or, for a target-wide one, the target's name or one of its subdomains, and never for a host-only target's subdomains), the destination scheme and port are one of its origins, and it has not expired. That check runs after the normal vetting (pinned addresses, `scannable_hosts`, exclusions, archived hosts) and the global pause, never widens it, and applies per request: a different host, a different port or scheme, a third-party host and another target or project never receive it, and a redirect is never followed with it.

**Where it is used.**

- **Nuclei** (the blanket and targeted passes, the weekly deep pass and the CVE template checks). The plain pass runs as before; then the same selection (tags, severities, the approved read-only template library) runs again over explicit `scheme://host[:port]` URLs of exactly the covered origins. The values are written to a nuclei secrets file (`-sf`, the `static` format of nuclei's authenticated scans, one `Header` secret per credential limited to the listed domains) in a private temporary directory (0700, file 0600) that is deleted when the run ends, never on the command line, in the environment or in a log; the run also gets `-dr` (no redirects), because nuclei would otherwise carry custom headers wherever a redirect leads. This was checked against the nuclei 3.11.1 source (`-sf` and `-dr` exist, secrets are looked up per request on the request's host and port, 80 and 443 are treated alike); it was not run against a real nuclei in the build. Two limits: nuclei cannot tell `http://host` from `https://host` on the default ports, so two credentials that would need those two get only the HTTPS one, and a template that hardcodes `http://{{Hostname}}` would send the values over plain HTTP to the same host (the read-only policy and the explicit HTTPS targets make this rare, but it is possible).
- **Web route check** (`cveFeed/route_auth.py`). Each covered route is asked once more with the headers and cookie, one GET with no redirect followed, and the answer is stored in the route's evidence as `authenticated` (state, status, title, redirect target, when), beside the anonymous state, which is unchanged. The body of a signed-in page is never searched for sensitive data and never stored. When a route still shows a login page, the activity line says the stored session may no longer be valid.
- **Not used**, deliberately: the version and identity probes and the WordPress probe (they follow redirects between names, and what they look for is on the public front page), WPScan, bbot, nmap and the TLS and hygiene checks.

**Findings.** A finding saved from a signed-in request carries the tag `seen-while-authenticated` (also `seen_while_authenticated` in the findings API), its activity line says so, and a route's `authenticated` evidence is marked `seen_while_authenticated`. Every stored request, response, curl command and extracted value of a signed-in result has the header values, the cookie and cookie values, the part of a value after its scheme word (`Bearer abc` gives `abc`) and their URL, JSON and base64 forms replaced with `[redacted]` before it is saved, and the same applies to error text. Signed-in nuclei runs have their own ledger keys (`nuclei-auth`, 24 hours, `CVENGINE_TTL_NUCLEI_AUTH`; `route-auth-signed`, 24 hours, `CVENGINE_TTL_ROUTE_AUTH_SIGNED`) that include the credential's revision, so a replaced credential is used at once.

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

## One host, many names

Names that resolve to exactly the same set of addresses are one host in a project: `example.com` and `www.example.com` on the same servers. The project's own target name is shown (otherwise the shortest), the other names appear as **Also answers to**, and CVE matches, findings, and exposure are counted once. Names behind a CDN or shared edge address, names with a different set of addresses, names that never resolved, and the same addresses in another project stay separate hosts. The dashboard, Hosts page, history, and API count the same way.

## Host score

Every host has a score from 0 to 100 and the reasons behind it, shown as "Why the score is N" on the Hosts page. Hosts, search, and the attack-surface map sort highest first. The score adds capped components: CVE matches (fire 40, smoke 20, ice 5, plus 10 for an AI-confirmed fire match, up to 50), open findings (up to 25), web route auth (up to 15), sensitive data (up to 25), a public IP (10), recent change (up to 10), and zombies (up to 15). It is recomputed after each scan, when a verdict is saved, and daily.

## CVE intelligence

1. **Feed.** The [cve.now](https://cve.now) feed brings CVSS and affected version ranges. Each sync adds new CVEs and refreshes up to 10 more, either ones that have matches or ones published in the last 90 days that arrived with no affected-product data, so a CVE that gains an exploit or a new range updates its matches. An hourly task covers the last 14 days of the feed.
2. **Exploitation sources.** An hourly task (`sync_threat_intel`) also reads sources that cover the whole history: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [ENISA EUVD](https://euvd.enisa.europa.eu/) (exploited in the wild), optionally [VulnCheck KEV](https://docs.vulncheck.com/community/vulncheck-kev/introduction) (needs `CVENGINE_VULNCHECK_API_KEY`), [FIRST EPSS](https://www.first.org/epss/) (probability of exploitation), [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) (public exploit code), and [Metasploit](https://github.com/rapid7/metasploit-framework) (weaponized modules). A source only adds evidence: a CVE missing from one never loses what another reported, and the CVE detail names each source. A CVE these sources name that is not stored is imported from its [CVE List V5](https://github.com/CVEProject/cvelistV5) record, up to 2,000 an hour, known exploited first, so the whole exploited history is in within hours.
3. **Tier** (see [Fire, smoke, and ice](FIRE-SMOKE-ICE.md)). *Fire*: known exploited, has a public exploit, has CVSS 9.0 or higher, or has EPSS of 0.1 or more with CVSS 7.0 or higher. *Smoke*: CVSS 7.0 or higher, or EPSS of 0.1 or more. *Ice*: everything else.
4. **Match.** A match is a finding, so it needs hard evidence about the host: the product it runs is the *same product* the CVE names **and** its version is inside a bounded affected range. Other evidence only attaches to a match that exists: a template hit, a distribution tracker verdict, a report from the host's own inventory, or runZero reporting the same CVE.
   - **Same product.** CPE equality, the same normalised name, or a known alias (`Next.js` and the npm package `next`). A shorter name matches a longer one only when the extra words describe the same product (`server`, `http`, `daemon`, `framework`, `core`, a vendor in front such as `Apache` or `F5`) or name an edition or service of it: `apache` is `Apache HTTP Server`, `nginx` is `NGINX Open Source` and `NGINX Plus`, `Grafana` is `Grafana OSS`, `GitLab` is `GitLab CE/EE`, `Postfix` is `Postfix smtpd`, `FortiOS` is `Fortinet FortiOS` and `Exchange Server` is `Microsoft Exchange Server 2016 Cumulative Update 14`. Anything else around a name is another product: `nginx` is not `ingress-nginx`, `nginx-ui` or `NGINX Ingress Controller`, `php` is not `phpMyAdmin`, `cloudflare` is not a plugin that works with it, `WordPress` is not one of its plugins, `jquery-ui-rails` (a gem with its own version numbers) is not jQuery UI, and a bare `Apache` banner is not Tomcat or Log4j. A technology stored as a CPE (`cpe:/a:openbsd:openssh:7.2p2`) or a banner token (`OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`) is read as its product and version first. An entry for another product is never range-tested, so a version is never compared with the wrong product's ranges.
   - **No version, no match.** A product seen with no version (a bare `nginx` fingerprint) says nothing about which of its hundreds of advisories apply, so it never creates a match. It stays on the host as a technology or port and is listed as an *unverified product* (the host page, the host record's `unverified_products`, and `unversioned_products(host)` in code) for whatever finds the version: a banner read, a version probe, a host inventory. Once a version is known the product matches like any other.
   - **No usable bound, no match.** An advisory that names the product but gives no version bound ("all versions", "unspecified", a git range) cannot be tested against the host's version, so it is not evidence either. Two exceptions, both kept as low-confidence candidates that need validation (never an "affected" verdict): a version older than every branch an advisory lists for a fire or smoke CVE (end-of-life branches get no fix), and a CISA KEV advisory with no usable bound (Apache HTTP Server CVE-2021-41773, Jenkins CVE-2024-23897 and similar) for a host running that product at a known version, stored with `evidence.unbounded`. An unbounded advisory of any other CVE stays unmatched, but the host is still template-tested when the CVE is fire or smoke.
   - **Operating systems.** An OS fingerprint (`Ubuntu`, `Windows Server`, an nmap `cpe:/o:` record) never matches a CVE by name from outside, and a CVE whose product is only an operating-system kernel or component (Linux kernel records with no network vector, Windows kernel and Win32k) is `local_only` and never matched: only a match the host reports itself (source `host`) can place its kernel or patch level, and such a match is never closed automatically. A kernel flaw reachable over a network, or on the KEV list, is not host-only. nmap's OS CPE does not turn an application into an OS: `Microsoft HTTPAPI httpd` and `Linux telnetd` stay applications.
   - **Existing data.** After every update, `correlate_cves` and the authoring task close the open matches the old rules made on a name alone ("Closed automatically: no version evidence ..."), and the periodic `reconcile_invalid_correlations` closes wrong-product and OS matches by re-reading the sighting each was made from. A match is kept when anything vouches for it: a person worked it (remediation other than open), assigned it, commented on it or asked for a validation, the AI confirmed it, or it has a template hit, a distribution "vulnerable" verdict, a runZero report or a host report. The closure also settles the match's triage row ("not applicable") and refreshes the dashboard counts. Closed matches are not counted in heat, scores, dashboards or notifications, and a later correlation does not reopen them unless the evidence changes (a version appears). A match whose version moved out of range or whose product is gone is closed. Each match stores its evidence.
5. **Distro backports.** Linux distributions fix CVEs without changing the upstream version. cvENGINE reads the distribution and package release from the banner and, for Ubuntu and Debian, compares it with the fixed version from the [Debian security tracker](https://security-tracker.debian.org) and [OSV](https://osv.dev), labeling the match *patched by distro*, *vulnerable per distro tracker*, or *version-only*. Other distributions, such as RHEL, are recognized and stay version-only. Matches are labeled, never dropped.
6. **Auto-fire (optional, off by default).** After a feed sync stores new CVEs, each new fire or smoke CVE is handled once (a run that ended in an error is retried for 48 hours). The AI confirms its matches, and the ones it calls affected or uncertain are tested on their hosts. Hosts that run the CVE's product with no version found have no match, but they are tested too: a template test is a hard check that needs no version. The cap is set under **Settings, AI model** (default 200 hosts per CVE).
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
exploit probability, then score), so a new CVE from any feed gets one within the hour and the back catalog fills in behind it:

1. The **rules author** reads the CVE's own affected products and ranges, and any installed nuclei template. No AI, no cost.
2. The **AI author** is asked once per CVE, for the hot ones only (known exploited, exploit probability or public exploit, or a
   critical score), and only within `CVENGINE_DETECTION_AI_PER_DAY` (default 25; 5 per run). It sees feed text only, never a project
   or an asset, and its answer is parsed against the schema: a check that does not validate is dropped on its own, and the reason is
   kept on the record. Its checks are added after the rules' checks with an `ai-` id and never replace them. A failed ask is retried
   after a week when the model returned nothing it could parse. An answer that parsed but failed validation is kept with its reasons and not asked again. The same task refreshes the nuclei templates outside the schedule, at most every 3 hours, when a hot CVE from the last two days has no installed template.

A `manual` record is never overwritten. When a CVE's affected data changes, the rules checks are rewritten and the AI checks kept.
`manage.py author_cve_detections [--ai]` fills the whole catalog at once.

The policy the AI follows for each new CVE (scope first: `external`, `local_only`, `unclear`; then the record), when a record is revised, and how an administrator adds facts are in [CVE-INTAKE.md](CVE-INTAKE.md). A CVE only usable from the host itself (`local_only`) is never matched to a host.

### Validating a match

Each detection record also says how to decide a match, so nobody has to rediscover it per CVE:

- `validation.remote_determinable` is `yes` (a nuclei template, an HTTP marker or a reviewed nmap script, at high or medium confidence, can decide it from outside), `partial` (only the reported version or the exposed service, which a backported fix can fool) or `no` (there is no remote check, or the attack vector is local or physical and nothing remote can decide it). `validation.max_remote_state` is the best a remote check can reach on the triage scale: `confirmed` (validated), `likely` or `needs_validation`.
- `validation.validated_when`, `needs_validation_when`, `likely_false_positive_when` and `not_applicable_when` list what moves a match to each state, and `recommended_tools` names the tools (nuclei, nmap, curl, openssl, the package manager, grep, systemctl).
- Every remote check has a `how`: the tool, the invocation with `<TARGET>` and `<PORT>` to fill in, and how to decide from the output. Every local check has `commands`: one read-only command per platform (Debian, Red Hat, Alpine, other Linux, Windows) with the shell, whether it needs elevated rights, an `explain` sentence for a person logged in to the host, and a structured `expect` (`version_lt`, `exit_code`, `output_equals`) that a future authenticated scan can evaluate without parsing prose.

The commands are rendered by the application from the validated parameters of each check, with every value quoted; a model never writes one, and a record read from a seed or a model reply has its commands thrown away and rendered again.

### Seeding the catalog

Building the catalog from the cve.now feed takes one request per CVE, so a new install used to spend hours rebuilding what another instance already had. A **seed** is the whole catalog as one file: every CVE (fire, smoke and ice) with its scores, exploitation signals, affected ranges and references, plus its detection record. On first start it is the first step of the first-run chain, ahead of the feed sync, and an install that still has fewer than 5,000 CVEs is offered it again when a worker starts (at most once a day). cvENGINE downloads the seed published as the `cve-seed` release of this repository, checks it against its manifest (count, size, sha256), imports the CVEs it lacks and their detection records, runs the correlation if there are already hosts, and the incremental feed carries on from there. Detection records marked `manual` are never exported or imported. A CVE already present is never overwritten, nothing in the file is trusted (each field is typed and clipped, each strategy is validated again), and offline or a failed check only means the feed builds the catalog up gradually, as before.

- Maintainer: on an instance with the full catalog, `make export-cve-seed` writes `web/cve-seed.jsonl.gz` and its manifest (it first writes any missing detection records), and `scripts/publish-cve-seed.sh` uploads both to the `cve-seed` release.
- Anyone: `manage.py import_cve_seed [file | --url https://...]` imports a file or the published seed by hand.
- `CVENGINE_CVE_SEED=off` turns the automatic load off; `CVENGINE_CVE_SEED_URL` points it at your own mirror (https, with the `.manifest.json` beside it).

## Keeping scans fast and polite

- **One run per host.** A successful scanner run is reused inside its window: 168 hours for nmap, bbot, route checks, naabu, firewall identification, deep nuclei, and archived-URL lookups, 24 hours for nuclei, the certificate watch, hygiene, re-tests, WPScan, node2shell, and RDP screenshots. Failed or skipped work never counts as coverage, and a Redis claim keeps two pipelines off the same asset. Set the windows with `CVENGINE_TTL_*` ([CONFIGURATION.md](CONFIGURATION.md)).
- **Parents are reused.** A target under one already discovered (`www.example.com` after `example.com`) skips bbot when its parent finished in the last 7 days.
- **Memory aware.** Heavy jobs wait in a queue that hands out memory by estimated cost. If memory runs short, the largest job stops first and bbot, nuclei, and nmap retry lighter. Watch it under **Settings, Resources**.
- **Rescan a host.** **Rescan host** (or `assess_host`) runs a full, fresh assessment of one host: DNS, ports, exposure, nuclei, firewall fingerprint, routes, correlation, AI triage, and TLS, ignoring recent results but keeping scope, exclusions, and resource limits. Progress shows stage by stage, and you can stop it.
- **New hosts between scans.** When the certificate watch sees a new hostname, a short pipeline runs on up to 200 new hosts: the same stages a scan ends with (nmap, RDP screenshot, exposure checks, technology pass, firewall fingerprint, route checks, WPScan, node2shell if enabled, correlation, targeted pass, triage, and change recording). Agents can start it with `rescan_hosts`.
- **Background full port scan.** A slow task sweeps all 65,535 TCP ports of one in-scope IP at a time (10 minutes per host at most), oldest first. Ports it finds are fingerprinted and the host is re-tested. `CVENGINE_FULLSCAN=0` turns it off.
- **Other sites and subdirectory applications.** Two slow sweeps on their own `vhost_queue` ask the project's known names at its web addresses and the well-known application paths of its web hosts, a few at a time, once a week each (see [Other sites and applications on a host](#other-sites-and-applications-on-a-host)). `CVENGINE_VHOST=0` and `CVENGINE_SUBDIR_APPS=0` turn them off.
- **Paced deep nuclei.** Every 10 minutes one due host gets the approved broad template set on its name and up to 20 nonstandard ports, which covers an inventory of about 1,000 hosts each week.
- **Weekly deep discovery.** Daily, each apex domain without a deep discovery in the last 7 days gets one, up to 50 per run. If only its subdomains were targets, the apex is added. This is the one automatic rediscovery without an AI model.
- **Pause everything.** An App Admin can **Pause all scanning** from **All projects, Activity**. The pause survives restarts: work that touches targets or spends AI budget waits, running scanners stop cooperatively, and running scans are marked aborted. Bookkeeping that touches no target keeps running (the feeds, notifications, pruning, rescoring). **Resume** releases the queue.

### Cloud storage exposure

A slow background sweep (its own queue, `bucketscan_queue`, daily at 01:38 UTC, never part of a scan) looks for AWS S3, Google Cloud Storage and Azure Blob storage that belongs to a project's domains and is public or dangling. It reads only the storage platforms' documented endpoints, never a project host: anonymous HTTPS `GET` and `HEAD` on port 443, no credentials, no signature, one listing page (20 keys at most) and one `HEAD` of a listed object that does not look sensitive. Object content is never downloaded, nothing is written, and the storage endpoints (shared platforms) are never port-scanned. Each name is resolved once through the same vetted transport as the other probes, so an answer in a prohibited range is never connected to.

Candidate buckets, in order of ownership confidence (the tier is kept on the finding):

1. **cname.** A host of the project has a CNAME to a storage endpoint: `<bucket>.s3.amazonaws.com` and its regional and website forms, `c.storage.googleapis.com` (the host name is then the bucket), `<account>.blob.core.windows.net`.
2. **served.** A host answers with a storage `Server` header (`AmazonS3`, `UploadServer`); the bucket is inferred from the host name.
3. **reference.** A storage URL in data cvENGINE already holds: crawled and archived endpoints, page URLs, route redirects, stored scanner responses. An Azure container is tested only when such a URL names it.
4. **guess.** Permutations of the label of each target's registrable domain (`example`, `example-backup`, `example-assets`, `example-dev` and 37 more suffixes, plus the domain itself and its `www.` form at S3) checked at S3 and GCS. Azure account names are never guessed. Turn guesses off with `CVENGINE_BUCKETS_GUESS=0`.

| Result | Finding |
| --- | --- |
| Public listing, tier cname or served | High; critical when the listed names look like backups, database dumps or keys |
| Public listing, tier reference, name carries the project's own domain label | The same as above |
| Public listing, tier reference otherwise | Medium, "ownership unconfirmed" |
| Public listing, tier guess | Medium, never worse: "name guess, ownership unconfirmed, verify the bucket is yours" |
| Name not registered (S3 `NoSuchBucket`, Azure account with no DNS name), tier cname or reference | High, a takeover: anyone can register the name. A GCS name with a dot is medium, because only a verified domain owner may create it |
| Not registered, tier served or guess | Nothing: an inferred name proves nothing |
| Exists, listing refused | An observation (info) on the host, never a finding |

The findings are hygiene findings (check names `bkt_listing` and `bkt_takeover`), so status, assignee, comments, triage, notifications and the API work as for every other finding; the hygiene task leaves them alone. At most 20 object names are stored, and a name segment that looks like a secret (a provider key id, a token, a JWT, `key=value` with a secret word, a long random token) is stored as `[redacted]`. A finding resolves when a later check of the same bucket ran and no longer finds it, or when the reference that led to it is gone (a removed CNAME is the fix for a takeover); a check that gets no answer changes nothing and is asked again the next day.

Politeness: one global request rate shared by every worker (`CVENGINE_BUCKETS_RPS`, 2 a second by default, at most 5), at most `CVENGINE_BUCKETS_MAX_PER_SWEEP` buckets per project per sweep (strongest tier first, longest waiting first), a weekly window per bucket (`CVENGINE_TTL_BUCKETS`), one sweep at a time, and a stop while scanning is paused. Excluded names, hosts of an excluded domain, archived hosts, hosts that resolve to a prohibited address and projects whose bug bounty engagement has not confirmed automated testing are skipped.

### Shared platform addresses

A name on Netlify, Vercel, GitHub Pages, Heroku, or a CDN edge answers on addresses that belong to the platform. cvENGINE recognizes them from the name's CNAME, the `Server` header, or the CDN flag and never points nmap or the full-port sweep at them. The host record says so.

### Shared provider domains

A tenant of a multi-tenant provider owns only its own subdomain. For `acme.jfrog.com`, the registrable domain `jfrog.com` belongs to the provider and all its customers, so cvENGINE never promotes it to an apex or enumerates it. A curated list (`SHARED_DOMAINS` in `web/targetApp/shared_domains.py`) marks such domains, and a target under one is **host scoped**: bbot runs with strict scope, the apex sweep skips it, and the certificate watch asks only about that host. Each target has a **scope mode**: `auto` (the list decides), `host`, or `parent` (for a domain you control that sits on the list).

### Excluded hosts

An organization can remove a host and exclude it (**Remove & exclude**, or the API). An exclusion matches the exact host name, case-insensitively, and every stage skips an excluded host in every project of that organization. Adding it as a target is refused. The Hosts page shows names that point at the same addresses as one host, so **Remove & exclude** offers to take those other names with it (otherwise the next name would simply take its place on the page). To drop a whole domain, put `-example.com` on a line in **Add targets** (or call `exclude_host` with `include_subdomains`): the name, every name under it (`www.example.com`, `a.b.example.com`, never `notexample.com`) and every target named like them are removed in every project of the organization you can write to, their running scans are stopped, and nothing under that domain is discovered, scanned or added again. A line such as `-com` or `-co.uk` is refused. **Delete host data** removes a host from one project only and leaves it free to be found again.

## The work conductor

Scans used to start only when someone asked or when a daily or weekly sweep ran, so for most of the day nothing was running even with a thousand hosts to look after. Now a watchdog runs every minute and keeps the discovery queue topped up: when fewer than `CVENGINE_WORK_DEPTH` scans (default 3) are running or queued, it starts standard-mode discovery of the targets that have gone longest without one: never scanned first, then the stalest. It starts at most one per project per round so no project starves the others, and it never picks a target scanned within `CVENGINE_WORK_MIN_GAP_HOURS` (default 2), one that already has a scan going, one an organization excluded, a project whose bug bounty engagement has not confirmed that automated testing is allowed (or is paused or finished), or anything at all while scanning is paused (an update's pause included). Each start is logged in the target's project activity. Set `CVENGINE_WORK_DEPTH=0` to turn it off. The system status (`get_system_status`, App Admin) shows its depth, the scans running and queued, and its last round, and reports a problem when targets exist, scanning is not paused and nothing is running or queued.

The other work that keeps the instance busy has its own schedule, below: validation of fire and smoke matches, re-tests of changed hosts, the paced full port scan and deep nuclei, triage, and the AI review every three hours.

## Schedules

A superuser can change CVE sync, certificate watch, the hygiene hour, and both time limits on the Administration page. The rest are fixed.

| Task | Default |
| --- | --- |
| CVE feed sync | every 30 minutes |
| Exploitation sources | hourly; each source re-read when due (6 to 24 hours) |
| Certificate watch | every 20 minutes |
| Hygiene sweep | daily at 03:17 UTC |
| TLS audit with testssl.sh (up to 40 ports per run) | daily at 02:20 UTC |
| Discovery time limit, per bbot run | 6 hours |
| nuclei time limit, per run | 4 hours |
| Work conductor (keeps the discovery queue fed) | every minute |
| Tailscale sync (devices, findings, scans of connected tailnets; [Tailscale](TAILSCALE.md)) | every 15 minutes |
| Validation of every CVE match (fire first), change re-tests | every 5 minutes |
| Cloud storage exposure sweep ([details](#cloud-storage-exposure)) | daily at 01:38 UTC |
| Other sites on an address (`vhost_sweep`), applications under subdirectories (`subdir_apps_sweep`) | hourly at :27, and every 30 minutes at :13 and :43, on `vhost_queue` |
| Background full port scan, paced deep nuclei | every 10 minutes, one host per run |
| AI review and capacity tuning | every 3 hours |
| Stuck job cleanup | every 15 minutes |
| runZero sync (projects with a token) | checked hourly, each project every 6 hours (`CVENGINE_RUNZERO_SYNC_HOURS`) |
| CVE feed coverage, bounty catalogue | hourly |
| Archived host rediscovery, inactive host review | daily |
| Deep discovery of apex domains | daily at 02:43 UTC |
| Distro fix sync | daily at 03:17 UTC |
| Triage and validation sweeps | daily at 04:41 and 05:17 UTC |
| nuclei template update | 04:41, 10:41, 16:41, and 22:41 UTC |
| CVE detection authoring | every 30 minutes, at :17 and :47 |
| Daily statistics snapshot | daily at 02:11 UTC |
| Invalid correlation reconcile | every 5 minutes |
| Update check | 05:23 and 17:23 UTC |
| Host rescore | daily at 05:29 UTC |
| Change log pruning (90 days) | daily at 04:11 UTC |
| Log archive and cleanup | Sundays at 03:23 UTC |

See also: [ARCHITECTURE.md](ARCHITECTURE.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
