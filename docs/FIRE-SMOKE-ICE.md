# Fire, smoke, and ice

Every CVE that cvENGINE reads, and every CVE finding on your hosts, gets a temperature: **fire**, **smoke**, or **ice**. It is how cvENGINE decides what deserves attention first, and it drives the dashboard, notifications, the validation order, OpenVAS and the remediation queue.

## Why it matters

Thousands of CVEs are published every month, and most are never exploited in the wild. A severity score alone (CVSS) tells you how bad a flaw could be, not whether anyone is using it, and a probability (EPSS) is a forecast, not a fact. Chasing every high score buries you. So heat rests on two facts: **is the CVE being exploited**, and **is it really on your host**.

- **Known exploitation**: CISA KEV, ENISA EUVD's exploited list, or VulnCheck KEV (with a key), catalogs of vulnerabilities known to be exploited in the wild. In this page "on the KEV" means any of them.
- **A public exploit**: an Exploit-DB entry or a Metasploit module.
- **Proof on the host** (below): a check reproduced it, the host or its distribution reported it, or the version was read from the component itself.

CVSS and EPSS stay on every row, column, sort, badge, report and in the AI's context. They no longer set heat.

## The rule (the heat policy)

| Heat | Rule |
| --- | --- |
| **Fire** | On the KEV (or with a public exploit) **and** the vulnerable version is **proven** on the host |
| **Smoke** | On the KEV (or with a public exploit) **and** we only **think** the version is there (an inferred version) |
| **Ice** | **Not** on the KEV **and** no public exploit, whatever its CVSS or EPSS, proven or not |

Two overrides keep their meaning: a match whose fix the host's **distribution backported** is ice, and so is one whose CVE publishes **no affected version range** (kept for review, see below).

KEV itself means exploited in the wild, so a KEV entry satisfies "with an exploit" on its own; a public exploit without a KEV listing counts the same. A CVE in general (the feed, before it meets a host) is **fire** when it is on the KEV or has a public exploit and **ice** otherwise: smoke is a statement about a host ("we think it is here"), so the feed has none.

The rule is deterministic, runs before any AI is involved, and lives in one place: `web/cveFeed/threat.py` (`is_hot`, `match_heat`) and `web/cveFeed/match_policy.py` (`version_proven`, the one definition of proof).

### What counts as proof

The rule is about **proving the version is present**, not about proving the flaw is exploitable. cvENGINE keeps two notions apart:

- **Vulnerability confirmed** (`match_policy.has_hard_evidence`): something showed the flaw itself, or an authority on the host vouched for it. A behavioural template hit (`template_result = vulnerable`: a nuclei CVE template that shows the flaw, a confirmed OpenVAS test, testssl), the distribution's tracker listing the installed package as vulnerable, the host's own inventory report, runZero reporting the CVE on that host, or a validation hit (one of cvENGINE's read-only checks reproduced it). Only this lifts the AI's classification above *needs validation*, creates a confirmed scanner finding, counts as a validation `hit` and is announced as a confirmed template hit.
- **Version proven** (`match_policy.version_read_from_component`): the vulnerable version was read from the component itself at high confidence, with nothing shown about the flaw. A version-class template hit (`template_result = version_only`: a template that only reads a static page or a banner and decides on a version string), a JavaScript library's own file banner or code signature, or a service banner nmap's probe read from a vendor-built product (one no distribution packages and the operating system does not service). It makes no finding, is not a validation `hit` and leaves triage at *needs validation*, but it is what the heat rule asks for.

`match_policy.version_proven(match)`, the one definition the heat reads, is the union of the two: hot and version proven is **fire**, even when the flaw itself has not been shown. In detail, it is true when the match has either:

1. **Hard evidence about the host** ("vulnerability confirmed" above); or
2. **The version read from the component itself** ("version proven" above):
   - a version-class template hit on the host (`template_result = version_only`);
   - a JavaScript library whose **own file** states the version: its comment banner (confidence 0.9) or a code signature only the library's file has (0.8), for the copy that actually runs on the page (`evidence.version_source = body`, `copy_state = effective`, confidence at least 0.8);
   - a network service that answered **nmap's version probe** itself (`evidence.method = probed`), of a **vendor-built product** (`evidence.vendor_banner`: on the allow-list `match_policy.VENDOR_PRODUCT_PREFIXES`, `match_policy.vendor_built`), and whose banner shows **no distribution packaging** either (`evidence.distro` absent). The list is positive, so it fails safe: a product cvENGINE does not know is no proof by its banner. It holds the vendor-built, self-contained products where KEV entries concentrate: VPN gateways and firewalls (Fortinet, Citrix NetScaler, Ivanti and Pulse Secure, Palo Alto, SonicWall, F5 BIG-IP), file-transfer and IT management servers (MOVEit, GoAnywhere, CrushFTP, ManageEngine, SolarWinds), Jenkins, Atlassian, GitLab, TeamCity, Zimbra, WebLogic, VMware vCenter, and Apache projects shipped as their own build (ActiveMQ, Solr, Spark, OFBiz, ...).

Never proof (smoke at most when hot):

- a version from a script's file name, CDN path or `?ver=` query string (confidence 0.4 or less);
- a copy of a library a later one replaces, a fallback, or a copy of a set whose running copy is unknown (their confidence is capped at 0.4 and 0.5);
- technology detection (Wappalyzer, httpx, a page generator, a response header), WPScan, an OpenVAS test below its quality bar, a library version another tool read;
- a version inherited from another host or a redirect;
- the banner of a **product a distribution packages**, whether or not it names the distribution (`OpenSSH 9.6p1 Ubuntu-3ubuntu13.5`, `Apache/2.4.6 (CentOS)`, but also RHEL's bare `OpenSSH 7.4 (protocol 2.0)`, SUSE's `Apache httpd 2.4.51 (Linux/SUSE)`, Amazon Linux's `() OpenSSL/1.0.2k-fips`, nginx on RHEL, FreeBSD, Oracle and Fedora builds): OpenSSH, Apache httpd, nginx, OpenSSL, MySQL and MariaDB, PostgreSQL, PHP, Exim, Postfix, BIND, Dovecot, Samba, ProFTPD, vsftpd and the other daemons distributions ship (PowerDNS, Asterisk, MIT and Heimdal Kerberos, Erlang, libssh, Tomcat, Jetty, Traffic Server, ...). Distributions backport fixes without changing the upstream version they print, so the banner proves nothing until the distribution's tracker says vulnerable (proof) or patched (ice). The same goes for a product the **operating system services** (IIS and HTTP.sys, Microsoft ESMTP and ftpd, patched by Windows Update with the version string unchanged), and for any product not on the vendor list;
- a port row stored before correlation recorded whether the product is vendor-built (`evidence.vendor_banner` absent): from the next correlation it reads as proof again; that pages nothing when the old row already proved the version but for that field, and pages once when the proof is new (nmap now probes the service, the version moved) (see Notifications);
- nmap's guess from the port number (`method = table`), or a port row stored before nmap's method was kept;
- an AI verdict: text never confirms.

To tighten the definition, drop a clause from `version_read_from_component` and its database form `version_read_from_component_q`; every list, count, score, alert and API follows. Triage keeps its own, stricter ceiling: the AI never rates a match above *needs validation* without hard evidence (`match_policy.is_version_only`), whatever the heat.

### Rolling back: `CVENGINE_HEAT_POLICY=legacy`

The policy is a setting: **Settings, configMaxxing, Heat policy** (1 the KEV rule, the default; 0 legacy), or `CVENGINE_HEAT_POLICY=kev|legacy` in `.env` ([Configuration](CONFIGURATION.md)). `legacy` brings back the rule before it, exactly:

| Tier | Legacy rule |
| --- | --- |
| **Fire** | Known exploited, **or** a public exploit, **or** CVSS 9.0 or higher, **or** EPSS of 0.1 or more with CVSS 7.0 or higher |
| **Smoke** | Not fire, and CVSS 7.0 or higher **or** EPSS of 0.1 or more |
| **Ice** | Everything else |

Under legacy a match inherits its CVE's tier, an AI-confirmed CVSS 7+ match reads fire, and a match with no hard evidence is held to `CVENGINE_VERSION_ONLY_MAX_HEAT` (`smoke` by default; a version read from a file is not hard evidence there). Under the KEV rule `CVENGINE_VERSION_ONLY_MAX_HEAT` is not read: the rule itself says what an unproven match shows.

A change applies at once to every list, count, map, report, alert and API (heat is computed when it is read, nothing is migrated). Host scores are stored: the first worker tick (every 30 seconds) or worker start that sees a different policy queues one full rescore, so they follow within minutes. The upgrade that introduced the policy queues that rescore once by itself.

## From the feed to your hosts

- **A match needs a version.** A tier says how dangerous a CVE is, not whether it applies. A host running a product with no version found has no match at all, until a version is identified: it is listed as an *unverified product*, not counted in heat or the score. The one exception is a CISA KEV advisory that gives no version bound, kept for a host running that product at a known version as a low-confidence candidate that needs validation. See [Match](PIPELINE.md#cve-intelligence).
- **A KEV match is fire only with proof.** A KEV (or exploited) CVE matched on a version we only inferred is **smoke**, with a **KEV** badge and the reason "on the KEV; version not proven". When proof lands (a validation hit, a template hit, the host's report, runZero, the distribution tracker, or a later scan reading the version from the file or the service itself) it turns **fire** at once.
- **Validation is how smoke earns fire.** The heat shown and the order of validation are separate: a KEV or exploited match whose version is not proven is validated in the fire lane, first (`threat.validation_heat`: the heat once proven). Every confirmer orders by it: the validation sweep, OpenVAS (which hosts it selects, Fire before Smoke, and the host's Checks line), and agent validation work (`queue_agent_work` with `kind: validate` and `tier: fire`). A CVE that is neither on the KEV nor exploited is ice in that order too: proving it would not change its heat, so it is validated last, with what Fire and Smoke leave.
- **Not on the KEV and no exploit is ice, even when proven.** A confirmed CVSS 9.8 flaw with a high EPSS and no exploitation evidence is ice, with the reason "not on the KEV and no known exploit"; its CVSS, EPSS and the proof stay on the row. It turns fire by itself the day it is listed on the KEV or gets a public exploit (the exploitation sources are read hourly).
- **An unknown version range makes it ice, and a review item.** That KEV candidate is a *version unknown* match: on the host it is ice, and it adds at most 2 points to the host score (1 each). It is marked for review ("Version of the CVE is not known: review when the affected versions are published"); only a person decides it, or the CVE gaining a version range does.
- **A distribution patch makes it ice.** If the host's distribution backported the fix, the match is ice however dangerous the CVE is. See [distro backports](PIPELINE.md#cve-intelligence).
- **A scanner finding that names a CVE follows the same rule.** A nuclei CVE template, the CVE template pass, an OpenVAS result, a WPScan finding or another scanner finding that carries CVE ids is a CVE on the host, so its heat is the CVE rule's, not its severity's: one of its CVEs on the KEV or with a public exploit, and the finding a confirmation (the template or the active test matched the flaw), is **fire**; hot but not confirmed (an OpenVAS result below its quality bar, tagged `qod-unconfirmed`, or a WPScan finding, which reads a plugin's version) is **smoke**, fire once a validation reproduces it; none of its CVEs on the KEV or exploited (or none stored by cvENGINE) is **ice**, whatever its severity. So a template-confirmed CVSS 9.8 CVE with no exploitation evidence is ice both as a match and as a finding. Its severity stays on the row; its share of the host score and its validation lane follow its heat too (a finding that names CVEs adds 25 points when fire, 10 when smoke, 3 when ice, instead of its severity's; it is validated in the fire lane when hot and not automatically when ice, as it is already a scanner's check). The CVE ids come from the scanner's own output: nuclei's `classification.cve-id`, the CVE template pass, OpenVAS and WPScan; a Sentinel's nuclei result carries them when the Sentinel reports `cve_ids`.
- **A host takes its hottest signal.** A host's heat is the hottest of its CVE matches and its open findings. A scanner finding that names no CVE (an exposure, a misconfiguration, a default login) and a hygiene finding have no KEV listing to read, so they keep their severity heat: critical and high read as fire, medium as smoke, low as ice. A host with nothing is clean, and one nothing has probed yet is not scanned. Under `legacy` every finding keeps its severity heat.

The 0 to 100 [host score](PIPELINE.md#host-score) reads a match's heat on the host, the same one the lists show: a fire match adds 40 points, smoke 20, and ice 5.

## Detection is not narrowed

The policy decides what a finding is worth, not what is looked for. Auto-fire, the CVE template pass on each host and correlation's end-of-life branch rule keep acting on the CVEs they always did: known exploited, a public exploit, CVSS 7 or higher, or EPSS reached (`threat.attention_tier`). A critical CVE without exploitation evidence is still correlated, template-tested and shown (as ice); if it reaches the KEV, it is already matched and tested.

## What the tiers drive

- **Dashboard.** The feed temperature bars count fire, smoke, and ice over every CVE (under the KEV rule a CVE in general is fire or ice). The attack-surface map, the Live graph and SOC mode color each host by its heat.
- **Hosts and search.** The Hosts page filters by a host's temperature (fire, smoke, ice, clean, not scanned), and the search API takes `heat=` the same way ([Search](SEARCH.md#reading-the-results)). The Findings and Matches lists, their `heat` filter, the PDF report's counts (with a legend for the policy in force and each finding's reason) and the daily stats history read the same heat. Both lists also filter on **Known exploited (KEV) only** (`kev=1`).
- **Notifications.** New matches that are fire on the host (on the KEV or exploited, and proven) are announced to your Slack, Discord, Telegram, or Lark channels. A smoke match is not paged when it is made; when proof later turns it fire it is paged then, once ("confirmed, now fire-tier"): a validation hit, the host's report, runZero, a version check, and proof that arrives through correlation (nmap starts to probe the service, a later route check reads the library's own file), which also rescores the host at once; a behavioural template hit is announced as a confirmed template hit. A proven match whose CVE later joins the KEV or gains a public exploit turns fire and is paged once ("turned fire-tier: the CVE is now on the KEV or has a known exploit"), at the hourly threat-intelligence read, the cve.now refresh or a forced cve.now backfill that brings the news (all of them, however many: what one run cannot claim is carried by the next); a match of that CVE whose version is not proven turns smoke and is not paged (it goes to the front of validation instead). Ice never pages: a template hit on a CVE that is neither on the KEV nor exploited is recorded and shown, not announced. Each finding is paged as fire at most once per heat rule (`CVEMatch.fire_notified_at` and `fire_notified_rule`), not once per scan: a rescan's copy of the same CVE on the same host carries the page. A change of the rule pages nothing by itself: when the rule changes (the update that introduced it, migration 0137; a switch on the card or in `.env`, or the legacy cap, picked up at worker start and on the 30 second tick), every match that is fire under the new rule and existed before the switch is marked as announced under it without a message. The mark is per rule: what was marked under legacy never holds back a page that is new under the KEV rule (a match legacy rated fire, which the KEV rule rated ice, is paged when its CVE joins the KEV), and the other way round. A match still waiting for its page is left to it: those of a scan still running (paged when it ends) and those made in the last six hours (a feed sync pages its new matches after the AI has judged them). The first correlation that records the new `vendor_banner` field on an old row pages nothing when the old row was already proven but for that field. Under `legacy` the new pages (proof through correlation, a CVE turning hot) are not sent, as before. Saved-search alerts are about the hosts a search matches and are unchanged.
- **OpenVAS.** OpenVAS is spent only on Fire and Smoke hosts by the validation heat, so a host whose only CVEs are ice (a high CVSS without exploitation evidence, as matches or as scanner findings) no longer qualifies; an open scanner finding that names no CVE, rated medium or above, still does ([OpenVAS](OPENVAS.md)).
- **Remediation.** The work list for agents and teams comes fire first.
- **API.** `GET cves?tier=fire` lists the CVEs of one tier ([AGENT-API.md](AGENT-API.md)). A match carries `cve.tier` (its heat on the host), `cve.feed_tier` (the CVE's own tier), `cve.validation_tier` (the heat once proven), `cve.heat_capped` (held below it), `cve.kev`, `cve.exploit_db`, `version_only`, `version_proven` and `heat_reason`; a Findings row carries `heat`, `heat_reason`, `kev`, `exploit`, `version_only`, `version_proven` and `heat_capped`, and a host's reasons carry `heat_reason`.

## A worked example

A CVE for a VPN gateway is published with CVSS 9.8. It is not on the KEV and has no public exploit: **ice**, CVSS 9.8 on the row, and it is correlated and template-tested like any critical CVE; one of your hosts runs the gateway, and nmap read its version from the vendor's own banner, so the match exists, proven, and shows ice. A week later CISA adds the CVE to the KEV. At the next threat-intelligence read (hourly) it is **fire** in the feed, that host's match turns **fire**, the host is rescored and the match is paged once ("turned fire-tier: the CVE is now on the KEV or has a known exploit"); the next scan's copy of it is not paged again. Another host only shows the gateway's version through technology detection: **smoke**, "on the KEV; version not proven", not paged, and first in line for validation. A read-only check reproduces it, the match turns **fire**, and it is paged once. A medium CVE in a library you do run, with no exploitation evidence, stays **ice** and never interrupts you.

See also: [PIPELINE.md](PIPELINE.md) for the full flow, [documentation index](README.md).
