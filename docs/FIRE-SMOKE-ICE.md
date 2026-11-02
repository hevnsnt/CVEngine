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
- **Version proven** (`match_policy.version_read_from_component`): the vulnerable version was read from the component itself at high confidence, with nothing shown about the flaw. A version-class template hit (`template_result = version_only`: a template that only reads a static page or a banner and decides on a version string), a JavaScript library's own file banner or code signature, or a service banner nmap's probe read from a service with no distribution packaging. It makes no finding, is not a validation `hit` and leaves triage at *needs validation*, but it is what the heat rule asks for.

`match_policy.version_proven(match)`, the one definition the heat reads, is the union of the two: hot and version proven is **fire**, even when the flaw itself has not been shown. In detail, it is true when the match has either:

1. **Hard evidence about the host** ("vulnerability confirmed" above); or
2. **The version read from the component itself** ("version proven" above):
   - a version-class template hit on the host (`template_result = version_only`);
   - a JavaScript library whose **own file** states the version: its comment banner (confidence 0.9) or a code signature only the library's file has (0.8), for the copy that actually runs on the page (`evidence.version_source = body`, `copy_state = effective`, confidence at least 0.8);
   - a network service that answered **nmap's version probe** itself (`evidence.method = probed`) and whose banner shows **no distribution packaging** (`evidence.distro` absent).

Never proof (smoke at most when hot):

- a version from a script's file name, CDN path or `?ver=` query string (confidence 0.4 or less);
- a copy of a library a later one replaces, a fallback, or a copy of a set whose running copy is unknown (their confidence is capped at 0.4 and 0.5);
- technology detection (Wappalyzer, httpx, a page generator, a response header), WPScan, an OpenVAS test below its quality bar, a library version another tool read;
- a version inherited from another host or a redirect;
- a **distribution-packaged server banner** (`OpenSSH 9.6p1 Ubuntu-3ubuntu13.5`, `Apache/2.4.6 (CentOS)`) while the distribution's tracker has no verdict: distributions backport fixes without changing the upstream version they print, so the banner proves nothing until the tracker says vulnerable (proof) or patched (ice);
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
- **A host takes its hottest signal.** A host's heat is the hottest of its CVE matches and its open findings (scanner and hygiene findings keep their severity: critical and high read as fire, medium as smoke, low as ice). A host with nothing is clean, and one nothing has probed yet is not scanned.

The 0 to 100 [host score](PIPELINE.md#host-score) reads a match's heat on the host, the same one the lists show: a fire match adds 40 points, smoke 20, and ice 5.

## Detection is not narrowed

The policy decides what a finding is worth, not what is looked for. Auto-fire, the CVE template pass on each host and correlation's end-of-life branch rule keep acting on the CVEs they always did: known exploited, a public exploit, CVSS 7 or higher, or EPSS reached (`threat.attention_tier`). A critical CVE without exploitation evidence is still correlated, template-tested and shown (as ice); if it reaches the KEV, it is already matched and tested.

## What the tiers drive

- **Dashboard.** The feed temperature bars count fire, smoke, and ice over every CVE (under the KEV rule a CVE in general is fire or ice). The attack-surface map, the Live graph and SOC mode color each host by its heat.
- **Hosts and search.** The Hosts page filters by a host's temperature (fire, smoke, ice, clean, not scanned), and the search API takes `heat=` the same way ([Search](SEARCH.md#reading-the-results)). The Findings and Matches lists, their `heat` filter, the PDF report's counts (with a legend for the policy in force and each finding's reason) and the daily stats history read the same heat. Both lists also filter on **Known exploited (KEV) only** (`kev=1`).
- **Notifications.** New matches that are fire on the host (on the KEV or exploited, and proven) are announced to your Slack, Discord, Telegram, or Lark channels. A smoke match is not paged when it is made; when proof later turns it fire it is paged then, once ("confirmed, now fire-tier", including when a version check proved the version; a behavioural template hit as a confirmed template hit). Ice never pages: a template hit on a CVE that is neither on the KEV nor exploited is recorded and shown, not announced. Each match is paged as fire at most once (`CVEMatch.fire_notified_at`). Saved-search alerts are about the hosts a search matches and are unchanged.
- **OpenVAS.** OpenVAS is spent only on Fire and Smoke hosts by the validation heat, so a host whose only CVE matches are ice (a high CVSS without exploitation evidence) no longer qualifies; an open scanner finding rated medium or above still does ([OpenVAS](OPENVAS.md)).
- **Remediation.** The work list for agents and teams comes fire first.
- **API.** `GET cves?tier=fire` lists the CVEs of one tier ([AGENT-API.md](AGENT-API.md)). A match carries `cve.tier` (its heat on the host), `cve.feed_tier` (the CVE's own tier), `cve.validation_tier` (the heat once proven), `cve.heat_capped` (held below it), `cve.kev`, `cve.exploit_db`, `version_only`, `version_proven` and `heat_reason`; a Findings row carries `heat`, `heat_reason`, `kev`, `exploit`, `version_only`, `version_proven` and `heat_capped`, and a host's reasons carry `heat_reason`.

## A worked example

A CVE for a VPN gateway is published with CVSS 9.8. It is not on the KEV and has no public exploit: **ice**, CVSS 9.8 on the row, and it is correlated and template-tested like any critical CVE. A week later CISA adds it to the KEV: it is **fire** in the feed. cvENGINE has a gateway on one of your hosts whose distribution-free banner nmap read from the service itself: that match is **fire** at once, and paged. Another host only shows the gateway's version through technology detection: **smoke**, "on the KEV; version not proven", first in line for validation. A read-only check reproduces it, the match turns **fire**, and it is paged once. A medium CVE in a library you do run, with no exploitation evidence, stays **ice** and never interrupts you.

See also: [PIPELINE.md](PIPELINE.md) for the full flow, [documentation index](README.md).
