# Fire, smoke, and ice

Every CVE that cvENGINE reads gets a temperature: **fire**, **smoke**, or **ice**. It is how cvENGINE decides what deserves attention first, and it drives the dashboard, auto-fire, notifications, and the remediation queue.

## Why it matters

Thousands of CVEs are published every month, and most are never exploited in the wild. A severity score alone (CVSS) tells you how bad a flaw could be, not whether anyone is using it. Chasing every high score buries you, and ignoring scores misses the real threats.

cvENGINE combines severity with evidence of real-world danger:

- **Known exploitation**: CISA KEV, ENISA EUVD's exploited list, or VulnCheck KEV (with a key), catalogs of vulnerabilities known to be exploited.
- **A public exploit**: an Exploit-DB entry or a Metasploit module.
- **EPSS**, a probability that the CVE will be exploited. cvENGINE treats 0.1 or more as "reached".
- **CVSS**, the severity score.

The result is a short, honest list: the CVEs that are dangerous right now, the ones to watch, and the rest.

## The three tiers

| Tier | Meaning | Rule |
| --- | --- | --- |
| **Fire** | Dangerous now | Known exploited (CISA KEV, ENISA EUVD, VulnCheck KEV), **or** has a public exploit (Exploit-DB, Metasploit), **or** CVSS 9.0 or higher, **or** EPSS of 0.1 or more together with CVSS 7.0 or higher |
| **Smoke** | Warning signs | Not fire, and CVSS 7.0 or higher **or** EPSS of 0.1 or more |
| **Ice** | Cold, low priority | Everything else |

The rule is deterministic and runs on every CVE the moment it arrives, before any AI is involved. The thresholds live in one place, `web/cveFeed/threat.py`, and are easy to retune.

## From the feed to your hosts

A tier describes a CVE in general. What matters to you is how hot it is on **your** assets, so cvENGINE adjusts it per match:

- **A match inherits its CVE's tier, up to what its evidence supports.** A fire CVE on one of your hosts is a fire match when something about the host itself shows it: a template hit (a nuclei CVE template, or a confirmed OpenVAS test), the distribution's tracker listing the installed package as vulnerable, the host's own inventory report, runZero reporting the CVE on that host, or one of cvENGINE's validation checks reproducing it.
- **A version alone is smoke at most, KEV or not.** A match that rests only on a version string (read from a banner by nmap, from a script or page by technology detection, by WPScan, or by an OpenVAS test below its quality bar) inside the CVE's affected range is a *version-only* match. It never shows as fire, even for a CVE in CISA KEV: it is smoke if its CVE is fire or smoke, and ice if its CVE is ice. A version string is a lead, not proof: a backported fix, a proxy answering for another server or a script name that is not the library's real version all look the same from outside. The **KEV** badge stays on the row whatever the heat, and the host's reasons say "version only: shown as smoke until a check confirms it". Fire therefore means "dangerous now and shown to apply to this host", not "a known-exploited CVE whose version range the host's banner falls in". The one definition of what is hard evidence is `cveFeed.match_policy.has_hard_evidence`; the cap is `CVENGINE_VERSION_ONLY_MAX_HEAT` (`smoke` by default, `fire` restores the old behaviour, `ice` is stricter; see [Configuration](CONFIGURATION.md)).
- **Validation is how a version-only match earns fire.** The heat shown and the order of validation are separate: a known-exploited version-only match is still validated in the fire lane, first (`threat.validation_heat`). Every confirmer orders by that uncapped heat: the validation sweep, OpenVAS (which hosts it selects, Fire before Smoke, and the host's Checks line), and agent validation work (`queue_agent_work` with `kind: validate` and `tier: fire` takes it, at fire priority). A validation hit, or a template hit, is hard evidence, so the match turns fire the moment it lands.
- **A confirmed smoke becomes fire.** If triage rates the match confirmed or likely and the CVSS is 7.0 or higher, it reads as fire (a version-only match cannot be rated above needs validation, so this needs hard evidence too).
- **A match needs a version.** A tier says how dangerous a CVE is, not whether it applies. A host running a product with no version found has no match at all, whatever the tier, until a version is identified: it is listed as an *unverified product*, not counted in heat or the score. The one tier-driven exception is a CISA KEV advisory that gives no version bound, kept for a host running that product at a known version as a low-confidence candidate that needs validation. Fire and smoke CVEs are template-tested on both kinds of host. See [Match](PIPELINE.md#cve-intelligence).
- **An unknown version range makes it ice, and a review item.** That KEV candidate is a *version unknown* match: whatever the CVE's tier (KEV, a critical score), on the host it is ice, never fire or smoke, and it adds at most 2 points to the host score (1 each, `scoring.VERSION_UNKNOWN_CAP`). It is marked for review: the Needs validation list and the match's reason read "Version of the CVE is not known: review when the affected versions are published". The model is not asked and cannot dismiss it; only a person decides it, or the CVE gaining a version range does: the next correlation then re-evaluates it like any match with a range (heat, score and review state follow its version).
- **A distribution patch makes it ice.** If the host's distribution backported the fix, the match is ice however dangerous the CVE is. See [distro backports](PIPELINE.md#cve-intelligence).
- **A host takes its hottest signal.** A host's heat is the hottest of its CVE matches and its open findings (critical and high findings read as fire, medium as smoke, low as ice). A host with nothing is clean, and one nothing has probed yet is not scanned.

The 0 to 100 [host score](PIPELINE.md#host-score) reads a match's heat on the host, the same one the lists show: a fire match adds 40 points, smoke 20, and ice 5 (a match whose CVE has no known version range adds a point, at most 2 in all). So a version-only KEV match adds 20, not 40.

Every heat is computed when it is read, so the rule applies to matches stored before it with no migration: a version-only KEV match that read fire reads smoke after the upgrade, and one with a template hit or a validation hit stays fire. Host scores are stored: they follow at the daily rescore (after the upgrade, within a day), and when you change `CVENGINE_VERSION_ONLY_MAX_HEAT` the first worker that starts with the new value queues one full rescore, which runs even if the daily rescore ran within the hour. When hard evidence reaches a match later (a validation hit, adopted or carried to a rescan's match, the host's report, runZero), its host is rescored and the dashboards and graph re-read at once.

## What the tiers drive

- **Dashboard.** The feed temperature bars count fire, smoke, and ice and filter the feed (a CVE's own tier: KEV is fire there). The attack-surface map, the Live graph and SOC mode color each host by its heat, version-only cap included.
- **Hosts and search.** The Hosts page filters by a host's temperature (fire, smoke, ice, clean, not scanned) with chips that count every host the search matches, and the search API takes `heat=` the same way ([Search](SEARCH.md#reading-the-results)). The Findings and Matches lists, their `heat` filter, the PDF report's counts and the daily stats history read the same heat. Both lists also filter on **Known exploited (KEV) only** (`kev=1`), whatever the heat, so every KEV match can still be found.
- **Auto-fire.** When it is on, cvENGINE acts on fire and smoke CVEs as the feed delivers them, confirming their matches and testing them on the affected hosts. Ice CVEs wait.
- **Notifications.** New matches that are fire on the host (a fire-tier CVE with hard evidence: a template hit, the distribution tracker, the host's report, runZero, a validation hit) are announced to your Slack, Discord, Telegram, or Lark channels, along with confirmed template hits and scan summaries. A version-only match is not paged when it is made. When hard evidence later turns it from smoke to fire, it is paged then, once: a template hit as a confirmed template hit, and the host's inventory report, runZero or one of cvENGINE's other checks as "confirmed, now fire-tier", naming the current scan's match only. A match that was already fire is not paged again when more evidence reaches it, and a hit adopted from another row of the same finding or carried to a rescan's match is not paged either: it was announced when it was found. Each match is paged as fire at most once (`CVEMatch.fire_notified_at`). Matches the AI doubts wait for a test to prove them.
- **Remediation.** The work list for agents and teams comes fire first, so the most dangerous fixes are on top. Validation work is ordered by the heat without the version-only cap, so a KEV match that rests on its version is checked first.
- **API.** `GET cves?tier=fire` lists the CVEs of one tier ([AGENT-API.md](AGENT-API.md)). A match carries `cve.tier` (its heat on the host), `cve.feed_tier` (the CVE's own tier), `cve.validation_tier` (the heat without the version-only cap), `cve.heat_capped`, `cve.kev` and `version_only`; a Findings row carries `heat`, `kev`, `version_only` and `heat_capped`. `findings?kev=1` and `matches?kev=1` keep only KEV matches.

## A worked example

A CVE for a VPN gateway is published with CVSS 9.8 and is listed in CISA KEV. It is **fire** the moment it arrives. cvENGINE finds a gateway on one of your hosts whose banner names an affected version: the match is **smoke** with a KEV badge, and it is first in line for validation. A read-only check reproduces it, the match turns **fire**, and the host jumps to the top of the dashboard. A medium CVE in a library you do not run stays **ice** and never interrupts you.

See also: [PIPELINE.md](PIPELINE.md) for the full flow, [documentation index](README.md).
