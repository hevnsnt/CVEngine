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

- **A match inherits its CVE's tier.** A fire CVE on one of your hosts is a fire match.
- **A confirmed smoke becomes fire.** If triage rates the match confirmed or likely and the CVSS is 7.0 or higher, it reads as fire.
- **A match needs a version.** A tier says how dangerous a CVE is, not whether it applies. A host running a product with no version found has no match at all, whatever the tier, until a version is identified: it is listed as an *unverified product*, not counted in heat or the score. The one tier-driven exception is a CISA KEV advisory that gives no version bound, kept for a host running that product at a known version as a low-confidence candidate that needs validation. Fire and smoke CVEs are template-tested on both kinds of host. See [Match](PIPELINE.md#cve-intelligence).
- **An unknown version range makes it ice, and a review item.** That KEV candidate is a *version unknown* match: whatever the CVE's tier (KEV, a critical score), on the host it is ice, never fire or smoke, and it adds at most 2 points to the host score (1 each, `scoring.VERSION_UNKNOWN_CAP`). It is marked for review: the Needs validation list and the match's reason read "Version of the CVE is not known: review when the affected versions are published". The model is not asked and cannot dismiss it; only a person decides it, or the CVE gaining a version range does: the next correlation then re-evaluates it like any match with a range (heat, score and review state follow its version).
- **A distribution patch makes it ice.** If the host's distribution backported the fix, the match is ice however dangerous the CVE is. See [distro backports](PIPELINE.md#cve-intelligence).
- **A host takes its hottest signal.** A host's heat is the hottest of its CVE matches and its open findings (critical and high findings read as fire, medium as smoke, low as ice). A host with nothing is clean, and one nothing has probed yet is not scanned.

The 0 to 100 [host score](PIPELINE.md#host-score) reads a match's CVE tier: a fire match adds 40 points, smoke 20, and ice 5 (a match whose CVE has no known version range adds a point, at most 2 in all).

## What the tiers drive

- **Dashboard.** The feed temperature bars count fire, smoke, and ice and filter the feed. The attack-surface map colors each host by its heat.
- **Auto-fire.** When it is on, cvENGINE acts on fire and smoke CVEs as the feed delivers them, confirming their matches and testing them on the affected hosts. Ice CVEs wait.
- **Notifications.** New fire-tier matches with evidence (version in range, a template hit, or the distribution tracker) are announced to your Slack, Discord, Telegram, or Lark channels, along with confirmed template hits and scan summaries. Matches the AI doubts wait for a test to prove them.
- **Remediation.** The work list for agents and teams comes fire first, so the most dangerous fixes are on top.
- **API.** `GET cves?tier=fire` lists the CVEs of one tier ([AGENT-API.md](AGENT-API.md)).

## A worked example

A CVE for a VPN gateway is published with CVSS 9.8 and is listed in CISA KEV. It is **fire** the moment it arrives. cvENGINE finds a gateway on one of your hosts running an affected version, the AI confirms it, a read-only check reproduces it, and the host jumps to the top of the dashboard. A medium CVE in a library you do not run stays **ice** and never interrupts you.

See also: [PIPELINE.md](PIPELINE.md) for the full flow, [documentation index](README.md).
