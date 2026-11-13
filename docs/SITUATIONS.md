# Situations

The **Situations** page answers one question: *what needs me?* It lists your hosts that have something open on them that needs a person, most urgent first, one host a row, each with a short plain account of what is wrong and what to do first. When nothing needs you, it says so.

It is a tab of the **Overview** (Overview, Situations), so the left rail keeps its eight entries and Overview stays the current one. The same answer, in the same order and words, is available to agents: `GET projects/{slug}/situations` and the MCP tools `list_situations` and `get_situation` ([AGENT-API.md](AGENT-API.md)).

Everything here is computed from numbers cvENGINE already has. A situation never defines a second meaning of a number: heat is [fire, smoke and ice](FIRE-SMOKE-ICE.md) (including a heat a person set by hand), proof is the "Proven on this host" card of a finding, and what is closed is what the Findings page calls closed.

## What a situation is

One **host** of a project together with everything open on it that needs a person. Four tiers, worst first:

| Tier | What is in it |
| --- | --- |
| **Proven** | A CVE match or scanner finding that one of cvENGINE's own checks reproduced (the validation hit behind the "Proven on this host" card). |
| **Likely** | A CVE match or scanner finding that shows fire or smoke, that no check has proven yet, and that the AI reviewer has not called a false positive. |
| **Exposed** | An open database (a check connected with no credentials), a dangling DNS record, an open admin or cleartext service (Telnet, FTP, rlogin and the like, or a tailnet admin port), or an exposed secret that counts. |
| **Minor** | Everything else still open: hygiene findings (certificates, email, TLS) and findings or CVE matches that show ice. |

Not part of a situation: findings that are fixed, an accepted risk or a false positive; CVE matches the AI ruled out; scanner findings the scans no longer see; informational findings; secrets that are public by design, accepted, revoked or false positives.

The sets are the Overview's own (`counts.exposed_matches`, `counts.actionable_findings`, `counts.actionable_hygiene`), so **every host the Overview counts as exposed has a situation**. A host with only hygiene findings also has one, though the Overview does not call it exposed.

A heat set by hand is respected: setting a finding to ice moves it to **Minor** even if a check proved it, and setting it to fire or smoke makes it at least **Likely**. A finding the AI reviewer called a false positive with high confidence, which the server did not close because somebody worked it (or it is a critical scanner finding, or closing is switched off), is **Minor**, not likely, until the reviewer's newest verdict says otherwise. A verdict the server refused for the evidence (hard evidence, a floor, or text aimed at an AI in it) or that the model was not sure of (low or medium confidence) never moves a finding, and neither does a finding a retest reopened (it reproduced): the ranking does not follow a model the server itself did not believe.

**One host** is what the Hosts page calls one host: names that resolve to exactly the same addresses are one situation, named the way the Hosts page names it. The other names are `also_known_as`. A name that has findings but no scanned host record (an email domain, say) is its own situation.

## The rank rule

Position 1 is the first thing to look at. A situation sorts by these, in order:

1. **Worst tier**: proven, then likely, then exposed, then minor. Proof beats likelihood.
2. **Known exploited**: a proven or likely CVE match whose CVE is on the KEV list, yes before no. Known exploited beats severity alone. (Only CVE matches carry this; a scanner finding does not.)
3. **Internet-facing** before inside a declared internal network.
4. **Worst severity** among its items (a CVE by its CVSS band, as the Findings list bands it).
5. **How many** proven, likely and exposed items it has, more first.
6. **Age**: the oldest open item first.
7. The host name, then the project, so the order is total and the same data always gives the same list.

Each row says why in one short phrase, `rank_reason`, built from the same facts: `Proven by a check, known exploited, internet-facing`, `Likely real, internal`, `Lower priority only, internet-facing`, with `, heat set by you` added when a person's heat is in play.

## The narrative

Each situation has two to four plain sentences, built by code from the data (not by an AI model): what the host is, what is proven or likely and how, what is exposed, and what to do first. The same data gives the same text, and the list row and the detail say the same thing. Three examples from the scale fixture (5,000 hosts, [Timings](#timings)):

> h201.t9.example.com is an internet-facing web server running Postfix. A check reproduced CVE-2099-90200 and 1 more on it (nuclei check, 2026-11-09), and it is on the known-exploited list. It also has 1 exposed item. Do this first: Update Postfix (fixes CVE-2099-90200).

> h5.t5.example.com is an internet-facing web server running Node.js. Nothing is proven yet, but 5 findings look real, the first being CORS misconfiguration. Do this first: Fix CORS misconfiguration.

> h0.t0.example.com is an internet-facing web server running OpenSSH. It exposes a secret that anyone can read. Do this first: Revoke the exposed secret and issue a new one.

Text that came from a scan (a banner, a finding name) is cut to one line of plain text with control, invisible and direction-changing characters removed, and a banner is told only when it looks like a product name (`nginx/1.18.0 (Ubuntu)`). A hostile string can therefore neither break the page nor talk to an agent that reads the narrative. The page draws every field with `textContent`, and a finding's link is used only when it points at one of the existing panes.

To keep the words the same in a row (which carries 12 findings) and in the detail (up to 200), they are built from the counts and the first five items only.

## The page

`/cve/<project>/situations/` (and `/cve/_all/situations/`). One row per host, two lines: the rank, the host, the counts (`2 proven`, `1 likely`, `3 exposed`, `4 minor`) and an **internal** badge; then the headline and the first action. Click a row (or press Enter on it) to open it in place: the narrative, why it ranks there, and its findings, each linking to the pane that already shows it (Findings, Hygiene, Secrets), with **Open the host**. A host with more findings than a row carries offers **Show all**.

- **Search** matches any name of a host. **Filters, Show** keeps the situations whose worst tier is at least proven, likely or exposed.
- **Load more** pages on, 30 rows at a time, like the other lists.
- Three different empty states, from the server's `state`, never from the rows: **Nothing needs you** (hosts were scanned and nothing open needs a person; not drawn while the list is still loading), **Nothing has been scanned yet** (no host has been scanned: add a target), and, when a search or filter matches nothing, a plain line saying so.

## REST and MCP

`GET /api/v1/projects/{slug}/situations` and the MCP tool `list_situations`:

| Parameter | Meaning |
| --- | --- |
| `q` | Part of a host name (any name of the host). |
| `tier` | `all` (default), `exposure`, `likely` or `proven`: keep situations whose worst tier is at least that. |
| `page`, `page_size` | As the other lists (`page_size=0` for the numbers alone). |

The answer: `count` (situations after `q` and `tier`), `situations` (all of them), `hosts` (hosts in the project's inventory), `state` (`attention`, `clear` or `unscanned`), `last_scan_at` (set when `state` is `clear`), `page`, `page_size` and `results`. `_all` ranks across the projects you can see; each row names its project.

Each row of `results` has:

| Field | Meaning |
| --- | --- |
| `rank` | Position in the whole ordered list (not in the page). |
| `project`, `project_name` | The project the host belongs to. |
| `host`, `also_known_as`, `host_id`, `host_link`, `internal` | The host as the Hosts page names it, its other names, its host row id (null for a name with no scanned record), the Hosts page link, and whether it is inside a declared internal network. |
| `headline` | One short line: `Proven: CVE-2099-1 and 2 more`. |
| `rank_reason` | Why it is where it is, one short phrase. |
| `counts` | `{proven, likely, exposure, minor}`: items open in each tier. |
| `first_action` | What to do first, one phrase. |
| `narrative` | The two to four sentences. |
| `oldest` | When the oldest open item was first seen. |
| `findings`, `findings_total`, `findings_truncated` | The top findings (12 in the list, up to 200 in the detail) and how many there are in all. Each has `kind` (`match`, `vulnerability`, `hygiene` or `secret`), `id`, `title`, `tier`, `severity`, `heat`, `known_exploited`, `set_by_you`, `first_seen`, `proof` (`{check, at}` when a check reproduced it) and `link` (the page that shows it). |

`GET /api/v1/projects/{slug}/situations/{host}` and `get_situation` return one row with up to 200 findings: the same text, rank and counts as the list. 404 when nothing open on that host needs a person, or the host is not in the project. A host name needs one project, so `_all` is a 400 there. Everything is scoped to the projects the token's user can see.

## How it is computed

`cveFeed/situations.py`. Set-based: four grouped queries (CVE matches, scanner findings, hygiene findings, secrets) give each host's counts, two queries give the hosts (the same collapse the Hosts page uses), and only the hosts of the page are read item by item (one windowed query per source). The number of queries does not depend on the number of hosts or findings (`tests/test_situations.py` pins it). Nothing is stored: there is no table and no migration, so the page is always as current as the findings.

### Timings

Measured on a throwaway database built by `manage.py seed_scale_fixture --hosts 5000 --secrets 200`, with 12,000 scanner findings and 30 proven or exposed hosts added: 5,000 host names (4,596 hosts after the Hosts page's collapse), 42,024 scanner findings, 10,000 CVE matches and 2,475 hygiene findings (54,499 findings), 4,560 situations. One local Postgres, the API through the Django test client:

| Request | Time | Queries |
| --- | --- | --- |
| list, first page of 50, first request of a process | about 1.1 s | 21 |
| list, first page of 50 (30 rows: the same) | about 0.46 s | 18 |
| list, page 20 of 50 | about 0.49 s | 17 |
| list, a search | about 0.39 s | 17 |
| list, the counts alone (`page_size=0`) | about 0.38 s | 12 |
| one situation | about 0.40 s | 18 |

The page makes one request per screen and does not poll.
