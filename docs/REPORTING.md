# Reporting

The **Reporting** page (`/cve/reports/`, the rail entry between Scans and Scanners) makes a findings report or a hosts report for an organization or for one project, as a PDF or a CSV file, and sets up weekly or monthly summaries sent by email. Everything in a report is read from results cvENGINE already holds: making one never scans, probes or resolves a host.

## The page

A **Report on** picker lists every organization and project you can read, grouped by organization:

- **Whole organization (N projects)** is first in a group. When you can read only some of the organization's projects (you were added to those projects, not to the organization), it says **N of your projects in <Org>** and the report covers those.
- Then one entry per project. Projects with no organization are under **No organization**.

`?project=<slug>` or `?org=<slug>` in the address preselects the scope, and the address follows your choice, so a link can be shared. Without either, the page starts on the project you are working in, then on the organization the All projects view is narrowed to, then on the first entry.

Three tabs (`#findings`, `#hosts`, `#email`):

- **Findings report**: **PDF report** (a penetration-test style report: executive summary, summary of findings, one write-up per serious issue, methodology, appendices) or **CSV spreadsheet** (one row per finding). A switch includes closed findings (fixed, accepted risk, false positive).
- **Hosts report**: **PDF report** (summary and host table), **CSV spreadsheet** (heat, score, findings, technologies, owner), or **Scope list for a testing company**, the existing **Export all hosts** dialog, which holds no findings, notes, owners or scores.

The **Email reports** tab is described [below](#email-reports).

**Generate** queues the report, shows *Queued* and *Building*, and downloads the file when it is ready. **Your recent reports** lists your reports of the last 24 hours (kind, format, scope, state) with a **Download** button.

## Formats

| Format | For | What it holds |
| --- | --- | --- |
| Findings PDF | Executives, auditors, clients | The report described in [Front end](FRONTEND.md#pdf-reports): cover, contents, executive summary, summary of findings (one numbered row per issue, by severity), one write-up per critical, high or medium issue with every affected host, scope and methodology, and appendices (low and informational issues, asset inventory, exposed secrets, closed findings) |
| Hosts PDF | The same readers, when the question is "what do we have exposed" | Cover, summary (hosts on fire, smoke and ice, clean hosts, hosts found in the last 30 days, the most common technologies and open ports), the host table, method and validity. No finding, hygiene or secret sections; each host shows how many open findings it has |
| Findings CSV | Spreadsheets and ticket imports | One row per finding: kind, heat, severity, title, CVE, CVSS, known exploited, host, host alias, project, organization, status, assignee, basis, fixed in, first seen, last seen, link to the Findings page |
| Hosts CSV | Spreadsheets | One row per machine (names on the same addresses are one host): host, alias, also answers to, IP addresses, open ports, technologies, heat, score, open findings, owner, criticality, project, organization |
| Scope list | Handing hosts to a penetration testing company | The **Export all hosts** file ([Agent API](AGENT-API.md)): no posture data at all |

A CSV is built by the same worker job as a PDF and downloaded the same way. It starts with a byte order mark so Excel reads it as UTF-8, and a cell that begins with `=`, `+`, `-`, `@`, a tab or a carriage return gets an apostrophe in front, so a host name or a finding title from a scanned machine stays text. A CSV holds at most `CVENGINE_REPORT_CSV_MAX_ROWS` rows (20,000 by default), hottest first, and the report row says how many were left out.

## Organization and project reports

A project report holds that project's rows. An organization report holds the organization's projects **you can read**:

| You are | An organization report covers |
| --- | --- |
| App Admin, Org Admin, Org Member or Org Audit | Every project of the organization |
| Added to some of its projects only | Those projects. The picker says **N of your projects**, and the cover of a PDF says it does not cover the organization's other projects |

The same host name in two projects of an organization is two hosts in the report, each with its own findings and alias. Another organization's rows never appear. The worker works out your access again when it runs, so a report asked for just before you lost access fails with "you no longer have access" and leaves no file.

## Email reports

An email report sends a weekly or monthly summary of one project or one whole organization to up to ten addresses. Everything in it is read from stored results; sending it never contacts a host.

**Prerequisite: outgoing mail.** An App Admin sets up the SMTP server under Settings, Email. Until then email reports can be created and are kept, but nothing is sent: each period is recorded as *Skipped: outgoing mail is not set up*, and sending starts by itself once mail is set up (a skipped period is not made up). Deliverability depends on that server: set SPF and DKIM for its sender address.

**What the email says**, in order: the scope and period; **At a glance**; **This week's most important vulnerabilities**; the **Top findings**; **New hosts** and hosts that went away; **Hygiene** (open issues, certificates expiring within 30 days); a line about the full report (attached, over the size limit with a link, or could not be attached); and a button into cvENGINE. The HTML is table-based with inline styles, readable in a dark theme and on a phone, with no image or tracking, and always under 100 KB so Gmail does not clip it; a plain-text part says the same. Everything that came from a scanned host is escaped.

**At a glance is calm on purpose.** It opens with the same sentence the top of the Overview says (`cveFeed.overview.status_block`, one implementation: "Nothing needs you right now.", "3 hosts likely have vulnerabilities and need review."), then four tiles:

- **Needs attention**: hosts with a proven, likely or high-priority hygiene situation (the Overview's own count, see [Situations](FRONTEND.md)). Its change since the last report is red only when it rises and green when it falls; the daily snapshot keeps the figure (`StatsSnapshot.needs_hosts`), so the first report after an upgrade, and any period with no snapshot behind it, shows no comparison.
- **Externally facing hosts**: hosts reachable from the internet. More discovered hosts is not bad news, so its change is grey whichever way it goes.
- **New issues worth a look**: items first seen in the period that are Fire or Smoke, or in the proven, likely or high-hygiene tiers; not every new low-level item.
- **Fixed** in the period.

The big totals are one quiet line under the tiles ("1,712 lower-priority items are tracked in cvENGINE (643 low-priority CVE matches, 673 hygiene notes)"), never a tile, with a second line saying how many distinct issues those open findings are ("1,712 findings in 310 distinct issues. Version-only matches on the same product and version of one host are one fix, so they count as one issue."; see [Distinct issues](FRONTEND.md#distinct-issues)), and the Fire, Smoke and Ice counts of CVE matches are said in words ("No Fire. 14 Smoke (worth a look). 643 Ice (low priority)"). The first report says there is nothing to compare with yet. The subject and the preheader follow the same rule: *: N on fire* when something is on fire, *: N proven* when a check proved something, *: N hosts worth a look*, else *: nothing needs you*; raw totals are never in them.

**Top findings** are grouped: findings of one title in one project are one row ("Dangling NS Records (NS records without SOA): 5 hosts in Endless") with the host names under it (five, then "+N more"), hottest first, then by how many hosts. Up to five rows, each linking into cvENGINE.

**Most important vulnerabilities.** The section of the email called *This week's most important vulnerabilities* (this month's for a monthly report) is also at the top of the Email reports tab for the selected scope, and is `GET reporting/threats` and the MCP tool `get_threat_digest`. See [below](#the-most-important-vulnerabilities).

**Schedule.** Weekly (a weekday) or monthly (a day from 1 to 28, where day 1 covers the whole previous month), a time on the quarter hour and an IANA time zone. A time that does not exist on a spring-forward day is sent the hour after. The period of an email is the week or month that ends at its send time.

**Never sent twice.** The next slot is claimed before the email is made (a compare-and-set), every period has one delivery row, and a send interrupted part-way (a worker that died) is marked *unknown* after two hours and is never retried by itself. After an outage only the latest period is sent, once; missed weeks are not made up. A refused recipient address is final. A failure that cannot have delivered the email (the connection, a time-out) is retried for the recipients it failed for, after 30 minutes and after 2 hours, then given up. The result is on the card: *Sent Nov 17, 08:00 to 3 recipients*, *1 of 3 failed: the mail server refused the recipient address*, *Skipped: outgoing mail is not set up*, *Never sent*.

**Who it runs as.** The email is made with the access of the subscription's *owner*, the last person who saved it, worked out again at every send. When that person is removed, disabled or can no longer manage the scope, the report switches itself off (*Paused automatically*) and says why; someone with access saves it again to resume.

**Attachments.** *None*, *PDF* or *CSV*: the findings report of the scope, as on demand. A file over `CVENGINE_REPORT_EMAIL_MAX_MB` (10 by default, 1 to 25) is not attached; the email says so and links to the Reporting page. A report that cannot be made does not stop the email.

**Unsubscribe.** Every message carries `List-Unsubscribe` and `List-Unsubscribe-Post` (RFC 8058, the mail program's own Unsubscribe button) and a link of its own per recipient. Opening the link shows a confirmation and changes nothing; pressing its button removes that address. The address is remembered as unsubscribed: adding it back needs a tick in the dialog (`confirm_opted_out` in the API). When the last recipient unsubscribes the report switches itself off. Links are signed and stop working if a report's key is rotated; a bad link gets one plain answer.

**Test and preview.** *Send test to me* sends the real email, marked *[Test]*, to your own address only (one a minute per report, ten an hour per person). *Preview* shows it without sending anything, for the saved report or for unsaved settings, as HTML in a sandboxed frame or as plain text.

| | App Admin | Org Admin | Org Member | Project member (write role) | Audit | Read-only token |
| --- | --- | --- | --- | --- | --- | --- |
| See a project's email reports | yes | yes | yes | their projects | yes | yes |
| See an organization's email reports | yes | yes | yes | no (404) | organization audit: yes; project audit: no | as the person |
| Create, change, pause, test, delete a project's | yes | yes | yes | yes | no (403) | no (403) |
| Create, change, pause, test, delete an organization's | yes | yes | no (403) | no | no | no |

An organization's email reports are managed by an Org Admin or App Admin only, so they always cover the whole organization. Every change is audited (`report.subscription.*`), with the recipients.

## The most important vulnerabilities

Built from what cvENGINE already holds, with no AI model and no scan: nothing in it is asked of a model or run, and it never contacts a host.

**What is picked**, newest first within each group, at most `CVENGINE_DIGEST_TOP_VULNS` (6; 1 to 12):

1. **Zero Wire briefings** published in the period. Cloudflare Radar's [Zero Wire](https://radar.cloudflare.com/zero-wire) is a public feed of short security briefings. cvENGINE reads its RSS feed every six hours (`radar.cloudflare.com/zero-wire/feed`, the same fixed-address fetch, time-outs and proxy settings as the other feeds, at most 2 MB and 50 items) and keeps only each briefing's title, link, a one-sentence summary (the action to take), the CVE ids it names and its tags. The briefing's own text is never stored or shown, a link that is not under `https://radar.cloudflare.com/zero-wire/` is dropped, an XML document with a type declaration or entities is refused, and no feed text is ever sent to an AI model or run: it is data, escaped wherever it is shown. It is **on by default**; an App Admin switches it off with the checkbox at the top of the Email reports tab (nothing is fetched while it is off). A failed read is shown there and retried at the next run; emails use whatever is stored.
2. **CVEs** that CISA (or VulnCheck) added to its Known Exploited Vulnerabilities catalog in the period, and CVEs published in the period with a CVSS of 9.0 or more and a public exploit or a high exploitation probability, that no picked briefing already names. A CVE that only works from the host itself is left out. They are ranked by what they reach (hosts that match, then hosts that run the product), known ransomware use, CVSS and the date added.

**How many of your hosts it reaches** is two numbers in distinct machines, folded exactly as the Hosts page folds them (`counts.machines`): two names on the same addresses are one host, and every copy of a name (a second target's row, a certificate-transparency row with no address beside the scanned one) is the machine of the row the Hosts page shows for that name. The Overview card, the email, `reporting/threats` and `get_threat_digest` read the same fold, and the Overview's link lists one name per machine, the one the Hosts page shows it under, so the card's number, the link and the page agree:

- *N of your hosts match by version*: open CVE matches in the scope that are not closed, not ruled out by the AI and not false positives; *(M confirmed by a check)* when a check reproduced it.
- *K more run <product>, version unknown*: hosts with a technology or an open-port product the correlation connects to the CVE and no version read for it, that do not already match. A product only a lead names (a `.php` link, the web archive, Shodan's InternetDB) is not one of them ([PIPELINE.md](PIPELINE.md#a-php-link-is-a-lead)). A product with no version read can be neither ruled in nor out, so it is counted apart, never as a match.

A briefing that names CVEs we hold is counted through them (merged per host). One that names none is matched by its product tags (*N of your hosts run nginx*, through the same product-name aliases correlation uses; class tags such as RCE, Memory corruption, CMS or Runtime are ignored); a product nobody runs says *No host in <scope> is known to run <product>.* A period with nothing new says so, so readers know it was checked.

**In the email** the section is narrower than the list above: it holds only what is found on your own hosts (at least one host that matches by version), never a product that merely runs somewhere or an announcement that reaches no host. CVEs of one product are one item, the way the Overview's threat cards group them ("PHP: four critical flaws", with the CVE ids), five items at most and then *plus N more in cvENGINE* (a link to the Overview). Each item names the hosts it was found on as `hostname · Project name` (five, then *+N more hosts*, from the scope's own projects only), keeps the *Fixed in* line and the badges, says *Version unknown on N more hosts* only when the item has matching hosts, and has a summary of about two sentences. When nothing is on your hosts the section is one line: *None of this week's newly exploited or critical vulnerabilities were found on your hosts. We checked N.* The Overview's threat cards and `GET reporting/threats` are unchanged and keep their own fold of the items that reach no host.

Footnotes say where the text comes from: *Briefings from Cloudflare Radar Zero Wire (radar.cloudflare.com/zero-wire); summaries quoted from the feed; host counts from cvENGINE's own scans.* and, for CVEs, which catalog they were picked from.

## Who may ask, and who may download

A report is a read: any role that can read the scope may ask for one, audit included, and so may a read-only API token. Only the person who asked can download a report, for 24 hours (`CVENGINE_REPORT_TTL_HOURS`); anyone else, an App Admin included, gets the same `404` as for a report that does not exist. Every request is written to the audit log with its scope, kind and format. Limits on how many reports one person or the whole server may have in progress are in [Configuration](CONFIGURATION.md#pdf-reports).

## REST and MCP

| What | REST | MCP |
| --- | --- | --- |
| Ask for a project report | `POST projects/{slug}/reports` `{kind, format, host, include_closed}` | `export_report` (`project`) |
| Ask for an organization report | `POST orgs/{org}/reports` `{kind, format, include_closed}` | `export_report` (`org`) |
| Poll one | `GET projects/{slug}/reports/{id}`, `GET orgs/{org}/reports/{id}` | `get_report` |
| Download it | `GET .../reports/{id}/download` (`application/pdf` or `text/csv`) | over REST |
| What you can report on | `GET reporting/scopes` | `list_report_scopes` |
| Your recent reports | `GET reporting/reports` | |
| Most important vulnerabilities | `GET reporting/threats`; `GET/PUT reporting/zero-wire` (the switch: an App Admin in the web interface only) | `get_threat_digest` |
| Email reports | `GET/POST report-subscriptions`, `GET/PATCH/DELETE report-subscriptions/{id}`, `POST .../{id}/test`, `GET .../{id}/preview`, `GET .../{id}/deliveries`, `GET reporting/digest-preview` | `list_report_subscriptions`, `get_report_subscription`, `create_report_subscription`, `update_report_subscription`, `delete_report_subscription`, `send_report_subscription_test`, `preview_report_subscription`, `list_report_deliveries` |

The details, with the limits and the errors, are in [Agent API](AGENT-API.md#pdf-reports) and [Agent API, Email reports](AGENT-API.md#email-reports).

## Code

`agentapi/report_scope.py` (the scope and its access rules), `cveFeed/report_export.py` (the queue, the job and the download), `cveFeed/report_data.py` and `cveFeed/templates/cveFeed/report.html` (what a PDF prints), `cveFeed/report_csv.py` (the CSV), `agentapi/reports.py` (REST and MCP), `cveFeed/report_threats.py` and `cveFeed/zero_wire.py` (the section and the feed; fixture `tests/fixtures/zero-wire-feed.xml`, tests `tests/test_report_threats.py`), `cveFeed/report_digest.py` and `cveFeed/templates/cveFeed/email/` (the email's content and look), `cveFeed/report_digests.py` and `cveFeed/report_schedule.py` (sending and the schedule), `agentapi/report_subscriptions.py` (REST and MCP), `cveFeed/report_digest_views.py` (unsubscribe), `static/cve/reports.js`, `report-email.js` and `reports-logic.js` (the page). Tests: `tests/test_reporting.py`, `tests/test_report_subscriptions.py`, `tests/test_report_pdf.py`, `tests/test_reports_logic.mjs`, `tests/test_reports_page.mjs`.
