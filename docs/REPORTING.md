# Reporting

The **Reporting** page (`/cve/reports/`, the rail entry between Scans and Scanners) makes a findings report or a hosts report for an organization or for one project, as a PDF or a CSV file. Everything in a report is read from results cvENGINE already holds: making one never scans, probes or resolves a host.

## The page

A **Report on** picker lists every organization and project you can read, grouped by organization:

- **Whole organization (N projects)** is first in a group. When you can read only some of the organization's projects (you were added to those projects, not to the organization), it says **N of your projects in <Org>** and the report covers those.
- Then one entry per project. Projects with no organization are under **No organization**.

`?project=<slug>` or `?org=<slug>` in the address preselects the scope, and the address follows your choice, so a link can be shared. Without either, the page starts on the project you are working in, then on the organization the All projects view is narrowed to, then on the first entry.

Two tabs (`#findings`, `#hosts`):

- **Findings report**: **PDF report** (summary, every finding with its evidence and remediation) or **CSV spreadsheet** (one row per finding). A switch includes closed findings (fixed, accepted risk, false positive).
- **Hosts report**: **PDF report** (summary and host table), **CSV spreadsheet** (heat, score, findings, technologies, owner), or **Scope list for a testing company**, the existing **Export all hosts** dialog, which holds no findings, notes, owners or scores.

**Generate** queues the report, shows *Queued* and *Building*, and downloads the file when it is ready. **Your recent reports** lists your reports of the last 24 hours (kind, format, scope, state) with a **Download** button.

## Formats

| Format | For | What it holds |
| --- | --- | --- |
| Findings PDF | Executives, auditors, clients | The report described in [Front end](FRONTEND.md#pdf-reports): cover, executive summary, hosts, one section per finding, hygiene, exposed secrets, method and validity |
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

The details, with the limits and the errors, are in [Agent API](AGENT-API.md#pdf-reports).

## Code

`agentapi/report_scope.py` (the scope and its access rules), `cveFeed/report_export.py` (the queue, the job and the download), `cveFeed/report_data.py` and `cveFeed/templates/cveFeed/report.html` (what a PDF prints), `cveFeed/report_csv.py` (the CSV), `agentapi/reports.py` (REST and MCP), `static/cve/reports.js` and `reports-logic.js` (the page). Tests: `tests/test_reporting.py`, `tests/test_report_pdf.py`, `tests/test_reports_logic.mjs`.
