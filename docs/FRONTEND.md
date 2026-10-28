# Front end

The interface is server-rendered page shells plus plain ES modules that fill them from the REST API (`/api/v1`) and a few UI-only JSON endpoints under `/cve/api/`. The UI and agents share the same project-scoped code. There is no build step, no framework, and no CDN.

## Design

`web/static/cve/cve.css` is a light, monochrome design system: ink on neutral grays, wide-tracked caps for labels, and fine corner marks on the main panels. Color is rare and means something: red and amber for severity and threat tier, slate for low, a green dot for healthy, and brand orange for running state and the active navigation marker. Type is [Geist](https://github.com/vercel/geist-font), vendored.

- **Shell** (`base.html`, `shell.js`): a sidebar from 1024px wide, a top bar, a bottom tab bar, and a "More" sheet below that. The top bar holds the palette (Ctrl/Cmd+K or "/") and Add targets. The palette jumps to pages, projects, organizations, and saved views, and from two characters on it runs a [host search](SEARCH.md) with filter suggestions (Tab completes), a live preview of up to six hosts, and a syntax help sheet. Enter runs the highlighted row; pick the **Search hosts** row to open the Hosts page with the query. When your projects span two or more organizations, an **organization switcher** in the top bar narrows the project list to one organization (or **All organizations** in the All projects view).
- **Dashboard**: opens on **All projects** when you can see two or more. Exposed hosts, a map of the highest-scoring live hosts (up to 400, as many as fit) colored by threat, CVE feed temperature bars that filter the feed, live counters, a discovery ticker, and an AI activity card, each scrolling back through its last 100 lines. A strip says how many changes happened since you last looked. A 90-day activity strip shows new findings (by heat) and inventory changes per day, and the CVE matches and Findings counters carry 14-day sparklines. The Changes page has a 7 and 30 day area chart, and the Scans page an 18-week scan heatmap.
- **Mobile**: 16px gutters, 44px touch targets, stacked-card tables, visible focus rings, and reduced-motion support.
- **Safe by construction**: DOM is built with `textContent` (the only `innerHTML` uses are the QR image on My account and fixed icons in the row menu and the Add targets dialog), and destructive actions use an in-page confirmation.

Static files are content-versioned and nginx sends `Cache-Control: no-cache` for `/staticfiles/`, so a CDN cannot serve one release's stylesheet with the next release's pages.

## Pages

| Page | What |
| --- | --- |
| `/cve/` | Dashboard and live CVE feed |
| `/cve/<project>/targets/` | Add a domain, IP, CIDR, range, or URL, set its scope, and start a scan. App Admins and the organization's admins also get a **Sign-in** button per target: stored headers and a cookie for authenticated checks, each with an explicit scope (one host, or all hosts of the target with a warning), a mandatory expiry (30, 90 or 120 days, or never) and the days left shown in the list. The values are entered only here or over REST, never through MCP ([Pipeline](PIPELINE.md#authenticated-checks)) |
| `/cve/<project>/scans/`, `.../scans/<id>/` | Scan list with stop controls, and scan detail: stages, subdomains, endpoints, findings, activity |
| `/cve/<project>/hosts/` | Inventory sorted by score, one row per host (names that resolve to the same addresses are one host, and the other names appear as **Also answers to**), with [Shodan-style search](SEARCH.md), heat chips, saved views, **Save search** and **Saved searches** (server-kept searches with alerts), a screenshot **Gallery** (which loads `/cve/<project>/hosts/<id>/screenshot/?size=thumb`, a cached 320 px-wide JPEG made on first request and kept beside the original; without `size`, or when Pillow cannot read the file, the full image), CSV export, and Select mode. The detail pane has six tabs (keys 1 to 6): **Overview** (exposed surface, hosting, a **Checks** line saying "NN of NNN applicable checks done" and naming the first few that are due, see [Check coverage](PIPELINE.md#check-coverage), technologies, why the heat and score, what the web archive remembers, and "Also served here": the other sites found on this host's addresses under another name, each with its status and title), **Services** (ports, banners, script output, database facts, RDP login screens), **Web** (routes and their auth state, sensitive-data and zombie badges, screenshot comparison, and the applications found under subdirectories: each confirmed product with its path and version, then the unconfirmed leads, or what an edge that challenged the scanner should allow), **Findings**, **History** (the last 365 days of changes, grouped by day), and **Manage** (asset info, **Rescan host**, **Download PDF report**, pin, archive, **Delete host data**, **Remove & exclude**). |
| `/cve/<project>/vulns/` | **Findings**: CVE matches, scanner findings, and hygiene findings in one list, hottest first, with a detail pane. Filter by type, severity, status, and overdue (`?type=`, `?severity=`, `?status=`, `?host=` preselect). Each row shows its age against fixed targets (critical 7 days, high 30, medium 90, low 180). The default view is what heats a host. CSV export and bulk status. |
| `/cve/<project>/matches/` | CVE-on-host matches with a detail pane, remediation status, bulk status, and AI verdict filters (`?cve=`, `?host=` preselect) |
| `/cve/<project>/changes/` | What changed: hosts, ports, versions, technologies, certificates, auth state, and screenshots |
| `/cve/<project>/suppliers/` | **Suppliers**: the vendors the project depends on, never owned hosts. A technology search at the top (`php`, `node`, `nginx 1.1`; commas for any-of) with the most widespread technologies as one-click chips, then each supplier (tier, last checked, open findings) with a Shodan-style host card per domain: technology stack with versions, `Server` and `X-Powered-By`, certificate summary, and a fold-out with the raw headers and certificate detail. **Copy message** puts a plain-text note about what the supplier announces (and the open findings with what to ask) on the clipboard; nothing is sent. Organization admins and App Admins add and remove suppliers and accept findings; everyone else reads. |
| `/cve/<project>/hygiene/`, `.../activity/`, `.../keys/` | Email and TLS checks, the full AI activity log, and API keys for OSINT services, set per project or, by an organization admin, per organization (a project key overrides it) |
| `/cve/_all/<section>/` | **All projects**: the same sections across every project you can see |
| `/cve/graph/` | Live asset graph. The mouse wheel zooms around the pointer in every browser (0.04x to 6x) and the page does not scroll over it; it stays fitted until you pan or zoom, and **Fit graph** or a double click refits. In All projects, nodes cluster by project and registered domain. Domains and hosts a scan is working on right now carry a pulsing red ring (read every 3 seconds from `GET /cve/api/graph-live`, which lists the running scans, the step each is in, and the hosts they are working on). **SOC mode** (or `?soc=1`) puts the graph over the whole window with a status bar (scans running and queued, hosts on fire and smoke, nodes, a clock) and a **Scanning now** list; everything not being scanned dims while a scan runs. **Full screen** asks the browser for real full screen, **Escape** or **Exit SOC mode** leaves. |
| `/cve/bounty/` | Bug bounty workbench, for authorized users ([BUG-BOUNTY.md](BUG-BOUNTY.md)) |
| `/cve/agents/` | API tokens and MCP connection commands |
| `/cve/sentinels/` | **Sentinels**: scan-stage agents (`kind=scanner`). See below |
| `/cve/{slug}/sentinels/` | A project's **Sentinels** tab, linked from the More sheet and side rail only once a Sentinel covering the project has registered. See below |
| `/cve/admin/` | Administration: people, organizations, projects, audit log, activity and error log, plus timings and scheduler health for superusers |
| `/cve/account/` | Your password, two-step sign-in, and a **Display and alerts** card (theme, time zone, desktop notifications) |
| `/cve/about/` | Version, license, and credits (account menu, About) |
| `/cve/settings/` | Superusers: AI model, API vault, Tailscale, notifications, scan policy, IP allowlist, proxy, reports, resources, updates, factory reset |
| `/cve/welcome/`, `/cve/setup/` | First-run setup (`/cve/` sends a superuser there on a fresh install; `?skip=1` skips it) and connecting an AI model. For superusers, the account menu shows **Connect AI model**, and **AI Model Usage** once one is connected ([AI-USAGE.md](AI-USAGE.md)). |
| `/login/` | Sign-in with two-step verification |

Finding and match detail panes show why it matters, how it was found, when it was first and last seen, the AI's classification (and the model's own words when a rule overrode it), how to fix it, and every check that ran with the exact command to repeat it. A CVE match also has a **Validate now** button.

**All projects** is offered when you can see two or more projects. Adding and changing targets and scans, and detail pane edits, are not available there: each detail pane ends with "Open in <project> to make changes". Select mode and the row menu still work on Hosts and Findings, and each change goes to that row's own project. A small chip names each row's project, and links open the item in its own project. **Add targets** stays available, with a `#Project` line above each list.

## Working in lists

- **URL carries the view.** Hosts reads `?q=`, `sort=name`, `heat=fire|smoke|ice|clean|unscanned`, `view=gallery`, and `host=<name>`. Defaults stay out of the link, so a bookmark is short.
- **CSV export** on Hosts and Findings downloads the current filter (UTF-8 with a BOM, 20,000 rows at most, 2,000 for Findings). A leading `=`, `+`, `-`, or `@` is escaped so spreadsheets do not run it.
- **Row menu**: the `...` button on a row, or `.` on a focused row. Copy name or link, open in a new tab, pin, archive, or set a status.
- **Undo**: pin, archive, criticality, owner, and status changes offer Undo for 10 seconds when every row succeeded.
- **Keys**: `g` then `l` Live, `a` graph, `h` Hosts, `c` Changes, `v` Activity, `m` matches, `f` Findings, `y` Hygiene, `t` Targets, `s` Scans, `k` API keys, `b` Bug bounty. In lists `j` and `k` move, Enter opens, `x` selects, `f` focuses the filter. On a host `1` to `6` switch tabs. On a host or finding `y` copies the name (a finding's link is `Y`), and on a CVE match `e` focuses the remediation status. `Esc` leaves Select mode. `?` shows the sheet. Keys are off while you type.

## PDF reports

**Download PDF report** is on the Live page once a project is selected (not in All projects) and on a host's **Manage** tab. It asks the server for a report, shows Queued and Building while it polls, and downloads the file when it is ready. A switch, **Include fixed and accepted-risk findings**, is off by default: a report lists open findings only. The report is built in a background task (`generate_report`, queue `cve_feed_queue`), stored under `/usr/src/scan_results/.reports/` with a random name, and offered only to the person who asked for 24 hours; the weekly maintenance removes whatever is left. Any role that can read the project can export it, audit included. The same report is available to agents ([AGENT-API.md](AGENT-API.md#pdf-reports)).

A project report has, in order:

1. **Cover**: project and organization, generation time, scope (targets, hosts, last completed scan) and whether closed findings are included. The company name, accent colour and footer come from Settings > Reports.
2. **Executive summary**: counts by fire, smoke and ice and by severity, the ten hottest findings, hosts on fire or smoke, and how many candidates triage ruled out as false positives.
3. **Hosts**: a table by score with heat, findings, open ports and owner, repeated header on every page. A host report adds the host's services (with banners) and the lines of its score.
4. **Findings**: one section per CVE match or scanner finding, hottest first: CVE ids and CVSS, exploitation signals, the basis ("confirmed: a check reproduced it" or "version-based"), evidence, the exact command or probe that showed it when one was recorded, remediation text and fixed versions, and the status, assignee and notes people recorded.
5. **Hygiene**: TLS and certificate findings and email (SPF, DKIM, DMARC) findings, with the same status columns.
6. **Method and validity**: completed scans, the last run of each scanner, and the caveats: version-based findings can be backported fixes, the scan is outside-in and unauthenticated, results are point-in-time, checks are read-only, and AI text is guidance.

Matches the AI ruled out, and findings triage classed as a likely false positive or not applicable, are never listed (the summary says how many). Limits per report: 500 hosts, 1,000 detailed findings, 500 hygiene findings ([CONFIGURATION.md](CONFIGURATION.md#pdf-reports)); the counts always cover everything, and the PDF says what the limits left out, so a very large project is best reported host by host. Banners, titles, response text and finding text come from the hosts that were scanned, so they are escaped and printed as text, and the renderer runs in its own process with no network access and no file access beyond the page it was given.

## Sentinels

`/cve/sentinels/` lists registered Sentinels (name, scope, capabilities, status, live/last heartbeat, and tasks in progress, completed and failed, from `GET /api/v1/agents?kind=scanner`), with **Suspend**/**Revoke** (and **Approve**/**Reinstate** for a pending or suspended one), which call the same `PATCH /api/v1/agents/{id}` the Agents admin surface already uses. A scope selector (**Project**, **Organization**, or **Instance (everything)**) with the matching field (a project picker, an organization slug, or nothing) and **Provision** call `POST /api/v1/projects/{slug}/sentinels/enroll?format=blob` (needs the admin role in the project or its organization), `POST /api/v1/orgs/{slug}/sentinels/enroll?format=blob` (needs the admin role in that organization), or `POST /api/v1/sentinels/enroll?format=blob` (App Admin only), and show the one-time, 30-minute provisioning blob to copy, with a short instruction to paste it into `CVENGINE_SENTINEL_BLOB` in the Sentinel client's environment. The blob is exactly the matching `sentinels/enroll` endpoint's own JSON payload, base64-encoded (`agentapi.sentinel_broker.encode_enrollment_blob`; no new crypto, no custom framing): the page does not build or serve a download itself, since the Sentinel client is a Docker Compose service that lives in its own repository, [hevnsnt/cvengine-sentinel](https://github.com/hevnsnt/cvengine-sentinel), not a per-OS package the web app ships. The `generate_sentinel_enrollment` MCP tool takes optional `project`/`org` arguments (at most one; neither means instance-wide) and returns the same blob plus the clone URL and the exact `docker compose` setup steps, so an agent with only Docker and shell access to a target machine (no prior context on Sentinels) can provision one unattended. See [AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents).

**Per project.** Once any Sentinel whose scope covers a project (named directly, via its organization, or instance-wide; pending, active or suspended, not revoked) has registered, that project gains a **Sentinels** link (More sheet, and the side rail under Work) to `/cve/{slug}/sentinels/`. The page lists the Sentinels covering the project from `GET /api/v1/projects/{slug}/sentinels` (status, live or offline, last heartbeat, the level it covers the project at, capabilities, and this project's task counts; another tenant's scope and the owner are not shown), with **Approve**/**Suspend**/**Revoke** only on the rows the caller may administer (`manageable`), plus this project's recent work from `GET /api/v1/projects/{slug}/sentinel-tasks`. Provisioning stays on the global page. A project administrator also sees an **Internal networks** card there: list, declare (CIDR plus description) and remove the private networks the project owns, via `projects/{slug}/internal-ranges`; the card stays hidden for anyone else (the API answers 403).

## Settings and extending

Under **Settings** (superusers): **AI model** (Anthropic, OpenAI, OpenRouter, Ollama, or vLLM with **Load models** and **Save and test**, the daily AI planning budget, and the auto-fire card), **Scan engines** (the **Nuclei templates** switch and the engine YAML), and **Updates**. Both are described in [CONFIGURATION.md](CONFIGURATION.md#settings-in-the-app). **Updates** sets how updates are installed (Manual or Automatic), the update source (repository, branch, token), and shows a six-step timeline after you Approve (approved, the host picks it up, scans pause and drain, files update, services rebuild, scanning resumes), usually 3 to 6 minutes. When no host updater reports, it shows the one command to run, with a Copy button. For superusers a slim bar on every page announces a new version (Review and update, Dismiss) and, once approved, shows the progress and greys the page while services rebuild ([UPDATES.md](UPDATES.md)).

The **Add targets** dialog takes an organization and project, `#Project` and `##Organization` grouped pastes, a file (`.txt`, `.csv`, `.list`), a live count, a discovery mode (Standard, Deep, Passive, or Just add), and an authorization tick, then links to **Watch it live**.

`/cve/settings/` is backed by `cveFeed/settings_api.py` (`/cve/api/settings/...`), needs a superuser session and CSRF, and is not part of the agent API. Secrets are write-only: responses say whether one is set, and a blank value keeps the stored one.

Page logic lives in `web/static/cve/app.js`. To add a section, add an entry to `SECTIONS` in `cveFeed/views.py`, a URL pattern, and a function in `pages`. The pages inherited from reNgine are retired and forward to their cvENGINE equivalents. The scan report (`/scan/create_report/<id>`) and the plain-text exports (`/scan/export/{subdomains,urls,endpoints}/<id>`) remain.

See also: [AGENT-API.md](AGENT-API.md), [TENANCY.md](TENANCY.md), [documentation index](README.md).

## Themes, preferences and the keyboard

Light is the default and is always on. Dark applies only when the viewer picks Dark, or Auto while the system is dark (account
menu, Theme). `static/cve/theme.js` runs in the head before the stylesheet and sets `data-theme` on `<html>`, so there is no flash.
Every color in `cve.css` is a token: the dark palette is one block of overrides after `:root`. `--ink` is the high-contrast
foreground and also the fill of selected rows and primary buttons, so in dark it becomes light and `--on-ink` (the text on that
fill) becomes dark. Text on solid fire, smoke, ice and ok fills stays white through `--on-solid`. Do not add a raw hex or `rgba()`
outside the token blocks; the one allowed exception is the QR code, which must stay black on white.

Per-browser preferences (localStorage, nothing sent to the server): theme (`cve.theme`), time zone (`cve.tz`, local or UTC),
saved views on Hosts and Findings (`cve.views.v1.<project>.<page>`, 12 per page), the last project used in each organization (`cve.org.last.v1`), Live graph pin positions (`cve.pins.<project|all>`), the "new since you last looked" baseline (`cve.seen.v1.<project>.<page>`) and
desktop notifications (`cve.notify.desktop`).

Modules: `views.js` (filters in the URL and saved views), `saved-searches.js` (saved searches with alerts, kept on the server), `bulk.js` (select mode and the action bar; actions run the single-item
request four at a time), `keys.js` (vim-style keys and the `?` sheet), `seen.js` (new markers), `notify.js` (scan notices),
`prefs.js` (time zone formatting, theme chooser), `charts.js` (area chart, heatmap, sparkline), `csv.js` (CSV export of the current filter, formula-safe), `rowmenu.js` (row actions menu), `palette-search.js` (Shodan-style filters, suggestions and host preview in Ctrl+K). Script URLs are content-hashed, so restart the
web container after editing a static file.

Checks used while building these: axe-core (WCAG 2.0 and 2.1 A and AA) on 18 pages in light, dark and auto, with zero
violations, plus a computed-style comparison showing the light theme is unchanged by the token work.
