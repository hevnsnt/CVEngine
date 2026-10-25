# Front end

The interface is server-rendered page shells plus plain ES modules that fill them from the REST API (`/api/v1`) and a few UI-only JSON endpoints under `/cve/api/`. The UI and agents share the same project-scoped code. There is no build step, no framework, and no CDN.

## Design

`web/static/cve/cve.css` is a light, monochrome design system: ink on neutral grays, wide-tracked caps for labels, and fine corner marks on the main panels. Color is rare and means something: red and amber for severity and threat tier, slate for low, a green dot for healthy, and brand orange for running state and the active navigation marker. Type is [Geist](https://github.com/vercel/geist-font), vendored.

- **Shell** (`base.html`, `shell.js`): a sidebar from 1024px wide, a top bar, a bottom tab bar, and a "More" sheet below that. The top bar holds the palette (Ctrl/Cmd+K or "/") and Add targets. The palette jumps to pages, projects, and saved views, and from two characters on it runs a [host search](SEARCH.md) with filter suggestions (Tab completes), a live preview of up to six hosts, and a syntax help sheet. Enter opens the Hosts page with the query.
- **Dashboard**: opens on **All projects** when you can see two or more. Exposed hosts, a map of the 100 highest-scoring live hosts colored by threat, CVE feed temperature bars that filter the feed, live counters, a discovery ticker, and an AI activity card, each scrolling back through its last 100 lines. A strip says how many changes happened since you last looked. **Trends** chart new findings and inventory changes per day (7, 30, or 90 days), and the CVE matches and Findings counters carry 14-day sparklines.
- **Mobile**: 16px gutters, 44px touch targets, stacked-card tables, visible focus rings, and reduced-motion support.
- **Safe by construction**: DOM is built with `textContent` (the only `innerHTML` uses are the QR image on My account and a fixed icon in the row menu), and destructive actions use an in-page confirmation.

Static files are content-versioned and nginx sends `Cache-Control: no-cache` for `/staticfiles/`, so a CDN cannot serve one release's stylesheet with the next release's pages.

## Pages

| Page | What |
| --- | --- |
| `/cve/` | Dashboard and live CVE feed |
| `/cve/<project>/targets/` | Add a domain, IP, CIDR, range, or URL, set its scope, and start a scan |
| `/cve/<project>/scans/`, `.../scans/<id>/` | Scan list with stop controls, and scan detail: stages, subdomains, endpoints, findings, activity |
| `/cve/<project>/hosts/` | Inventory sorted by score, one row per hostname, with [Shodan-style search](SEARCH.md), heat chips, saved views, a screenshot **Gallery**, CSV export, and Select mode. The detail pane has six tabs (keys 1 to 6): **Overview** (exposed surface, hosting, technologies, why the heat and score, what the web archive remembers), **Services** (ports, banners, script output, database facts, RDP login screens), **Web** (routes and their auth state, sensitive-data and zombie badges, screenshot comparison), **Findings**, **History** (the last 365 days of changes, grouped by day), and **Manage** (asset info, **Rescan host**, pin, archive, **Delete host data**, **Remove & exclude**). |
| `/cve/<project>/vulns/` | **Findings**: CVE matches, scanner findings, and hygiene findings in one list, hottest first, with a detail pane. Filter by type, severity, status, and overdue (`?type=`, `?severity=`, `?status=`, `?host=` preselect). Each row shows its age against fixed targets (critical 7 days, high 30, medium 90, low 180). The default view is what heats a host. CSV export and bulk status. |
| `/cve/<project>/matches/` | CVE-on-host matches with a detail pane, remediation status, bulk status, and AI verdict filters (`?cve=`, `?host=` preselect) |
| `/cve/<project>/changes/` | What changed: hosts, ports, versions, technologies, certificates, auth state, and screenshots |
| `/cve/<project>/hygiene/`, `.../activity/`, `.../keys/` | Email and TLS checks, the full AI activity log, and project API keys for OSINT services |
| `/cve/_all/<section>/` | **All projects**: the same sections across every project you can see |
| `/cve/graph/` | Live asset graph |
| `/cve/bounty/` | Bug bounty workbench, for authorized users ([BUG-BOUNTY.md](BUG-BOUNTY.md)) |
| `/cve/agents/` | API tokens and MCP connection commands |
| `/cve/admin/` | Administration: people, organizations, projects, audit log, activity and error log, plus timings and scheduler health for superusers |
| `/cve/account/` | Your password and two-step sign-in |
| `/cve/settings/` | Superusers: AI model, API vault, notifications, scan engines, IP allowlist, proxy, reports, resources, updates, factory reset |
| `/cve/welcome/`, `/cve/setup/` | First-run setup and connecting an AI model. Once a model is connected, the account menu shows **AI Model Usage** ([AI-USAGE.md](AI-USAGE.md)). |
| `/login/` | Sign-in with two-step verification |

Finding and match detail panes show why it matters, how it was found, when it was first and last seen, the AI's classification (and the model's own words when a rule overrode it), how to fix it, and every check that ran with the exact command to repeat it. A CVE match also has a **Validate now** button.

**All projects** is offered when you can see two or more projects. Adding and changing targets and scans, and detail pane edits, are not available there: each detail pane ends with "Open in <project> to make changes". Select mode and the row menu still work on Hosts and Findings, and each change goes to that row's own project. A small chip names each row's project, and links open the item in its own project. **Add targets** stays available, with a `#Project` line above each list.

## Working in lists

- **URL carries the view.** Hosts reads `?q=`, `sort=name`, `heat=fire|smoke|ice|clean|unscanned`, `view=gallery`, and `host=<name>`. Defaults stay out of the link, so a bookmark is short.
- **CSV export** on Hosts and Findings downloads the current filter (UTF-8 with a BOM, 20,000 rows at most, 2,000 for Findings). A leading `=`, `+`, `-`, or `@` is escaped so spreadsheets do not run it.
- **Row menu**: the `...` button on a row, or `.` on a focused row. Copy name or link, open in a new tab, pin, archive, or set a status.
- **Undo**: pin, archive, criticality, owner, and status changes offer Undo for 10 seconds when every row succeeded.
- **Keys**: `g` then `l` Live, `a` graph, `h` Hosts, `c` Changes, `v` Activity, `m` matches, `f` Findings, `y` Hygiene, `t` Targets, `s` Scans, `k` API keys, `b` Bug bounty. In lists `j` and `k` move, Enter opens, `x` selects, `f` focuses the filter. In a host or finding `1` to `6` switch tabs and `y` copies the name. `?` shows the sheet. Keys are off while you type.

## Settings and extending

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
saved views on Hosts and Findings (`cve.views.v1.<project>.<page>`, 12 per page), Live graph pin positions (`cve.pins.<project|all>`), the "new since you last looked" baseline (`cve.seen.v1.<project>.<page>`) and
desktop notifications (`cve.notify.desktop`).

Modules: `views.js` (filters in the URL and saved views), `bulk.js` (select mode and the action bar; actions run the single-item
request four at a time), `keys.js` (vim-style keys and the `?` sheet), `seen.js` (new markers), `notify.js` (scan notices),
`prefs.js` (time zone formatting, theme chooser), `charts.js` (area chart, heatmap, sparkline), `csv.js` (CSV export of the current filter, formula-safe), `rowmenu.js` (row actions menu), `palette-search.js` (Shodan-style filters, suggestions and host preview in Ctrl+K). Script URLs are content-hashed, so restart the
web container after editing a static file.

Checks used while building these: axe-core (WCAG 2.0 and 2.1 A and AA) on 18 pages in light, dark and auto, with zero
violations, plus a computed-style comparison showing the light theme is unchanged by the token work.
