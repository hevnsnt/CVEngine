# Front end

The interface is server-rendered page shells plus plain ES modules that fill them from the REST API (`/api/v1`) and a few UI-only JSON endpoints under `/cve/api/`. The UI and agents share the same project-scoped code. There is no build step, no framework, and no CDN.

## Design

`web/static/cve/cve.css` is a light, monochrome design system: ink on neutral grays, wide-tracked caps for labels, and fine corner marks on the main panels. Color is rare and means something: red and amber for severity and threat tier, slate for low, a green dot for healthy, and brand orange for running state and the active navigation marker. Type is Geist and Geist Mono, vendored.

- **Shell** (`cveFeed/templates/cveFeed/base.html`, `static/cve/shell.js`): a sidebar from 1024px wide. Below that, a top bar, a bottom tab bar, and a "More" sheet. The top bar holds the jump palette (Ctrl/Cmd+K or "/") and Add targets.
- **Dashboard**: exposed hosts, an attack-surface map with one tile per host colored by threat and ordered by score, CVE feed temperature bars that filter the feed, live counters, a live discovery ticker, and an AI activity card. Both cards scroll back through their last 100 lines.
- **Mobile**: 16px gutters, 44px touch targets, stacked-card tables under 640px, visible focus rings, and reduced-motion support.
- **Safe by construction**: DOM is built with `textContent`, never `innerHTML`, and destructive actions use an in-page confirmation (`ask()` in `ui.js`).

Static files are content-versioned (`{% asset %}` and an import map) and nginx sends `Cache-Control: no-cache` for `/staticfiles/`, so a CDN cannot serve one release's stylesheet with the next release's pages.

## Pages

| Page | What |
| --- | --- |
| `/cve/` | Dashboard and live CVE feed |
| `/cve/<project>/targets/` | Add a domain, IP, CIDR, range, or URL, set its scope, and start a scan |
| `/cve/<project>/scans/` | Scan list with stop controls, refreshing while scans run |
| `/cve/<project>/scans/<id>/` | Scan detail: stages, subdomains, endpoints, findings, activity |
| `/cve/<project>/hosts/` | Inventory sorted by score, one row per hostname, with the reasons for the score, notable web routes and their auth state, sensitive-data and zombie badges, recent changes, and a screenshot comparison after a visible change |
| `/cve/_all/<section>/` | **All projects**: targets, scans, hosts, changes, activity, vulns, matches, and hygiene across every project you can see, read-only |
| `/cve/<project>/changes/` | What changed: hosts, ports, versions, technologies, certificates, auth state, and screenshots |
| `/cve/<project>/vulns/` | Findings as a list with a detail pane, filtered by severity and AI classification. The default view hides info-level detections. |
| `/cve/<project>/matches/` | CVE-on-host matches as a list with a detail pane, with remediation status set in the pane |
| `/cve/<project>/hygiene/` | TLS, SPF, DKIM, DMARC, and CAA checks |
| `/cve/<project>/activity/` | The full AI activity log, with a kind filter |
| `/cve/<project>/keys/` | Project API keys for OSINT services |
| `/cve/graph/` | Live asset graph |
| `/cve/agents/` | API tokens and MCP connection commands |
| `/cve/admin/` | Administration: people, organizations, projects, audit log, and the activity and error log (organization admins and superusers), plus timings and scheduler health (superusers) |
| `/cve/account/` | Your password and two-step sign-in |
| `/cve/settings/` | Superusers: AI model, API vault, notifications, scan engines, IP allowlist, proxy, reports, resources, updates, factory reset |
| `/cve/welcome/`, `/cve/setup/` | First-run guided setup, and connecting an AI model (superusers). Once a model is connected, the Setup menu shows **AI Model Usage** ([AI-USAGE.md](AI-USAGE.md)). |
| `/login/`, `/mfa/*` | Sign-in and two-step sign-in |

### Finding detail

Vulnerabilities and CVE matches use the list-and-detail layout of Hosts, with a back button on phones. Each card shows the AI classification (Confirmed, Likely, Needs validation, Likely false positive, Not applicable, or Not triaged) and a second badge for the validation result. The detail pane shows why the finding matters, how it was found, when it was first and last seen with the host's recent changes, the AI's classification (and the model's own words when a rule overrode it), how to fix it, and every check that ran with the exact command to repeat it. Checks run on their own, so there is no run button.

## All projects

The first option in the project switcher, **All projects**, is offered to users who can see two or more projects. It opens the same sections across every project, read-only: no stop, delete, scope, or remediation controls, and each detail pane ends with "Open in <project> to make changes". A small outlined chip names each row's project, and links open the item in its own project. **Add targets** stays available, with a `#Project` line above each list.

The Hosts detail pane also holds an Asset info editor (owner, purpose, criticality) and two confirmed destructive buttons: **Delete host data** (this project) and **Remove & exclude** (the whole organization).

## Settings

`/cve/settings/` is backed by `cveFeed/settings_api.py` (`/cve/api/settings/...`). It needs a superuser session and CSRF, and it is deliberately not part of the agent API. Secrets (AI key, API vault, webhook URLs, bot tokens) are write-only: responses say whether one is set, and a blank value keeps the stored one. Scan engine YAML is validated, and an engine with scan history cannot be deleted.

## Extending

Page logic lives in `web/static/cve/app.js`. To add a section, add an entry to `SECTIONS` in `cveFeed/views.py`, a URL pattern, and a function in `pages`.

The pages inherited from reNgine were retired, and `RetireClassicUiMiddleware` forwards their old addresses to the matching CVEngine page. The scan report (`/scan/create_report/<id>`) and the plain-text exports (`/scan/export/{subdomains,urls,endpoints}/<id>`) remain.

See also: [AGENT-API.md](AGENT-API.md), [TENANCY.md](TENANCY.md), [documentation index](README.md).
