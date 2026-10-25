// CVEngine project pages: targets, scans, hosts, vulnerabilities, CVE matches (the last two as list plus detail, like hosts).
// Plain ES module over the REST API (/api/v1). DOM is built with textContent only.
import {
  ask,
  button as uiButton,
  dialog,
  field,
  text as uiText,
} from "/staticfiles/cve/ui.js";
import { cveAnchor, hostAnchor, hostHref, ipAnchor, linkify, needsValidation } from "/staticfiles/cve/links.js";

const root = document.getElementById("section");
const { slug, kind } = root.dataset;
const csrf = root.querySelector("[name=csrfmiddlewaretoken]").value;
const base = `/api/v1/projects/${encodeURIComponent(slug)}`;
// "_all" is the read-only combined view over every project the caller may see. Each of its rows names its own project, and every
// link, detail request and screenshot goes to that project, never to "_all". Anything that changes data stays per project.
const ALL = slug === "_all";
const projectOf = (row) => (ALL ? (row && row.project) || null : slug);
const baseOf = (project) => `/api/v1/projects/${encodeURIComponent(project)}`;
const scanHref = (project, id) => `/cve/${encodeURIComponent(project)}/scans/${id}/`;
const SCAN_STATUS = {
  "-1": "queued",
  0: "failed",
  1: "running",
  2: "success",
  3: "aborted",
};
const REFRESH_MS = 5000;
const LIVE_MS = 8000;

const fullScanAgo = (iso) => {
  if (!iso) return "never";
  const mins = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (mins < 60) return `${mins} min ago`;
  return mins < 2880 ? `${Math.round(mins / 60)} h ago` : `${Math.round(mins / 1440)} days ago`;
};

const el = (tag, cls, text, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};
const badge = (text, cls = "") => el("span", `badge ${cls}`.trim(), text);
// a hostname printed anywhere (except the host page itself) links to that host's page
const hostUrl = hostHref;
const hostLink = (name, project = slug) => (name && project ? hostAnchor(project, name) : name ? el("span", "", name) : el("span", "", "-"));
// a CVE id printed anywhere links to its match on that host; without a match id, to the matches that name it
const cveLink = (project, cveId, matchId, host) => (project ? cveAnchor(project, cveId, matchId, host) : el("span", "", cveId));
// "CVE CVE-2026-1" in a host's search reasons links to that CVE's match on the host; the host and IP are this row itself
const matchedWhy = (text, project, host) => {
  const m = /^CVE (CVE-\d{4}-\d{4,})$/i.exec(text);
  if (!m || !project) return document.createTextNode(text);
  const n = el("span");
  n.append("CVE ", cveAnchor(project, m[1].toUpperCase(), null, host));
  return n;
};
// a link to the record its own row selects: it keeps its address, but a plain click only selects the row
const selfLink = (a) => {
  a.classList.add("self-link");
  return a;
};
const rowIp = (project, address) => {
  const n = el("span", "note");
  n.append(selfLink(ipAnchor(project, address)));
  return n;
};
// nodes separated by commas
const joinNodes = (nodes) => {
  const box = el("span");
  nodes.forEach((n, i) => box.append(...(i ? [", ", n] : [n])));
  return box;
};
// one line of a list row made of nodes and text
const rowLine = (...parts) => {
  const n = el("span", "note host-why");
  n.append(...parts);
  return n;
};
// the project a row belongs to, as a small chip (all-projects view only; null elsewhere, which append() skips via filter)
const projChip = (row) => {
  if (!ALL || !row) return null;
  if (!row.project) return el("span", "proj-chip sys", "System", { title: "System-wide: not tied to one project" });
  return el("span", "proj-chip", row.project_name || row.project, { title: `Project ${row.project}` });
};
// all-projects view: a Project column after the first one; one project: the columns as they are
const projColumn = { label: "Project", render: (r) => projChip(r) || "-" };
const withProject = (columns, at = 1) => (ALL ? [...columns.slice(0, at), projColumn, ...columns.slice(at)] : columns);
// a trailing actions column (stop, delete ...) has no place in the read-only all-projects view
const readOnlyColumns = (columns) => (ALL ? columns.slice(0, -1) : columns);
// where an item's actions live: its own project's page
const openInProject = (row, section, hash = "") => {
  const box = el("p", "note ro-note");
  const project = projectOf(row);
  if (!project) return box;
  box.append(
    document.createTextNode("Read-only here. "),
    el("a", "", `Open in ${row.project_name || project} to make changes`, { href: `/cve/${encodeURIComponent(project)}/${section}/${hash}` }),
  );
  return box;
};

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try {
    data = await res.json();
  } catch (_) {
    /* empty body */
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function toast(message, isError = false) {
  const t = el("div", `toast${isError ? " err" : ""}`, message, {
    role: "status",
  });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

const query = (obj) => {
  const p = new URLSearchParams();
  Object.entries(obj).forEach(([k, v]) => {
    if (v !== "" && v != null) p.set(k, v);
  });
  return p.toString();
};

// --- generic paginated list -------------------------------------------------
function createList({
  mount,
  path,
  params = () => ({}),
  render,
  empty,
  autoRefresh,
  onLoaded,
}) {
  let page = 1;
  let timer = null;
  let lastCount = null;
  const body = el("div");
  const more = el("div", "more-row");
  mount.append(body, more);

  // quiet: a refresh the reader did not ask for. The rows are swapped when the answer arrives, with no skeleton in between.
  async function load(reset, quiet = false) {
    if (reset) page = 1;
    if (reset && !quiet) {
      body.textContent = "";
      body.append(
        el("div", "skeleton"),
        el("div", "skeleton"),
        el("div", "skeleton"),
      );
    }
    try {
      const data = await api(
        "GET",
        `${path}?${query({ ...params(), page, page_size: 30 })}`,
      );
      const items = data.results || [];
      lastCount = data.count;
      if (reset) body.textContent = "";
      if (reset && !items.length) body.append(el("p", "empty", empty));
      else render(body, items, reset);
      if (onLoaded) onLoaded(data, reset);
      more.textContent = "";
      if (data.page * data.page_size < data.count) {
        const b = el(
          "button",
          "btn ghost",
          `Load more (${data.count - data.page * data.page_size} left)`,
        );
        b.type = "button";
        b.onclick = () => {
          page += 1;
          load(false);
        };
        more.append(b);
      }
      clearTimeout(timer);
      if (autoRefresh && autoRefresh(items))
        timer = setTimeout(() => load(true), REFRESH_MS);
    } catch (err) {
      if (quiet) return; // a failed background refresh keeps what is on screen
      body.textContent = "";
      body.append(el("p", "msg err", err.message));
    }
  }
  const live = {
    alive: () => body.isConnected,
    atTop: () => page === 1, // someone who pressed "Load more" keeps their place
    count: () => lastCount,
    peek: async () => (await api("GET", `${path}?${query({ ...params(), page: 1, page_size: 1 })}`)).count,
    reload: () => load(true, true),
  };
  return {
    reload: () => load(true),
    start: () => {
      liveLists.add(live);
      return load(true);
    },
  };
}

// --- live numbers -------------------------------------------------------------------------------
// Every number on a page is read again every few seconds, from the same definitions the dashboard uses (/cve/api/stats and
// the list endpoints). When a headline number moves, or a filter chip's count does, or a list's own count does, the list
// reloads quietly. Nothing here polls while the tab is hidden.
const liveLists = new Set();
const livePickers = new Set();
const liveCustom = new Set();
const LIVE_KEYS = ["targets", "hosts", "hosts_live", "exposed_hosts", "matches", "scanner_findings", "scans_running", "scans_queued",
  "certs_expiring", "certs_total", "hygiene_open"];
let liveSig = null;
let liveBusy = false;
async function liveTick() {
  if (document.hidden || liveBusy) return;
  liveBusy = true;
  try {
    const s = await api("GET", `/cve/api/stats?project=${encodeURIComponent(slug)}`);
    const sig = LIVE_KEYS.map((k) => s[k]).join(",");
    let moved = liveSig !== null && sig !== liveSig;
    liveSig = sig;
    for (const p of [...livePickers]) {
      if (!p.node.isConnected) livePickers.delete(p);
      else if (await p.refresh()) moved = true;
    }
    for (const c of [...liveCustom]) {
      if (!c.alive()) liveCustom.delete(c);
      else await c.run();
    }
    for (const l of [...liveLists]) {
      if (!l.alive()) liveLists.delete(l);
      else if (l.atTop() && (moved || (await l.peek()) !== l.count())) await l.reload();
    }
  } catch (_) {
    /* the next tick tries again */
  } finally {
    liveBusy = false;
  }
}
setInterval(liveTick, LIVE_MS);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) liveTick();
});

function table(columns, heatOf) {
  let tbody = null;
  return (mount, items, reset) => {
    if (reset || !tbody) {
      const t = el("table", "table");
      const head = el("tr");
      columns.forEach((c) => {
        const th = el("th", "", c.head ? null : c.label);
        if (c.head) th.append(c.head());
        head.append(th);
      });
      const thead = el("thead");
      thead.append(head);
      t.append(thead);
      tbody = el("tbody");
      t.append(tbody);
      const wrap = el("div", "table-wrap");
      wrap.append(t);
      mount.append(wrap);
    }
    items.forEach((item) => {
      const tr = el("tr");
      const heat = heatOf && heatOf(item);
      if (heat) tr.dataset.heat = heat;
      columns.forEach((c) => {
        const td = el("td", c.cls || "", null, { "data-label": c.label });
        const out = c.render(item);
        if (out instanceof Node) td.append(out);
        else td.textContent = out == null ? "" : out;
        tr.append(td);
      });
      tbody.append(tr);
    });
  };
}

const duration = (from, to) => {
  const ms = (to ? new Date(to) : new Date()) - new Date(from);
  if (!Number.isFinite(ms) || ms < 0) return "-";
  const m = Math.floor(ms / 60000);
  if (m < 1) return `${Math.max(1, Math.round(ms / 1000))}s`;
  return m < 60 ? `${m}m` : `${Math.floor(m / 60)}h ${m % 60}m`;
};
const meterCell = (n, of) => {
  const box = el("div", "meter-cell");
  const bar = el("div", "meter");
  const fill = el("i");
  fill.style.width = of ? `${Math.round((100 * n) / of)}%` : "0%";
  bar.append(fill);
  box.append(bar, el("b", "", n ?? 0));
  return box;
};
// A KPI tile: big number, mono label; "hot" colours it when the number is above zero.
const tile = (label, n, { hot = "", onClick = null, href = "" } = {}) => {
  const t = el(href ? "a" : onClick ? "button" : "div", `tile${n ? ` ${hot}` : " dim"}`.trimEnd());
  if (href) t.setAttribute("href", href);
  if (onClick) {
    t.type = "button";
    t.onclick = onClick;
  }
  t.append(el("b", "", n ?? "-"), el("span", "", label));
  return t;
};

const debounce = (fn, ms = 300) => {
  let t;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
};
const shortDate = (iso) => (iso ? iso.slice(0, 16).replace("T", " ") : "-");

function searchBox(placeholder, onChange) {
  const input = el("input", "", null, {
    type: "search",
    placeholder,
    "aria-label": placeholder,
  });
  input.addEventListener("input", debounce(onChange));
  return input;
}

// A row of toggle buttons with live counts: one is always pressed, "value" is its key. count(key) -> Promise<number>.
function picker(label, options, count, onChange) {
  const node = el("div", "picker", null, { role: "group", "aria-label": label });
  const out = { node, value: options[0][0] };
  const buttons = new Map();
  options.forEach(([key, text, dot]) => {
    const b = el("button", "", null, { type: "button", "aria-pressed": String(key === out.value) });
    if (dot) b.append(el("span", `dot ${dot}`));
    b.append(document.createTextNode(text), el("b", "", "·"));
    b.onclick = () => {
      out.value = key;
      buttons.forEach((btn, k) => btn.setAttribute("aria-pressed", String(k === key)));
      onChange();
    };
    buttons.set(key, b);
    node.append(b);
  });
  // resolves true when any chip's number moved since it was last drawn (the first draw is not a move)
  out.refresh = () =>
    Promise.all(
      options.map(([key]) =>
        count(key)
          .then((n) => {
            const label = buttons.get(key).lastChild;
            const moved = /^\d+$/.test(label.textContent) && label.textContent !== String(n);
            label.textContent = n;
            return moved;
          })
          .catch(() => false),
      ),
    ).then((moves) => moves.some(Boolean));
  out.node = node;
  livePickers.add(out);
  return out;
}

function select(label, options, onChange) {
  const s = el("select", "", null, { "aria-label": label });
  options.forEach(([value, text]) =>
    s.append(Object.assign(el("option", "", text), { value })),
  );
  s.addEventListener("change", onChange);
  return s;
}

// --- asset changes (the Changes page and the host pane share these) ------------------------------
const CHANGE_LABEL = {
  host_new: "New host",
  host_returned: "Host returned",
  host_retired: "Host retired",
  port_opened: "Port opened",
  port_closed: "Port closed",
  service_changed: "Version changed",
  tech_added: "Technology added",
  tech_removed: "Technology removed",
  tech_version_changed: "Technology version",
  cert_changed: "Certificate changed",
  auth_changed: "Auth state",
  sensitive_found: "Sensitive data",
  zombie_host: "Zombie host",
  zombie_cleared: "Zombie cleared",
  route_retired: "Route retired",
  zombie_route: "Zombie route",
  screenshot_changed: "Screenshot changed",
};
const AUTH_RANK = { open: 0, login: 1, session_required: 2, sso: 3 };
const AUTH_LABEL = { open: "open", login: "login page", session_required: "session required", sso: "SSO", redirect: "redirect", not_found: "not found" };
const authLabel = (s) => AUTH_LABEL[s] || s || "unknown";
const pathOf = (url) => {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch (_) {
    return url || "";
  }
};
// Amber ("smoke") for more exposure, slate ("ice") for less, plain for the rest.
function changeClass(c) {
  if (["host_new", "host_returned", "port_opened", "zombie_host", "zombie_route", "sensitive_found"].includes(c.kind)) return "smoke";
  if (["port_closed", "host_retired", "route_retired", "zombie_cleared"].includes(c.kind)) return "ice";
  if (c.kind === "auth_changed") {
    const was = AUTH_RANK[(c.before || {}).auth_state];
    const now = AUTH_RANK[(c.after || {}).auth_state];
    return was != null && now != null && now < was ? "smoke" : "";
  }
  return "";
}
const svcText = (s) => [s.product || s.service, s.version].filter(Boolean).join(" ");
const dateOnly = (iso) => (iso ? String(iso).slice(0, 10) : "?");
function changeDetail(c) {
  const b = c.before || {};
  const a = c.after || {};
  switch (c.kind) {
    case "host_new":
      return `New host${a.ips && Object.keys(a.ips).length ? ` · ${Object.keys(a.ips).join(", ")}` : ""}`;
    case "host_returned":
      return "Resolves again after being retired";
    case "host_retired":
      return "No longer resolves";
    case "port_opened":
      return `${c.ip}:${a.port || c.port} ${svcText(a)}`.trim();
    case "port_closed":
      return `${c.ip}:${b.port || c.port} ${svcText(b)}`.trim();
    case "service_changed":
      return `${a.port || c.port} ${svcText(b) || "?"} -> ${svcText(a) || "?"}`;
    case "tech_added":
      return String(a);
    case "tech_removed":
      return String(b);
    case "tech_version_changed":
      return `${b} -> ${a}`;
    case "cert_changed": {
      const parts = [];
      if (b.issuer !== a.issuer) parts.push(`issuer ${b.issuer || "?"} -> ${a.issuer || "?"}`);
      if (b.subject !== a.subject) parts.push(`subject ${b.subject || "?"} -> ${a.subject || "?"}`);
      if (b.not_after !== a.not_after) parts.push(`expires ${dateOnly(b.not_after)} -> ${dateOnly(a.not_after)}`);
      if (!parts.length) parts.push("names or key changed");
      return parts.join(", ");
    }
    case "auth_changed":
      return `${pathOf(a.url || b.url)}: ${authLabel(b.auth_state)} -> ${authLabel(a.auth_state)}`;
    case "sensitive_found":
      return `${pathOf(a.url)}: ${(a.types || []).join(", ")}`;
    case "zombie_host":
      return `DNS is gone but it still answers on ${(a.alive || []).join(", ")}`;
    case "zombie_cleared":
      return "Resolves again";
    case "route_retired":
      return `${pathOf(b.url || a.url)}: ${authLabel(b.auth_state)} -> gone (${a.http_status})`;
    case "zombie_route":
      return `${pathOf(a.url)} answers again (${a.http_status})`;
    case "screenshot_changed":
      return `front page changed (distance ${a.distance} of 64)${["login", "sso"].includes(a.root_auth) ? ", now shows a login page" : ""}`;
    default:
      return c.kind;
  }
}
const SENSITIVE_GROUP = {
  credentials: ["aws_key", "google_key", "slack_token", "github_token", "stripe_key", "jwt", "private_key"],
  pii: ["email", "phone", "card"],
  internal: ["internal_ip", "internal_host"],
};
const AUTH_BADGE = { open: "smoke", login: "", session_required: "ice", sso: "success", redirect: "queued", not_found: "queued", error: "queued" };
const NOTABLE_ROUTES = ["open", "login", "session_required", "sso"];
function routeLine(r) {
  const line = el("div", "find");
  line.append(badge(authLabel(r.auth_state), AUTH_BADGE[r.auth_state] || ""));
  if (r.zombie_since) line.append(badge("zombie", "smoke"));
  else if (r.retired_at) line.append(badge("retired", "queued"));
  line.append(el("span", "mono", r.path), el("span", "note", r.http_status ? String(r.http_status) : ""));
  const types = Object.keys(r.sensitive || {});
  if (types.some((t) => SENSITIVE_GROUP.credentials.includes(t))) line.append(badge("credentials", "fire"));
  if (types.some((t) => SENSITIVE_GROUP.pii.includes(t))) line.append(badge("PII", "smoke"));
  if (types.some((t) => SENSITIVE_GROUP.internal.includes(t))) line.append(badge("internal", "ice"));
  const detail = r.provider || r.redirect_to;
  if (detail) line.append(el("span", "note", detail));
  if (types.length) {
    // counts and a masked sample only: the API never returns the values
    const first = r.sensitive[types[0]];
    line.append(el("span", "note", `GET ${r.path} → ${types.map((t) => `${t} x${r.sensitive[t].count}`).join(", ")} (${first.sample})`));
  }
  return line;
}
function shotPair(c, project = slug) {
  const pair = el("div", "shot-pair");
  [c.before, c.after].forEach((side, i) => {
    if (!side || !side.subdomain_id) return;
    const img = el("img", "shot", null, {
      src: `/cve/${encodeURIComponent(project)}/hosts/${side.subdomain_id}/screenshot/`,
      alt: `${i ? "Current" : "Previous"} screenshot of ${c.host}`,
      loading: "lazy",
    });
    img.onerror = () => img.remove();
    pair.append(img);
  });
  return pair;
}
function changeCell(c, project = slug) {
  const box = el("div");
  box.append(linkify(el("span"), changeDetail(c), project, { kinds: ["ip"] }));
  if (c.kind === "screenshot_changed" && project) box.append(shotPair(c, project));
  return box;
}

// --- triage: badges, and the list-plus-detail layout of Vulnerabilities and CVE matches ----------------------
// Every finding carries the AI's classification and the state of CVEngine's own read-only checks. A likely false positive is
// listed like any other row: triage never hides a finding.
const CLASS_BADGE = {
  confirmed: ["Confirmed", "fire"],
  likely: ["Likely", "smoke"],
  needs_validation: ["Needs validation", "ice"],
  likely_false_positive: ["Likely false positive", "fp"],
  not_applicable: ["Not applicable", "fp"],
};
const VALIDATION_BADGE = {
  hit: ["Validated", "success"],
  observed: ["Metadata observed", "queued"],
  clean: ["Not reproduced", "queued"],
  failed: ["Check failed", "queued"],
  pending: ["Check queued", "queued"],
  skipped_blocked: ["Check skipped", "queued"],
};
const STEP_RESULT = {
  hit: "reproduced",
  no_match: "not reproduced",
  reaffirmed: "still holds",
  version_changed: "the version differs now",
  observed: "observed",
  failed: "failed",
  blocked: "not run",
};
const SEV_HEAT = { critical: "fire", high: "fire", medium: "smoke", low: "ice", info: "" };
const CLASS_OPTIONS = [
  ["", "All classifications"],
  ["confirmed", "Confirmed"],
  ["likely", "Likely"],
  ["needs_validation", "Needs validation"],
  ["likely_false_positive", "Likely false positive"],
];
// ``of`` = {project, kind, id} names the finding the label sits on: "Needs validation" then opens it (a match: with Validate now pressed)
const aiBadge = (t = {}, of = null) => {
  if (t.classification === "needs_validation" && of && of.project && of.id) return needsValidation(of.project, of.kind, of.id);
  if (t.classification && CLASS_BADGE[t.classification]) return badge(...CLASS_BADGE[t.classification]);
  if (t.status === "not_triaged") return badge("Not triaged", "fp");
  if (t.status === "error") return badge("Triage failed", "queued");
  return badge("Queued", "queued");
};
const validationBadge = (t = {}) => {
  const v = VALIDATION_BADGE[t.validation_status];
  return v ? badge(v[0], v[1]) : null;
};
const detailSection = (title) => {
  const box = el("div", "why");
  box.append(el("h3", "sec", title));
  return box;
};
const kvBox = (rows) => {
  const box = el("div", "kvs");
  rows.forEach(({ label, value }) => {
    const d = el("div", "kv");
    d.append(el("span", "k", label), el("span", "v", value));
    box.append(d);
  });
  return box;
};
// "ACME  ·  SRV01  ·  srv01.acme.example": what the RDP and SMB scripts say a Windows address is called
const factLine = (facts) => {
  const f = facts || {};
  return [f.os, f.computer_name, f.fqdn || f.dns_domain || f.domain].filter(Boolean).join("  ·  ");
};
// The top of the host page, Shodan-style: who hosts it, what answers on the web, what the operating system is
const hostOverview = (h) => {
  const http = h.http || {};
  const hosting = h.hosting || {};
  const rows = [];
  if (hosting.provider) {
    const note = [hosting.kind, hosting.shared_ip ? "shared address" : "", hosting.infrastructure].filter(Boolean).join(", ");
    rows.push({ label: "Hosting", value: note ? `${hosting.provider} (${note})` : hosting.provider });
  } else if (hosting.infrastructure) rows.push({ label: "Hosting", value: hosting.infrastructure });
  const systems = [...new Set(h.ips.map((ip) => ip.os || (ip.facts || {}).os).filter(Boolean))];
  if (systems.length) rows.push({ label: "Operating system", value: systems.join(", ") });
  const identities = [...new Set(h.ips.map((ip) => factLine(ip.facts)).filter(Boolean))];
  if (identities.length) rows.push({ label: "Windows identity", value: identities.join("; ") });
  if (http.webserver) rows.push({ label: "Web server", value: http.webserver });
  if (http.powered_by) rows.push({ label: "Powered by", value: http.powered_by });
  if (http.title) rows.push({ label: "Page title", value: http.title });
  if (http.url) rows.push({ label: "Front page", value: `${http.url}${http.status ? ` (HTTP ${http.status})` : ""}` });
  if (http.redirect_to) rows.push({ label: "Redirects to", value: http.redirect_to });
  if (http.cname) rows.push({ label: "CNAME", value: http.cname });
  const countries = [...new Set(h.ips.map((ip) => ip.country).filter(Boolean))];
  if (countries.length) rows.push({ label: "Country", value: countries.join(", ") });
  const reverse = [...new Set(h.ips.map((ip) => ip.reverse).filter(Boolean))];
  if (reverse.length) rows.push({ label: "Reverse DNS", value: reverse.join(", ") });
  const shared = h.ips.filter((ip) => ip.names_on_ip > 1).map((ip) => `${ip.address} (${ip.names_on_ip} names)`);
  if (shared.length) rows.push({ label: "Shared with", value: shared.join(", ") });
  if (!rows.length) return el("div");
  const box = el("div", "why host-overview");
  box.append(el("h3", "sec", "Overview"), kvBox(rows));
  return box;
};
// Technologies with version, kind and where they were seen; what only the web archive remembers is listed apart and labelled
const technologyTable = (h) => {
  const details = h.technology_details || [];
  const archived = h.archived_technologies || [];
  if (!details.length && !archived.length) return null;
  const box = el("div", "tech-table");
  if (details.length) {
    box.append(el("h3", "sec", `Technologies (${details.length})`));
    details.forEach((t) => {
      const line = el("div", "find tech-line");
      line.append(el("strong", "", t.name));
      if (t.version) line.append(el("span", "chip", t.version));
      if (t.category) line.append(badge(t.category, "queued"));
      line.append(el("span", "note", t.source ? `seen via ${t.source}` : ""));
      box.append(line);
    });
  }
  if (archived.length) {
    box.append(el("h3", "sec", "Seen in the web archive"));
    box.append(el("p", "note", "Historical only: archived pages show this host ran these at some point, not that it runs them now."));
    const chips = el("div", "host-labels");
    archived.forEach((a) => chips.append(el("span", "chip", `${a.name} (${a.urls} URLs)`, { title: (a.examples || []).join("\n") })));
    box.append(chips);
  }
  return box;
};
// A port's RDP login-screen capture (cveFeed.rdp_shot): the image, exactly as read by the AI (never guessed), and its summary.
// Only ever present when nmap already confirmed the server accepts a connection without Network Level Authentication.
const rdpShotCard = (shot) => {
  const box = el("div", "rdp-shot");
  box.append(el("div", "note", "RDP login screen (captured with no credentials sent)"));
  if (shot.url) {
    const img = el("img", "shot rdp-shot-img", null, { src: shot.url, alt: "RDP login screen capture", loading: "lazy" });
    img.onerror = () => img.remove();
    box.append(img);
  }
  if (shot.logged_in_user) box.append(badge(`Signed in: ${shot.logged_in_user}`, "smoke"));
  else if (!shot.error) box.append(badge("No one signed in", "success"));
  if (shot.summary) box.append(el("p", "note", shot.summary));
  if (shot.error) box.append(el("p", "note", `Could not be read: ${shot.error}`));
  if (shot.captured_at) box.append(el("p", "note", `Captured ${shortDate(shot.captured_at)}`));
  return box;
};
const DB_FIELD_LABELS = {
  version: "Version", protocol: "Protocol", role: "Role", architecture: "Architecture",
  uptime: "Uptime", authentication: "Authentication", auth: "Authentication",
  windows_server: "Windows server", version_number: "Version number",
  computer_name: "Computer name", domain: "Domain", fqdn: "FQDN", dns_domain: "DNS domain", os: "Operating system",
};
// A database port's richer metadata (cveFeed.db_intel), read from its own pre-authentication greeting. This is
// version and identity only, never a sign of whether the server needs a password: that question is answered
// separately, by the critical finding cveFeed.db_exposure raises when a real connection goes through unchallenged.
const dbFactsCard = (db) => {
  const rows = [];
  const seen = new Set();
  Object.values(db || {}).forEach((facts) => {
    Object.entries(facts || {}).forEach(([key, value]) => {
      if (key === "admin_party" || seen.has(key) || value === "" || value == null) return;
      seen.add(key);
      rows.push({ label: DB_FIELD_LABELS[key] || key, value: String(value) });
    });
  });
  if (!rows.length) return null;
  const box = el("div", "db-facts");
  box.append(kvBox(rows));
  if (Object.values(db || {}).some((facts) => facts && facts.admin_party)) {
    box.append(badge("Admin party: no authentication configured", "critical"));
  }
  return box;
};
const excerpt = (label, text) => {
  const box = el("div");
  box.append(el("div", "note", label), el("pre", "banner", text));
  return box;
};
const OS_LABEL = { linux: "Linux", windows: "Windows", any: "Linux or Windows" };
// When no external check can settle a finding, the model suggests short, read-only local commands a host owner
// can run themselves (cveFeed.triage.suggest_local_checks). Unverified by this tool: shown as a suggestion, not evidence.
const localChecksBox = (local) => {
  const box = el("div", "local-checks");
  const commands = local?.commands || [];
  if (!commands.length && !local?.caveat) return box;
  box.append(el("p", "note", "AI-suggested, unverified: confirm against the vendor's own documentation."));
  commands.forEach((c) => {
    const row = el("div", "local-check");
    const head = el("div", "tools");
    head.append(badge(OS_LABEL[c.os] || c.os, "queued"));
    const copy = el("button", "btn ghost sm", "Copy", { type: "button" });
    copy.onclick = () => navigator.clipboard.writeText(c.command);
    head.append(copy);
    row.append(head, el("pre", "banner", c.command));
    if (c.look_for) row.append(el("p", "note", `Looks for: ${c.look_for}`));
    box.append(row);
  });
  if (local?.caveat) box.append(el("p", "note", local.caveat));
  return box;
};

function renderFinding(d, cfg, row) {
  const out = [];
  const project = projectOf(row); // the finding's own project: its host, history and screenshots live there
  const head = el("div", "host-head");
  head.append(el("h2", "host-title", d.title));
  if (d.severity) head.append(badge(d.severity, d.severity));
  if (d.assessment_status === "closed_not_applicable") head.append(badge("Closed: invalid product match", "ice"));
  head.append(aiBadge(d.ai, { project, kind: d.kind, id: d.id }));
  const vb = validationBadge({ validation_status: d.validation.status });
  if (vb) head.append(vb);
  const chip = projChip(row);
  if (chip) head.append(chip);
  const idline = el("p", "note");
  if (d.host) { idline.append(hostLink(d.host, project)); if (d.target && d.target !== d.host) idline.append(document.createTextNode(" · "), hostLink(d.target, project)); }
  else if (d.target) idline.append(hostLink(d.target, project));
  out.push(head, idline);

  if (d.automatic_validation) {
    const job = d.automatic_validation;
    const status = detailSection(job.source === "manual" ? "Manual validation" : "Automatic validation");
    status.append(kvBox([
      { label: "Queue priority", value: job.priority === 0 ? "Fire" : job.priority === 3 ? "Manual" : "Smoke" },
      { label: "Job", value: `#${job.id} · ${job.status}` },
      { label: "Queued", value: shortDate(job.created) },
      { label: "Started", value: shortDate(job.started) },
      { label: "Finished", value: shortDate(job.finished) },
      { label: "Check outcome", value: job.check_state || "Waiting" },
      { label: "AI review", value: job.ai_state || "Waiting" },
      ...(job.reason ? [{ label: "Why skipped", value: job.reason.replaceAll("_", " ") }] : []),
    ]));
    if (job.error) status.append(el("p", "note", job.error));
    out.push(status);
  }

  if (d.assessment_status === "closed_not_applicable") {
    const closure = detailSection("Assessment closure");
    closure.append(el("p", "", d.assessment_reason));
    closure.append(el("p", "note", "This closure applies to the recorded candidate match only. It does not establish that other software on the host is safe, and it is separate from remediation."));
    out.push(closure);
  }

  if (d.kind === "match" && d.cve) {
    const advisory = detailSection("About this CVE");
    advisory.append(el("p", d.cve.description ? "" : "note", d.cve.description || "No description is available in the CVE feed yet."));
    if (d.cve.summary && d.cve.summary !== d.cve.description) {
      advisory.append(el("h3", "sec", "Feed summary"), el("p", "", d.cve.summary));
    }
    if (d.cve.affected && d.cve.affected.length) {
      advisory.append(el("h3", "sec", "Products and versions in the advisory"));
      d.cve.affected.forEach((item) => {
        const name = [item.vendor, item.product || item.package].filter(Boolean).join(" ");
        const ranges = (item.ranges || []).map((r) => Object.entries(r).filter(([k, v]) => v && k !== "type")
          .map(([k, v]) => `${k} ${v}`).join(", ")).filter(Boolean).join("; ");
        advisory.append(el("div", "find", `${name || "Unspecified product"}${ranges ? `: ${ranges}` : ""}`));
      });
    } else advisory.append(el("p", "note", "Affected product and version data is unavailable."));
    const exploitation = d.cve.exploitation || {};
    const signal = (value, yes, no) => value === true ? yes : value === false ? no : "Unknown";
    // who reported each signal, when the threat-intelligence sources did (CISA KEV, ENISA EUVD, EPSS, Exploit-DB, Metasploit)
    const by = (exploitation.exploited_by || []).map((e) => `${e.source}${e.since ? ` since ${e.since}` : ""}${e.ransomware ? ", used in ransomware" : ""}`);
    const exploits = Object.entries(exploitation.public_exploits || {}).map(([source, n]) => `${source} (${n})`);
    const epss = exploitation.epss ? `${(exploitation.epss.score * 100).toFixed(1)}% chance of exploitation in 30 days${exploitation.epss.percentile != null ? ` (${Math.round(exploitation.epss.percentile * 100)}th percentile)` : ""}` : "";
    advisory.append(kvBox([
      { label: "Exploited in the wild", value: by.length ? `Listed: ${by.join("; ")}` : signal(exploitation.cisa_kev, "Listed in CISA KEV", "Not listed in the current feed") },
      { label: "Public exploit", value: exploits.length ? exploits.join(", ") : signal(exploitation.exploit_db, "Reported by feed", "No entry reported by feed") },
      { label: "EPSS", value: epss || signal(exploitation.epss_elevated, "Elevated (reported by feed)", "Not reported by feed") },
    ]));
    advisory.append(el("p", "note", exploitation.note || "Advisory signals do not prove this host is vulnerable."));
    if (d.cve.sources && d.cve.sources.length) {
      const names = d.cve.sources.map((source) => typeof source === "string" ? source :
        [source.name, source.id, source.url].filter(Boolean).join(" · ")).filter(Boolean);
      if (names.length) advisory.append(el("p", "note", `Feed sources: ${names.join("; ")}`));
    }
    if (d.cve.references && d.cve.references.length) {
      advisory.append(el("h3", "sec", "Advisory links"));
      d.cve.references.forEach((url) => {
        const line = el("div", "find");
        line.append(el("a", "", url, { href: url, target: "_blank", rel: "noopener noreferrer" }));
        advisory.append(line);
      });
    }
    out.push(advisory);
  }

  const why = detailSection("Why this matters");
  const noAssessment = {
    not_triaged: "No AI provider is configured, so there is no written assessment. The evidence below stands on its own.",
    pending: "Waiting for AI triage.",
    untracked: "Waiting for AI triage.",
    error: "The last triage attempt failed. It is retried automatically.",
  };
  why.append(el("p", d.why_it_matters ? "" : "note", d.why_it_matters || noAssessment[d.ai.status] || "The model gave no assessment."));
  out.push(why);

  const how = detailSection("How it was found");
  how.append(kvBox(d.how_found.steps));
  Object.entries(d.how_found.excerpts || {}).forEach(([k, v]) => {
    if (v) how.append(excerpt(k === "request" ? "Request (excerpt)" : "Response (excerpt)", v));
  });
  out.push(how);

  const seen = detailSection("Seen");
  seen.append(kvBox([
    { label: "First seen", value: shortDate(d.first_seen) },
    { label: "Last seen", value: shortDate(d.last_seen) },
  ]));
  if (!d.history.length) seen.append(el("p", "note", "No inventory changes are recorded for this host."));
  d.history.forEach((c) => {
    const line = el("div", "find");
    line.append(badge(CHANGE_LABEL[c.kind] || c.kind, changeClass(c)), changeCell(c, project), el("span", "note", shortDate(c.detected)));
    seen.append(line);
  });
  out.push(seen);

  const ai = detailSection("AI classification");
  const top = el("div", "find");
  top.append(aiBadge(d.ai, { project, kind: d.kind, id: d.id }));
  if (d.ai.reason) top.append(el("span", "", d.ai.reason));
  ai.append(top);
  if (d.ai.overridden) {
    const said = el("div", "find");
    said.append(el("span", "note", "The model said:"), aiBadge({ classification: d.ai.model_classification }), el("span", "", d.ai.model_reason));
    ai.append(said);
    ai.append(el("p", "note", "Deterministic evidence rules determine whether a candidate can be cleared or confirmed."));
  }
  if (d.ai.hard_evidence.length) {
    ai.append(el("h3", "sec", "Hard evidence"));
    d.ai.hard_evidence.forEach((t) => ai.append(el("div", "find", t)));
  }
  if (d.ai.invalid_output) ai.append(el("p", "note", "The model's reply could not be used, so this is marked as needing validation."));
  if (d.severity_ai) ai.append(el("p", "note", `Scanner severity ${d.severity}; AI view ${d.severity_ai}${d.ai.severity_reason ? `: ${d.ai.severity_reason}` : ""}`));
  if (d.ai.advice.length && d.kind !== "match") {
    ai.append(el("h3", "sec", "Checks suggested by the model"));
    d.ai.advice.forEach((a) => ai.append(el("div", "find", `${a.kind}: ${a.note}`)));
    ai.append(el("p", "note", "These suggestions have not been executed unless a matching check appears below."));
  }
  if (d.ai.model) ai.append(el("p", "note", `Assessed by ${d.ai.model}${d.ai.triaged ? ` on ${shortDate(d.ai.triaged)}` : ""}`));
  if (d.ai.diagnostic) {
    const data = JSON.stringify(d.ai.diagnostic, null, 2);
    ai.append(excerpt("Safe diagnostic to share with support", data));
    const copy = el("button", "btn ghost sm", "Copy diagnostic", { type: "button" });
    copy.onclick = () => navigator.clipboard.writeText(data);
    ai.append(copy);
  }
  out.push(ai);

  const fix = detailSection("Remediation");
  if (d.remediation.text) fix.append(el("p", "", d.remediation.text));
  if (d.remediation.scanner) fix.append(el("p", "", d.remediation.scanner));
  if ((d.remediation.fixed_in || []).length) fix.append(el("p", "note", `Fixed in: ${d.remediation.fixed_in.join(", ")}`));
  if (!d.remediation.text && !d.remediation.scanner && !(d.remediation.fixed_in || []).length) {
    fix.append(el("p", "note", "No remediation advice is recorded yet."));
  }
  if (cfg.statusControl) {
    // the status is a change: in the all-projects view it is shown, and set from the finding's own project
    if (!ALL) fix.append(cfg.statusControl(d));
    else {
      const ro = el("div", "tools");
      ro.append(el("span", "note", "Remediation status"), badge((d.remediation.status || "open").replace(/_/g, " ")));
      fix.append(ro, openInProject(row, cfg.kind === "match" ? "matches" : "vulns", `#${row.id}`));
    }
  }
  out.push(fix);

  const check = detailSection("Confirm it yourself");
  if (d.kind === "match" && d.assessment_status !== "closed_not_applicable") {
    const controls = el("div", "tools");
    const run = el("button", "btn sm", "Validate now", { type: "button" });
    run.dataset.validate = "now";
    const state = el("span", "note", "Runs this match's safe template checks and requests AI review in the queue.");
    run.onclick = async () => {
      run.disabled = true;
      try {
        const path = `${baseOf(project)}/matches/${d.id}/validate`;
        let job = await api("POST", path, {});
        state.textContent = `Validation ${job.status}.`;
        while (job.status === "queued" || job.status === "running") {
          await new Promise((resolve) => setTimeout(resolve, 3000));
          if (!controls.isConnected) return;
          job = await api("GET", `${path}/${job.id}`);
          state.textContent = `Validation ${job.status}.`;
        }
        if (job.status === "failed") state.textContent = `Validation failed: ${job.error || "see check details"}. AI review: ${job.result?.ai_state || "unknown"}.`;
        else {
          const checks = job.result?.checks || {};
          const review = job.result?.ai_state || "unknown";
          const planNote = (job.result?.plans || (job.result?.plan ? [job.result.plan] : []))
            .map((plan, index) => ` Plan ${index + 1}: ${plan.reason}`).join("");
          const draft = job.result?.template_candidate;
          const draftNote = draft ? ` Template candidate: ${draft.status}; not run on this host.` : "";
          const checkNote = ["no_check", "not_run", "observed"].includes(job.result?.check_state)
            ? `${job.result?.assessment_status === "unsupported_external" ? "External validation is unsupported with current evidence." : job.result?.check_state === "observed" ? "Only metadata was observed." : "No check executed."} ${(job.result?.check_notes || []).join(" ") || "Available evidence does not support a specific check yet."}`
            : `${checks.ran || 0} checks ran, ${checks.reused || 0} reused, ${checks.capped || 0} deferred.`;
          state.textContent = `Validation request completed: ${checkNote}${planNote}${draftNote} AI review: ${review}. Refresh to see the evidence.`;
        }
      } catch (err) {
        state.textContent = err.message;
      }
      run.disabled = false;
    };
    controls.append(run, state);
    check.append(controls);
  }
  const v = d.validation;
  const none = {
    no_check: "No validated check exists for this finding yet.",
    pending: "Checks are queued and run automatically.",
    none: "Checks run automatically after triage. None has run yet.",
    skipped_blocked: "The checks were not run: the host is outside this project or resolves to an address that must not be scanned.",
  };
  if (!v.steps.length) check.append(el("p", "note", none[v.status] || none.none));
  if (v.status === "no_check") check.append(localChecksBox(d.remediation.local_checks));
  v.steps.forEach((step) => {
    const card = el("div", "svc");
    if (step.display) card.append(el("pre", "banner mono", step.display));
    const result = `${STEP_RESULT[step.result] || step.result}${step.error ? `: ${step.error}` : ""}`;
    card.append(el("div", "find", `${step.label} · ran ${shortDate(step.ran_at)} · ${result}`));
    if (step.summary) card.append(el("div", "note", step.summary));
    if (step.note) card.append(el("div", "note", step.note));
    if (step.output_excerpt && step.output_excerpt !== step.summary) card.append(el("pre", "banner", step.output_excerpt));
    check.append(card);
  });
  Object.entries(v.evidence || {}).forEach(([kindName, e]) => {
    if (e.request) check.append(excerpt(`Evidence from the ${kindName.replace("_", " ")} check: request`, e.request));
    if (e.response) check.append(excerpt("Response", e.response));
    if (e.reply) check.append(excerpt("The service replied", e.reply));
  });
  if (v.status === "failed" && v.next_attempt) check.append(el("p", "note", `A failed check is never counted as clean. It is tried again after ${shortDate(v.next_attempt)}.`));
  if (v.status === "clean") check.append(el("p", "note", d.ai.hard_evidence.length
    ? "The check did not reproduce the finding; the hard evidence listed above still needs to be reconciled."
    : "This check did not reproduce the finding. It does not prove the host is unaffected."));
  if (v.status === "observed") check.append(el("p", "note", "These checks observed host metadata only. They did not validate or rule out this CVE on this host."));
  out.push(check);
  return out;
}

// One page of findings: the list down the left, the selected finding's full picture on the right (like Hosts). cfg:
// kind (the API's finding kind), path, noun and plural, filters (nodes), params(), empty, onLoaded, row(item) -> {heat, title, meta[],
// notes[]}, statusControl(detail) -> node (optional).
// A CVE match's remediation status, set in its detail pane with the fix (the CVE matches and Findings pages)
function matchStatusControl(d) {
  const s = select(
    "Remediation status",
    [
      ["open", "Open"],
      ["in_progress", "In progress"],
      ["fixed", "Fixed"],
      ["accepted_risk", "Accepted risk"],
    ],
    async () => {
      try {
        await api("PATCH", `${base}/matches/${d.id}`, { status: s.value });
        d.remediation.status = s.value;
        toast("Status updated");
      } catch (err) {
        s.value = d.remediation.status;
        toast(err.message, true);
      }
    },
  );
  s.value = d.remediation.status;
  const box = el("div", "tools");
  box.append(el("span", "note", "Remediation status"), s);
  if (d.remediation.note) box.append(el("p", "note", d.remediation.note));
  return box;
}

function findingPage(mount, cfg) {
  const split = el("div", "split");
  const side = el("aside", "split-list card");
  const pane = el("section", "split-pane card");
  pane.setAttribute("aria-live", "polite");
  split.append(side, pane);
  mount.append(split);
  const rows = el("div", "host-rows");
  side.append(...cfg.filters, rows);
  const byId = new Map();
  let current = null;
  let token = 0;
  // A page of one kind keys its rows by id. A mixed page (cfg.kindOf: the unified Findings list) keys them "kind-id", since a
  // CVE match and a scanner finding can share an id, and each row opens the detail of its own kind.
  const kindOf = (item) => (cfg.kindOf ? cfg.kindOf(item) : cfg.kind);
  const keyOf = (item) => (cfg.kindOf ? `${kindOf(item)}-${item.id}` : String(item.id));
  const parseKey = (key) => {
    if (!cfg.kindOf) return Number(key) ? { id: Number(key), kind: cfg.kind } : null;
    if (Number(key)) return { id: Number(key), kind: cfg.kind }; // an older link (#id) names the page's own kind
    const m = /^(match|vulnerability|hygiene|route)-(\d+)$/.exec(key || "");
    return m ? { id: Number(m[2]), kind: m[1] } : null;
  };
  // The address of a selected finding. Fetching the detail needs its project, so in the all-projects view the hash carries it
  // (#project:key) and a reload reopens the finding even when it is not on the first page. One project: #key.
  const hashOf = (item) => (ALL ? `${item.project}:${keyOf(item)}` : keyOf(item));
  const wantedFromHash = () => {
    const [target, flag] = location.hash.slice(1).split("&");
    const [a, b] = target.split(":");
    const validate = flag === "validate";
    if (ALL) return b && parseKey(b) && /^[-\w]+$/.test(a) ? { key: b, project: a, validate } : null;
    return parseKey(a) ? { key: a, project: slug, validate } : null;
  };

  // ``validate``: arrived through a "Needs validation" label, which means "open this and run Validate now"
  async function show(key, project = slug, { validate = false } = {}) {
    key = key == null ? null : String(key);
    current = key;
    rows.querySelectorAll(".host-row").forEach((r) => r.classList.toggle("sel", r.dataset.key === current));
    split.classList.toggle("has-sel", !!key);
    pane.textContent = "";
    const wanted = parseKey(key);
    if (!wanted) {
      pane.append(el("p", "empty", `Select a ${cfg.noun} to see how it was found and what to do about it.`));
      return;
    }
    const { id, kind } = wanted;
    const mine = (token += 1);
    const back = el("button", "btn ghost sm back", `← All ${cfg.plural}`, { type: "button" });
    back.onclick = () => {
      history.replaceState(null, "", location.pathname + location.search);
      show(null);
    };
    pane.append(back, el("div", "skeleton"), el("div", "skeleton"));
    try {
      // the detail comes from the finding's own project; in the all-projects view the row (when loaded) supplies its name too
      const row = byId.get(key) || { id, project };
      const d = await api("GET", `${baseOf(project)}/findings/${kind}/${id}`);
      if (mine !== token) return;
      pane.textContent = "";
      pane.append(back, ...renderFinding(d, cfg.forKind ? cfg.forKind(kind) : cfg, row));
      if (validate) {
        if (location.hash.includes("&validate")) history.replaceState(null, "", `${location.pathname}${location.search}#${ALL ? `${project}:${key}` : key}`); // a reload must not run it again
        const run = pane.querySelector("[data-validate]");
        if (run && !run.disabled) {
          run.scrollIntoView({ block: "center" });
          run.focus();
          run.click();
        } else if (run == null) pane.append(el("p", "note", "Validate now is not available for this finding."));
      }
    } catch (err) {
      if (mine !== token) return;
      pane.textContent = "";
      pane.append(back, el("p", "msg err", err.message));
    }
  }

  const list = createList({
    mount: side,
    path: cfg.path,
    params: cfg.params,
    empty: cfg.empty,
    onLoaded: cfg.onLoaded,
    render: (_, items, reset) => {
      if (reset) {
        rows.textContent = "";
        byId.clear();
      }
      items.forEach((item) => {
        byId.set(keyOf(item), item);
        const r = cfg.row(item);
        const row = selectableRow(keyOf(item), r.heat, "key");
        const title = el("span", "cve-id");
        if (r.title instanceof Node) title.append(r.title);
        else title.textContent = r.title;
        row.append(title);
        const meta = el("span", "host-meta");
        meta.append(...r.meta.filter(Boolean));
        row.append(meta);
        (r.notes || []).filter(Boolean).forEach((n) => row.append(n instanceof Node ? n : el("span", "note host-why", n)));
        row.onclick = (e) => {
          if (e.target.closest("a")) return; // a link inside the row goes where it points
          history.replaceState(null, "", location.pathname + location.search + `#${hashOf(item)}`);
          show(keyOf(item), projectOf(item));
        };
        rows.append(row);
      });
      const wanted = wantedFromHash();
      if (current == null && wanted) show(wanted.key, wanted.project, { validate: wanted.validate });
      else if (current == null && window.matchMedia("(min-width:900px)").matches && items.length) show(keyOf(items[0]), projectOf(items[0]));
    },
  });
  // A "Needs validation" label elsewhere on this page opens its finding here without leaving the page (and, for a match, presses
  // Validate now); from any other page the same link navigates here and the hash does it.
  document.addEventListener("click", (e) => {
    const link = e.target.closest && e.target.closest("a.needs-validation");
    if (!link || e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    const { kind, id, project } = link.dataset;
    // the unified Findings list opens a finding of any kind; the matches page only its own
    const mine = cfg.kindOf ? Boolean(FINDING_KINDS[kind]) : kind === cfg.kind;
    if (!root.isConnected || !mine || (!ALL && project !== slug)) return;
    e.preventDefault();
    const key = cfg.kindOf ? `${kind}-${id}` : String(id);
    history.replaceState(null, "", location.pathname + location.search + `#${ALL ? `${project}:${key}` : key}`);
    show(key, project, { validate: kind === "match" });
  });
  show(null);
  list.start();
  return list;
}

const FINDING_KINDS = { match: 1, vulnerability: 1, hygiene: 1, route: 1 };
// A list row that selects an item. It is a div, not a button: a row holds links (the host, the CVE) and a link inside a button
// is invalid HTML that browsers handle inconsistently. Keyboard use matches a button's.
function selectableRow(id, heat, attr = "id") {
  const row = el("div", "host-row", null, { role: "button", tabindex: "0" });
  row.dataset[attr] = id;
  row.dataset.heat = heat || "";
  row.addEventListener("keydown", (e) => {
    if ((e.key === "Enter" || e.key === " ") && e.target === row) {
      e.preventDefault();
      row.click();
    }
  });
  return row;
}

// --- targets across every project (read-only): no selection, delete, scope, discovery or scan; those are per project ----------
function allTargets(mount) {
  const tools = el("div", "tools");
  const q = searchBox("Search targets", () => list.reload());
  tools.append(q);
  mount.append(
    tools,
    el(
      "p",
      "note ro-note",
      'Read-only. Open a project to scan, discover or delete its targets. "Add targets" works here with a #Project line above each list.',
    ),
  );
  const list = createList({
    mount,
    path: `${base}/targets`,
    params: () => ({ q: q.value }),
    empty: 'No targets yet. Use "Add targets" with #Project headers to paste a list of domains, IPs or ranges.',
    render: table(
      withProject([
        { label: "Target", render: (t) => hostLink(t.name, projectOf(t)) },
        { label: "Scope", render: (t) => (t.host_scoped ? "this host only" : t.scope_mode === "parent" ? "includes parent domain" : "auto") },
        { label: "Hosts", cls: "num", render: (t) => t.hosts ?? "-" },
        { label: "Exposed", render: (t) => meterCell(t.exposed, t.hosts) },
        { label: "Added", render: (t) => shortDate(t.created) },
        { label: "Last scan", render: (t) => shortDate(t.last_scan) },
        {
          label: "",
          render: (t) => el("a", "btn ghost sm", "Open project", { href: `/cve/${encodeURIComponent(projectOf(t))}/targets/` }),
        },
      ]),
    ),
  });
  document.addEventListener("cve:targets-added", () => list.reload());
  list.start();
}

// --- pages ----------------------------------------------------------------------
const pages = {
  async targets(mount) {
    if (ALL) return allTargets(mount);
    const tools = el("div", "tools");
    const q = searchBox("Search targets", () => reload());
    tools.append(q);
    mount.append(tools);
    const post = (path, body) => api("POST", `${base}/${path}`, body);
    // selection: individual rows, a whole loaded page, or every target matching the search
    const selected = new Set();
    const boxes = new Map();
    let total = 0;
    let allMatching = false;
    const bar = el("div", "selbar");
    bar.hidden = true;
    mount.insertBefore(bar, tools.nextSibling);
    const headBox = el("input", "", null, { type: "checkbox", "aria-label": "Select all targets" });
    // phones hide the table header, so a second "select all" lives above the table
    const phoneBox = el("input", "", null, { type: "checkbox", "aria-label": "Select all targets" });
    const phoneAll = el("label", "selall");
    phoneAll.append(phoneBox, document.createTextNode(" Select all"));
    mount.insertBefore(phoneAll, bar.nextSibling);
    const count = () => (allMatching ? total : selected.size);
    const syncBar = () => {
      bar.textContent = "";
      const n = count();
      headBox.checked = boxes.size > 0 && [...boxes.values()].every((b) => b.checked);
      headBox.indeterminate = !headBox.checked && [...boxes.values()].some((b) => b.checked);
      phoneBox.checked = headBox.checked;
      phoneBox.indeterminate = headBox.indeterminate;
      if (!n) {
        bar.hidden = true;
        return;
      }
      bar.hidden = false;
      bar.append(el("span", "", allMatching ? `All ${total} matching targets selected.` : `${n} selected.`));
      if (!allMatching && headBox.checked && total > selected.size) {
        const all = el("button", "btn ghost sm", `Select all ${total} targets${q.value ? " matching the search" : ""}`, { type: "button" });
        all.onclick = () => {
          allMatching = true;
          syncBar();
        };
        bar.append(all);
      }
      const del = el("button", "btn danger sm", `Delete ${n}`, { type: "button" });
      del.onclick = async () => {
        const sure = await ask(
          `${n} target${n === 1 ? "" : "s"} will be deleted with all their hosts, scans and results. This cannot be undone.`,
          { title: `Delete ${n} target${n === 1 ? "" : "s"}?`, ok: `Delete ${n}` },
        );
        if (!sure) return;
        del.disabled = true;
        try {
          const r = await post(
            "targets/delete",
            allMatching ? { all_matching: true, q: q.value } : { ids: [...selected] },
          );
          toast(`Deleted ${r.deleted}${r.skipped_running ? `; ${r.skipped_running} skipped (scan running)` : ""}`);
          reload();
        } catch (err) {
          toast(err.message, true);
          del.disabled = false;
        }
      };
      const clear = el("button", "btn ghost sm", "Clear", { type: "button" });
      clear.onclick = () => {
        selected.clear();
        allMatching = false;
        boxes.forEach((b) => (b.checked = false));
        syncBar();
      };
      bar.append(del, clear);
    };
    const toggleAll = (on) => {
      allMatching = false;
      boxes.forEach((b, id) => {
        b.checked = on;
        if (on) selected.add(id);
        else selected.delete(id);
      });
      syncBar();
    };
    headBox.onchange = () => toggleAll(headBox.checked);
    phoneBox.onchange = () => toggleAll(phoneBox.checked);
    // How far a target's scope reaches: a tenant on a provider's domain (acme.jfrog.com) is scanned as that host only; the
    // select overrides the shared-domain list (auto), forces host-only, or says the parent domain is the user's own.
    const scopeCell = (t) => {
      const box = el("div", "scope-cell");
      const note = el("span", "note", "");
      const show = () => {
        note.textContent = t.host_scoped ? "provider domain: scanning this host only" : "";
      };
      const pick = el("select", "", null, { "aria-label": `Scope of ${t.name}` });
      for (const [value, label] of [
        ["auto", "Scope: auto"],
        ["host", "Scope: this host only"],
        ["parent", "Scope: include parent domain"],
      ]) {
        const o = el("option", "", label, { value });
        o.selected = t.scope_mode === value;
        pick.append(o);
      }
      pick.onchange = async () => {
        pick.disabled = true;
        try {
          const r = await post(`targets/${t.id}/scope`, { scope_mode: pick.value });
          t.scope_mode = r.scope_mode;
          t.host_scoped = r.host_scoped;
          show();
          toast(`${t.name}: scope ${r.scope_mode}`);
        } catch (err) {
          pick.value = t.scope_mode;
          toast(err.message, true);
        }
        pick.disabled = false;
      };
      show();
      box.append(pick, note);
      return box;
    };
    const rowBox = (t) => {
      const b = el("input", "", null, { type: "checkbox", "aria-label": `Select ${t.name}` });
      b.checked = allMatching || selected.has(t.id);
      b.onchange = () => {
        allMatching = false;
        if (b.checked) selected.add(t.id);
        else selected.delete(t.id);
        syncBar();
      };
      boxes.set(t.id, b);
      return b;
    };
    const reload = () => {
      selected.clear();
      boxes.clear();
      allMatching = false;
      syncBar();
      list.reload();
    };
    const list = createList({
      mount,
      path: `${base}/targets`,
      onLoaded: (data) => {
        total = data.count;
        syncBar();
      },
      params: () => ({ q: q.value }),
      empty:
        'No targets yet. Use "Add targets" to paste a list of domains, IPs or ranges.',
      render: table([
        { label: "", cls: "sel", head: () => headBox, render: rowBox },
        { label: "Target", render: (t) => hostLink(t.name) },
        { label: "Scope", render: (t) => scopeCell(t) },
        { label: "Hosts", cls: "num", render: (t) => t.hosts ?? "-" },
        { label: "Exposed", render: (t) => meterCell(t.exposed, t.hosts) },
        { label: "Added", render: (t) => shortDate(t.created) },
        { label: "Last scan", render: (t) => shortDate(t.last_scan) },
        {
          label: "",
          render: (t) => {
            const box = el("div", "row-actions");
            const discover = el("button", "btn sm", "Discover", {
              type: "button",
            });
            discover.onclick = async () => {
              discover.disabled = true;
              try {
                const r = await post(`targets/${t.id}/discover`, {});
                toast(`Discovery #${r.scan_id} started`);
              } catch (err) {
                toast(err.message, true);
              }
              discover.disabled = false;
            };
            const scan = el("button", "btn ghost sm", "Scan", {
              type: "button",
            });
            scan.title =
              "Run discovery, fingerprinting and nuclei on this target (anything already covered is reused)";
            scan.onclick = async () => {
              scan.disabled = true;
              try {
                const r = await post("scans", { target_id: t.id });
                toast(`Scan #${r.scan_id} started`);
              } catch (err) {
                toast(err.message, true);
              }
              scan.disabled = false;
            };
            box.append(discover, scan);
            return box;
          },
        },
      ]),
    });
    document.addEventListener("cve:targets-added", () => reload());
    list.start();
  },

  scans(mount) {
    const status = picker(
      "Scan status",
      [
        ["", "All"],
        ["running", "Running", "smoke"],
        ["stalled", "Stalled", "fire"],
        ["queued", "Queued"],
        ["finished", "Finished", "clean"],
        ["failed", "Failed", "fire"],
        ["aborted", "Aborted"],
      ],
      async (key) => (await api("GET", `${base}/scans?${query({ status: key, page_size: 1 })}`)).count,
      () => list.reload(),
    );
    // Stop all: every running and queued scan of this project, after a confirmation
    const stopAll = el("button", "btn sm", "Stop all", { type: "button" });
    stopAll.title = "Stop every running and queued scan in this project";
    stopAll.onclick = async () => {
      const sure = await ask("Every running and queued scan in this project will be stopped. Scanner processes are killed; what they already found is kept.", {
        title: "Stop all scans?",
        ok: "Stop all",
      });
      if (!sure) return;
      stopAll.disabled = true;
      try {
        const r = await api("POST", `${base}/scans/stop`);
        toast(`${r.stopped} scan${r.stopped === 1 ? "" : "s"} stopped`);
        list.reload();
      } catch (err) {
        toast(err.message, true);
      }
      stopAll.disabled = false;
    };
    const bar = el("div", "scans-bar");
    bar.append(status.node);
    if (!ALL) bar.append(stopAll); // stopping scans is per project
    mount.append(bar);
    const list = createList({
      mount,
      path: `${base}/scans`,
      params: () => ({ status: status.value }),
      empty: "No scans here. Start one from Targets.",
      autoRefresh: (items) =>
        items.some((s) => s.status === -1 || (s.status === 1 && !s.stalled)),
      onLoaded: (_, reset) => reset && status.refresh(),
      render: table(
        withProject(readOnlyColumns([
          {
            label: "#",
            cls: "num",
            render: (s) => el("a", "", `#${s.id}`, { href: scanHref(projectOf(s), s.id) }),
          },
          {
            label: "Target",
            render: (s) => {
              const box = el("span");
              box.append(hostLink(s.target, projectOf(s)));
              if (s.kind === "retest") box.append(" ", badge("re-test", "queued"));
              return box;
            },
          },
          {
            label: "Status",
            render: (s) =>
              badge(
                s.stalled
                  ? "stalled"
                  : s.status === -1 && s.queue_position != null
                    ? `queued, ${s.queue_position} ahead`
                    : SCAN_STATUS[s.status] || s.status,
                s.stalled ? "failed" : SCAN_STATUS[s.status],
              ),
          },
          { label: "Hosts", cls: "num", render: (s) => s.hosts ?? "-" },
          {
            label: "Findings",
            render: (s) => {
              if (!s.findings) return "-";
              const box = el("span", "ports");
              box.style.margin = "0";
              box.append(badge(s.top_severity, s.top_severity), el("span", "port", `${s.findings}`));
              return box;
            },
          },
          {
            label: "Duration",
            cls: "num",
            render: (s) => duration(s.started, s.finished),
          },
          { label: "Started", render: (s) => shortDate(s.started) },
          {
            label: "",
            render: (s) => {
              if (ALL || (s.status !== -1 && s.status !== 1)) return "";
              const stop = el("button", "btn ghost sm", "Stop", { type: "button", "aria-label": `Stop scan #${s.id}` });
              stop.onclick = async () => {
                stop.disabled = true;
                try {
                  await api("POST", `${base}/scans/${s.id}/stop`);
                  toast(`Scan #${s.id} stopped`);
                  list.reload();
                } catch (err) {
                  toast(err.message, true);
                  stop.disabled = false;
                }
              };
              return stop;
            },
          },
        ]), 2),
        (s) => (s.status === 0 ? "fire" : s.status === 1 ? "smoke" : ""),
      ),
    });
    list.start();
  },

  hosts(mount) {
    // Shodan-style master/detail: host list down the left, the selected host's full picture on the right.
    const split = el("div", "split");
    const side = el("aside", "split-list card");
    const pane = el("section", "split-pane card");
    pane.setAttribute("aria-live", "polite");
    split.append(side, pane);
    mount.append(split);
    // The query lives in the URL (?q=) so a search can be shared: words, tech:php, port:3306, ip:10.0.0.0/24, -host:www
    const params = new URLSearchParams(location.search);
    const syncUrl = () => {
      const next = new URLSearchParams(location.search);
      next.delete("host");
      if (q.value.trim()) next.set("q", q.value);
      else next.delete("q");
      const qs = next.toString();
      history.replaceState(null, "", location.pathname + (qs ? `?${qs}` : ""));
    };
    const q = searchBox("Search hosts: php, port:3306, tech:nginx, auth:open -host:www", () => {
      syncUrl();
      list.reload();
    });
    // /hosts/?host=name (from the dashboard map) opens that host
    const wantedHost = params.get("host") || "";
    q.value = params.get("q") || (wantedHost ? `host:"${wantedHost}"` : "");
    const sortBy = select(
      "Sort",
      [
        ["score", "Highest score first"],
        ["name", "Name"],
      ],
      () => list.reload(),
    );
    const rows = el("div", "host-rows");
    side.append(q, sortBy, rows);
    const byId = new Map();
    let current = null;

    const kv = (k, v) => {
      const d = el("div", "kv");
      d.append(el("span", "k", k), el("span", "v", v));
      return d;
    };
    const jsonRows = (obj) => {
      const box = el("div", "kvs");
      Object.entries(obj || {})
        .filter(([, v]) => v !== "" && v != null && typeof v !== "object")
        .slice(0, 12)
        .forEach(([k, v]) => box.append(kv(k, String(v))));
      return box;
    };

    // Asset info: the owner, purpose and criticality a person keeps for the host (saved per project)
    const CRITICALITY = ["unknown", "low", "medium", "high", "critical"];
    const hostPath = (h, tail) => `${baseOf(projectOf(h))}/hosts/${encodeURIComponent(h.host)}/${tail}`;
    // all-projects view: the asset information is shown, not edited, and removing a host is done from its own project
    function assetInfoReadOnly(h) {
      const box = el("div", "asset-info");
      box.append(el("h3", "sec", "Asset info"));
      const p = h.profile || {};
      const rows = [
        ["Owner", p.owner],
        ["Purpose", p.purpose],
        ["Criticality", p.criticality && p.criticality !== "unknown" ? p.criticality : ""],
      ].filter(([, v]) => v);
      if (rows.length) box.append(kvBox(rows.map(([label, value]) => ({ label, value }))));
      else box.append(el("p", "note", "No asset information is recorded for this host."));
      box.append(openInProject(h, "hosts", `?host=${encodeURIComponent(h.host)}`));
      return box;
    }
    function assetInfo(h) {
      const box = el("div", "asset-info");
      box.append(el("h3", "sec", "Asset info"));
      const p = h.profile || {};
      const owner = uiText(p.owner || "", { maxlength: "200", placeholder: "Team or person responsible" });
      const purpose = uiText(p.purpose || "", { maxlength: "500", placeholder: "What this host is for" });
      const crit = select("Criticality", CRITICALITY.map((c) => [c, c[0].toUpperCase() + c.slice(1)]), () => {});
      crit.value = CRITICALITY.includes(p.criticality) ? p.criticality : "unknown";
      const grid = el("div", "asset-grid");
      grid.append(field("Owner", owner), field("Purpose", purpose), field("Criticality", crit));
      const save = uiButton("Save", async () => {
        const r = await api("POST", hostPath(h, "profile"), { owner: owner.value, purpose: purpose.value, criticality: crit.value });
        h.profile = { owner: r.owner, purpose: r.purpose, criticality: r.criticality };
        toast("Asset info saved");
      }, "btn sm");
      box.append(grid, save);
      return box;
    }
    // After a removal the host is gone from the list: back to the Hosts list, refreshed
    function afterRemoval() {
      history.replaceState(null, "", location.pathname + location.search);
      showHost(null);
      list.reload();
    }
    function hostActions(h) {
      const box = el("div", "host-danger");
      box.append(
        el("h3", "sec", "Remove this host"),
        el("p", "note", "Delete host data removes it from this project only; a later scan can find it again. Remove & exclude removes it from every project in this organization and never scans it again."),
      );
      const row = el("div", "host-danger-actions");
      const del = el("button", "btn danger-ghost sm", "Delete host data", { type: "button" });
      del.onclick = async () => {
        const sure = await ask(`Remove ${h.host} and its findings from this project? It can be rediscovered by a future scan.`, {
          title: "Delete host data?",
          ok: "Delete host data",
        });
        if (!sure) return;
        del.disabled = true;
        try {
          const r = await api("POST", hostPath(h, "delete"), {});
          toast(`Deleted ${h.host}: ${r.findings} finding${r.findings === 1 ? "" : "s"} removed from this project`);
          afterRemoval();
        } catch (err) {
          toast(err.message, true);
          del.disabled = false;
        }
      };
      const exclude = el("button", "btn danger sm", "Remove & exclude", { type: "button" });
      exclude.onclick = () =>
        dialog("Remove & exclude?", (body, close) => {
          body.append(
            el("p", "note", `Remove ${h.host} everywhere in this organization and never scan it again? This deletes its findings across all your projects.`, { style: "font-size:14px" }),
          );
          const reason = uiText("", { maxlength: "300", placeholder: "Why (optional)" });
          body.append(field("Reason", reason));
          const actions = el("div", "actions");
          const no = el("button", "btn ghost", "Cancel", { type: "button" });
          no.onclick = close;
          const yes = el("button", "btn danger", "Remove & exclude", { type: "button" });
          yes.onclick = async () => {
            yes.disabled = true;
            try {
              const r = await api("POST", hostPath(h, "exclude"), { reason: reason.value });
              close();
              toast(`Excluded ${h.host}: removed from ${r.projects_affected} project${r.projects_affected === 1 ? "" : "s"}, ${r.findings_removed} finding${r.findings_removed === 1 ? "" : "s"}`);
              afterRemoval();
            } catch (err) {
              toast(err.message, true);
              yes.disabled = false;
            }
          };
          actions.append(no, yes);
          body.append(actions);
          setTimeout(() => no.focus(), 0);
        });
      row.append(del, exclude);
      box.append(row);
      return box;
    }

    function showHost(h) {
      current = h && h.id;
      rows.querySelectorAll(".host-row").forEach((r) =>
        r.classList.toggle("sel", Number(r.dataset.id) === current),
      );
      split.classList.toggle("has-sel", !!h);
      pane.textContent = "";
      if (!h) {
        pane.append(el("p", "empty", "Select a host to see what is known about it."));
        return;
      }
      const back = el("button", "btn ghost sm back", "← All hosts");
      back.type = "button";
      back.onclick = () => {
        history.replaceState(null, "", location.pathname + location.search);
        showHost(null);
      };
      const head = el("div", "host-head");
      head.append(el("h2", "host-title", h.host));
      const HEAT = { fire: ["Fire", "fire"], smoke: ["Smoke", "smoke"], ice: ["Ice", "ice"], clean: ["Clean", "success"], unscanned: ["Not scanned", "queued"] };
      if (HEAT[h.heat]) head.append(badge(HEAT[h.heat][0], HEAT[h.heat][1]));
      if (h.http_status) head.append(badge(`HTTP ${h.http_status}`));
      head.append(badge(`Score ${h.score || 0}`));
      const chip = projChip(h);
      if (chip) head.append(chip);
      if (h.zombie) head.append(badge("Zombie: DNS gone, still answering", "smoke"));
      if (h.excluded) head.append(badge("Excluded: never scanned", "smoke"));
      if (h.archived) head.append(badge("Archived: history retained", "queued"));
      if (h.pinned) head.append(badge("Pinned", "success"));
      pane.append(back, head);
      const assessBox = el("div", "why");
      const assessHead = el("div", "host-assess-head");
      assessHead.append(el("h3", "sec", "Host assessment"));
      const assessButton = el("button", "btn sm", "Rescan host");
      assessButton.type = "button";
      assessButton.disabled = !!(h.excluded || h.archived);
      assessButton.title = h.excluded ? "This host is excluded from scanning" : h.archived ? "Restore this host before scanning" : "Refresh DNS and run the permitted host checks now";
      assessHead.append(assessButton);
      const assessBody = el("div", "note", "Checking for an existing assessment…");
      assessBox.append(assessHead, assessBody);
      pane.append(assessBox);
      const assessPath = `${baseOf(projectOf(h))}/host-assessments`;
      let pollToken = 0;
      const drawAssessment = (job) => {
        if (current !== h.id) return;
        assessBody.textContent = "";
        if (!job || job.status === "never_requested") {
          assessBody.append(el("p", "note", "No requested host assessment yet. Inventory alone does not establish scan coverage."));
          return;
        }
        const labels = { queued: "Queued", running: "Running", completed: "Completed", inconclusive: "Inconclusive", failed: "Failed", stopped: "Stopped" };
        assessBody.append(badge(labels[job.status] || job.status, job.status === "completed" ? "success" : job.status === "failed" ? "fire" : "queued"));
        if (job.scan_id) assessBody.append(el("a", "note", `Scan #${job.scan_id}`, { href: `/cve/${encodeURIComponent(projectOf(h))}/scans/#${job.scan_id}` }));
        if (job.error) assessBody.append(el("p", "note", job.error));
        (job.stages || []).forEach((stage) => {
          const state = { "-1": "queued", "0": "failed", "1": "running", "2": "completed", "3": "stopped" }[String(stage.status)] || "unknown";
          assessBody.append(el("p", "note", `${stage.title || stage.name}: ${state}${stage.error_message ? `: ${stage.error_message}` : ""}`));
        });
        if (job.status === "queued" || job.status === "running") {
          assessButton.disabled = true;
          assessButton.textContent = "Assessment in progress";
          const stop = el("button", "btn ghost sm", "Stop assessment");
          stop.type = "button";
          stop.onclick = async () => {
            stop.disabled = true;
            try { drawAssessment(await api("POST", `${assessPath}/${job.id}/stop`, {})); }
            catch (e) { assessBody.append(el("p", "note", e.message)); stop.disabled = false; }
          };
          assessBody.append(stop);
          const token = ++pollToken;
          setTimeout(async () => {
            if (current !== h.id || token !== pollToken) return;
            try { drawAssessment(await api("GET", `${assessPath}/${job.id}`)); }
            catch (e) { assessBody.append(el("p", "note", `Status refresh failed: ${e.message}`)); }
          }, 4000);
        } else {
          pollToken++;
          assessButton.disabled = !!(h.excluded || h.archived);
          assessButton.textContent = "Rescan host";
        }
      };
      assessButton.onclick = async () => {
        assessButton.disabled = true;
        assessBody.textContent = "Queueing a fresh assessment…";
        try { drawAssessment(await api("POST", assessPath, { host_id: h.id })); }
        catch (e) { assessBody.textContent = e.message; assessButton.disabled = !!(h.excluded || h.archived); }
      };
      api("GET", `${assessPath}?host_id=${h.id}`).then(drawAssessment).catch((e) => {
        if (current === h.id) assessBody.textContent = e.message;
      });
      if (!h.ips.length) pane.append(el("p", "note", "No scannable address is recorded. A rescan starts with fresh resolution; until then, service reachability is unknown."));
      if (h.archived || !ALL) {
        const archiveBox = el("div", "why");
        archiveBox.append(el("h3", "sec", "Asset lifecycle"));
        archiveBox.append(el("p", "note", h.archived
          ? `Archived${h.archive_reason ? `: ${h.archive_reason}` : ""}. History is retained; automatic scans skip this host.`
          : "Active in scan scheduling. Pin a critical asset to keep it from archival."));
        if (h.archive_checked_at) archiveBox.append(el("p", "note", `Last rediscovery check: ${h.archive_check_status || "unknown"} · ${h.archive_checked_at}`));
        if (ALL) archiveBox.append(openInProject(h, "hosts", `?host=${encodeURIComponent(h.host)}`));
        else {
          const actions = el("div", "host-assess-head");
          const pin = el("button", "btn ghost sm", h.pinned ? "Unpin host" : "Pin host");
          pin.type = "button";
          pin.onclick = async () => {
            pin.disabled = true;
            try { const state = await api("POST", hostPath(h, "pin"), { pinned: !h.pinned }); h.pinned = state.pinned; showHost(h); }
            catch (e) { archiveBox.append(el("p", "note", e.message)); pin.disabled = false; }
          };
          actions.append(pin);
          const change = el("button", "btn ghost sm", h.archived ? "Restore host" : "Archive host");
          change.type = "button";
          change.onclick = async () => {
            if (!h.archived && !window.confirm(`Archive ${h.host}? Its history will be kept and it will leave active scan scheduling. You can restore it later.`)) return;
            change.disabled = true;
            try {
              const state = await api("POST", hostPath(h, h.archived ? "restore" : "archive"), h.archived ? {} : { reason: "Manually archived" });
              h.archived = !!state.archived_at; h.archive_reason = state.archive_reason; h.archive_checked_at = state.last_check_at;
              h.archive_check_status = state.last_check_status; showHost(h);
            } catch (e) { archiveBox.append(el("p", "note", e.message)); change.disabled = false; }
          };
          actions.append(change);
          archiveBox.append(actions);
        }
        pane.append(archiveBox);
      }
      // informational detections (a WAF, a server version, federated sign-in): chips, not findings
      if (h.labels && h.labels.length) {
        const chips = el("div", "host-labels");
        h.labels.forEach((l) => chips.append(el("span", "chip", l.label, l.detail ? { title: l.detail } : {})));
        pane.append(chips);
      }
      const openPorts = h.ips.reduce((n, ip) => n + ip.ports.length, 0);
      const stats = el("div", "tiles");
      stats.style.margin = "14px 0 0";
      stats.append(
        tile("Open ports", openPorts),
        tile("Open findings", h.vuln_count ?? (h.vulns || []).filter((v) => v.severity !== "info").length, { hot: "smoke" }),
        tile("CVE matches", h.cve_matches, { hot: "fire", href: h.cve_matches ? `/cve/${encodeURIComponent(projectOf(h))}/matches/?host=${encodeURIComponent(h.host)}` : "" }),
      );
      pane.append(stats);
      pane.append(hostOverview(h));
      // why the host has its colour, so the rating can be checked rather than trusted
      const why = el("div", "why");
      const reasons = h.heat_reasons || [];
      if (reasons.length) {
        why.append(el("h3", "sec", `Why this host is ${HEAT[h.heat] ? HEAT[h.heat][0].toLowerCase() : h.heat}`));
        reasons.forEach((r) => {
          const line = el("div", "find");
          const text = `${r.kind === "cve" ? "" : "Finding: "}${r.label}`;
          // each reason opens the finding's own page: how it was found, the AI's classification, the checks that ran
          const label = r.id
            ? el("a", "", text, { href: `/cve/${encodeURIComponent(projectOf(h))}/${r.finding === "match" ? "matches" : "vulns"}/#${r.id}` })
            : el("span", "", text);
          line.append(badge(r.temp, r.temp), label, el("span", "note", r.detail));
          if (r.kind === "cve") line.append(el("span", "note host-why", r.description || "Description unavailable in the CVE feed."));
          if (r.id) line.append(aiBadge({ classification: r.classification, status: r.classification ? "triaged" : "pending" }, { project: projectOf(h), kind: r.finding === "match" ? "match" : "vulnerability", id: r.id }));
          why.append(line);
        });
      } else if (h.heat === "clean") {
        why.append(el("p", "note", "No CVE matches and no open findings are recorded for this host."));
      }
      pane.append(why);
      // the score is the sum of these lines, so it can be checked rather than trusted
      if (h.score_detail && h.score_detail.length) {
        const scoreBox = el("div", "why");
        scoreBox.append(el("h3", "sec", `Why the score is ${h.score}`));
        h.score_detail.forEach((d) => {
          const line = el("div", "find");
          // a line that cites a CVE match or a finding opens that item's page (the same links as the colour reasons above)
          const hit =
            reasons.find((r) => r.id && r.label && d.label.includes(r.label)) ||
            (/CVE match/.test(d.label) ? reasons.find((r) => r.id && r.finding === "match") : null);
          line.append(
            hit
              ? el("a", "", d.label, { href: `/cve/${encodeURIComponent(projectOf(h))}/${hit.finding === "match" ? "matches" : "vulns"}/#${hit.id}` })
              : el("span", "", d.label),
            el("span", "note mono", `+${d.points}`),
          );
          scoreBox.append(line);
        });
        pane.append(scoreBox);
      }
      if (h.title) pane.append(el("p", "sub", h.title));
      if (h.target) pane.append(el("p", "note", "Target: ", hostLink(h.target, projectOf(h))));
      const compareBox = el("div", "shot-compare");
      if (h.screenshot) {
        const img = el("img", "shot", null, {
          src: `/cve/${encodeURIComponent(projectOf(h))}/hosts/${h.id}/screenshot/`,
          alt: `Screenshot of ${h.host}`,
          loading: "lazy",
        });
        img.onerror = () => img.remove();
        pane.append(img);
        pane.append(compareBox);
      }
      const techBox = technologyTable(h);
      if (techBox) pane.append(techBox);
      const recent = el("div", "recent-changes");
      pane.append(el("h3", "sec", "Recent changes"), recent);
      api("GET", `${baseOf(projectOf(h))}/changes?${query({ host: h.host, since: "30d", page_size: 10 })}`)
        .then((data) => {
          if (current !== h.id) return;
          const items = (data.results || []).filter((c) => c.host === h.host);
          if (!items.length) recent.append(el("p", "note", "No changes in the last 30 days."));
          const shot = items.find((c) => c.kind === "screenshot_changed" && c.before && c.before.subdomain_id);
          if (shot) {
            // the front page changed: let the previous screenshot be looked at next to the current one
            const toggle = el("button", "btn ghost sm", "Compare with previous", { type: "button" });
            const before = el("img", "shot", null, {
              src: `/cve/${encodeURIComponent(projectOf(h))}/hosts/${shot.before.subdomain_id}/screenshot/`,
              alt: `Previous screenshot of ${h.host}`,
              loading: "lazy",
            });
            before.hidden = true;
            before.onerror = () => toggle.remove();
            toggle.onclick = () => {
              before.hidden = !before.hidden;
              toggle.textContent = before.hidden ? "Compare with previous" : "Hide previous";
            };
            compareBox.append(toggle, before);
          }
          items.forEach((c) => {
            const line = el("div", "find");
            line.append(badge(CHANGE_LABEL[c.kind] || c.kind, changeClass(c)), changeCell(c, projectOf(h)), el("span", "note", shortDate(c.detected)));
            recent.append(line);
          });
        })
        .catch(() => recent.append(el("p", "note", "Changes could not be loaded.")));
      if (h.names && h.names.length) {
        pane.append(el("h3", "sec", "Names this IP answers to"));
        h.names.forEach(([how, name]) =>
          pane.append(el("div", "ip-line", `${name}  ·  ${how === "ptr" ? "reverse DNS" : "certificate"}`)),
        );
        pane.append(el("p", "note", "Not added as targets: they may be out of scope."));
      }
      const portTotal = h.ips.reduce((n, ip) => n + ip.ports.length, 0);
      pane.append(el("h3", "sec", `Services (${portTotal})`));
      if (!h.ips.length) pane.append(el("p", "note", "No IP addresses resolved yet."));
      h.ips.forEach((ip) => {
        pane.append(el("div", "ip-line", ip.address + (ip.os ? `  ·  ${ip.os}` : "")));
        const identity = factLine(ip.facts);
        if (identity) pane.append(el("div", "note", identity));
        pane.append(el("div", "note", `full port scan: ${fullScanAgo(ip.full_scanned_at)}${ip.full_scanned_at ? ` (${ip.full_scan_ports} open)` : ""}`));
        ip.ports.forEach((p) => {
          const card = el("div", "svc");
          const top = el("div", "svc-top");
          top.append(
            el("span", "svc-port", `${p.number}/${p.protocol || "tcp"}`),
            el("span", "svc-name", [p.product || p.service, p.version].filter(Boolean).join(" ")),
          );
          card.append(top);
          if (p.info) card.append(el("div", "note", p.info));
          if (p.cpe) card.append(el("div", "note mono", p.cpe));
          if (p.banner) card.append(el("pre", "banner", p.banner));
          Object.entries(p.scripts || {}).forEach(([id, text]) => {
            const det = el("details", "nse");
            det.append(el("summary", "mono", id), el("pre", "banner", text));
            card.append(det);
          });
          if (p.db) { const facts = dbFactsCard(p.db); if (facts) card.append(facts); }
          if (p.http) card.append(jsonRows(p.http));
          if (p.tls) card.append(jsonRows(p.tls));
          if (p.rdp_screenshot) card.append(rdpShotCard(p.rdp_screenshot));
          pane.append(card);
        });
      });
      const routesBox = el("div", "web-routes");
      pane.append(el("h3", "sec", "Web routes"), routesBox);
      api("GET", `${baseOf(projectOf(h))}/routes?${query({ host: h.host, page_size: 50 })}`)
        .then((data) => {
          if (current !== h.id) return;
          const items = (data.results || []).filter((r) => r.host === h.host);
          // only routes that matter: an open page, a login, a session-gated page or SSO. 404s, plain redirects and errors are noise
          const notable = items.filter((r) => NOTABLE_ROUTES.includes(r.auth_state));
          if (!items.length) routesBox.append(el("p", "note", "No web routes have been checked on this host."));
          else if (!notable.length) routesBox.append(el("p", "note", "No notable web routes."));
          notable.forEach((r) => routesBox.append(routeLine(r)));
          if (notable.length && items.length > notable.length)
            routesBox.append(el("p", "note", `${items.length - notable.length} other routes probed (redirects, 404s)`));
        })
        .catch(() => routesBox.append(el("p", "note", "Web routes could not be loaded.")));
      // findings (low or worse) and informational detections are counted apart, as on the Scanner findings page and the dashboard
      const findingLines = (title, items, total) => {
        if (!items.length) return;
        pane.append(el("h3", "sec", `${title} (${total ?? items.length})`));
        items.forEach((v) => {
          const line = el("div", "find");
          const label = v.id
            ? el("a", "", v.name, { href: `/cve/${encodeURIComponent(projectOf(h))}/vulns/#${v.id}` })
            : el("span", "", v.name);
          line.append(badge(v.severity, v.severity), label);
          if (v.classification) line.append(aiBadge({ classification: v.classification, status: "triaged" }, { project: projectOf(h), kind: "vulnerability", id: v.id }));
          pane.append(line);
        });
      };
      findingLines("Open findings", (h.vulns || []).filter((v) => v.severity !== "info"), h.vuln_count);
      findingLines("Informational detections", (h.vulns || []).filter((v) => v.severity === "info"), h.info_count);
      if (ALL) pane.append(assetInfoReadOnly(h));
      else pane.append(assetInfo(h), hostActions(h));
    }

    const list = createList({
      mount: side,
      path: `${base}/search`,
      params: () => ({ q: q.value, sort: sortBy.value }),
      empty: "No hosts match. Hosts appear as discovery and port scans finish.",
      render: (m, items, reset) => {
        if (reset) {
          rows.textContent = "";
          byId.clear();
        }
        items.forEach((h) => {
          byId.set(h.id, h);
          const ports = h.ips.reduce((n, ip) => n + ip.ports.length, 0);
          const row = selectableRow(h.id, h.heat);
          // the name and the address are links to this very record (so they can be shared or opened in a new tab); a plain click selects the row
          const nameBox = el("span", "cve-id");
          nameBox.append(selfLink(hostAnchor(projectOf(h), h.host)));
          row.append(nameBox);
          const meta = el("span", "host-meta");
          meta.append(
            el("span", "chip", String(h.score || 0)),
            h.ips[0] ? rowIp(projectOf(h), h.ips[0].address) : el("span", "note", "no IP"),
            el("span", "note", `${ports} port${ports === 1 ? "" : "s"}`),
          );
          if (h.cve_matches) meta.append(badge(String(h.cve_matches), "fire"));
          const chip = projChip(h);
          if (chip) meta.append(chip);
          row.append(meta);
          if (h.matched && h.matched.length) row.append(rowLine(...h.matched.slice(0, 3).flatMap((t, i) => [i ? " · " : "", matchedWhy(t, projectOf(h), h.host)])));
          row.onclick = (e) => {
            const link = e.target.closest("a");
            if (link && !link.classList.contains("self-link")) return;
            if (link) e.preventDefault();
            history.replaceState(null, "", `#${h.id}`);
            showHost(h);
          };
          rows.append(row);
        });
        const wanted = Number(location.hash.slice(1));
        const named = wantedHost && items.find((h) => h.host === wantedHost);
        if (current == null && named) showHost(named);
        else if (current == null && wanted && byId.has(wanted)) showHost(byId.get(wanted));
        else if (current == null && window.matchMedia("(min-width:900px)").matches && items.length)
          showHost(items[0]);
      },
    });
    showHost(null);
    list.start();
  },

  vulns(mount) {
    // The unified Findings list: CVE matches on hosts, scanner findings and hygiene findings as one population, hottest first.
    // Two labelled axes (what kind of finding, how severe) and one switch (actionable or everything) instead of one row of chips.
    const TYPE_LABEL = { cve: "CVE match", scanner: "Scanner", hygiene: "Hygiene" };
    const wanted = new URLSearchParams(location.search);
    const initial = (key, allowed) => (allowed.includes(wanted.get(key)) ? wanted.get(key) : null);
    const header = el("p", "note");
    mount.append(header);
    const params = () => ({ type: type.value, severity: sev.value, status: status.value, host: q.value });
    const countOf = (over) => async (key) => (await api("GET", `${base}/findings?${query({ ...params(), ...over(key), page_size: 1 })}`)).total;
    const q = searchBox("Filter by host", () => reload());
    const type = picker(
      "Type",
      [["all", "All"], ["cve", "CVE matches"], ["scanner", "Scanner"], ["hygiene", "Hygiene"]],
      countOf((key) => ({ type: key })),
      () => reload(),
    );
    const sev = picker(
      "Severity",
      [
        ["all", "Any severity"],
        ["critical", "Critical", "fire"],
        ["high", "High", "fire"],
        ["medium", "Medium", "smoke"],
        ["low", "Low", "ice"],
        ["info", "Info"],
      ],
      countOf((key) => ({ severity: key })),
      () => reload(),
    );
    const status = picker(
      "Status",
      [["actionable", "Actionable"], ["all", "Everything"]],
      countOf((key) => ({ status: key })),
      () => reload(),
    );
    [[type, "type", ["all", "cve", "scanner", "hygiene"]], [sev, "severity", ["all", "critical", "high", "medium", "low", "info"]],
     [status, "status", ["actionable", "all"]]].forEach(([p, key, allowed]) => {
      const start = initial(key, allowed);
      if (start) {
        p.value = start;
        p.node.querySelectorAll("button").forEach((b, i) => b.setAttribute("aria-pressed", String(allowed[i] === start)));
      }
    });
    const hint = el("p", "note", "Actionable is what makes a host hot on its card: CVE matches the AI has not ruled out, and open scanner and hygiene findings above info. Everything adds informational, closed and ruled-out findings.");
    mount.append(hint);
    function reload() {
      [type, sev, status].forEach((p) => p.refresh());
      list.reload();
    }
    function describe({ counts = {}, total = 0, count = 0, truncated = false }) {
      header.textContent = "";
      const link = (key, n) => el("a", "", `${n} ${{ cve: n === 1 ? "CVE match" : "CVE matches", scanner: n === 1 ? "scanner finding" : "scanner findings", hygiene: n === 1 ? "hygiene finding" : "hygiene findings" }[key]}`,
        { href: `/cve/${encodeURIComponent(slug)}/${{ cve: "matches", scanner: "vulns", hygiene: "hygiene" }[key]}/${key === "scanner" ? "?type=scanner" : ""}` });
      header.append(`${total} finding${total === 1 ? "" : "s"}: `);
      ["cve", "scanner", "hygiene"].forEach((key, i) => header.append(...(i ? [" · "] : []), link(key, counts[key] || 0)));
      if (truncated) header.append(` (the list shows the first ${count}; narrow the filters to see the rest)`);
    }
    const list = findingPage(mount, {
      kind: "vulnerability",
      kindOf: (item) => item.kind,
      forKind: (kind) => (kind === "match" ? { kind, statusControl: matchStatusControl } : { kind }),
      noun: "finding",
      plural: "findings",
      path: `${base}/findings`,
      filters: [q, type.node, sev.node, status.node],
      params,
      empty: "No findings match these filters.",
      onLoaded: (data, reset) => {
        if (reset) describe(data);
      },
      row: (f) => ({
        heat: f.heat,
        title: f.type === "cve" && projectOf(f) ? cveAnchor(projectOf(f), f.title, f.id) : f.title,
        meta: [badge(TYPE_LABEL[f.type] || f.type), badge(f.severity, f.severity), aiBadge(f.triage, { project: projectOf(f), kind: f.kind, id: f.id }), validationBadge(f.triage),
               f.status && !["open", "actionable"].includes(f.status) ? badge(String(f.status).replace(/_/g, " ")) : null, projChip(f)],
        notes: [rowLine(f.host ? hostLink(f.host, projectOf(f)) : "-", f.note ? ` · ${f.note}` : ""), f.description || ""],
      }),
    });
    [type, sev, status].forEach((p) => p.refresh());
  },

  matches(mount) {
    // /matches/?cve=CVE-X&host=name is where a CVE named in free text points: the matches for it, narrowed to a host when known
    const urlq = new URLSearchParams(location.search);
    let cveOnly = /^CVE-\d{4}-\d{4,}$/i.test(urlq.get("cve") || "") ? urlq.get("cve").toUpperCase() : "";
    const q = searchBox("Filter by host", () => list.reload());
    q.value = (urlq.get("host") || "").slice(0, 255);
    const cveNote = el("div", "tools");
    const paintCveNote = () => {
      cveNote.textContent = "";
      cveNote.hidden = !cveOnly;
      if (!cveOnly) return;
      const clear = el("button", "btn ghost sm", "Show all matches", { type: "button" });
      clear.onclick = () => {
        cveOnly = "";
        history.replaceState(null, "", location.pathname + location.hash);
        paintCveNote();
        status.refresh();
        list.reload();
      };
      cveNote.append(el("span", "note", `Matches for ${cveOnly}`), clear);
    };
    // Matches the AI has ruled out are kept (nothing is hidden) but are not what the dashboard's CVE matches counts, so the
    // page opens on the same view and says so.
    const verdict = select(
      "AI verdict",
      [
        ["active", "Not ruled out by the AI"],
        ["not_affected", "Ruled out by the AI"],
        ["", "Any verdict"],
      ],
      () => {
        status.refresh();
        list.reload();
      },
    );
    const status = picker(
      "Remediation status",
      [
        ["", "All"],
        ["open", "Open"],
        ["in_progress", "In progress"],
        ["fixed", "Fixed"],
        ["accepted_risk", "Accepted risk"],
      ],
      async (key) => (await api("GET", `${base}/matches?${query({ status: key, host: q.value, classification: cls.value, verdict: verdict.value, cve: cveOnly, page_size: 1 })}`)).count,
      () => list.reload(),
    );
    const cls = select("AI classification", CLASS_OPTIONS, () => {
      status.refresh();
      list.reload();
    });
    const statusControl = matchStatusControl;
    const list = findingPage(mount, {
      kind: "match",
      noun: "match",
      plural: "matches",
      path: `${base}/matches`,
      filters: [cveNote, q, status.node, cls, verdict],
      params: () => ({ host: q.value, status: status.value, classification: cls.value, verdict: verdict.value, cve: cveOnly }),
      empty: "No CVE matches yet. They appear when a new CVE matches a host in your inventory.",
      onLoaded: (_, reset) => reset && status.refresh(),
      statusControl,
      row: (m) => ({
        heat: m.cve.tier,
        title: projectOf(m) ? cveAnchor(projectOf(m), m.cve.cve_id, m.id) : m.cve.cve_id,
        meta: [badge(m.cve.tier, m.cve.tier), aiBadge(m.triage, { project: projectOf(m), kind: "match", id: m.id }), validationBadge(m.triage), projChip(m)],
        notes: [rowLine(m.host ? hostLink(m.host, projectOf(m)) : "-", ` · ${[m.product, m.version].filter(Boolean).join(" ") || "-"}`), m.cve.short_description || "Description unavailable in the CVE feed."],
      }),
    });
    paintCveNote();
  },
};

pages.hygiene = function hygiene(mount) {
  const head = el("div", "tools");
  const run = el("button", "btn sm", "Run checks now", { type: "button" });
  run.onclick = async () => {
    run.disabled = true;
    try {
      const r = await api("POST", `${base}/hygiene/run`, {});
      toast(
        `Checking ${r.queued} target${r.queued === 1 ? "" : "s"}. Results appear in a minute.`,
      );
      setTimeout(paintTiles, 60000);
    } catch (err) {
      toast(err.message, true);
    }
    run.disabled = false;
  };
  if (!ALL) head.append(run); // running the checks is per project
  mount.append(head);

  // headline numbers, each a count request with page_size 1
  const tiles = el("div", "tiles");
  mount.append(tiles);
  const countOf = (path, qs) =>
    api("GET", `${base}/${path}?${query({ ...qs, page_size: 1 })}`).then((r) => r.count).catch(() => null);
  const paintTiles = async () => {
    const [tracked, expiring, crit, high, open] = await Promise.all([
      countOf("certificates", {}),
      countOf("certificates", { expiring_within: 30 }),
      countOf("hygiene", { severity: "critical" }),
      countOf("hygiene", { severity: "high" }),
      countOf("hygiene", {}),
    ]);
    tiles.textContent = "";
    tiles.append(
      tile("Certificates tracked", tracked),
      tile("Expiring in 30 days", expiring, { hot: "smoke" }),
      tile("Critical or high issues", crit == null ? null : crit + (high || 0), { hot: "fire" }),
      tile("Open issues", open, { hot: "ice" }),
    );
  };
  paintTiles();
  liveCustom.add({ alive: () => tiles.isConnected, run: paintTiles });

  const dayBadge = (d) => {
    if (d == null) return "-";
    const cls =
      d < 0 ? "critical" : d <= 7 ? "high" : d <= 30 ? "medium" : "success";
    return badge(d < 0 ? `expired ${-d}d ago` : `${d} days`, cls);
  };
  const certs = el("section", "card hy-card");
  certs.append(
    el("h2", "", "Certificates"),
    el(
      "p",
      "note",
      "Soonest expiry first. Anything under 30 days needs renewing now.",
    ),
  );
  mount.append(certs);
  createList({
    mount: certs,
    path: `${base}/certificates`,
    empty:
      "No certificates checked yet. They are checked after discovery, daily, or when you run the checks.",
    render: table(withProject([
      { label: "Host", render: (c) => { const n = el("span"); n.append(hostLink(c.host, projectOf(c)), document.createTextNode(`:${c.port}`)); return n; } },
      {
        label: "Expires",
        cls: "cert-expiry",
        render: (c) => (c.not_after ? c.not_after.slice(0, 10) : "-"),
      },
      { label: "Left", render: (c) => dayBadge(c.days_left) },
      { label: "Issuer", render: (c) => c.issuer || "-" },
      { label: "Key", render: (c) => c.key || "-" },
      {
        label: "TLS",
        render: (c) =>
          c.legacy_tls ? badge("1.0/1.1 on", "medium") : c.protocol || "-",
      },
    ]), (c) => (c.days_left == null ? "" : c.days_left < 0 ? "critical" : c.days_left <= 7 ? "high" : c.days_left <= 30 ? "medium" : "")),
  }).start();

  const issues = el("section", "card hy-card");
  issues.append(el("h2", "", "TLS and email authentication"));
  const tools = el("div", "tools");
  const sev = picker(
    "Severity",
    [
      ["", "All"],
      ["critical", "Critical", "fire"],
      ["high", "High", "fire"],
      ["medium", "Medium", "smoke"],
      ["low", "Low", "ice"],
      ["info", "Info"],
    ],
    (key) => countOf("hygiene", { severity: key, check: kind.value, q: q.value }),
    () => list.reload(),
  );
  const kind = select(
    "Area",
    [
      ["", "All areas"],
      ["tls", "TLS and certificates"],
      ["spf", "SPF"],
      ["dkim", "DKIM"],
      ["dmarc", "DMARC"],
      ["caa", "CAA"],
      ["mx", "Mail exchangers"],
      ["mta_sts", "MTA-STS"],
      ["smtp_tlsrpt", "TLS reporting"],
      ["dane", "DANE"],
      ["dnssec", "DNSSEC"],
      ["bimi", "BIMI"],
      ["arc", "ARC"],
      ["adsp", "ADSP"],
      ["mailchannels", "MailChannels"],
    ],
    () => list.reload(),
  );
  const q = searchBox("Filter by host", () => list.reload());
  tools.append(kind, q);
  issues.append(sev.node, tools);
  mount.append(issues);
  const list = createList({
    mount: issues,
    path: `${base}/hygiene`,
    params: () => ({ severity: sev.value, check: kind.value, q: q.value }),
    empty:
      "No open issues. Certificates, TLS settings, SPF, DKIM and DMARC all look healthy.",
    onLoaded: (_, reset) => reset && sev.refresh(),
    render: table(withProject([
      { label: "Severity", render: (f) => badge(f.severity, f.severity) },
      {
        label: "Issue",
        cls: "full",
        render: (f) => {
          const b = el("div", "row-card");
          b.append(el("span", "", f.title), el("span", "note", f.detail));
          return b;
        },
      },
      { label: "Host", render: (f) => hostLink(f.host, projectOf(f)) },
      { label: "Since", render: (f) => shortDate(f.first_seen) },
    ], 3), (f) => f.severity),
  });
  list.start();
};

// --- scan detail: overview + tabs over the scan's sub-resources ------------------
pages.changes = function changes(mount) {
  const tools = el("div", "tools");
  const since = select(
    "Since",
    [
      ["24h", "Last 24 hours"],
      ["7d", "Last 7 days"],
      ["30d", "Last 30 days"],
    ],
    () => {
      kinds.refresh();
      list.reload();
    },
  );
  since.value = "7d";
  const host = searchBox("Filter by host", () => {
    kinds.refresh();
    list.reload();
  });
  tools.append(host, since);
  const count = async (key) =>
    (await api("GET", `${base}/changes?${query({ since: since.value, host: host.value, kind: key, page_size: 1 })}`)).count;
  const kinds = picker(
    "Kind",
    [
      ["", "All"],
      ["host_new", "New hosts", "smoke"],
      ["port_opened", "Ports opened", "smoke"],
      ["service_changed", "Version changes"],
      ["tech_added", "Technologies added"],
      ["cert_changed", "Certificates"],
      ["auth_changed", "Auth state"],
      ["sensitive_found", "Sensitive data", "smoke"],
      ["screenshot_changed", "Screenshots"],
      ["zombie_host", "Zombie hosts", "smoke"],
      ["zombie_route", "Zombie routes", "smoke"],
      ["route_retired", "Retired routes", "ice"],
      ["port_closed", "Ports closed", "ice"],
      ["host_retired", "Retired hosts", "ice"],
    ],
    count,
    () => list.reload(),
  );
  mount.append(tools, kinds.node);
  const list = createList({
    mount,
    path: `${base}/changes`,
    params: () => ({ since: since.value, host: host.value, kind: kinds.value }),
    empty: "No changes in this period. Changes appear when a scan finds something different from the last one.",
    onLoaded: (_, reset) => reset && kinds.refresh(),
    render: table(withProject([
      { label: "When", render: (c) => shortDate(c.detected) },
      { label: "Kind", render: (c) => badge(CHANGE_LABEL[c.kind] || c.kind, changeClass(c)) },
      { label: "Host", cls: "mono", render: (c) => hostLink(c.host, projectOf(c)) },
      { label: "Detail", render: (c) => changeCell(c, projectOf(c)) },
      {
        label: "Scan",
        render: (c) => (c.scan_id ? el("a", "", `#${c.scan_id}`, { href: scanHref(projectOf(c), c.scan_id) }) : "-"),
      },
    ], 3)),
  });
  list.start();
};

// The full AI activity log: this project's entries and the system-wide ones, newest first (the live card keeps the last 100).
const ACTIVITY_KIND = {
  feed: "Read feed",
  inventory: "Inventory",
  target: "Target",
  confirm: "Reasoning",
  write_check: "Writing",
  run_check: "Running",
  validate: "Validate",
  discovery: "Discover",
  scan: "Scan",
  hygiene: "Hygiene",
  changes: "Changes",
  remediation: "Remediation",
};
const ACTIVITY_BADGE = { target: "fire", validate: "success", hygiene: "success" };

pages.activity = function activity(mount) {
  const tools = el("div", "tools");
  if (ALL && root.dataset.appAdmin === "1") {
    const control = el("section", "card");
    const state = el("p", "note", "Loading global scanning state…", { role: "status" });
    const actions = el("div", "tools");
    const pause = el("button", "btn", "Pause all scanning", { type: "button" });
    const resume = el("button", "btn ghost", "Resume scanning", { type: "button" });
    let busy = false;
    async function refresh() {
      try {
        const data = await api("GET", "/cve/api/admin/scan-control");
        if (!control.isConnected) return;
        const active = data.active_worker_tasks === null ? "unknown" : String(data.active_worker_tasks);
        const changed = data.changed_at ? ` Changed ${shortDate(data.changed_at)} by ${data.actor || "system"}.` : "";
        state.textContent = `Global state: ${data.state.replaceAll("_", " ")}. Active worker tasks: ${active}.${changed} ${data.last_error || data.note}`;
        pause.disabled = busy || data.paused;
        resume.disabled = busy || !data.paused;
      } catch (err) {
        state.textContent = `Global scanning state unavailable: ${err.message}`;
        pause.disabled = resume.disabled = true;
      }
    }
    async function change(action, confirmation) {
      if (!window.confirm(`${confirmation}? This affects every project. Active scans will be stopped; queued work is kept.`)) return;
      busy = true;
      pause.disabled = resume.disabled = true;
      try {
        await api("POST", "/cve/api/admin/scan-control", { action, confirm: confirmation });
      } catch (err) {
        toast(err.message, true);
      } finally {
        busy = false;
        await refresh();
      }
    }
    pause.onclick = () => change("pause", "Pause all scanning");
    resume.onclick = () => change("resume", "Resume scanning");
    actions.append(pause, resume);
    control.append(el("h2", "", "Global scanning control"), state, actions,
      el("p", "note", "The pause holds new scheduled and queued work. Active scanner processes stop cooperatively; a status of pause requested means shutdown is not yet confirmed. Resume does not restart stopped scans."));
    mount.append(control);
    refresh();
    setInterval(() => { if (control.isConnected) refresh(); }, 5000);
  }
  const kinds = select("Kind", [["", "All kinds"], ...Object.entries(ACTIVITY_KIND)], () => list.reload());
  tools.append(kinds);
  mount.append(tools);
  const list = createList({
    mount,
    path: `${base}/activity`,
    params: () => ({ kind: kinds.value }),
    empty: "No activity yet. The engine reports here as it reads the feed, checks the inventory and runs scans.",
    render: table(withProject([
      { label: "When", render: (a) => shortDate(a.created) },
      { label: "Kind", render: (a) => badge(ACTIVITY_KIND[a.kind] || a.kind, ACTIVITY_BADGE[a.kind] || "") },
      {
        label: "Activity",
        render: (a) => {
          const box = linkify(el("span"), a.message, projectOf(a));
          if (a.repeat > 1) box.append(el("span", "a-repeat", ` ×${a.repeat}`));
          if (a.status === "failed") box.append(document.createTextNode(" "), badge("failed", "failed"));
          return box;
        },
      },
      {
        label: "Scan",
        // a system-wide entry names no project, so in the all-projects view its scan (if any) has no page to link to
        render: (a) => (a.scan_id ? (projectOf(a) ? el("a", "", `#${a.scan_id}`, { href: scanHref(projectOf(a), a.scan_id) }) : `#${a.scan_id}`) : "-"),
      },
    ], 2)),
  });
  list.start();
};

pages.scan = async function scanDetail(mount) {
  const scanBase = `${base}/scans/${root.dataset.scan}`;
  const tabs = el("div", "tools", null, { role: "tablist" });
  const panel = el("div");
  mount.append(tabs, panel);
  let refresh = null;
  let ticker = null; // live duration on a running scan's overview

  const tabDefs = {
    overview: { label: "Overview", open: overview },
    subdomains: {
      label: "Subdomains",
      open: (m) =>
        listTab(m, "subdomains", "Search subdomains", [
          { label: "Subdomain", render: (r) => hostLink(r.name) },
          { label: "HTTP", cls: "num", render: (r) => r.http_status || "-" },
          { label: "Title", render: (r) => r.title || "-" },
          { label: "IPs", render: (r) => (r.ips.length ? joinNodes(r.ips.map((ip) => ipAnchor(slug, ip))) : "-") },
          { label: "Tech", render: (r) => r.technologies.join(", ") || "-" },
        ], [["Export hosts", "subdomains"], ["Export URLs", "urls"]]),
    },
    endpoints: {
      label: "Endpoints",
      open: (m) =>
        listTab(m, "endpoints", "Search URLs", [
          { label: "URL", render: (r) => r.url },
          { label: "HTTP", cls: "num", render: (r) => r.http_status || "-" },
          { label: "Title", render: (r) => r.title || "-" },
          { label: "Type", render: (r) => r.content_type || "-" },
          { label: "Patterns", render: (r) => r.patterns.join(", ") || "-" },
        ], [["Export endpoints", "endpoints"]]),
    },
    findings: { label: "Findings", open: findings },
    activity: {
      label: "Activity",
      open: (m) =>
        listTab(m, "activity", null, [
          { label: "Task", render: (r) => r.title },
          { label: "Status", render: (r) => badge(r.status, r.status) },
          { label: "Time", render: (r) => shortDate(r.time) },
          { label: "Error", render: (r) => r.error || "-" },
        ]),
    },
  };

  function listTab(m, resource, placeholder, columns, exports = []) {
    let q = null;
    if (placeholder) {
      const tools = el("div", "tools");
      q = searchBox(placeholder, () => list.reload());
      tools.append(q);
      exports.forEach(([label, kind]) =>
        tools.append(el("a", "btn ghost sm", label, { href: `/scan/export/${kind}/${root.dataset.scan}`, download: "" })),
      );
      m.append(tools);
    }
    const list = createList({
      mount: m,
      path: `${scanBase}/${resource}`,
      params: () => ({ q: q ? q.value : "" }),
      empty: `No ${resource} yet.`,
      render: table(columns),
    });
    list.start();
  }

  function findings(m) {
    const sev = picker(
      "Severity",
      [
        ["", "All"],
        ["critical", "Critical", "fire"],
        ["high", "High", "fire"],
        ["medium", "Medium", "smoke"],
        ["low", "Low", "ice"],
        ["info", "Info"],
      ],
      async (key) => (await api("GET", `${scanBase}/vulnerabilities?${query({ severity: key, page_size: 1 })}`)).count,
      () => list.reload(),
    );
    m.append(sev.node);
    const list = createList({
      mount: m,
      path: `${scanBase}/vulnerabilities`,
      params: () => ({ severity: sev.value }),
      empty: "No findings in this scan.",
      onLoaded: (_, reset) => reset && sev.refresh(),
      render: table(
        [
          { label: "Severity", render: (v) => badge(v.severity, v.severity) },
          { label: "Finding", render: (v) => v.name },
          { label: "Host", render: (v) => hostLink(v.host) },
          { label: "CVE", render: (v) => (v.cves.length ? joinNodes(v.cves.map((c) => cveLink(slug, c, v.cve_matches && v.cve_matches[c], v.host))) : "-") },
          { label: "URL", render: (v) => v.url || "-" },
        ],
        (v) => v.severity,
      ),
    });
    list.start();
  }

  async function overview(m) {
    const draw = async () => {
      let s;
      let stages = [];
      try {
        s = await api("GET", scanBase);
        stages = (await api("GET", `${scanBase}/activity?page_size=50`)).results || [];
      } catch (err) {
        m.textContent = "";
        m.append(el("p", "msg err", err.message));
        return;
      }
      clearInterval(ticker);
      m.textContent = "";
      const live = s.status === -1 || s.status === 1;
      const head = el("div", "card scan-head");
      const top = el("div", "card-head");
      const title = el("h2");
      title.append(hostLink(s.target, slug));
      top.append(title, badge(SCAN_STATUS[s.status] || s.status, SCAN_STATUS[s.status]));
      const meta = el("div", "scan-meta");
      const dur = el("span", "", null);
      const paintDur = () => {
        dur.textContent = "";
        dur.append(document.createTextNode("Duration "), el("b", "", duration(s.started, s.finished)));
      };
      paintDur();
      if (live) ticker = setInterval(paintDur, 1000);
      const eng = el("span");
      eng.append(document.createTextNode("Engine "), el("b", "", s.engine));
      const began = el("span");
      began.append(document.createTextNode("Started "), el("b", "", shortDate(s.started)));
      meta.append(eng, began, dur);
      // report downloads: a PDF built by the server from this scan's results and the branding in Settings > Reports
      const pop = el("details", "pop");
      pop.append(el("summary", "btn ghost sm", "Download report"));
      const menu = el("div", "pop-menu");
      [
        ["Full report", "report_type=full"],
        ["Reconnaissance only", "report_type=recon"],
        ["Vulnerabilities only", "report_type=vulnerability"],
        ["Vulnerabilities, without info findings", "report_type=vulnerability&ignore_info_vuln=1"],
      ].forEach(([label, qs]) =>
        menu.append(el("a", "", label, { href: `/scan/create_report/${s.id}?${qs}&report_template=modern`, target: "_blank", rel: "noopener" })),
      );
      pop.append(menu);
      top.insertBefore(pop, top.lastChild);
      head.append(top, meta);
      if (stages.length) {
        const row = el("div", "phases");
        stages
          .slice()
          .sort((a, b) => (a.time || "").localeCompare(b.time || ""))
          .forEach((st) => {
            const box = el("div", `phase ${st.status}`);
            box.append(el("b", "", st.title), el("span", "", st.error ? st.error : st.status));
            row.append(box);
          });
        head.append(row);
      }
      if (s.error) head.append(el("p", "msg err", s.error));

      const tiles = el("div", "tiles");
      const go = (name) => () => open(name);
      const sc = s.severity_counts;
      tiles.append(
        tile("Subdomains", s.subdomains, { onClick: go("subdomains") }),
        tile("Endpoints", s.endpoints, { onClick: go("endpoints") }),
        tile("Findings, all severities", s.vulnerabilities, { onClick: go("findings") }),
        tile("Critical", sc.critical, { hot: "fire", onClick: go("findings") }),
        tile("High", sc.high, { hot: "fire", onClick: go("findings") }),
        tile("Medium", sc.medium, { hot: "smoke", onClick: go("findings") }),
      );
      m.append(head, tiles);
      if (s.vulnerabilities) {
        const bar = el("div", "sevbar", null, { role: "img", "aria-label": "Findings by severity" });
        ["critical", "high", "medium", "low", "info"].forEach((k) => {
          if (!sc[k]) return;
          const seg = el("i", k, null, { title: `${k}: ${sc[k]}` });
          seg.style.flexGrow = sc[k];
          bar.append(seg);
        });
        const card = el("div", "card");
        card.append(el("h2", "", "Findings by severity"), bar);
        card.querySelector("h2").style.marginBottom = "10px";
        m.append(card);
      }
      clearTimeout(refresh);
      if (live) refresh = setTimeout(draw, REFRESH_MS);
    };
    await draw();
  }

  function open(name) {
    clearTimeout(refresh);
    clearInterval(ticker);
    tabs
      .querySelectorAll("button")
      .forEach((b) =>
        b.setAttribute("aria-selected", String(b.dataset.tab === name)),
      );
    panel.textContent = "";
    tabDefs[name].open(panel);
  }
  Object.entries(tabDefs).forEach(([name, def]) => {
    const b = el("button", "btn ghost sm", def.label, {
      role: "tab",
      "data-tab": name,
      "aria-selected": "false",
    });
    b.type = "button";
    b.onclick = () => open(name);
    tabs.append(b);
  });
  open("overview");
};

pages.keys = async function apiKeys(mount) {
  mount.append(
    el(
      "p",
      "note page-intro",
      "Choose one project or an organization. An organization key applies to its current and future projects; " +
        "a project key overrides it for that project. Discovery passes configured Shodan and other OSINT keys " +
        "to the matching BBOT modules. Secrets are write-only and never shown again.",
    ),
  );
  const scopes = [];
  const projects = (await api("GET", "/api/v1/projects")).results;
  projects.forEach((p) => scopes.push({ value: `project:${p.slug}`, kind: "project", name: p.name,
    path: baseOf(p.slug) + "/api-keys" }));
  if (root.dataset.admin === "1") {
    try {
      const orgs = (await api("GET", "/cve/api/admin/orgs")).results;
      orgs.forEach((o) => scopes.push({ value: `org:${o.id}`, kind: "org", name: o.name,
        path: `/cve/api/admin/orgs/${o.id}/api-keys` }));
    } catch (error) {
      mount.append(el("p", "msg err", `Organization scopes could not be loaded: ${error.message}`));
    }
  }
  const scopePicker = el("select", "", null, { "aria-label": "API key scope" });
  scopePicker.append(el("option", "", "Choose scope", { value: "" }));
  scopes.forEach((s) => scopePicker.append(el("option", "",
    `${s.kind === "org" ? "Organization" : "Project"} · ${s.name}${s.kind === "org" ? " (all projects)" : ""}`,
    { value: s.value })));
  scopePicker.value = ALL ? "" : `project:${slug}`;
  mount.append(field("Apply key to", scopePicker));
  const scopeNote = el("p", "note");
  mount.append(scopeNote);
  const list = el("div", "grid");
  mount.append(list);
  let data = { results: [], can_edit: false };
  let requestVersion = 0;
  const selectedScope = () => scopes.find((s) => s.value === scopePicker.value);

  function openEditor(svc) {
    const scope = selectedScope();
    if (!scope) return;
    dialog(`Configure ${svc.label}`, (body, close) => {
      body.append(el("p", "note", scope.kind === "org"
        ? `Organization ${scope.name}: this key will apply to its current and future projects unless each has an override.`
        : `Project ${scope.name}: this key applies only to this project.`));
      if (svc.scope === "org") body.append(el("p", "note", "This project currently inherits the organization key. Enter a new value to override it."));
      const inputs = svc.fields.map((f) => {
        const input = uiText("", {
          type: f.secret ? "password" : "text",
          autocomplete: "off",
          spellcheck: "false",
          placeholder:
            f.secret && svc.set[f.name] && svc.scope !== "org" ? "saved (leave blank to keep)" : "",
        });
        body.append(field(f.label, input));
        return { name: f.name, input };
      });
      const actions = el("div", "actions");
      const remove = el("button", "btn ghost", "Remove", { type: "button" });
      remove.style.display = (scope.kind === "org" ? svc.configured : svc.scope === "project") ? "" : "none";
      remove.onclick = async () => {
        try {
          if (scope.kind === "org" && !await ask(
            `Remove the ${svc.label} default for organization ${scope.name}? Projects with their own override keep it; others lose this source.`,
            { title: "Remove organization key", ok: "Remove key" })) return;
          await api("DELETE", `${scope.path}/${svc.service}`);
          toast(`${svc.label} key removed`);
          close();
          draw();
        } catch (err) {
          toast(err.message, true);
        }
      };
      const save = el("button", "btn", "Save", { type: "button" });
      save.onclick = async () => {
        save.disabled = true;
        try {
          const values = Object.fromEntries(
            inputs.map((i) => [i.name, i.input.value]).filter(([, v]) => v),
          );
          if (scope.kind === "org" && !await ask(
            `Save ${svc.label} for organization ${scope.name}? Its current and future projects will use this key unless each has an override.`,
            { title: "Set organization default", ok: "Save for organization", danger: false })) {
            save.disabled = false;
            return;
          }
          await api("PUT", `${scope.path}/${svc.service}`, values);
          toast(`${svc.label} key saved`);
          close();
          draw();
        } catch (err) {
          toast(err.message, true);
          save.disabled = false;
        }
      };
      const cancel = el("button", "btn ghost", "Cancel", { type: "button" });
      cancel.onclick = close;
      actions.append(remove, el("span", "grow"), cancel, save);
      body.append(actions);
    });
  }

  const show = picker(
    "Show",
    [
      ["", "All"],
      ["set", "Configured", "clean"],
      ["unset", "Not set"],
    ],
    async (key) =>
      data.results.filter((v) => (key === "set" ? v.configured : key === "unset" ? !v.configured : true)).length,
    () => paint(),
  );
  mount.insertBefore(show.node, list);
  list.className = "keys-grid";

  function paint() {
    list.textContent = "";
    data.results
      .filter((v) => (show.value === "set" ? v.configured : show.value === "unset" ? !v.configured : true))
      .forEach((svc) => {
        const card = el("div", `card keytile${svc.configured ? " on" : ""}`);
        const top = el("div", "keytile-top");
        top.append(el("b", "", svc.label));
        top.append(
          svc.configured
            ? badge(selectedScope()?.kind === "org" ? "organization default" : svc.scope === "project" ? "project override" : "inherited from organization", "success")
            : badge("not set", "queued"),
        );
        card.append(top);
        if (!svc.used_in_scans) card.append(el("p", "note", "No scan module uses this key yet. It is stored for later."));
        if (!data.can_edit) card.append(el("p", "note", "Audit role: read only."));
        else {
          const b = el("button", `btn sm${svc.configured ? " ghost" : ""}`, svc.configured ? "Edit" : "Configure", { type: "button" });
          b.onclick = () => openEditor(svc);
          card.append(b);
        }
        list.append(card);
      });
  }

  async function draw() {
    const scope = selectedScope();
    const request = ++requestVersion;
    if (!scope) {
      data = { results: [], can_edit: false };
      scopeNote.textContent = "Select a project or an organization before viewing or changing its keys.";
      show.refresh();
      paint();
      return;
    }
    scopeNote.textContent = scope.kind === "org"
      ? `Organization ${scope.name}: defaults for all its current and future projects. Project overrides take precedence.`
      : `Project ${scope.name}: inherited organization keys are identified below.`;
    try {
      const next = await api("GET", scope.path);
      if (request !== requestVersion) return;
      data = { ...next, can_edit: scope.kind === "org" || next.can_edit };
      show.refresh();
      paint();
    } catch (error) {
      if (request !== requestVersion) return;
      data = { results: [], can_edit: false };
      list.textContent = "";
      list.append(el("p", "msg err", `Could not load ${scope.name} keys: ${error.message}`));
    }
  }
  scopePicker.onchange = draw;
  await draw();
};

pages[kind](root.querySelector("#view"));
