import { el, badge, table } from "/staticfiles/cve/ui.js";
import { fmtDateTime } from "/staticfiles/cve/prefs.js";
import * as L from "/staticfiles/cve/internal-logic.js";
import { renderKeepingState } from "/staticfiles/cve/keep-state.js";

// The Internal network page: the status of only the internal hosts of the scope (cveFeed.internal_page, /cve/api/internal). The page polls
// while it is visible, so the scan activity stays live; nothing here writes.
const root = document.getElementById("internal");
const slug = root.dataset.slug;
const POLL_MS = 15000;
const sectionHref = (name, params) => `/cve/${encodeURIComponent(slug)}/${name}/${params ? `?${new URLSearchParams(params)}` : ""}`;

function setTile(key, value, foot) {
  const tile = root.querySelector(`[data-kpi="${key}"]`);
  if (!tile) return;
  tile.querySelector(".ov-kpi-value").textContent = Number(value || 0).toLocaleString();
  tile.querySelector(".ov-foot").textContent = foot || "";
}

function paintTiles(t) {
  setTile("hosts", t.hosts, t.hosts ? "inside your declared networks" : "none found yet");
  setTile("exposed", t.exposed_hosts, t.hosts ? `out of ${t.hosts.toLocaleString()} internal hosts` : "");
  setTile("critical", t.critical, `${(t.high || 0).toLocaleString()} high`);
  setTile("needs", t.needs, `internal host${t.needs === 1 ? "" : "s"} to look at`);
}

function dot(state) {
  const wrap = el("span", `in-net ${state}`);
  wrap.append(el("i", "in-dot"), el("span", "in-state", L.SENTINEL_WORDS[state] || state));
  return wrap;
}

// Each section is redrawn through renderKeepingState, so a poll never closes what the person opened or loses their place.
const draw = (id, nodes) => renderKeepingState(document.getElementById(id), () => nodes);

function networkBlocks(networks, now) {
  if (!networks.length) return [el("p", "empty", "No internal network is declared here yet. A project administrator declares one on the project's Sentinels page.")];
  const cols = [
    { label: "Range", cls: "mono", render: (n) => (n.description ? `${n.cidr} (${n.description})` : n.cidr) },
    { label: "Project", render: (n) => n.project_name || n.project },
    { label: "Live hosts", render: (n) => L.liveHostsText(n) },
    { label: "Last discovery", render: (n) => L.lastDiscoveryText(n, now) },
    { label: "Next discovery", render: (n) => L.nextDiscoveryText(n, now) },
    {
      label: "Sentinel inside",
      render: (n) => {
        const cell = el("span");
        cell.append(dot((n.sentinel && n.sentinel.state) || "none"));
        const names = L.sentinelNames(n.sentinel);
        if (names) cell.append(el("small", "note", ` ${names}`));
        return cell;
      },
    },
    { label: "Last error", cls: "clip", render: (n) => L.lastErrorText(n) || "None" },
  ];
  const out = [table(cols, networks)];
  const warnings = networks.map(L.rangeWarning).filter(Boolean);
  if (warnings.length) {
    const list = el("ul", "note");
    warnings.forEach((w) => list.append(el("li", "", w)));
    out.push(list);
  }
  return out;
}

function findingBlocks(f) {
  document.getElementById("in-find-all").textContent = f.total ? `All ${f.total.toLocaleString()} internal findings →` : "All internal findings →";
  if (!f.results.length) return [el("p", "empty", "No open findings on internal hosts.")];
  const cols = [
    { label: "Severity", render: (r) => badge(r.severity, ["critical", "high", "medium", "low"].includes(r.severity) ? r.severity : "") },
    {
      label: "Finding",
      render: (r) => {
        const a = el("a", "", r.title || "(untitled)", { href: sectionHref("vulns", { internal: "1", host: r.host || "" }) });
        return a;
      },
    },
    { label: "Type", render: (r) => r.kind },
    { label: "Host", cls: "mono", render: (r) => r.host_label || r.host || "" },
    { label: "Heat", render: (r) => r.heat || "" },
    ...(slug === "_all" ? [{ label: "Project", render: (r) => r.project_name || r.project || "" }] : []),
  ];
  return [table(cols, f.results)];
}

function activityBlocks(a, now) {
  const out = [];
  const scans = a.scans || { running: 0, queued: 0 };
  document.getElementById("in-scans").textContent = `${scans.running} internal scan${scans.running === 1 ? "" : "s"} running, ${scans.queued} queued`;
  const cols = [
    { label: "Task", render: (r) => L.taskName(r.kind) },
    { label: "Host or range", cls: "mono", render: (r) => r.host_label || r.host },
    { label: "Status", render: (r) => badge(r.status, L.STATUS_BADGE[r.status] || "") },
    { label: "Sentinel", render: (r) => r.sentinel || "Not claimed yet" },
    { label: "When", render: (r) => (r.finished_at ? `finished ${L.ago(r.finished_at, now)}` : r.claimed_at ? `started ${L.ago(r.claimed_at, now)}` : `queued ${L.ago(r.created_at, now)}`) },
    { label: "Error", cls: "clip", render: (r) => r.error || "" },
  ];
  if (a.active.length) out.push(table(cols, a.active));
  else out.push(el("p", "empty", "No internal scan work is waiting or running right now."));
  if (a.recent.length) out.push(el("h3", "note", "Finished in the last day"), table(cols, a.recent));
  return out;
}

async function load() {
  try {
    const r = await fetch(`/cve/api/internal?project=${encodeURIComponent(slug)}`, { credentials: "same-origin" });
    if (!r.ok) throw new Error(`status ${r.status}`);
    const d = await r.json();
    const now = Date.now();
    paintTiles(d.tiles);
    draw("in-nets-body", networkBlocks(d.networks || [], now));
    draw("in-find-body", findingBlocks(d.findings || { total: 0, results: [] }));
    draw("in-act-body", activityBlocks(d.activity || { active: [], recent: [] }, now));
    document.getElementById("in-updated").textContent = d.updated_at ? `Updated ${fmtDateTime(d.updated_at)}` : "";
    root.setAttribute("aria-busy", "false");
  } catch (_) {
    document.getElementById("in-updated").textContent = "Could not read the internal network status. Retrying.";
  }
}

load();
setInterval(() => {
  if (!document.hidden) load();
}, POLL_MS);
