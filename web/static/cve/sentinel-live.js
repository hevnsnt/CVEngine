// Sentinels, live: one card per scanner showing whether it is checking in, whether it is taking work and what it is doing right now.
// The state is drawn as a Thinking Orb (static/cve/thinking-orb.js): its particles work while the Sentinel works, listen while it waits
// for work, reach out while it waits for approval, and freeze when it is offline or suspended. Everything comes from
// GET /api/v1/sentinels/live and is set with textContent; the card ages itself every second between polls. When the server reports `orgs`,
// the cards are grouped by the organizations each Sentinel covers (an instance-wide one under "Every organization"), each group with the
// internal networks its projects declared.
import { api, badge, button, el, toast } from "/staticfiles/cve/ui.js";
import { thinkingOrb } from "/staticfiles/cve/thinking-orb.js";
import { detailCache, versionBlock } from "/staticfiles/cve/sentinel-settings.js";

const LIVE = "/api/v1/sentinels/live";
const POLL_MS = 5000;
const WORDS = {
  working: "Working",
  idle: "Idle, waiting for work",
  offline: "Offline",
  pending: "Waiting for approval",
  suspended: "Suspended",
};
const KIND = { nmap: "nmap", naabu: "naabu", nuclei_light: "nuclei (light)", nuclei_targeted: "nuclei (targeted)", nuclei_deep: "nuclei (deep)", testssl: "testssl", nmap_udp: "nmap UDP", wpscan: "wpscan", openvas: "OpenVAS", discover: "internal discovery" };
const kindName = (k) => KIND[k] || k;

function span(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d`;
}
const ago = (seconds) => (seconds == null ? "never" : `${span(seconds)} ago`);
const seconds = (iso) => (iso ? (Date.now() - new Date(iso).getTime()) / 1000 : null);

// One orb per Sentinel, kept across refreshes: a card is redrawn every few seconds, its orb is moved into the new card and only told the new
// state, so it never restarts.
const orbs = new Map();
const ORB_STATE = { working: "working", idle: "listening", pending: "connecting", offline: "breathing", suspended: "breathing" };
// a Sentinel covering two organizations is drawn in both groups, so an orb belongs to a group and a Sentinel
function orbFor(s, group) {
  const busy = s.state === "working" && s.current.length > 1 ? "solving" : ORB_STATE[s.state] || "breathing";
  const key = `${group}:${s.id}`;
  let o = orbs.get(key);
  if (!o) {
    o = thinkingOrb({ state: busy, size: 64 });
    orbs.set(key, o);
  }
  o.setState(busy, `${s.name}: ${WORDS[s.state] || s.state}`);
  o.setPaused(s.state === "offline" || s.state === "suspended");
  o.node.classList.toggle("asleep", s.state === "offline" || s.state === "suspended");
  return o.node;
}

function task(t) {
  const row = el("div", "sl-task");
  const what = el("div", "sl-what");
  what.append(el("b", "mono", kindName(t.kind)), document.createTextNode(` on ${t.label || t.host || "a target"}`));
  const meta = el("span", "sl-meta", `${t.project}${t.status === "claimed" ? " · starting" : ""}`);
  row.append(what, meta);
  if (t.since) row.append(el("span", "sl-since", "", { "data-since": t.since }));
  return row;
}

function recent(t) {
  const li = el("li", `sl-r ${t.status}`);
  li.append(el("i", "sl-dot"), el("b", "mono", kindName(t.kind)), el("span", "sl-host", t.label || t.host || ""));
  const tail = t.status === "failed" ? t.error || "failed" : t.seconds != null ? span(t.seconds) : "";
  li.append(el("span", "sl-tail", tail));
  if (t.finished) li.append(el("span", "sl-when", "", { "data-ago": t.finished }));
  return li;
}

const INTERNAL = "network:internal";

function card(s, reload, detail, group) {
  const c = el("article", `sl-card sl-${s.state}`, null, { "data-id": s.id });
  const head = el("header", "sl-head");
  head.append(orbFor(s, group));
  const title = el("div", "sl-title");
  const state = el("p", "sl-state", WORDS[s.state] || s.state);
  if (s.capabilities.includes(INTERNAL)) state.append(" ", badge("Internal network", "internal"));
  title.append(el("h3", "", s.name), state);
  head.append(title);
  const actions = el("div", "sl-actions");
  const patch = (status) => async () => {
    await api("PATCH", `/api/v1/agents/${s.id}`, { status });
    await reload();
  };
  if (s.status === "pending") actions.append(button("Approve", patch("active"), "btn sm"));
  if (s.status === "suspended") actions.append(button("Reinstate", patch("active"), "btn sm"));
  if (s.status !== "suspended") actions.append(button("Suspend", patch("suspended"), "btn ghost sm"));
  actions.append(
    button(
      "Revoke",
      async () => {
        if (!confirm(`Revoke ${s.name}? This cannot be undone.`)) return;
        await patch("revoked")();
      },
      "btn ghost sm",
    ),
  );
  head.append(actions);
  c.append(head);

  const beat = el("p", "sl-beat");
  beat.append(el("i", `sl-pulse ${s.live ? "on" : ""}`), el("span", "", "", { "data-seen": s.last_seen || "" }));
  c.append(beat);
  const version = versionBlock(detail, { onChange: reload });
  if (version) c.append(version);
  if (s.problem) c.append(el("p", "sl-note", s.problem));
  else if (s.status_note) c.append(el("p", "sl-note", s.status_note));

  const now = el("div", "sl-now");
  if (s.current.length) s.current.forEach((t) => now.append(task(t)));
  else now.append(el("p", "sl-quiet", s.state === "offline" ? "Not taking work until it checks in again." : s.state === "idle" ? "Checking in and ready. Nothing to do right now." : ""));
  c.append(now);

  const st = s.stats;
  const stats = el("dl", "sl-stats");
  const stat = (label, value) => {
    const d = el("div");
    d.append(el("dt", "", label), el("dd", "", String(value)));
    return d;
  };
  stats.append(stat("Done, last hour", st.done_1h), stat("Failed, last hour", st.failed_1h), stat("Done, 24 hours", st.done_24h), stat("Average task", st.average_seconds == null ? "none yet" : span(st.average_seconds)));
  c.append(stats);

  if (s.recent.length) {
    const list = el("ul", "sl-recent", null, { "aria-label": `Recent tasks of ${s.name}` });
    s.recent.forEach((t) => list.append(recent(t)));
    c.append(list);
  }
  const kinds = s.capabilities.filter((k) => k !== INTERNAL);
  const tools = kinds.length ? kinds.map(kindName).join(", ") : "no capabilities";
  c.append(el("p", "sl-foot", `${tools}${s.os ? ` · ${s.os}` : ""} · up to ${s.max_concurrent} at once`));
  Object.entries(s.withheld_kinds || {}).forEach(([k, w]) => {
    const retry = new Date(w.retry_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    c.append(el("p", "sl-foot", `${kindName(k)} failed ${w.failures} times in a row: cvENGINE runs it itself until ${retry}, then tries this Sentinel again.`));
  });
  return c;
}

function summary(data) {
  const rows = data.results;
  const live = rows.filter((r) => r.live && r.status === "active").length;
  const working = rows.filter((r) => r.state === "working").length;
  const bar = el("div", "sl-sum");
  const cell = (n, label) => {
    const d = el("div");
    d.append(el("b", "", String(n)), el("span", "", label));
    return d;
  };
  bar.append(cell(`${live} of ${rows.length}`, "checking in"), cell(working, "working now"), cell(data.queued, "tasks waiting for a Sentinel"));
  return bar;
}

function openvasQueue(queue) {
  const box = el("section", "sl-openvas", null, { "aria-label": "OpenVAS queue", "aria-live": "off" });
  const head = el("div", "sl-openvas-head");
  head.append(el("h3", "", "OpenVAS queue"), el("span", "sl-openvas-count", `${queue.counts.next} due · ${queue.counts.not_due} not due`));
  box.append(head);
  if (queue.running) {
    const run = queue.running;
    const active = el("div", "sl-openvas-running");
    active.append(el("b", "", `Scanning ${run.project}`),
      el("span", "", `${run.hosts.join(", ")} · ${run.via === "sentinel" ? "Sentinel" : "local scanner"}`));
    const progress = typeof run.progress === "number" ? `${run.progress}%` : "in progress";
    active.append(el("span", "sl-openvas-progress", `${run.status || "Running"} · ${progress} · ${run.budget_hours}h budget`));
    box.append(active);
  } else box.append(el("p", "sl-quiet", "No OpenVAS scan is running."));

  const due = el("div", "sl-openvas-list");
  due.append(el("h4", "", `Next due (${queue.counts.next})`));
  if (queue.next.length) {
    const list = el("ul");
    queue.next.forEach((row) => {
      const item = el("li");
      item.append(el("b", "mono", row.host), el("span", "", row.project));
      if (row.heat) item.append(badge(row.heat, row.heat));
      list.append(item);
    });
    due.append(list);
  } else due.append(el("p", "sl-quiet", "No hosts are due."));
  if (queue.counts.next > queue.next.length) due.append(el("p", "note", `Showing ${queue.next.length} of ${queue.counts.next} due hosts.`));
  box.append(due);

  if (queue.counts.not_due) {
    const deferred = el("details", "sl-openvas-deferred");
    deferred.append(el("summary", "", `Not due (${queue.counts.not_due})`));
    const list = el("ul");
    queue.not_due.forEach((row) => {
      const item = el("li");
      item.append(el("b", "mono", row.host), el("span", "", row.project), el("span", "sl-openvas-reason", row.reason || "Not due"));
      list.append(item);
    });
    deferred.append(list);
    if (queue.counts.not_due > queue.not_due.length) deferred.append(el("p", "note", `Showing ${queue.not_due.length} of ${queue.counts.not_due} not due hosts.`));
    box.append(deferred);
  }
  return box;
}

// The groups to draw: instance-wide Sentinels first, then each organization that has a Sentinel or an internal network, then any
// Sentinel whose scope names nothing this user can see. A server too old to report `orgs` gets one group with no heading.
function groups(data) {
  if (!data.orgs) return [{ key: "all", title: null, sentinels: data.results, networks: [] }];
  const out = [];
  const every = data.results.filter((s) => s.scope_level === "instance");
  if (every.length) out.push({ key: "instance", title: "Every organization", note: "Instance-wide Sentinels take work from every project.", sentinels: every, networks: [] });
  data.orgs.forEach((o) => {
    const mine = data.results.filter((s) => (s.orgs || []).includes(o.slug));
    if (mine.length || o.networks.length) out.push({ key: `org:${o.slug}`, title: o.name, slug: o.slug, sentinels: mine, networks: o.networks });
  });
  const loose = data.results.filter((s) => s.scope_level !== "instance" && !(s.orgs || []).length);
  if (loose.length) out.push({ key: "none", title: "No organization you can see", note: "Their scope names projects outside your organizations.", sentinels: loose, networks: [] });
  return out;
}

const SENTINEL_INSIDE = { online: "Sentinel inside is checking in", offline: "No Sentinel inside is checking in", none: "No internal Sentinel covers it" };

function networks(rows) {
  const wrap = el("div", "sl-nets");
  wrap.append(el("h4", "", "Internal networks"));
  const t = el("table", "sl-net-table");
  const head = el("tr");
  ["Network", "Project", "Hosts", "Last discovery", "Sentinel inside"].forEach((h) => head.append(el("th", "", h, { scope: "col" })));
  const thead = el("thead");
  thead.append(head);
  t.append(thead);
  const body = el("tbody");
  rows.forEach((n) => {
    const error = n.last_discovery_error || n.last_error;
    const tr = el("tr", error ? "err" : "");
    const net = el("td");
    net.append(el("b", "mono", n.cidr));
    if (n.description) net.append(el("span", "note", n.description));
    // the last live-host sweep of the range (a server too old to sweep has only the last internal scan)
    const last = el("td");
    const when = n.last_discovery_at || n.last_scan_at;
    if (when) last.append(el("span", "", "", { "data-ago": when }));
    else last.append(el("span", "note", "never"));
    if (n.last_discovery_at && n.last_discovery_hosts != null) last.append(el("span", "note", `${n.last_discovery_hosts} live ${n.last_discovery_hosts === 1 ? "host" : "hosts"} found`));
    if (error) last.append(el("span", "msg err", error));
    const inside = el("td");
    const st = (n.sentinel && n.sentinel.state) || "none";
    inside.append(badge(st === "online" ? `${n.sentinel.online} online` : st === "offline" ? "offline" : "none", st === "online" ? "success" : st === "offline" ? "failed" : ""));
    inside.title = SENTINEL_INSIDE[st] || "";
    const project = el("td", "mono", n.project);
    tr.append(net, project, el("td", "num", String(n.hosts)), last, inside);
    body.append(tr);
  });
  t.append(body);
  wrap.append(t);
  return wrap;
}

// which organization groups this viewer folded away, kept across redraws and visits
const FOLD_KEY = "cve.sentinels.folded";
const folded = new Set();
try {
  JSON.parse(localStorage.getItem(FOLD_KEY) || "[]").forEach((k) => folded.add(k));
} catch (_) {
  /* no storage: every group starts open */
}
function remember() {
  try {
    localStorage.setItem(FOLD_KEY, JSON.stringify([...folded]));
  } catch (_) {
    /* keep it for this visit only */
  }
}

function section(g, reload, details) {
  const grid = el("div", "sl-grid");
  g.sentinels.forEach((s) => grid.append(card(s, reload, details.get(s.id), g.key)));
  if (!g.title) return grid;
  const box = el("details", "sl-org");
  box.open = !folded.has(g.key);
  box.addEventListener("toggle", () => {
    if (box.open) folded.delete(g.key);
    else folded.add(g.key);
    remember();
  });
  const sum = el("summary", "sl-org-head");
  sum.append(el("h3", "", g.title));
  const live = g.sentinels.filter((s) => s.live && s.status === "active").length;
  const chips = el("span", "chips");
  chips.append(el("span", "chip", g.sentinels.length ? `${live} of ${g.sentinels.length} checking in` : "no Sentinel"));
  if (g.networks.length) chips.append(el("span", "chip", `${g.networks.length} internal ${g.networks.length === 1 ? "network" : "networks"}`));
  const failing = g.networks.filter((n) => n.last_discovery_error || n.last_error).length;
  if (failing) chips.append(badge(`${failing} failing`, "failed"));
  sum.append(chips);
  box.append(sum);
  if (g.note) box.append(el("p", "note", g.note));
  if (g.networks.length) box.append(networks(g.networks));
  if (g.sentinels.length) box.append(grid);
  else box.append(el("p", "sl-quiet", "No Sentinel covers this organization. Its internal networks are not being scanned."));
  return box;
}

const DETAIL_MS = 15000; // settings, version and update come from each Sentinel's detail, asked for less often than the live list

export function sentinelLive(mount) {
  let data = null;
  let timer = null;
  const details = detailCache(() => paint());
  const ids = () => (data ? data.results.map((s) => s.id) : []);
  const paint = () => {
    mount.textContent = "";
    if (!data) return;
    if (!data.results.length) {
      mount.append(el("p", "empty", "No Sentinel has registered yet. Generate an enrollment secret for a project and give it to a Sentinel's setup."));
      if (!(data.orgs || []).some((o) => o.networks.length) && !data.openvas) return;
    } else mount.append(summary(data));
    if (data.openvas) mount.append(openvasQueue(data.openvas));
    const drawn = groups(data);
    drawn.forEach((g) => mount.append(section(g, reload, details)));
    const kept = new Set(drawn.flatMap((g) => g.sentinels.map((s) => `${g.key}:${s.id}`)));
    orbs.forEach((o, key) => {
      if (!kept.has(key)) {
        o.destroy();
        orbs.delete(key);
      }
    });
    tick();
  };
  // ages the "seen 12s ago" and "running for 40s" text between polls without asking the server
  const tick = () => {
    mount.querySelectorAll("[data-seen]").forEach((n) => {
      const sec = seconds(n.dataset.seen);
      n.textContent = n.dataset.seen ? `Last check-in ${ago(sec)}` : "Has never checked in";
    });
    mount.querySelectorAll("[data-since]").forEach((n) => (n.textContent = `running for ${span(seconds(n.dataset.since))}`));
    mount.querySelectorAll("[data-ago]").forEach((n) => (n.textContent = ago(seconds(n.dataset.ago))));
  };
  async function load() {
    try {
      data = await api("GET", LIVE);
      paint();
    } catch (err) {
      if (!data) toast(err.message, true);
    }
  }
  async function reload() {
    await load();
    await details.refresh(ids());
  }
  reload();
  setInterval(() => {
    if (!document.hidden) details.refresh(ids());
  }, DETAIL_MS);
  timer = setInterval(() => {
    if (document.hidden) return;
    load();
  }, POLL_MS);
  setInterval(tick, 1000);
  return () => clearInterval(timer);
}

const mount = document.getElementById("live");
if (mount) sentinelLive(mount);
