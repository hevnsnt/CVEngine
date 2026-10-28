// Sentinels, live: one card per scanner showing whether it is checking in, whether it is taking work and what it is doing right now.
// The state is drawn as a Thinking Orb (static/cve/thinking-orb.js): its particles work while the Sentinel works, listen while it waits
// for work, reach out while it waits for approval, and freeze when it is offline or suspended. Everything comes from
// GET /api/v1/sentinels/live and is set with textContent; the card ages itself every second between polls.
import { api, button, el, toast } from "/staticfiles/cve/ui.js";
import { thinkingOrb } from "/staticfiles/cve/thinking-orb.js";

const LIVE = "/api/v1/sentinels/live";
const POLL_MS = 5000;
const WORDS = {
  working: "Working",
  idle: "Idle, waiting for work",
  offline: "Offline",
  pending: "Waiting for approval",
  suspended: "Suspended",
};
const KIND = { nmap: "nmap", naabu: "naabu", nuclei_light: "nuclei (light)", nuclei_targeted: "nuclei (targeted)", nuclei_deep: "nuclei (deep)", testssl: "testssl", nmap_udp: "nmap UDP", wpscan: "wpscan", openvas: "OpenVAS" };
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
function orbFor(s) {
  const busy = s.state === "working" && s.current.length > 1 ? "solving" : ORB_STATE[s.state] || "breathing";
  let o = orbs.get(s.id);
  if (!o) {
    o = thinkingOrb({ state: busy, size: 64 });
    orbs.set(s.id, o);
  }
  o.setState(busy, `${s.name}: ${WORDS[s.state] || s.state}`);
  o.setPaused(s.state === "offline" || s.state === "suspended");
  o.node.classList.toggle("asleep", s.state === "offline" || s.state === "suspended");
  return o.node;
}

function task(t) {
  const row = el("div", "sl-task");
  const what = el("div", "sl-what");
  what.append(el("b", "mono", kindName(t.kind)), document.createTextNode(` on ${t.host || "a target"}`));
  const meta = el("span", "sl-meta", `${t.project}${t.status === "claimed" ? " · starting" : ""}`);
  row.append(what, meta);
  if (t.since) row.append(el("span", "sl-since", "", { "data-since": t.since }));
  return row;
}

function recent(t) {
  const li = el("li", `sl-r ${t.status}`);
  li.append(el("i", "sl-dot"), el("b", "mono", kindName(t.kind)), el("span", "sl-host", t.host || ""));
  const tail = t.status === "failed" ? t.error || "failed" : t.seconds != null ? span(t.seconds) : "";
  li.append(el("span", "sl-tail", tail));
  if (t.finished) li.append(el("span", "sl-when", "", { "data-ago": t.finished }));
  return li;
}

function card(s, reload) {
  const c = el("article", `sl-card sl-${s.state}`, null, { "data-id": s.id });
  const head = el("header", "sl-head");
  head.append(orbFor(s));
  const title = el("div", "sl-title");
  title.append(el("h3", "", s.name), el("p", "sl-state", WORDS[s.state] || s.state));
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
  const tools = s.capabilities.length ? s.capabilities.map(kindName).join(", ") : "no capabilities";
  c.append(el("p", "sl-foot", `${tools}${s.os ? ` · ${s.os}` : ""} · up to ${s.max_concurrent} at once`));
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

export function sentinelLive(mount) {
  let data = null;
  let timer = null;
  const paint = () => {
    mount.textContent = "";
    if (!data) return;
    if (!data.results.length) {
      mount.append(el("p", "empty", "No Sentinel has registered yet. Generate an enrollment secret for a project and give it to a Sentinel's setup."));
      return;
    }
    mount.append(summary(data));
    const grid = el("div", "sl-grid");
    data.results.forEach((s) => grid.append(card(s, load)));
    const kept = new Set(data.results.map((s) => s.id));
    orbs.forEach((o, id) => {
      if (!kept.has(id)) {
        o.destroy();
        orbs.delete(id);
      }
    });
    mount.append(grid);
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
  load();
  timer = setInterval(() => {
    if (document.hidden) return;
    load();
  }, POLL_MS);
  setInterval(tick, 1000);
  return () => clearInterval(timer);
}

const mount = document.getElementById("live");
if (mount) sentinelLive(mount);
