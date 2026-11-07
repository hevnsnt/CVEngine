// Scanners: the answer to "are the scanners working?" in one click. Everything comes from endpoints that already exist:
//   /api/v1/sentinels/live     the Sentinels this person may see, and how many tasks wait for one
//   /cve/api/scanner           the page strip's sentence when work waits with no scanner to take it
//   /cve/api/admin/health      workers, scheduler heartbeat, scanning pause and scan counts (App Admin only; a short live inspection)
// Nothing is hidden by this page: the server decides what each person may read. Text is set with textContent only.
import { api, el } from "/staticfiles/cve/ui.js";

const root = document.getElementById("health");
const isAdmin = root.dataset.appAdmin === "1";
const EVERY_MS = 30000;

const WORKERS = { responding: ["All responding", false], degraded: ["Needs attention", true], unknown: ["Not confirmed", true] };
const BEAT = { running: ["Running", false], silent: ["Silent", true], unknown: ["Not confirmed", true] };

function cell(title, big, note, warn) {
  const c = el("div", `card health-cell${warn ? " warn" : ""}`);
  c.append(el("span", "eyebrow", title), el("b", "", big));
  if (note) c.append(el("p", "note", note));
  return c;
}

function sentinelCell(live) {
  const list = live && live.results ? live.results : [];
  const by = (state) => list.filter((s) => s.state === state).length;
  const online = by("working") + by("idle");
  if (!list.length) {
    return { node: cell("Sentinels", "None registered", "Scans run on this server until a Sentinel registers. Provision one from Sentinels."), problem: "" };
  }
  const bits = [["working", "working"], ["idle", "idle"], ["offline", "offline"], ["pending", "waiting for approval"], ["suspended", "suspended"]]
    .filter(([state]) => by(state)).map(([state, word]) => `${by(state)} ${word}`);
  const warn = online === 0;
  return { node: cell("Sentinels", `${online} of ${list.length} online`, bits.join(", "), warn), problem: warn ? "No Sentinel is online." : "" };
}

function waitingCell(live, strip) {
  const queued = live && live.queued != null ? live.queued : 0;
  const lines = [strip && strip.message, strip && strip.disabled_message, strip && strip.never_seen_message].filter(Boolean);
  const warn = queued > 0 && lines.length > 0;
  return { node: cell("Work waiting for a Sentinel", String(queued), lines.join(" ") || (queued ? "Queued; a Sentinel takes it at its next check-in." : "Nothing is waiting."), warn), problem: warn ? lines[0] : "" };
}

function adminCells(h) {
  const out = [];
  const [wWord, wWarn] = WORKERS[h.workers_state] || ["Not confirmed", true];
  out.push({ node: cell("Workers", wWord, h.worker_note || "", wWarn), problem: wWarn ? `Workers: ${h.worker_note || wWord}` : "" });
  const beat = h.beat || { state: "unknown" };
  const [bWord, bWarn] = BEAT[beat.state] || ["Not confirmed", true];
  const tick = beat.seconds_since_tick != null ? `Last tick ${beat.seconds_since_tick}s ago.` : "No heartbeat has been recorded yet.";
  out.push({ node: cell("Scheduler", bWord, tick, bWarn), problem: bWarn && beat.state === "silent" ? "The scheduler has gone quiet." : "" });
  const scans = (h.jobs && h.jobs.scans) || { pending: 0, running: 0 };
  out.push({
    node: cell("Scanning", h.scanning_paused ? "Paused" : "On", `${scans.running} scan${scans.running === 1 ? "" : "s"} running, ${scans.pending} queued.`, !!h.scanning_paused),
    problem: h.scanning_paused ? "Scanning is paused." : "",
  });
  return out;
}

async function load(first) {
  const [live, strip, health] = await Promise.all([
    api("GET", "/api/v1/sentinels/live").catch(() => null),
    fetch("/cve/api/scanner", { credentials: "same-origin", cache: "no-store" }).then((r) => (r.ok ? r.json() : null)).catch(() => null),
    isAdmin ? api("GET", "/cve/api/admin/health").catch((e) => ({ error: e.message })) : Promise.resolve(null),
  ]);
  if (!root.isConnected) return;
  const cells = [sentinelCell(live), waitingCell(live, strip)];
  if (isAdmin) {
    if (health && !health.error) cells.push(...adminCells(health));
    else cells.push({ node: cell("Workers and scheduler", "Not read", (health && health.error) || "The health check did not answer.", true), problem: "Workers and scheduler could not be read." });
  }
  const problems = cells.map((c) => c.problem).filter(Boolean);
  const head = el("p", "health-line");
  head.append(el("span", `badge ${problems.length ? "high" : "success"}`, problems.length ? "Needs attention" : "All working"));
  if (problems.length) head.append(el("span", "note", problems.join(" ")));
  const grid = el("div", "health-grid");
  cells.forEach((c) => grid.append(c.node));
  root.replaceChildren(head, grid);
}

let timer = null;
async function loop(first) {
  try {
    await load(first);
  } catch (err) {
    root.replaceChildren(el("p", "msg err", err.message));
  }
  timer = setTimeout(() => loop(false), EVERY_MS);
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    clearTimeout(timer);
    loop(false);
  }
});
loop(true);
