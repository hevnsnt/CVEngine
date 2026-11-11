// Scanners: the answer to "are the scanners working?" in one click. Everything comes from endpoints that already exist:
//   /api/v1/sentinels/live     the Sentinels this person may see, and how many tasks wait for one
//   /cve/api/scanner           the page strip's sentence when work waits with no scanner to take it
//   /cve/api/admin/health      workers, scheduler heartbeat, scanning pause and scan counts (App Admin only; a short live inspection)
// Nothing is hidden by this page: the server decides what each person may read. Text is set with textContent only.
import { api, el, waiting, couldNotRead, SLOW_MS } from "/staticfiles/cve/ui.js";
import { renderKeepingState } from "/staticfiles/cve/keep-state.js";

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

function paint(cells) {
  const problems = cells.map((c) => c.problem).filter(Boolean);
  const settled = cells.every((c) => c.settled);
  const head = el("p", "health-line");
  // the verdict waits until every cell has answered: "All working" over a placeholder would be a guess
  if (settled || problems.length) head.append(el("span", `badge ${problems.length ? "high" : "success"}`, problems.length ? "Needs attention" : "All working"));
  if (problems.length) head.append(el("span", "note", problems.join(" ")));
  const grid = el("div", "health-grid");
  cells.forEach((c) => grid.append(c.node));
  head.setAttribute("data-keep-key", "health-line");
  grid.setAttribute("data-keep-key", "health-grid");
  // the page asks again every few seconds: a refresh that changed nothing touches nothing, and one that did keeps what the person selected or scrolled
  renderKeepingState(root, () => [head, grid]);
}

// Each cell has its own request and its own state: "wait" (a placeholder that says what is being checked), "ok" or "error" (could not be read,
// with Retry). A cell fills in when its request answers, so a slow worker check never holds the Sentinels back. After SLOW_MS still waiting,
// the placeholder says it is taking longer than usual; the count lives here so a redraw does not start it over.
const slots = {
  live: { state: "wait", slow: false, timer: null, data: null, error: "" },
  strip: { data: null },
  health: { state: isAdmin ? "wait" : "off", slow: false, timer: null, data: null, error: "" },
};
const READ = {
  live: () => api("GET", "/api/v1/sentinels/live"),
  health: () => api("GET", "/cve/api/admin/health"),
};

function placeholder(title, what, slot) {
  const c = el("div", "card health-cell");
  c.append(el("span", "eyebrow", title), waiting(what, { slow: slot.slow }));
  return { node: c, problem: "", settled: false };
}

function unreadable(title, what, slot) {
  const c = el("div", "card health-cell warn");
  c.append(el("span", "eyebrow", title), couldNotRead(what, () => refresh(slot === slots.live ? "live" : "health"), slot.error));
  return { node: c, problem: `${what} could not be read.`, settled: true };
}

function draw() {
  if (!root.isConnected) return;
  const { live, strip, health } = slots;
  const cells = [];
  if (live.state === "wait") {
    cells.push(placeholder("Sentinels", "Checking the Sentinels", live), placeholder("Work waiting for a Sentinel", "Checking what is waiting", live));
  } else if (live.state === "error") {
    cells.push(unreadable("Sentinels", "The Sentinel list", live), unreadable("Work waiting for a Sentinel", "The count of waiting work", live));
  } else {
    cells.push({ ...sentinelCell(live.data), settled: true }, { ...waitingCell(live.data, strip.data), settled: true });
  }
  if (health.state === "wait") cells.push(placeholder("Workers and scheduler", "Checking the workers and the scheduler", health));
  else if (health.state === "error") cells.push(unreadable("Workers and scheduler", "The worker check", health));
  else if (health.state === "ok") cells.push(...adminCells(health.data).map((c) => ({ ...c, settled: true })));
  paint(cells);
}

function arm(slot) {
  clearTimeout(slot.timer);
  slot.slow = false;
  slot.timer = setTimeout(() => {
    if (slot.state !== "wait") return;
    slot.slow = true;
    draw();
  }, SLOW_MS);
}

async function refresh(name, quiet = false) {
  const slot = slots[name];
  if (!quiet || slot.state === "wait") {
    slot.state = "wait";
    arm(slot);
    draw();
  }
  try {
    slot.data = await READ[name]();
    slot.state = "ok";
  } catch (err) {
    slot.state = "error";
    slot.error = err.message || "";
  }
  clearTimeout(slot.timer);
  draw();
}

// The strip's sentence is extra: when it does not answer, the work cell simply has no extra sentence.
async function readStrip() {
  slots.strip.data = await fetch("/cve/api/scanner", { credentials: "same-origin", cache: "no-store" }).then((r) => (r.ok ? r.json() : null)).catch(() => null);
  draw();
}

// The frame is drawn at once; the requests start together and none waits for another.
async function load() {
  const reads = [refresh("live", true), readStrip()];
  if (isAdmin) reads.push(refresh("health", true));
  await Promise.all(reads);
}

let timer = null;
async function loop() {
  try {
    await load();
  } catch (err) {
    root.replaceChildren(el("p", "msg err", err.message));
  }
  timer = setTimeout(loop, EVERY_MS);
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    clearTimeout(timer);
    loop();
  }
});
loop();
