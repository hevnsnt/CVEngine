// Superusers only: a slim bar when the twice-daily check found a newer CVEngine version. Approval happens in Settings.
const csrf = document.querySelector("[name=csrfmiddlewaretoken]");
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

const POLL_MS = 4000;
const STEPS = ["Pause", "Drain scans", "Rebuild", "Resume"];

// After approval an orange bar sits at the top of every page and says what the update is doing. The page is greyed out only while
// the services rebuild, and released when they answer again. The server may report `phase` (idle, draining, applying, restarting,
// resuming, done, failed) and `scans_running`; when it does not, the phase is inferred: reachable and approved is draining, and
// unreachable is rebuilding.
function watchUpdate(first) {
  const bar = el("div", "update-live");
  bar.setAttribute("role", "status");
  bar.setAttribute("aria-live", "polite");
  const head = el("div", "ul-head");
  const msg = el("strong", "", "");
  const detail = el("span", "ul-detail", "");
  const more = el("a", "ul-link", "Details");
  more.href = "/cve/settings/#updates";
  head.append(msg, detail, more);
  const steps = el("ol", "ul-steps");
  const items = STEPS.map((t) => steps.appendChild(el("li", "", t)));
  const track = el("div", "ul-track");
  track.append(el("i"));
  bar.append(head, steps, track);
  const layout = document.querySelector(".layout") || document.getElementById("main");
  layout.parentNode.insertBefore(bar, layout.parentNode.firstChild);
  const body = [...document.querySelectorAll(".layout, #main")];
  const grey = (on) => {
    document.documentElement.classList.toggle("updating", on);
    body.forEach((n) => (on ? n.setAttribute("inert", "") : n.removeAttribute("inert")));
  };
  let unreachable = 0;
  let sawDown = false;
  const paint = (step, text, extra, busy = true) => {
    msg.textContent = text;
    detail.textContent = extra || "";
    items.forEach((li, i) => (li.className = i < step ? "ok" : i === step && busy ? "now" : i === step ? "ok" : ""));
    track.classList.toggle("done", !busy);
  };
  const scansNow = async () => {
    try {
      const r = await fetch("/cve/api/stats", { credentials: "same-origin", cache: "no-store" });
      return r.ok ? (await r.json()).scans_running : null;
    } catch (_) {
      return null;
    }
  };
  const finish = (now) => {
    grey(false);
    paint(3, `Updated to ${now.latest || first.latest}`, "Scanning has resumed. Reloading.", false);
    setTimeout(() => location.reload(), 2500);
  };
  const tick = async () => {
    let now = null;
    try {
      const r = await fetch("/cve/api/settings/updates", { credentials: "same-origin", cache: "no-store" });
      if (!r.ok) throw new Error(String(r.status));
      now = await r.json();
    } catch (_) {
      unreachable += 1;
      sawDown = true;
      grey(true);
      paint(2, "Rebuilding CVEngine", "The page is paused and returns when the services are back. Usually a minute or two.");
      return setTimeout(tick, POLL_MS);
    }
    unreachable = 0;
    if (now.phase === "failed" || (now.status !== "approved" && now.status !== "up_to_date" && !sawDown)) {
      grey(false);
      bar.classList.add("failed");
      paint(2, "The update did not finish", now.last_error || now.phase_detail || "Open Details to see the log.", false);
      return;
    }
    if (now.status !== "approved") {
      if (sawDown || now.phase === "done" || now.status === "up_to_date") return finish(now);
      bar.remove(); // approval was cancelled
      grey(false);
      return;
    }
    const phase = now.phase;
    if (phase === "applying" || phase === "restarting") {
      grey(true);
      paint(2, "Rebuilding CVEngine", now.phase_detail || "Building and restarting the services.");
    } else if (phase === "resuming") {
      grey(false);
      paint(3, "Back up. Resuming scanning", now.phase_detail || "");
    } else {
      grey(false);
      const n = now.scans_running != null ? now.scans_running : await scansNow();
      if (n > 0) paint(1, `Waiting for ${n} running scan${n === 1 ? "" : "s"} to finish`, "No new scans start. The rebuild begins when they are done.");
      else paint(1, `Updating to ${now.latest}`, "No scans are running. Waiting for the host updater to start the rebuild.");
    }
    setTimeout(tick, POLL_MS);
  };
  paint(0, `Update to ${first.latest} approved`, "Pausing new scans.");
  setTimeout(tick, 1200);
}

async function run() {
  let s;
  try {
    const r = await fetch("/cve/api/settings/updates", { credentials: "same-origin" });
    if (!r.ok) return;
    s = await r.json();
  } catch (_) {
    return;
  }
  if (s.status === "approved") return watchUpdate(s);
  if (s.status !== "available") return;
  const bar = el("div", "updatebar");
  bar.setAttribute("role", "status");
  const msg =
    s.status === "approved"
      ? `Update to ${s.latest} approved by ${s.approved_by}. The host will apply it shortly.`
      : `A new version of CVEngine is available${s.behind_by ? ` (${s.behind_by} commit${s.behind_by === 1 ? "" : "s"})` : ""}: ${s.latest_message}`;
  bar.append(el("span", "", msg));
  const review = el("a", "btn sm", s.status === "approved" ? "Details" : "Review and update");
  review.href = "/cve/settings/#updates";
  bar.append(review);
  if (s.status === "available" && csrf) {
    const dismiss = el("button", "btn ghost sm", "Dismiss");
    dismiss.type = "button";
    dismiss.onclick = async () => {
      await fetch("/cve/api/settings/updates/dismiss", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRFToken": csrf.value },
      });
      bar.remove();
    };
    bar.append(dismiss);
  }
  const layout = document.querySelector(".layout") || document.getElementById("main");
  layout.parentNode.insertBefore(bar, layout);
}
run();
