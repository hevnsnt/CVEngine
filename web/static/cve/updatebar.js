// Superusers only: a slim bar when the twice-daily check found a newer CVEngine version. Approval happens in Settings.
import { hardReload, hideVeil, loadScene, manageVeil, showVeil } from "/staticfiles/cve/sitewatch.js";
const csrf = document.querySelector("[name=csrfmiddlewaretoken]");
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

const POLL_MS = 4000;
const elapsed = (ms) => {
  const sec = Math.max(0, Math.round(ms / 1000));
  return `${sec < 60 ? `${sec} s` : `${Math.floor(sec / 60)} min ${String(sec % 60).padStart(2, "0")} s`} since approval.`;
};
const STEPS = ["Pause", "Drain scans", "Rebuild", "Resume"];

// After approval an orange bar sits at the top of every page and says what the update is doing. The page is greyed out only while
// the services rebuild, and released when they answer again. The server may report `phase` (idle, draining, applying, restarting,
// resuming, done, failed) and `scans_running`; when it does not, the phase is inferred: reachable and approved is draining, and
// unreachable is rebuilding.
function watchUpdate(first) {
  const bar = el("div", "update-live");
  bar.setAttribute("role", "status");
  bar.setAttribute("aria-live", "polite");
  const text = el("div", "ul-text");
  const msg = el("strong", "", "");
  const detail = el("span", "ul-detail", "");
  text.append(msg, detail);
  const steps = el("ol", "ul-steps");
  const items = STEPS.map((t) => steps.appendChild(el("li", "", t)));
  const more = el("a", "btn sm ul-link", "Details");
  more.href = "/cve/settings/#updates";
  const track = el("div", "ul-track");
  track.append(el("i"));
  bar.append(el("span", "ul-dot"), text, steps, more, track);
  const layout = document.querySelector(".layout") || document.getElementById("main");
  layout.parentNode.insertBefore(bar, layout.parentNode.firstChild);
  // From the moment the host picks the update up, the whole page is covered by the "we are rebuilding" scene (static/cve/sitewatch.js holds
  // it in memory, so it shows even while nothing answers) with the current step as its status line. It stays until the update is done,
  // and then this page goes back to /cve/.
  manageVeil();
  loadScene();
  const grey = (on, status) => (on ? showVeil(status) : hideVeil());
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
    grey(true, `Updated to ${now.latest || first.latest}. Taking you back.`);
    paint(3, `Updated to ${now.latest || first.latest}`, "Scanning has resumed. Reloading.", false);
    setTimeout(() => hardReload("/cve/"), 1800);
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
      grey(true, "Waiting for the site to answer. Usually 2 to 5 minutes.");
      paint(2, "Rebuilding CVEngine", "The page is paused and returns when the services are back. Usually 2 to 5 minutes.");
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
      grey(true, now.phase_detail ? `Rebuilding: ${now.phase_detail}` : "Building and restarting the services.");
      paint(2, "Rebuilding CVEngine", now.phase_detail || "Building and restarting the services.");
    } else if (phase === "resuming") {
      grey(true, "Back up. Resuming scanning.");
      paint(3, "Back up. Resuming scanning", now.phase_detail || "");
    } else {
      grey(false);
      const n = now.scans_running != null ? now.scans_running : await scansNow();
      if (n > 0) paint(1, `Waiting for ${n} running scan${n === 1 ? "" : "s"} to finish`, "No new scans start meanwhile. The rebuild starts when the last one ends (minutes, or hours for a deep scan).");
      else {
        const waited = now.approved_at ? Date.now() - Date.parse(now.approved_at) : 0;
        const hu = now.host_updater || {};
        if (now.phase_detail) paint(1, `Updating to ${now.latest}`, `${now.phase_detail}. ${elapsed(waited)}`);
        else if (hu.alive) paint(1, `Updating to ${now.latest}`, `The host updater is listening and starts within seconds. ${elapsed(waited)}`);
        else if (hu.seen)
          paint(
            1,
            `Updating to ${now.latest}`,
            `Nothing will start: the host updater stopped reporting ${Math.max(1, Math.round((hu.age_seconds || 0) / 60))} min ago. Open Details for the command to run on the server. ${elapsed(waited)}`
          );
        else if (waited > 20000)
          paint(
            1,
            `Updating to ${now.latest}`,
            `Nothing will start by itself: the host updater is not installed on the server. Open Details for the one command to run. ${elapsed(waited)}`
          );
        else paint(1, `Updating to ${now.latest}`, "Waiting for the host to pick it up.");
      }
    }
    setTimeout(tick, POLL_MS);
  };
  paint(0, `Update to ${first.latest} approved`, "Pausing new scans.");
  setTimeout(tick, 1200);
}

const RECHECK_MS = 30000;
async function recheck() {
  if (document.hidden) return setTimeout(recheck, RECHECK_MS);
  try {
    const r = await fetch("/cve/api/settings/updates", { credentials: "same-origin", cache: "no-store" });
    const s = r.ok ? await r.json() : null;
    if (s && s.status === "approved") {
      document.querySelectorAll(".updatebar").forEach((n) => n.remove());
      return watchUpdate(s);
    }
  } catch (_) {
    /* down: sitewatch covers the page */
  }
  setTimeout(recheck, RECHECK_MS);
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
  // a page opened before the update was approved (here, in Settings or on another device) must still notice it and follow it
  setTimeout(recheck, RECHECK_MS);
  if (s.status !== "available" && s.status !== "diverged") return;
  const bar = el("div", "updatebar");
  bar.setAttribute("role", "status");
  const msg =
    s.status === "approved"
      ? `Update to ${s.latest} approved by ${s.approved_by}. The host will apply it shortly.`
      : s.status === "diverged"
        ? `CVEngine has ${s.behind_by} new commit${s.behind_by === 1 ? "" : "s"}, but this server has ${s.local_commits} of its own, so it cannot be updated for you: ${s.latest_message}`
        : `A new version of CVEngine is available${s.behind_by ? ` (${s.behind_by} commit${s.behind_by === 1 ? "" : "s"})` : ""}${s.branch_warning ? ` on the ${s.branch} branch, which is not a release` : ""}: ${s.latest_message}`;
  bar.append(el("span", "", msg));
  const review = el("a", "btn sm", s.status === "approved" || s.status === "diverged" ? "Details" : "Review and update");
  review.href = "/cve/settings/#updates";
  bar.append(review);
  if ((s.status === "available" || s.status === "diverged") && csrf) {
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
