// Superusers only: a slim bar when the twice-daily check found a newer CVEngine version. Approval happens in Settings.
const csrf = document.querySelector("[name=csrfmiddlewaretoken]");
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

const STEPS = ["Approved", "Applying", "Restarting", "Done"];
const POLL_MS = 4000;

// After approval the whole site is covered by a status panel. The host updater reports nothing but the outcome, so the steps are
// inferred: approved and still reachable = waiting for or applying the update; unreachable = restarting; installed matches = done.
function watchUpdate(first) {
  const veil = el("div", "update-veil");
  veil.setAttribute("role", "alertdialog");
  veil.setAttribute("aria-modal", "true");
  veil.setAttribute("aria-labelledby", "uv-title");
  const card = el("div", "update-card");
  const title = el("h2", "", "");
  title.id = "uv-title";
  const note = el("p", "note", "");
  const bar = el("div", "update-bar");
  bar.setAttribute("role", "progressbar");
  bar.setAttribute("aria-label", "Update progress");
  bar.append(el("i"));
  const list = el("ol", "update-steps");
  const items = STEPS.map((t) => list.appendChild(el("li", "", t)));
  const stop = el("a", "btn ghost sm", "Cancel approval or see details");
  stop.href = "/cve/settings/#updates";
  card.append(title, note, bar, list, stop);
  veil.append(card);
  document.body.append(veil);
  document.querySelectorAll(".layout, #main, .updatebar").forEach((n) => n.setAttribute("inert", ""));
  let step = 1;
  let down = 0;
  const paint = (t, n) => {
    title.textContent = t;
    note.textContent = n;
    bar.className = `update-bar${step === 3 ? " done" : ""}`;
    if (step === 3) bar.setAttribute("aria-valuenow", "100");
    else bar.removeAttribute("aria-valuenow");
    items.forEach((li, i) => li.className = i < step ? "ok" : i === step ? "now" : "");
  };
  paint(`Updating to ${first.latest}`, "Waiting for the host to start. Scans that are running finish first, so this can take a while. This page updates by itself.");
  const tick = async () => {
    try {
      const r = await fetch("/cve/api/settings/updates", { credentials: "same-origin", cache: "no-store" });
      if (!r.ok) throw new Error(String(r.status));
      const now = await r.json();
      if (down) {
        down = 0;
        step = 2;
      }
      if (now.status !== "approved") {
        if (now.installed_known && now.installed === now.latest || now.status === "up_to_date") {
          step = 3;
          paint("Update complete", `CVEngine is now on ${now.latest}. Reloading.`);
          return setTimeout(() => location.reload(), 1500);
        }
        veil.remove();
        document.querySelectorAll("[inert]").forEach((n) => n.removeAttribute("inert"));
        return; // approval was cancelled or the update failed: the page is usable again
      }
      step = 1;
      paint(`Updating to ${now.latest}`, "Applying the update. The site restarts briefly. This page updates by itself.");
    } catch (_) {
      down += 1;
      step = 2;
      paint("Restarting CVEngine", "The services are coming back up. This usually takes a minute or two.");
    }
    setTimeout(tick, POLL_MS);
  };
  setTimeout(tick, POLL_MS);
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
