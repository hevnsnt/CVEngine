// One-click PDF report. The server builds it in the background; this asks, polls, then downloads it through the authenticated API
// route (the file is private to the person who asked and expires after 24 hours). Nothing is built in the browser.
import { api, el, toast } from "/staticfiles/cve/ui.js";

const POLL_MS = 2000;
const GIVE_UP_MS = 20 * 60 * 1000;
const WORDS = { queued: "Queued…", running: "Building the report…" };

async function save(url, filename) {
  const res = await fetch(url, { credentials: "same-origin" });
  if (!res.ok) {
    let message = `Download failed (${res.status})`;
    try { message = (await res.json()).error || message; } catch (_) { /* not JSON */ }
    throw new Error(message);
  }
  const href = URL.createObjectURL(await res.blob());
  const a = el("a", "", "", { href, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 5000);
}

/**
 * A "Download PDF report" button with a switch for fixed and accepted-risk findings.
 * @param {{slug: string, host?: string, label?: string}} options host: an exact host name for a one-host report
 */
export function reportButton({ slug, host = "", label = "Download PDF report" }) {
  const box = el("span", "report-export");
  const button = el("button", "btn ghost sm", label, {
    type: "button",
    title: host ? "A PDF report of this host: its findings, evidence and remediation status" : "A PDF report of this project: summary, hosts, findings, evidence and remediation status",
  });
  const closed = el("input", "", "", { type: "checkbox" });
  const switchLabel = el("label", "report-switch note");
  switchLabel.append(closed, document.createTextNode(" Include fixed and accepted-risk findings"));
  const status = el("span", "note report-status", "", { role: "status", "aria-live": "polite" });
  box.append(button, switchLabel, status);

  const base = `/api/v1/projects/${encodeURIComponent(slug)}/reports`;
  const finish = (text = "") => {
    status.textContent = text;
    button.disabled = false;
    button.textContent = label;
  };
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "Working…";
    const started = Date.now();
    try {
      let state = await api("POST", base, { ...(host ? { host } : {}), include_closed: closed.checked });
      while (state.status === "queued" || state.status === "running") {
        status.textContent = WORDS[state.status];
        if (Date.now() - started > GIVE_UP_MS) throw new Error("The report is taking too long. Try a single host.");
        await new Promise((resolve) => setTimeout(resolve, POLL_MS));
        state = await api("GET", state.status_url);
      }
      if (state.status !== "done") throw new Error(state.error || "The report could not be made.");
      await save(state.download_url, `cvengine-report-${slug}${host ? `-${host}` : ""}.pdf`);
      const omitted = Object.values((state.summary || {}).omitted || {}).reduce((a, b) => a + b, 0);
      toast(omitted ? `Report downloaded. ${omitted} item${omitted === 1 ? "" : "s"} over the report limit are not listed.` : "Report downloaded");
      finish();
    } catch (err) {
      toast(err.message, true);
      finish(err.message);
    }
  });
  return box;
}
