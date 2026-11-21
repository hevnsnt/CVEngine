// One-click report (PDF or CSV, of a project or an organization). The server builds it in the background; this asks, polls, then downloads it through the authenticated API
// route (the file is private to the person who asked and expires after 24 hours). Nothing is built in the browser.
import { api, el, toast } from "/staticfiles/cve/ui.js";

const POLL_MS = 2000;
const GIVE_UP_MS = 20 * 60 * 1000;
const WORDS = { queued: "Queued…", running: "Building the report…" };

export async function save(url, filename) {
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

const FILE_TYPES = { pdf: "PDF", csv: "CSV" };

/** The name of the saved file: what the report is about, its kind and its format. */
export function reportFilename({ slug = "", org = "", kind = "findings", format = "pdf", host = "" }) {
  const what = host ? `-${host}` : kind === "hosts" ? "-hosts" : "";
  return `cvengine-report-${org || slug}${what}.${format}`;
}

/**
 * Ask for a report of a project (``slug``) or an organization (``org``), wait for it, and save it. ``kind`` is "findings" or "hosts", ``format`` "pdf" or "csv".
 * ``onStatus(text)`` hears the waiting words. Resolves with the finished report's state; rejects with the server's message.
 */
export async function runReport({ slug = "", org = "", kind = "findings", format = "pdf", host = "", includeClosed = false }, onStatus = () => {}) {
  const base = org ? `/api/v1/orgs/${encodeURIComponent(org)}/reports` : `/api/v1/projects/${encodeURIComponent(slug)}/reports`;
  const started = Date.now();
  let state = await api("POST", base, { ...(host ? { host } : {}), include_closed: includeClosed, kind, format });
  while (state.status === "queued" || state.status === "running") {
    onStatus(WORDS[state.status]);
    if (Date.now() - started > GIVE_UP_MS) throw new Error(host ? "The report is taking too long." : "The report is taking too long. Try a single host.");
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    state = await api("GET", state.status_url);
  }
  if (state.status !== "done") throw new Error(state.error || "The report could not be made.");
  await save(state.download_url, reportFilename({ slug, org, kind, format, host }));
  return state;
}

/** The toast after a download: how many items the report limits left out, if any. */
export function downloadedMessage(state) {
  const omitted = Object.values((state.summary || {}).omitted || {}).reduce((a, b) => a + b, 0);
  return omitted ? `Report downloaded. ${omitted} item${omitted === 1 ? "" : "s"} over the report limit are not listed.` : "Report downloaded";
}

/**
 * A "Download PDF report" button with a switch for closed findings (fixed, accepted risk, false positive).
 * @param {{slug?: string, org?: string, kind?: string, format?: string, host?: string, label?: string}} options host: an exact host name for a one-host report;
 *   org: an organization instead of a project; kind: "findings" or "hosts"; format: "pdf" or "csv"
 */
export function reportButton({ slug = "", org = "", kind = "findings", format = "pdf", host = "", label = `Download ${FILE_TYPES[format] || "PDF"} report` }) {
  const box = el("span", "report-export");
  const button = el("button", "btn ghost sm", label, {
    type: "button",
    title: host ? "A PDF report of this host: its findings, evidence and remediation status" : "A PDF report of this project: summary, hosts, findings, evidence and remediation status",
  });
  const closed = el("input", "", "", { type: "checkbox" });
  const switchLabel = el("label", "report-switch note");
  switchLabel.append(closed, document.createTextNode(" Include closed findings (fixed, accepted risk, false positive)"));
  const status = el("span", "note report-status", "", { role: "status", "aria-live": "polite" });
  box.append(button, switchLabel, status);

  const finish = (text = "") => {
    status.textContent = text;
    button.disabled = false;
    button.textContent = label;
  };
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "Working…";
    try {
      const state = await runReport({ slug, org, kind, format, host, includeClosed: closed.checked }, (text) => { status.textContent = text; });
      toast(downloadedMessage(state));
      finish();
    } catch (err) {
      toast(err.message, true);
      finish(err.message);
    }
  });
  return box;
}
