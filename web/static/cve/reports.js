// Reporting: findings and hosts reports of a project or an organization, as a PDF or a CSV file. The scope picker reads GET /api/v1/reporting/scopes (what this
// person may report on), a report is queued, polled and downloaded by report-export.js (the server builds it from stored results only), and "Your recent
// reports" is GET /api/v1/reporting/reports. Every name from the server is set with textContent.
//
// The tabs are #findings, #hosts and #email (report-email.js: the weekly and monthly email reports of the selected scope).
import { api, couldNotRead, el, emptyState, tabs, toast, waiting } from "/staticfiles/cve/ui.js";
import { fmtDateTime } from "/staticfiles/cve/prefs.js";
import { downloadedMessage, reportFilename, runReport, save } from "/staticfiles/cve/report-export.js";
import { emailTab } from "/staticfiles/cve/report-email.js";
import { openHostExport } from "/staticfiles/cve/host-export.js";
import { includesNote, initialScope, pagePath, scopeOf, scopeOptions } from "/staticfiles/cve/reports-logic.js";

const root = document.getElementById("reports-root");
const want = { project: root.dataset.project || "", org: root.dataset.org || "", slug: root.dataset.slug || "" };

const FINDINGS_FORMATS = [
  ["pdf", "PDF report (summary, every finding with evidence and remediation)"],
  ["csv", "CSV spreadsheet (one row per finding)"],
];
const HOSTS_FORMATS = [
  ["pdf", "PDF report (summary, host table)"],
  ["csv", "CSV spreadsheet (heat, score, findings, technologies, owner)"],
  ["scope", "Scope list for a testing company (no findings)"],
];
const KIND_WORDS = { findings: "Findings", hosts: "Hosts" };
const STATUS_WORDS = { queued: "Queued", running: "Building", done: "Ready", failed: "Failed", expired: "Expired" };

let scopes = [];
let meta = { me_email: "", limits: { attach_max_mb: 10 } };
let selected = "";
let tabApi = null;
let currentTab = "findings";
let renderRecent = () => {};

const current = () => scopeOf(scopes, selected);

function radios(name, options, value) {
  const group = el("fieldset", "plan-choices");
  group.append(el("legend", "note", "Format"));
  const inputs = options.map(([v, text]) => {
    const input = el("input", "", null, { type: "radio", name, value: v, id: `${name}-${v}` });
    input.checked = v === value;
    const row = el("label", "plan-opt", null, { for: `${name}-${v}` });
    row.append(input, el("span", "", text));
    group.append(row);
    return input;
  });
  return { group, inputs, value: () => (inputs.find((i) => i.checked) || {}).value };
}

function scopePicker() {
  const card = el("div", "card reports-scope");
  const label = el("label", "eyebrow", "Report on", { for: "reports-scope" });
  const select = el("select", "", null, { id: "reports-scope" });
  scopeOptions(scopes).forEach((g) => {
    const group = el("optgroup", "", null, { label: g.name });
    g.options.forEach((o) => group.append(Object.assign(el("option", "", o.label), { value: o.value })));
    select.append(group);
  });
  select.value = selected;
  const note = el("p", "note reports-includes");
  const paint = () => {
    const scope = current();
    const names = !scope ? [] : scope.kind === "project" ? [scope.name] : scopes.filter((s) => s.kind === "project" && s.org === scope.slug).map((s) => s.name);
    note.textContent = scope && scope.kind === "org" ? includesNote(names) : "";
    note.hidden = !note.textContent;
  };
  select.addEventListener("change", () => {
    selected = select.value;
    paint();
    history.replaceState(null, "", `${location.pathname}${pagePath(current(), currentTab)}`);
    if (tabApi) tabApi.open(currentTab);
  });
  paint();
  card.append(label, select, note);
  return card;
}

function reportRequest(scope, kind, format, includeClosed) {
  return { ...(scope.kind === "org" ? { org: scope.slug } : { slug: scope.slug }), kind, format, includeClosed };
}

// The Generate button of a tab: queues the report, shows the waiting words, saves the file, then refreshes the list of recent reports.
function generator(readChoice) {
  const box = el("div", "report-generate");
  const go = el("button", "btn", "Generate", { type: "button" });
  const status = el("span", "note report-status", "", { role: "status", "aria-live": "polite" });
  go.addEventListener("click", async () => {
    const scope = current();
    const choice = readChoice();
    if (!scope || !choice) return;
    if (choice.format === "scope") {
      openHostExport(scope.kind === "org" ? { slug: "", all: true } : { slug: scope.slug });
      return;
    }
    go.disabled = true;
    go.textContent = "Working…";
    status.textContent = "";
    try {
      const state = await runReport(reportRequest(scope, choice.kind, choice.format, choice.includeClosed), (text) => { status.textContent = text; });
      toast(downloadedMessage(state));
      status.textContent = "";
    } catch (err) {
      toast(err.message, true);
      status.textContent = err.message;
    }
    go.disabled = false;
    go.textContent = "Generate";
    renderRecent();
  });
  box.append(go, status);
  return box;
}

function findingsTab(panel) {
  const card = el("div", "card report-card");
  card.append(el("h2", "", "Findings report"), el("p", "note", "Open findings by default: CVE matches, scanner findings and hygiene, hottest first, with evidence, remediation and status."));
  const format = radios("findings-format", FINDINGS_FORMATS, "pdf");
  const closed = el("input", "", null, { type: "checkbox", id: "findings-closed" });
  const closedRow = el("label", "plan-opt", null, { for: "findings-closed" });
  closedRow.append(closed, el("span", "", "Include closed findings (fixed, accepted risk, false positive)"));
  card.append(format.group, closedRow, generator(() => ({ kind: "findings", format: format.value(), includeClosed: closed.checked })));
  panel.append(card, recentList());
}

function hostsTab(panel) {
  const card = el("div", "card report-card");
  card.append(el("h2", "", "Hosts report"), el("p", "note", "Every discovered host in the current inventory: heat, score, open findings, technologies, open ports and owner."));
  const format = radios("hosts-format", HOSTS_FORMATS, "pdf");
  card.append(format.group, generator(() => ({ kind: "hosts", format: format.value(), includeClosed: false })));
  panel.append(card, recentList());
}

function whenOf(iso) {
  return fmtDateTime(iso) || String(iso || "").slice(0, 16).replace("T", " ");
}

function recentList() {
  const box = el("div", "card report-recent");
  box.append(el("h2", "", "Your recent reports"));
  const list = el("div", "report-recent-list");
  box.append(list);
  async function draw() {
    list.textContent = "";
    list.append(waiting("Reading your reports"));
    try {
      const data = await api("GET", "/api/v1/reporting/reports");
      list.textContent = "";
      const rows = data.results || [];
      if (!rows.length) {
        list.append(el("p", "note", "No reports yet. A report is kept for 24 hours."));
        return;
      }
      rows.forEach((r) => list.append(recentRow(r)));
    } catch (err) {
      list.textContent = "";
      list.append(couldNotRead("Your recent reports", draw, err.message));
    }
  }
  renderRecent = draw;
  draw();
  return box;
}

function recentRow(r) {
  const row = el("div", "report-row");
  const what = el("div", "report-what");
  what.append(el("b", "", `${KIND_WORDS[r.kind] || r.kind} report, ${String(r.format).toUpperCase()}`), el("span", "note", `${r.scope.name} · ${whenOf(r.created)}`));
  const state = el("span", `badge ${r.status === "failed" ? "failed" : r.status === "done" ? "" : "running"}`.trim(), STATUS_WORDS[r.status] || r.status);
  row.append(what, state);
  if (r.status === "failed" && r.error) row.append(el("span", "note report-error", r.error));
  if (r.download_url) {
    const get = el("button", "btn ghost sm", "Download", { type: "button" });
    get.addEventListener("click", async () => {
      get.disabled = true;
      try {
        await save(r.download_url, reportFilename({ slug: r.scope.slug, org: r.scope.kind === "org" ? r.scope.slug : "", kind: r.kind, format: r.format, host: r.host || "" }));
      } catch (err) {
        toast(err.message, true);
      }
      get.disabled = false;
    });
    row.append(get);
  }
  return row;
}

async function start() {
  root.textContent = "";
  root.append(waiting("Reading what you can report on"));
  try {
    const data = await api("GET", "/api/v1/reporting/scopes");
    scopes = data.scopes || [];
    meta = { me_email: data.me_email || "", limits: data.limits || meta.limits };
  } catch (err) {
    root.textContent = "";
    root.append(couldNotRead("The reporting scopes", start, err.message));
    return;
  }
  root.textContent = "";
  selected = initialScope(scopes, want);
  if (!selected) {
    root.append(emptyState({ icon: "report", title: "Nothing to report on yet", body: "Reports cover the projects and organizations you can read. Add a target to a project first.", actions: [{ label: "Go to Overview", href: "/cve/" }] }));
    return;
  }
  root.append(scopePicker());
  const tabRoot = el("div", "reports-tabs");
  root.append(tabRoot);
  const TABS = {
    findings: { label: "Findings report", open: async (panel) => { currentTab = "findings"; findingsTab(panel); } },
    hosts: { label: "Hosts report", open: async (panel) => { currentTab = "hosts"; hostsTab(panel); } },
    email: {
      label: "Email reports",
      open: async (panel) => {
        currentTab = "email";
        await emailTab(panel, { scopes, scope: current(), me_email: meta.me_email, limits: meta.limits, isAppAdmin: root.dataset.superuser === "1" });
      },
    },
  };
  tabApi = tabs(tabRoot, TABS, "findings");
  history.replaceState(null, "", `${location.pathname}${pagePath(current(), currentTab)}`);
}

start();
