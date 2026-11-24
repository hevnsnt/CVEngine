// "Export all hosts" and "Export host": the choices, the address of the download and the words around it. No DOM here, so it is tested on its own
// (web/tests/test_host_export_logic.mjs). The files are made by the server (agentapi/host_export.py for every host, agentapi/host_export_one.py for one).

export const FORMATS = [
  ["csv", "Spreadsheet (CSV)"],
  ["txt", "Plain list for tools (one host or address per line)"],
];

export const SCOPES = [
  ["external", "Internet-facing only"],
  ["all", "Include internal hosts"],
];

export const DEFAULTS = { format: "csv", scope: "external", archived: false };

// What every export holds, said once: the dialog and the docs agree.
export const CONTAINS =
  "Host names, IP addresses, open ports and services, web URLs, project and target, first and last seen. No findings, notes, owners or scores are included, so the file can go to a testing company as it is.";

/** The route of the download: a project's, or an organization's. */
export function exportPath({ slug = "", org = "" }) {
  if (org) return `/api/v1/orgs/${encodeURIComponent(org)}/hosts/export`;
  return `/api/v1/projects/${encodeURIComponent(slug)}/hosts/export`;
}

/** The query string of one choice. Unknown values fall back to the safe default (internet-facing only, no archived hosts, CSV). */
export function exportQuery({ format = DEFAULTS.format, scope = DEFAULTS.scope, archived = DEFAULTS.archived } = {}) {
  const f = FORMATS.some(([v]) => v === format) ? format : DEFAULTS.format;
  const s = SCOPES.some(([v]) => v === scope) ? scope : DEFAULTS.scope;
  return new URLSearchParams({ format: f, scope: s, archived: archived ? "1" : "0" }).toString();
}

/** The organizations of a list of projects (``GET /api/v1/projects``): the ones the person can see, by name, each with its number of projects. */
export function organizationsOf(projects) {
  const seen = new Map();
  (projects || []).forEach((p) => {
    if (!p || !p.org) return;
    const row = seen.get(p.org) || { slug: p.org, name: p.org_name || p.org, projects: 0 };
    row.projects += 1;
    seen.set(p.org, row);
  });
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
}

/** The file name the server chose (Content-Disposition), or ``fallback``. */
export function filenameFrom(disposition, fallback) {
  const m = /filename="?([^";]+)"?/i.exec(disposition || "");
  return m && /^[\w.-]+$/.test(m[1]) ? m[1] : fallback;
}

const plural = (n, one, many) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/** The toast after a download: how many hosts the file holds (and, for the plain list, how many lines). */
export function doneMessage({ hosts, entries, format }) {
  if (!Number.isFinite(hosts)) return "Exported the host list";
  if (hosts === 0) return "Exported an empty list: no host matches these choices";
  const base = `Exported ${plural(hosts, "host", "hosts")}`;
  return format === "txt" && Number.isFinite(entries) ? `${base} (${plural(entries, "name or address", "names and addresses")})` : base;
}

/** The counts the server sends in headers, as numbers (NaN when a proxy removed them). */
export function countsFrom(headers) {
  const num = (name) => {
    const v = headers && typeof headers.get === "function" ? headers.get(name) : null;
    return v == null || v === "" ? NaN : Number(v);
  };
  return { hosts: num("X-Export-Hosts"), entries: num("X-Export-Entries") };
}

/** Whether the dialog may start: an organization export needs one chosen. */
export function canExport({ all, org }) {
  return !all || Boolean(org);
}

// One host: the Hosts page has a host selected when the address ends in its id (#40413). The page-head button follows: "Export host" then,
// "Export all hosts" on the list itself.

/** The host id the address selects (``#40413``, or ``#40413&...``), or null on the list itself. */
export function hostIdFromHash(hash) {
  const m = /^#?(\d+)(?:&|$)/.exec(String(hash || ""));
  const id = m ? Number(m[1]) : NaN;
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

/** The page-head button's words: one host when one is selected, every host otherwise. */
export function buttonLabel(hostId) {
  return hostId ? "Export host" : "Export all hosts";
}

export function buttonTitle(hostId) {
  return hostId
    ? "Download everything known about this host as a ZIP file: the record, findings, services, history, certificates, inventory and screenshots"
    : "Download every discovered host as a file to hand to a penetration testing company (no findings or notes in it)";
}

/** The route of one host's ZIP. */
export function hostExportPath({ slug, id }) {
  return `/api/v1/projects/${encodeURIComponent(slug)}/hosts/${encodeURIComponent(id)}/export`;
}

// What the one-host file holds, said once: the dialog lists it and the docs agree.
export const HOST_CONTAINS = [
  "host.json: the complete record (names, addresses, hosting, state, labels, heat and score with the reasons)",
  "Services and ports with versions, banners and service features",
  "Web data: routes, title, headers, technologies with versions and sources, certificates",
  "Every finding (CVE matches with their explanation and triage, scanner and hygiene findings) with status, assignment, retest and comments",
  "Exposed secrets as masked values only",
  "The full change history, the host's inventory report, probes and check coverage, the scans that saw it",
  "Screenshots as image files, and CSV files of the findings, services, history, certificates and inventory",
];

export const HOST_NOTE = "No secret value, token or password is in the file: secrets appear masked. Each export is written to the audit log.";

/** The counts the server sends with one host's ZIP. */
export function hostCountsFrom(headers) {
  const num = (name) => {
    const v = headers && typeof headers.get === "function" ? headers.get(name) : null;
    return v == null || v === "" ? NaN : Number(v);
  };
  return { findings: num("X-Export-Findings"), screenshots: num("X-Export-Screenshots") };
}

/** The toast after one host's download. */
export function hostDoneMessage({ name, findings, screenshots }) {
  const who = name ? `Exported ${name}` : "Exported the host";
  if (!Number.isFinite(findings)) return who;
  const shots = Number.isFinite(screenshots) ? `, ${plural(screenshots, "screenshot", "screenshots")}` : "";
  return `${who} (${plural(findings, "finding", "findings")}${shots})`;
}
