// "Export all hosts": the choices, the address of the download and the words around it. No DOM here, so it is tested on its own
// (web/tests/test_host_export_logic.mjs). The file itself is made by the server (agentapi/host_export.py).

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
