// The Reporting page's decisions, with no DOM so they are tested on their own (web/tests/test_reports_logic.mjs): which scopes the picker offers and
// which is selected first, the routes of a report, what a recipient list holds, and the words for an email report's schedule and last result.
// The page is static/cve/reports.js; the server decides what each person may read, this only lays out what it said.

export const MAX_RECIPIENTS = 10;
const EMAIL = /^[^@\s<>",;:()[\]\\]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z0-9-]{2,63}$/;
const WEEKDAYS = ["Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays", "Sundays"];
const NO_ORG = "No organization";

const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** The value a picker option carries for a scope: ``org:acme`` or ``project:acme-web``. */
export const scopeValue = (scope) => `${scope.kind}:${scope.slug}`;

/**
 * The picker's groups, one per organization (named after it), from ``GET /api/v1/reporting/scopes``. The first option of a group is the whole
 * organization ("N of your projects in <Org>" when the person reads only some of them); then one option per project. Projects with no organization go
 * last, under "No organization".
 * @returns {Array<{name: string, org: string, options: Array<{value: string, label: string, kind: string, slug: string, name: string}>}>}
 */
export function scopeOptions(scopes) {
  const list = scopes || [];
  const groups = [];
  const byOrg = new Map();
  list.filter((s) => s.kind === "org").forEach((o) => {
    const label = o.whole === false ? `${o.projects} of your projects in ${o.name}` : `Whole organization (${plural(o.projects, "project")})`;
    const group = { name: o.name, org: o.slug, options: [{ value: scopeValue(o), label, kind: "org", slug: o.slug, name: o.name }] };
    byOrg.set(o.slug, group);
    groups.push(group);
  });
  const loose = { name: NO_ORG, org: "", options: [] };
  list.filter((s) => s.kind === "project").forEach((p) => {
    let group = p.org ? byOrg.get(p.org) : loose;
    if (!group) {  // a project whose organization the list does not offer (it cannot be reported on as a whole): its own group
      group = { name: p.org_name || p.org, org: p.org, options: [] };
      byOrg.set(p.org, group);
      groups.push(group);
    }
    group.options.push({ value: scopeValue(p), label: p.name, kind: "project", slug: p.slug, name: p.name });
  });
  if (loose.options.length) groups.push(loose);
  return groups;
}

/**
 * The scope selected when the page opens: ``?project=`` or ``?org=`` from the address, else the shell's current project, else the organization the
 * All projects view is narrowed to, else the first option. Only a scope the picker offers can be chosen.
 * @param {Array} scopes  the scopes of the API
 * @param {{project?: string, org?: string, slug?: string}} want
 * @returns {string} an option value, or "" when there is nothing to report on
 */
export function initialScope(scopes, { project = "", org = "", slug = "" } = {}) {
  const has = (kind, name) => name && (scopes || []).some((s) => s.kind === kind && s.slug === name);
  if (has("project", project)) return `project:${project}`;
  if (has("org", org)) return `org:${org}`;
  if (has("project", slug)) return `project:${slug}`;
  const first = scopeOptions(scopes)[0];
  return first ? first.options[0].value : "";
}

/** The scope behind an option value, or null. */
export function scopeOf(scopes, value) {
  const [kind, ...rest] = String(value || "").split(":");
  const slug = rest.join(":");
  return (scopes || []).find((s) => s.kind === kind && s.slug === slug) || null;
}

/** The address of a page for a scope, so a link can be shared: ``?project=acme-web`` or ``?org=acme``, and the tab as the hash. */
export function pagePath(scope, tab = "") {
  if (!scope) return "";
  const query = scope.kind === "org" ? `org=${encodeURIComponent(scope.slug)}` : `project=${encodeURIComponent(scope.slug)}`;
  return `?${query}${tab ? `#${tab}` : ""}`;
}

/** The report routes of a scope (``reportButton`` builds the same ones). */
export function reportPath({ slug = "", org = "" }) {
  return org ? `/api/v1/orgs/${encodeURIComponent(org)}/reports` : `/api/v1/projects/${encodeURIComponent(slug)}/reports`;
}

/** "Includes: a, b, c and 2 more" for the projects a scope reads, clipped to five names. */
export function includesNote(names, shown = 5) {
  const list = (names || []).filter(Boolean);
  if (!list.length) return "";
  if (list.length <= shown) return `Includes: ${list.join(", ")}`;
  return `Includes: ${list.slice(0, shown).join(", ")} and ${list.length - shown} more`;
}

/**
 * What a recipient list holds. Separators are a comma, a semicolon or any whitespace. Addresses are lower-cased; ``valid`` keeps the first of each (up to
 * ``max``), ``invalid`` is what is not an address, ``duplicates`` the repeats, ``over`` the valid ones past the cap.
 */
export function parseRecipients(text, max = MAX_RECIPIENTS) {
  const out = { valid: [], invalid: [], duplicates: [], over: [] };
  const seen = new Set();
  String(text || "").split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean).forEach((raw) => {
    const email = raw.toLowerCase();
    if (!EMAIL.test(email)) out.invalid.push(raw);
    else if (seen.has(email)) out.duplicates.push(email);
    else {
      seen.add(email);
      (out.valid.length < max ? out.valid : out.over).push(email);
    }
  });
  return out;
}

const pad = (n) => String(n).padStart(2, "0");

/** "Weekly, Mondays 08:00 (Europe/London)": the same words as ``cveFeed.report_schedule.summary``. */
export function scheduleSummary(sub) {
  const time = String(sub.send_time || "").slice(0, 5);
  const zone = sub.timezone || "UTC";
  if (sub.cadence === "monthly") return `Monthly, day ${sub.day_of_month} at ${time} (${zone})`;
  return `Weekly, ${WEEKDAYS[Number(sub.weekday) || 0]} ${time} (${zone})`;
}

/** "in 2 days", "in 3 hours", "in 12 minutes", "now" or "overdue": how far ``iso`` is from ``now``. */
export function relativeText(iso, now = new Date()) {
  const ms = new Date(iso).getTime() - now.getTime();
  if (Number.isNaN(ms)) return "";
  const minutes = Math.round(Math.abs(ms) / 60000);
  const unit = minutes >= 2880 ? plural(Math.round(minutes / 1440), "day") : minutes >= 120 ? plural(Math.round(minutes / 60), "hour") : plural(minutes, "minute");
  if (minutes < 1) return "now";
  return ms > 0 ? `in ${unit}` : `${unit} ago`;
}

/** "Nov 24, 08:00 (in 2 days)" for a next send time, or "Not scheduled" when there is none. */
export function nextSendText(iso, now = new Date(), format = (d) => `${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })}, ${pad(d.getHours())}:${pad(d.getMinutes())}`) {
  if (!iso) return "Not scheduled";
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return "Not scheduled";
  return `${format(when)} (${relativeText(iso, now)})`;
}

/** One line for an email report's last result: sent, partly failed ("1 of 3 failed: the mail server refused the recipient address"), skipped or never sent. */
export function lastResultText(sub, format = (iso) => iso.slice(0, 16).replace("T", " ")) {
  const status = sub.last_status || "";
  const error = sub.last_error ? `: ${sub.last_error}` : "";
  if (!status) return "Never sent";
  const when = sub.last_sent_at ? format(sub.last_sent_at) : "";
  if (status === "sent") return `Sent ${when} to ${plural((sub.recipients || []).length, "recipient")}`.replace("  ", " ");
  if (status === "partial") return sub.last_error || "Some recipients failed";  // the server writes "1 of 3 failed: <why>"
  if (status === "skipped") return `Skipped${error}`;
  if (status === "disabled") return `Paused automatically${error}`;
  if (status === "unknown") return `Interrupted while sending${error}`;
  return `Failed${error}`;
}

/** "a@x.org, b@x.org +3": the first two recipients, then how many more. */
export function recipientsText(recipients, shown = 2) {
  const list = recipients || [];
  return list.slice(0, shown).join(", ") + (list.length > shown ? ` +${list.length - shown}` : "");
}

/** "PDF attached", "CSV attached" or "No attachment". */
export function attachText(attach) {
  return attach === "pdf" ? "PDF attached" : attach === "csv" ? "CSV attached" : "No attachment";
}

/** The status pill of an email report: ``[label, tone]`` (tone is a badge class: "" for active, "running" for paused, "failed" for paused automatically). */
export function statusPill(sub) {
  if (sub.enabled) return ["Active", ""];
  if (sub.last_status === "disabled") return ["Paused automatically", "failed"];
  return ["Paused", "running"];
}

/** ``url`` when it is an http or https address (a link the server built, shown as a link), else "": never a script or data address. */
export function safeLink(url) {
  return /^https?:\/\/[^\s]+$/i.test(String(url || "")) ? String(url) : "";
}

/** The class of an impact sentence in the threats card: "bad" when hosts match, "warn" when only the product runs, else "" . */
export function impactTone(impact) {
  return impact === "matched" ? "bad" : impact === "product" ? "warn" : "";
}

/** The name a new email report starts with: "Weekly report: <scope>", "Monthly report: <scope>". */
export function defaultName(cadence, scopeName) {
  return `${cadence === "monthly" ? "Monthly" : "Weekly"} report: ${scopeName}`;
}

/** The field a server message is about, so it can be shown beside it ("name", "recipients", "timezone", "send_time", else ""). */
export function fieldOfError(message) {
  const m = String(message || "").toLowerCase();
  if (/recipient|email address|unsubscribed/.test(m)) return "recipients";
  for (const key of ["timezone", "send_time", "day_of_month", "weekday", "name", "attach"]) if (m.includes(key)) return key;
  return "";
}
