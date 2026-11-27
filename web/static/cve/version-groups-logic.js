// Many CVEs, one fix: the CVE matches that rest on one product version reading of one host as one row (GET findings?group=product, and
// matches?group_by=product; cveFeed/version_groups.py on the server). Kept free of the DOM and of imports so that `node --test` can run it
// (tests/test_version_groups_logic.mjs); version-groups.js and app.js only draw what these return.
//
// A group is a Findings row whose `group.by` is "product": {product, version, host_names, hosts, cves, findings, heat, severity, triage
// {needs_validation, likely, confirmed, other}, fixed_in, fix_text, note, member_ids, members [{id, cve, host, heat, severity, status,
// classification, fixed}]}. Grouping is how the list is drawn: every member stays its own finding, with its own status, heat and history.

export const BY_PRODUCT = "product";
const HEAT_ORDER = { fire: 3, smoke: 2, ice: 1 };
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

export const isVersionGroup = (row) => Boolean(row && row.group && row.group.by === BY_PRODUCT && Array.isArray(row.group.member_ids) && row.group.member_ids.length > 1);

// "a", "a and b", "a, b and c"
export function joinNames(names) {
  const list = (names || []).filter(Boolean);
  if (list.length < 2) return list[0] || "";
  return `${list.slice(0, -1).join(", ")} and ${list[list.length - 1]}`;
}

// The collapsed row: "nginx 1.31.1: 18 CVEs (36 findings), upgrade to 1.31.9, on economicprinciples.org and www.economicprinciples.org".
// The fix is the server's words (only what the advisories state); without one the row says so rather than guess.
export function groupTitle(g) {
  const findings = g.findings !== g.cves ? ` (${plural(g.findings, "finding", "findings")})` : "";
  const fix = g.fix_text ? `, ${g.fix_text}` : ", no fixed version stated";
  const names = g.host_names || [];
  const more = g.hosts > names.length ? ` and ${g.hosts - names.length} more` : "";
  return `${g.product} ${g.version}: ${plural(g.cves, "CVE", "CVEs")}${findings}${fix}, on ${joinNames(names)}${more}`;
}

// The triage mix, largest first: "34 need validation · 2 confirmed · 4 likely". Empty when nothing is classified.
export function triageText(g) {
  const t = (g && g.triage) || {};
  const words = [["needs_validation", "need validation", "needs validation"], ["likely", "likely", "likely"], ["confirmed", "confirmed", "confirmed"], ["other", "other", "other"]];
  return words
    .filter(([k]) => t[k])
    .sort((a, b) => t[b[0]] - t[a[0]])
    .map(([k, one, many]) => `${t[k]} ${t[k] === 1 ? many : one}`)
    .join(" · ");
}

// The members for the expanded row: hottest, then most severe, then by CVE and host.
export const sortedMembers = (g) =>
  [...((g && g.members) || [])].sort(
    (a, b) =>
      (HEAT_ORDER[b.heat] || 0) - (HEAT_ORDER[a.heat] || 0) ||
      (SEVERITY_ORDER[b.severity] ?? -1) - (SEVERITY_ORDER[a.severity] ?? -1) ||
      String(a.cve).localeCompare(String(b.cve)) ||
      String(a.host).localeCompare(String(b.host)),
  );

// One member's line: "CVE-2026-1 on www.example.org · fixed in 1.31.9".
export const memberText = (m) => `${m.cve} on ${m.host}${m.fixed ? ` · fixed in ${m.fixed}` : ""}`;

// Where one member opens: its own finding on the CVE matches page.
export const memberHref = (project, id) => `/cve/${encodeURIComponent(project)}/matches/#${encodeURIComponent(String(id))}`;

// The rows of a grouped Findings answer that belong to one host (its name and the names the host page lists as its aliases): a group
// whose every name is one of them, or a single match on one of them. The host filter of the list is a substring, so a sibling such as
// stage.example.org comes back too and is left out here.
export function forHost(rows, names) {
  const mine = new Set((names || []).map((n) => String(n).toLowerCase()));
  const groups = [];
  const singles = [];
  (rows || []).forEach((r) => {
    if (r.type && r.type !== "cve") return;
    if (isVersionGroup(r)) {
      if ((r.group.host_names || []).every((n) => mine.has(String(n).toLowerCase()))) groups.push(r);
    } else if (mine.has(String(r.host || "").toLowerCase())) singles.push(r);
  });
  return { groups, singles };
}

// The line above the rows: "40 CVE matches in 3 rows: 2 groups by product and version, 1 on its own".
export function countLine(groups, singles) {
  const findings = groups.reduce((n, r) => n + (r.group.findings || 0), 0) + singles.length;
  const rows = groups.length + singles.length;
  const parts = [groups.length ? plural(groups.length, "group by product and version", "groups by product and version") : "", singles.length ? `${singles.length} on ${singles.length === 1 ? "its" : "their"} own` : ""].filter(Boolean);
  return `${plural(findings, "CVE match", "CVE matches")} in ${plural(rows, "row", "rows")}${parts.length ? `: ${parts.join(", ")}` : ""}`;
}
