// Findings page: the same script on sibling hosts is one row (GET findings?group=cve, cveFeed/finding_groups.py on the server). Kept free
// of the DOM and of imports so that `node --test` can run it (tests/test_finding_groups_logic.mjs); app.js only draws what these return.
//
// A group row is its hottest member's ordinary row plus `group` {id, hosts, findings, member_ids, members[{id, host, heat, status,
// remediation_status, classification, validation_status}], members_truncated, heat_counts, status_counts, ...}. Grouping is only how the
// list is drawn: every host keeps its own finding, status and audit, so an action on a group is the same action on each member, sent through
// the ordinary per-finding route (POST findings/status), and its result is read back per member.

export const GROUPED = "cve"; // the server's group mode the page asks for by default
export const EVERY_HOST = "none"; // "Show every host": one row per host, as before
export const STATUS_VALUES = ["open", "in_progress", "fixed", "accepted_risk"];
const HEAT_ORDER = { fire: 3, smoke: 2, ice: 1 };
const STATUS_WORD = { open: "open", in_progress: "in progress", fixed: "fixed", accepted_risk: "accepted risk", "ruled out": "ruled out" };

export const isGroup = (item) => Boolean(item && item.group && Array.isArray(item.group.member_ids) && item.group.member_ids.length > 1);

// The list request's parameters: the page's filters plus the group mode (left out when showing every host, the server's default).
export const listParams = (filters, mode) => (mode === EVERY_HOST ? { ...filters } : { ...filters, group: GROUPED });

// The chips' numbers: rows when grouped (what the list shows), findings otherwise.
export const chipCounts = (r) => ({ all: r.total || 0, ...((r && (r.row_counts || r.counts)) || {}) });

// "on 6 hosts" and the split of their own statuses, worst first: "4 open · 1 in progress · 1 fixed".
export function statusSplit(group) {
  const counts = (group && group.status_counts) || {};
  const order = ["open", "in_progress", "ruled out", "fixed", "accepted_risk"];
  const keys = Object.keys(counts).sort((a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99));
  return keys.map((k) => `${counts[k]} ${STATUS_WORD[k] || String(k).replace(/_/g, " ")}`).join(" · ");
}
export const hostsText = (group) => `on ${group.hosts} host${group.hosts === 1 ? "" : "s"}`;

// The split of heat across members when they differ ("2 fire · 4 ice"); empty when every member is as hot as the row.
export function heatSplit(group) {
  const counts = (group && group.heat_counts) || {};
  const keys = Object.keys(counts).filter((k) => counts[k]);
  if (keys.length < 2) return "";
  return keys.sort((a, b) => (HEAT_ORDER[b] || 0) - (HEAT_ORDER[a] || 0)).map((k) => `${counts[k]} ${k || "no heat"}`).join(" · ");
}

// The members for the expanded row, hottest first, then by host name.
export const sortedMembers = (group) =>
  [...((group && group.members) || [])].sort((a, b) => (HEAT_ORDER[b.heat] || 0) - (HEAT_ORDER[a.heat] || 0) || String(a.host).localeCompare(String(b.host)));

// The hash that opens one member on the Findings page (#match-12, or #project:match-12 in the all-projects view).
export const memberHash = (member, project, all) => `${all ? `${project}:` : ""}match-${member.id}`;

// A plain finding item for one member, as setStatusBatch sends it: kind, id, project and enough to name it in a failure report.
function memberItem(row, id, member) {
  return {
    kind: "match",
    id,
    project: row.project,
    title: row.title,
    host: member ? member.host : undefined,
    status: member ? member.remediation_status || member.status : undefined,
    __groupOf: row.group.id,
  };
}

// Every member of the selected items as its own finding item: a group becomes its members, anything else stays as it is.
export function expandForBulk(items) {
  const out = [];
  items.forEach((item) => {
    if (!isGroup(item)) {
      out.push(item);
      return;
    }
    const known = new Map((item.group.members || []).map((m) => [m.id, m]));
    item.group.member_ids.forEach((id) => out.push(memberItem(item, id, known.get(id))));
  });
  return out;
}

// The members' results read back onto the selected rows. A group succeeded when every member did; otherwise it is reported failed with
// only the members that failed left in it, so "Try the failed again" touches only those.
export function foldResults(items, result, keyOf) {
  const failedByKey = new Map(result.failed.map((f) => [keyOf(f.item), f]));
  const okKeys = new Set(result.ok.map(keyOf));
  const ok = [];
  const failed = [];
  items.forEach((item) => {
    if (!isGroup(item)) {
      const f = failedByKey.get(keyOf(item));
      if (f) failed.push(f);
      else if (okKeys.has(keyOf(item))) ok.push(item);
      return;
    }
    const bad = item.group.member_ids.map((id) => failedByKey.get(keyOf({ kind: "match", id }))).filter(Boolean);
    if (!bad.length) {
      ok.push(item);
      return;
    }
    const badIds = bad.map((f) => f.item.id);
    // one member left is that member's own finding, not a group of one (a group needs two); it keeps the row's selection key
    const narrowed =
      badIds.length === 1
        ? { ...bad[0].item }
        : { ...item, group: { ...item.group, member_ids: badIds, members: (item.group.members || []).filter((m) => badIds.includes(m.id)) } };
    if (item.__bulkKey !== undefined) narrowed.__bulkKey = item.__bulkKey;
    const n = item.group.member_ids.length;
    failed.push({ item: narrowed, error: `${bad.length} of ${n} hosts not updated: ${bad[0].error}` });
  });
  return { ok, failed };
}

// What Undo puts back. A row: its own earlier status. A group: each member's own earlier status, known only when every member is listed
// (a group of more than the server lists in full has no Undo: guessing would overwrite a status someone set on one host).
export function priorOf(item) {
  if (!isGroup(item)) {
    const was = item.status ?? item.remediation_status;
    return STATUS_VALUES.includes(was) ? was : undefined;
  }
  const g = item.group;
  if (g.members_truncated || !g.members || g.members.length !== g.member_ids.length) return undefined;
  const byMember = {};
  for (const m of g.members) {
    const was = m.remediation_status || m.status;
    if (!STATUS_VALUES.includes(was)) return undefined;
    byMember[m.id] = was;
  }
  return { byMember };
}

// Undo as [status, items] batches: each member back to its own earlier status.
export function restoreBatches(items, prior) {
  const by = new Map();
  const add = (was, item) => by.set(was, [...(by.get(was) || []), item]);
  items.forEach((item) => {
    const was = prior(item);
    if (was === undefined) return;
    if (typeof was === "string") add(was, item);
    else expandForBulk([item]).forEach((m) => was.byMember[m.id] && add(was.byMember[m.id], m));
  });
  return [...by.entries()];
}

// The line above the list: what the counts mean in each mode.
export function headerParts(r) {
  const counts = r.counts || {};
  const findings = r.findings_total ?? r.total ?? 0;
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  if (r.group !== GROUPED) return { lead: `${plural(findings, "finding", "findings")}: `, counts, grouped: "" };
  const rows = r.total || 0;
  const grouped = r.groups
    ? `${plural(r.grouped_findings || 0, "CVE match", "CVE matches")} on sibling hosts shown as ${plural(r.groups, "row", "rows")} (the same script on one site)`
    : "";
  return { lead: `${plural(findings, "finding", "findings")} in ${plural(rows, "row", "rows")}: `, counts, grouped };
}
