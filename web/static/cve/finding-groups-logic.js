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

// A member's own remediation status (open, in_progress, fixed, accepted_risk), from the full map the server sends with every group.
const statusOfMember = (group, id) => (group.member_status && group.member_status[String(id)]) || ((group.members || []).find((m) => m.id === id) || {}).remediation_status;
const ruledOut = (group, id) => (group.ruled_out_ids || []).includes(id);
// Fixed or accepted-risk (or ruled out by the AI): someone already settled it. An action on a group leaves these alone unless the person
// explicitly includes them.
export const CLOSED = ["fixed", "accepted_risk"];
const isClosedMember = (group, id) => CLOSED.includes(statusOfMember(group, id)) || ruledOut(group, id);

// Which members of a group an action to `value` changes: only those whose status it actually changes, and by default only the open and
// in progress ones. {ids, closed (settled members left as they are), same (already at value)}. Without a value (a plain expansion) every
// member is a target.
export function targetsOf(group, value, { includeClosed = false } = {}) {
  const ids = [];
  let closed = 0;
  let same = 0;
  group.member_ids.forEach((id) => {
    if (value !== undefined && statusOfMember(group, id) === value && !ruledOut(group, id)) same += 1;
    else if (!includeClosed && isClosedMember(group, id)) closed += 1;
    else ids.push(id);
  });
  return { ids, closed, same };
}
export const closedCount = (group) => group.member_ids.filter((id) => isClosedMember(group, id)).length;

// A plain finding item for one member, as setStatusBatch sends it: kind, id, project and enough to name it in a failure report.
function memberItem(row, id) {
  const member = (row.group.members || []).find((m) => m.id === id);
  return {
    kind: "match",
    id,
    project: row.project,
    title: row.title,
    host: member ? member.host : undefined,
    status: statusOfMember(row.group, id),
    __groupOf: row.group.id,
  };
}

// The findings an action sends: a group becomes the members the action applies to (targetsOf), anything else stays as it is. Without a
// value every member is sent (the members a retry or an Undo names are already narrowed).
export function expandForBulk(items, value, opts = {}) {
  const out = [];
  items.forEach((item) => {
    if (!isGroup(item)) {
      out.push(item);
      return;
    }
    const ids = value === undefined ? item.group.member_ids : targetsOf(item.group, value, opts).ids;
    ids.forEach((id) => out.push(memberItem(item, id)));
  });
  return out;
}

// The members' results read back onto the selected rows. A group succeeded when every member it sent did (`__changedIds` names them, for
// Undo; a group with nothing to change succeeds with none); otherwise it is reported failed with only the members that failed left in it,
// so "Try the failed again" touches only those.
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
    const memberKey = (id) => keyOf({ kind: "match", id });
    const bad = item.group.member_ids.map((id) => failedByKey.get(memberKey(id))).filter(Boolean);
    const changed = item.group.member_ids.filter((id) => okKeys.has(memberKey(id)));
    if (!bad.length) {
      ok.push({ ...item, __changedIds: changed });
      return;
    }
    const badIds = bad.map((f) => f.item.id);
    // one member left is that member's own finding, not a group of one (a group needs two); it keeps the row's selection key
    const narrowed =
      badIds.length === 1
        ? { ...bad[0].item }
        : { ...item, group: { ...item.group, member_ids: badIds, members: (item.group.members || []).filter((m) => badIds.includes(m.id)) } };
    if (item.__bulkKey !== undefined) narrowed.__bulkKey = item.__bulkKey;
    failed.push({ item: narrowed, error: `${bad.length} of ${bad.length + changed.length} hosts not updated: ${bad[0].error}` });
  });
  return { ok, failed };
}

// What Undo puts back. A row: its own earlier status. A group: each member's own earlier status (from member_status, complete however
// many members the row lists); a member the AI ruled out has no status to put back and is left out.
export function priorOf(item) {
  if (!isGroup(item)) {
    const was = item.status ?? item.remediation_status;
    return STATUS_VALUES.includes(was) ? was : undefined;
  }
  const g = item.group;
  const byMember = {};
  g.member_ids.forEach((id) => {
    const was = statusOfMember(g, id);
    if (STATUS_VALUES.includes(was)) byMember[id] = was;
  });
  return Object.keys(byMember).length ? { byMember } : undefined;
}

// Undo as [status, items] batches: each member the action changed (`__changedIds`) back to its own earlier status.
export function restoreBatches(items, prior) {
  const by = new Map();
  const add = (was, item) => by.set(was, [...(by.get(was) || []), item]);
  items.forEach((item) => {
    const was = prior(item);
    if (was === undefined) return;
    if (typeof was === "string") {
      add(was, item);
      return;
    }
    const changed = item.__changedIds ? new Set(item.__changedIds) : null;
    expandForBulk([item]).forEach((m) => {
      if ((!changed || changed.has(m.id)) && was.byMember[m.id]) add(was.byMember[m.id], m);
    });
  });
  return [...by.entries()];
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// What a confirmation says before a status change touches a group: how many hosts it changes, how many settled ones it leaves alone.
// null when no group is selected (single findings are changed without asking, as before).
export function confirmText(items, value, opts = {}) {
  const groups = items.filter(isGroup);
  if (!groups.length) return null;
  let ids = 0;
  let closed = 0;
  let same = 0;
  groups.forEach((item) => {
    const t = targetsOf(item.group, value, opts);
    ids += t.ids.length;
    closed += t.closed;
    same += t.same;
  });
  const singles = items.length - groups.length;
  const notes = [];
  if (closed) notes.push(`${closed} already fixed, accepted or ruled out left as they are`);
  if (same) notes.push(`${same} already ${STATUS_WORD[value] || value}`);
  return `Mark ${plural(ids, "host", "hosts")} in ${plural(groups.length, "group", "groups")}${singles ? ` and ${plural(singles, "other finding", "other findings")}` : ""} as ${STATUS_WORD[value] || value}${notes.length ? ` (${notes.join("; ")})` : ""}. Each host keeps its own history.`;
}

// The done message: findings (hosts) and sites, not rows. "214 findings on 6 sites".
export function doneSummary(okItems) {
  let findings = 0;
  const sites = new Set();
  okItems.forEach((item) => {
    if (isGroup(item)) {
      const n = item.__changedIds ? item.__changedIds.length : item.group.member_ids.length;
      findings += n;
      if (n) sites.add(item.group.registrable_domain);
    } else {
      findings += 1;
      sites.add(item.host || `${item.kind}-${item.id}`);
    }
  });
  return `${plural(findings, "finding", "findings")} on ${plural(sites.size, "site", "sites")}`;
}

// The menu label of a status change on a group row: what it changes and what it leaves.
export function menuLabel(item, value, label, opts = {}) {
  const t = targetsOf(item.group, value, opts);
  const left = opts.includeClosed ? "" : t.closed ? `; ${t.closed} fixed or accepted left as they are` : "";
  return `Mark as ${label}${opts.includeClosed ? ", including closed hosts" : ""} (${plural(t.ids.length, "host", "hosts")}${left})`;
}

export const TRUNCATED_NOTE = "Showing the first 20,000 matches grouped; narrow the filters or use Show every host.";

// The line above the list: what the counts mean in each mode, and whether the grouping read every match.
export function headerParts(r) {
  const counts = r.counts || {};
  const findings = r.findings_total ?? r.total ?? 0;
  if (r.group !== GROUPED) return { lead: `${plural(findings, "finding", "findings")}: `, counts, grouped: "", truncated: "" };
  const rows = r.total || 0;
  const grouped = r.groups
    ? `${plural(r.grouped_findings || 0, "CVE match", "CVE matches")} on sibling hosts shown as ${plural(r.groups, "row", "rows")} (the same library file on one site)`
    : "";
  return { lead: `${plural(findings, "finding", "findings")} in ${plural(rows, "row", "rows")}: `, counts, grouped, truncated: r.group_scan_truncated ? TRUNCATED_NOTE : "" };
}

// The dashboard's "in N" beside the per-host CVE match count: shown only when grouping makes it smaller and the count is exact (a
// truncated grouping pass hides it rather than print a wrong number).
export function dashboardNote(matches, groups, truncated) {
  if (truncated || groups == null || matches == null || !(groups < matches)) return { text: "", title: "" };
  return {
    text: `in ${groups}`,
    title: `${matches} matches, one per host, are ${groups} distinct findings: the same client-side library file on sibling hosts of one site counts once (the Findings list shows them grouped)`,
  };
}
