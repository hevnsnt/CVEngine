// A match explains itself (cveFeed/match_explain.py on the server): the words and choices the match page and the host page draw from the
// ``explain`` object of a match and the ``validate_plan`` of a host. Kept free of the DOM and of imports so that `node --test` can run it
// (tests/test_match_explain_logic.mjs); match-explain.js draws what these return. Nothing here invents data: every sentence is the server's.

// How sure cvENGINE is, as the badge tone the rest of the interface uses for it.
export const CONFIDENCE_TONE = { confirmed: "fire", likely: "smoke", not_confirmed: "queued", ruled_out: "ice" };
export const confidenceTone = (confidence) => CONFIDENCE_TONE[confidence] || "queued";

// What each answer means, in the order a person reads them: the good news first.
const OUTCOMES = [
  ["fixed", "Fixed", "success"],
  ["affected", "Still affected", "fire"],
  ["cant_tell", "Can't tell", "smoke"],
];
export function outcomeRows(outcomes) {
  const o = outcomes || {};
  return OUTCOMES.filter(([key]) => o[key]).map(([key, label, tone]) => ({ key, label, tone, text: String(o[key]) }));
}

// The closures a person can start from the explanation: none once the match is closed, none in a read-only view. Each carries the note the
// server wrote from the evidence, which the person completes (the build the command printed) before the normal closure route saves it.
const CLOSED = ["fixed", "accepted_risk", "false_positive"];
export function closeChoices(explain, status, { readOnly = false } = {}) {
  if (readOnly || CLOSED.includes(status)) return [];
  return ((explain && explain.close) || [])
    .filter((c) => c && (c.status === "fixed" || c.status === "false_positive") && typeof c.note === "string")
    .map((c) => ({ status: c.status, label: c.label || (c.status === "fixed" ? "Close as fixed" : "Close as false positive"), note: c.note }));
}

// Only an http(s) link is ever opened.
export const safeHref = (url) => (typeof url === "string" && /^https:\/\//i.test(url) ? url : "");

// The matches one group of the host plan resolves: the first ``max`` as links, and how many more there are.
export function shownResolves(resolves, max = 12) {
  const all = Array.isArray(resolves) ? resolves : [];
  return { shown: all.slice(0, max), more: Math.max(0, all.length - max) };
}

export const matchHref = (project, id) => `/cve/${encodeURIComponent(project)}/matches/#${encodeURIComponent(String(id))}`;

// The line above the host plan: how many questions settle how many open matches, and who can answer them.
export function planIntro(plan, host) {
  const groups = Array.isArray(plan) ? plan : [];
  const matches = groups.reduce((n, g) => n + (Number(g.count) || 0), 0);
  if (!groups.length) return "";
  const q = groups.length === 1 ? "One question" : `${groups.length} questions`;
  return `${q} on ${host || "the host"} settle${groups.length === 1 ? "s" : ""} ${matches} open match${matches === 1 ? "" : "es"}. Someone with a shell on the host can answer them; every command only reads. Start at the top: exploited CVEs come first.`;
}

// A group's one-line summary: "Is the installed httpd package patched? · 70 matches · listed as exploited".
export function groupSummary(group) {
  const g = group || {};
  const n = Number(g.count) || 0;
  return [g.question || "", `${n} match${n === 1 ? "" : "es"}`, g.kev ? "listed as exploited" : ""].filter(Boolean).join(" · ");
}
