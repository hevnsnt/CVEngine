// Retest on fix: how a finding marked fixed shows what a re-check found (cveFeed/fix_retest.py on the server). Kept free of the DOM and of imports so
// that `node --test` can run it (tests/test_retest_logic.mjs); app.js and finding-glance.js draw what these return.
//
// The server sends `retest` on every CVE match, scanner finding and hygiene finding: {state, label, text, at, sentinel, reason, can_retest}. `state` is
// "" for a finding that was not marked fixed (the UI draws nothing), else verifying, verified_fixed, still_reproduces, not_verified or no_check. Only
// verified_fixed means the check ran and the finding is gone: every other state of a fixed finding says plainly that it is not verified.

export const STATES = ["verifying", "verified_fixed", "still_reproduces", "not_verified", "no_check"];

// the Findings status filters this adds (the server's `status=` values and the words of the buttons)
export const FILTERS = [
  ["verified_fixed", "Verified fixed"],
  ["unverified_fixed", "Fixed, not verified"],
  ["reopened", "Reopened by retest"],
];

// badge tones that already exist in cve.css: green is for verified only, red for a finding that came back, amber for a fix nobody could confirm
const TONE = { verifying: "info", verified_fixed: "fixed", still_reproduces: "high", not_verified: "medium", no_check: "info" };

// The retest object of a row or a detail, or null when the finding shows nothing about one.
export const retestOf = (item) => (item && item.retest && STATES.includes(item.retest.state) ? item.retest : null);

export const toneOf = (r) => TONE[r && r.state] || "info";

// The row chip's words: the state, short ("Fixed, not verified"); the reason is in the tooltip and the detail.
export const chipText = (r) => (r ? r.label : "");

// The sentence of the tooltip and of the detail: "Fixed, not verified: the host did not answer", with the Sentinel that ran the check.
export function sentence(r) {
  if (!r) return "";
  const who = r.sentinel ? ` Checked by Sentinel ${r.sentinel}.` : "";
  return `${r.text}.${who}`;
}

// The lines the glance card shows, as [label, value] pairs in order: what is known, no more.
export function cardFacts(r) {
  if (!r) return [];
  const facts = [];
  if (r.at) facts.push(["Checked", r.at]);
  if (r.sentinel) facts.push(["By Sentinel", r.sentinel]);
  if (r.state === "not_verified" && r.reason) facts.push(["Why not verified", r.reason]);
  if (r.state === "still_reproduces" && r.reason) facts.push(["What it showed", r.reason]);
  return facts;
}

// What the card says under its heading, in plain words.
export function cardNote(r) {
  switch (r && r.state) {
    case "verifying":
      return "A Sentinel is running the check that proved this finding again. Until it answers, the fix is not verified.";
    case "verified_fixed":
      return "The check that proved this finding ran again and no longer reproduces it.";
    case "still_reproduces":
      return "The check that proved this finding ran again and still reproduces it, so the finding was reopened. The new request and answer are shown below.";
    case "not_verified":
      return "The check could not be run to an answer. The finding stays fixed but is not verified. It is tried again later (at most once a day).";
    case "no_check":
      return "There is no stored check or evidence to repeat, so this cannot be re-checked automatically. Marked fixed is not the same as verified.";
    default:
      return "";
  }
}

// Whether a Retest now button is offered: the finding is marked fixed, a check can be repeated, and one is not already running.
export const canRetestNow = (item) => {
  const r = retestOf(item);
  const status = item && (item.remediation_status ?? item.status);
  return !!(r && status === "fixed" && r.can_retest && r.state !== "verifying");
};

// "3 verified fixed, 2 fixed and not verified, 1 reopened": the counts the server sends as `retest` on the findings list, or "" when all are zero.
export function countsLine(c) {
  if (!c) return "";
  const parts = [];
  if (c.verified_fixed) parts.push(`${c.verified_fixed} verified fixed`);
  if (c.unverified_fixed) parts.push(`${c.unverified_fixed} fixed, not verified`);
  if (c.reopened) parts.push(`${c.reopened} reopened`);
  return parts.join(", ");
}
