// Closing a finding: the remediation statuses, which of them close one, and the note that says why (cveFeed/closure.py on the server).
// Kept free of the DOM and of imports so that `node --test` can run it (tests/test_closure_logic.mjs); app.js, bulk.js and suppliers.js
// draw what these return.
//
// Every closing status (fixed, accepted risk, false positive) asks for a note. The server accepts a closure without one; this UI will not
// close a finding as a false positive without saying why, since "not real" is the decision a later reader most needs explained.

export const STATUS_OPTIONS = [
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["fixed", "Fixed"],
  ["accepted_risk", "Accepted risk"],
  ["false_positive", "False positive"],
];
export const STATUS_VALUES = STATUS_OPTIONS.map(([value]) => value);
export const CLOSED = ["fixed", "accepted_risk", "false_positive"];
// a supplier finding: closed by hand as accepted or a false positive (resolved is set by the checks alone)
export const SUPPLIER_CLOSE_OPTIONS = [
  ["accepted", "Accepted"],
  ["false_positive", "False positive"],
];
export const NOTE_MAX = 2000;

const LABEL = Object.fromEntries([...STATUS_OPTIONS, ...SUPPLIER_CLOSE_OPTIONS, ["resolved", "Resolved"]]);

export const isClosing = (status) => CLOSED.includes(status) || status === "accepted";
export const statusLabel = (status) => LABEL[status] || String(status ?? "").replace(/_/g, " ");
export const asksForNote = (status) => isClosing(status);
export const noteRequired = (status) => status === "false_positive";

// The note as the server stores it: line endings made \n, control and invisible formatting characters removed, surrounding space trimmed.
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/g;
export const cleanNote = (text) =>
  String(text ?? "")
    .replace(/\r\n?/g, "\n")
    .replace(CONTROL, "")
    .trim();

// What is wrong with a note for this status, or null: a false positive needs one, and none may be longer than the server takes.
export function noteProblem(status, text) {
  const note = cleanNote(text);
  if (noteRequired(status) && !note) return "Say why this is a false positive, so the next person can trust the decision.";
  if (note.length > NOTE_MAX) return `A note can be at most ${NOTE_MAX} characters (this one is ${note.length}).`;
  return null;
}

// The words of the note dialog for closing `count` findings as `status`.
export function notePrompt(status, count = 1) {
  const what = count === 1 ? "this finding" : `${count} findings`;
  const label = statusLabel(status);
  const required = noteRequired(status);
  const help = [
    required ? "Required: say why it is not a real issue (for example, the host only redirects to another site)." : "Optional, but say why: it is kept with the status, with your name and the time.",
    count > 1 ? `The note goes on all ${count}.` : "",
    `At most ${NOTE_MAX} characters.`,
  ]
    .filter(Boolean)
    .join(" ");
  return {
    title: `Mark ${what} as ${label.toLowerCase()}`,
    label: required ? "Why is it a false positive?" : `Why is it ${label.toLowerCase()}?`,
    help,
    ok: `Mark as ${label}`,
    required,
  };
}

// The line a status badge's tooltip and the detail pane show for a closed finding: "False positive by Alice on 2026-11-02: why". An automatic
// closure is the engine's own reason. Empty for a finding that is not closed.
export function closureText(item) {
  if (!item) return "";
  const status = item.remediation_status ?? item.status;
  if (item.closed_automatically) return item.closure_note || "";
  if (!isClosing(status) || item.closure_note == null) return "";
  const who = item.closed_by ? ` by ${item.closed_by.name || item.closed_by.username}` : "";
  const when = item.closed_at ? ` on ${String(item.closed_at).slice(0, 10)}` : "";
  return `${statusLabel(status)}${who}${when}${item.closure_note ? `: ${item.closure_note}` : ""}`;
}
