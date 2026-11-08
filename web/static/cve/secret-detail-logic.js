// What the secret detail view says, as pure functions (tests/test_secret_detail.mjs). The server sends the facts (cveFeed.secrets_catalog, agentapi.secrets_api);
// this turns them into the sentences, counts and buttons of the panel. No value ever reaches this file: only the mask, the kind and where it was seen.

export const STATUS_WORDS = {
  unverified: "Unverified",
  live: "Live (validated)",
  inactive: "Inactive",
  inconclusive: "Inconclusive",
  public_by_design: "Intended public key",
  accepted: "Risk accepted",
  revoked: "Revoked",
  false_positive: "False positive",
};
export const QUIET = ["public_by_design", "accepted", "false_positive", "revoked"];

// The decisions a person can take, in the order the buttons appear. ``help`` is what the decision does to the host's score.
export const DECISIONS = [
  { status: "public_by_design", label: "Mark as intended public key", help: "A browser key meant to be in the page and restricted at the provider. It stops counting in the host scores." },
  { status: "false_positive", label: "Mark false positive", help: "Not a secret (a placeholder, a test value). It stops counting." },
  { status: "accepted", label: "Accept risk", help: "Known and accepted. It stops counting in the host scores." },
];

// The buttons for a secret in ``status``: the decision it already carries is marked, and a decided secret can go back to unverified.
export function decisionButtons(status) {
  const out = DECISIONS.map((d) => ({ ...d, current: d.status === status }));
  if (QUIET.includes(status)) out.push({ status: "unverified", label: "Reopen", help: "Back to the default: rated by its kind until a person or a validation says more.", current: false });
  return out;
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// "Found in 3 other places on 2 hosts", or that this is the only place. ``s`` is the detail: occurrences and hosts count the places served now.
export function otherPlaces(s) {
  const others = Math.max(0, (Number(s.occurrences) || 0) - 1);
  if (!others) return (Number(s.occurrences) || 0) ? "Served in one place only." : "Not served anywhere now: no scan has seen it in its latest read.";
  return `Also found in ${plural(others, "other place", "other places")}, ${plural(Number(s.hosts) || 0, "host", "hosts")} in all.`;
}

// Where a place is, in one line: the full URL, then the line number when the scanner gave one.
export function whereLine(o) {
  return `${o.url}${o.line != null ? ` (line ${o.line})` : ""}`;
}

// The masked text around the value, or the sentence that says why there is none.
export function contextView(o) {
  return o.context ? { text: o.context, note: "" } : { text: "", note: o.context_note || "Context not stored, rescan to capture." };
}

// The page a person can open to look for themselves: only an http or https address, never anything else a stored URL might hold.
export function openableUrl(url) {
  try {
    const u = new URL(String(url || ""));
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch (_) {
    return null;
  }
}

export function validationWords(s) {
  return (s.explain && s.explain.validated && s.explain.validated.words) || (s.validation && s.validation.outcome ? `Validated: ${s.validation.outcome}.` : "Not validated.");
}

export const memberLabel = (m) => (m && (m.name || m.username)) || "";
