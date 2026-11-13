// What the "AI review of this host" card says, in plain words, from the answer of GET projects/<slug>/hosts/<id>/review (agentapi/host_review_api.py).
// Pure functions, no DOM: host-review-card.js draws what these return. Every string that came from the model or the scanned host (a note, a title, a
// reason) is passed through untouched and is only ever shown as text. Tested in tests/test_host_review_logic.mjs.

export const MODES = [
  ["auto", "Automatic", "Automatic: the AI starts safe read-only steps by itself"],
  ["recommend", "Recommend only", "Recommend only: the AI proposes, a person starts"],
  ["off", "Off", "Off: no AI review of hosts in this project"],
];

export const modeHelp = (mode) => (MODES.find((m) => m[0] === mode) || MODES[1])[2];

const humanize = (code) => String(code || "").replace(/_/g, " ").trim();
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// The state the card is in: never, running, applied, failed, stale, or, with no review, why none can be asked for.
export function stateOf(data) {
  const review = data && data.review;
  if (review && review.running) return "running";
  if (review && review.status === "applied") return "applied";
  if (review && review.status === "failed") return "failed";
  if (review && review.status === "stale") return "stale";
  const code = data && data.readiness ? data.readiness.reason_code : "";
  if (code === "no_provider") return "no_provider";
  if (code === "nothing_open") return "nothing";
  if (code === "off") return "off";
  if (code === "disabled") return "disabled";
  if (code === "unavailable" || code === "paused" || code === "daily_limit") return "blocked";
  return "never";
}

const FAILURES = {
  provider_rate_limit: "The AI provider was too busy (a rate limit).",
  provider_timeout: "The AI provider took too long to answer.",
  provider_connect_timeout: "The AI provider could not be reached in time.",
  provider_network: "The AI provider could not be reached.",
  lease_expired: "The AI reviewer stopped before it answered.",
};

// Why a review failed, as a sentence. The server's reason reads "failed: <code>" or "failed: <words>".
export function failureText(review) {
  const raw = String((review && review.failure) || "").replace(/^(failed|stale):\s*/, "");
  if (review && review.status === "stale") return "The host changed while the AI was reading it, so nothing was applied. It will be reviewed again.";
  const known = FAILURES[raw];
  if (known) return `${known} Nothing was changed. It will be tried again later.`;
  return raw ? `The review did not finish: ${raw}. Nothing was changed.` : "The review did not finish. Nothing was changed.";
}

export const HELD_TEXT = "Text on this host (a banner, a page title) tells AI what to do. The AI's answers are shown below, but cvENGINE closed nothing and started nothing by itself, so a person decides.";

// What the card says when there is no review to show.
export function emptyText(data) {
  const state = stateOf(data);
  const why = (data && data.readiness && data.readiness.reason) || "";
  if (state === "no_provider") return "No AI provider is set up, so this host cannot be reviewed by the AI. An administrator adds one in Settings.";
  if (state === "nothing") return "Nothing is open on this host, so there is nothing for the AI to review.";
  if (state === "disabled") return "The AI host review is switched off for this installation. It is off until an administrator turns it on in Settings, because every review is an AI call your provider bills for.";
  if (state === "off") return "The AI host review is switched off for this project.";
  if (state === "blocked") return `A review cannot be asked for now: ${why || "the host is not reviewable"}.`;
  return "The AI has not reviewed this host yet. It reads every open finding of the host together, says which look real and which look like false positives, and picks one next step.";
}

// Review now: whether the button works and why not.
export function canReview(data) {
  const r = (data && data.readiness) || {};
  return { enabled: !!r.can_request, reason: r.can_request ? "" : r.reason || "" };
}

const VERDICT = { real: "Real finding", false_positive: "False positive", uncertain: "Not sure" };

// One finding's line: the verdict, what happened to the finding, the reason.
export function findingView(f) {
  let outcome = "";
  if (f.outcome === "closed") outcome = "Closed as a false positive.";
  else if (f.summary === "false_positive") outcome = `Kept open${f.held_reason ? `: ${f.held_reason}` : " (the AI's opinion only)"}.`;
  const reason = [humanize(f.reason_code), f.note].filter(Boolean).join(". ");
  return {
    title: f.title || "Finding",
    tone: f.summary === "real" ? "high" : f.summary === "false_positive" ? "ice" : "queued",
    label: `${VERDICT[f.summary] || "Not sure"} (${f.confidence || "low"} confidence)`,
    outcome,
    reason,
    kind: f.finding && f.finding.type,
    id: f.finding && f.finding.id,
  };
}

// The conclusion for the whole host, one or two sentences.
export function conclusion(review) {
  const c = review.counts || { real: 0, false_positive: 0, uncertain: 0, closed: 0, held: 0 };
  const total = c.real + c.false_positive + c.uncertain;
  if (!total) return "The AI read the host but gave no verdict on its findings.";
  const parts = [];
  if (c.real) parts.push(`${plural(c.real, "looks real", "look real")}`);
  if (c.false_positive) parts.push(`${plural(c.false_positive, "looks like a false positive", "look like false positives")}`);
  if (c.uncertain) parts.push(`${c.uncertain} ${c.uncertain === 1 ? "is" : "are"} not clear`);
  let text = `Of ${plural(total, "finding", "findings")}, ${parts.join(", ")}.`;
  if (c.closed) text += ` ${plural(c.closed, "was", "were")} closed as ${c.closed === 1 ? "a false positive" : "false positives"}.`;
  if (c.held) text += ` ${plural(c.held, "false positive was", "false positives were")} kept open because cvENGINE has proof, a person's work or a safety hold.`;
  return text;
}

// The next step: what to say, and which buttons it has.
export function stepView(step) {
  if (!step) return null;
  const what = step.description || humanize(step.action);
  const target = step.target ? ` (${step.target.title})` : "";
  const base = { action: step.action, note: step.note || "", detail: step.detail || "", start: false, dismiss: false, tone: "queued", heading: "", text: what + target };
  if (step.action === "none") return { ...base, heading: "Next step", text: "Nothing more is needed for this host now.", tone: "success" };
  if (step.action === "ask_person") {
    const open = step.state === "proposed" || step.state === "done";
    if (step.state === "dismissed") return { ...base, heading: "Needs a person", text: "The AI asked a person to look at this host. Dismissed.", tone: "queued" };
    return { ...base, heading: "Needs a person", text: "The AI asks a person to look at this host.", tone: "smoke", dismiss: open && !!step.can_dismiss };
  }
  if (step.state === "proposed") return { ...base, heading: "Suggested next step", start: !!step.can_start, dismiss: !!step.can_dismiss, tone: "smoke" };
  if (step.state === "started" || step.state === "done") {
    const how = step.mode === "auto" ? "Started automatically" : "Started by a person";
    return { ...base, heading: "Next step", text: `${how}: ${what}${target}.`, tone: "success" };
  }
  if (step.state === "refused") return { ...base, heading: "Next step", text: `${what}${target} could not be started${step.detail ? `: ${step.detail}` : ""}.`, detail: "", tone: "high" };
  if (step.state === "dismissed") return { ...base, heading: "Next step", text: `${what}${target}. Dismissed${step.dismissed_by ? ` by ${step.dismissed_by.username || step.dismissed_by.name || "a person"}` : ""}.`, tone: "queued" };
  if (step.state === "expired") return { ...base, heading: "Next step", text: `${what}${target}. Nobody acted on it, so it expired.`, tone: "queued" };
  return { ...base, heading: "Next step" };
}

// Why a proposed step was not started by itself, when the server said so (the project is on recommend only, the host carries instructions...).
export const heldDetail = (step) => (step && step.state === "proposed" && step.detail ? step.detail : "");
