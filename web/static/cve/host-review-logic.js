// What the "AI review of this host" card says, in plain words, from the answer of GET projects/<slug>/hosts/<id>/review (agentapi/host_review_api.py).
// Pure functions, no DOM: host-review-card.js draws what these return. Every string that came from the model or the scanned host (a note, a title) is
// passed through untouched and only ever shown as text. Tested in tests/test_host_review_card.mjs.

export const MODES = [
  ["recommend", "Recommend only", "Recommend only: the AI proposes steps and a person starts each one."],
  ["auto", "Automatic", "Automatic: the AI starts safe read-only steps by itself."],
  ["off", "Off", "Off: no AI review of hosts in this project."],
];

export const modeHelp = (mode) => (MODES.find((m) => m[0] === mode) || MODES[0])[2];

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// Every reason code the server can store for a finding verdict (cveFeed/reviewer.py REASON_CODES), as one plain sentence.
export const REASONS = {
  version_not_affected: "The version on this host is outside the range the advisory covers.",
  product_mismatch: "The product on this host is not the one the advisory is about.",
  evidence_is_claim: "It rests on text the host says about itself, not on how it behaves.",
  check_not_applicable: "The check does not apply to this kind of host.",
  generic_match: "A catch-all page answered, not the flaw itself.",
  duplicate: "The same issue is already reported on this host.",
  stale_evidence: "What it rests on is no longer on the host.",
  decoy: "The evidence looks planted for scanners.",
  confirmed_by_evidence: "cvENGINE's own evidence shows the flaw.",
  plausible_exposure: "Nothing rules it out, so it counts as a real exposure.",
  remediated: "The evidence shows it was fixed.",
  other: "",
};
export const reasonText = (code) => (code in REASONS ? REASONS[code] : "");

// The reasons the AI gives for its next step (cveFeed/host_review.py STEP_REASONS).
export const STEP_WHY = {
  needs_proof: "A check would show whether the finding is really there.",
  needs_fresh_data: "What is known about this host looks out of date.",
  needs_visual: "Looking at the pages would help.",
  needs_check: "A read-only check would settle it.",
  needs_person: "Someone should look at this host.",
  nothing_to_do: "Nothing needs doing now.",
};

// What the next step is called, per action (cveFeed/host_actions.py ACTIONS). ``name`` is the finding it is about, when it names one.
export const STEP_TITLES = {
  none: () => "Nothing more is needed for this host",
  validate_match: (name) => (name ? `Run the read-only check for ${name}` : "Run the read-only check"),
  revalidate_finding: (name) => (name ? `Check ${name} again` : "Check the finding again"),
  screenshot: () => "Take fresh screenshots of this host",
  draft_check: (name) => (name ? `Draft a detection check for ${name}` : "Draft a detection check"),
  ask_person: () => "Ask a person to look at this host",
  rescan_host: () => "Scan this host again",
  assess_host: () => "Run a full assessment of this host",
  run_hygiene: () => "Run the hygiene checks for this host's target",
};

// Why a false positive was not closed: the server's reason (reviewer.close_gate and the rules after it) as a short phrase that finishes "stays open because ...".
export function heldBecause(finding) {
  const held = String(finding.held_reason || "");
  if (/the host review does not close/.test(held)) return "a person decides";
  if (/verdict_claim/.test(held)) return "this host's text makes claims about its own findings";
  if (finding.outcome === "disputed" || /^hard evidence/.test(held)) return "a check reproduced it";
  if (/person has worked/.test(held)) return "a person is working on it";
  if (/text aimed at AI/.test(held)) return "this host's text contains instructions";
  if (/confidence is/.test(held)) return "the AI was not sure enough";
  if (/turned off in Settings/.test(held)) return "closing false positives is switched off in Settings";
  if (/critical scanner/.test(held)) return "a person closes critical scanner findings";
  if (/contradicts the earlier verdict/.test(held)) return "an earlier review called it real";
  if (/of the same evidence on other hosts said it is real/.test(held)) return "earlier reviews of the same evidence on other hosts said it is real";
  return "cvENGINE keeps it open";
}

// The quiet tag at the right of a verdict row: what happened to the finding.
export function outcomeTag(finding) {
  if (finding.outcome === "closed") return { text: "Closed", tone: "success" };
  if (finding.summary === "false_positive" && /the host review does not close/.test(finding.held_reason || "")) return { text: "Looks like a false positive: a person decides", tone: "smoke" };
  if (finding.summary === "false_positive") {
    const why = heldBecause(finding);
    return { text: /instructions/.test(why) ? "Held: this host's text contains instructions" : `Kept open: ${why}`, tone: "queued" };
  }
  return { text: "Open", tone: "" };
}

// The state the card is in: running, applied, failed, stale, or, with no review, why none can be asked for.
export function stateOf(data) {
  const review = data && data.review;
  const code = data && data.readiness ? data.readiness.reason_code : "";
  if (code === "disabled" || code === "off") return "off";
  if (review && review.running) return "running";
  if (review && review.status === "applied") return "applied";
  if (review && review.status === "failed") return /too large/.test(review.failure || "") ? "too_large" : "failed";
  if (review && review.status === "stale") return "stale";
  if (code === "no_provider") return "no_provider";
  if (code === "nothing_open") return "nothing";
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
  if (/too large/.test(raw)) return "It has more to read than the AI can take at once. It is tried again tomorrow.";
  if (FAILURES[raw]) return `${FAILURES[raw]} Nothing was changed. It is tried again later.`;
  return raw ? `${raw.charAt(0).toUpperCase()}${raw.slice(1)}. Nothing was changed.` : "Nothing was changed.";
}

export const CLAIMS_TEXT = "Text on this host makes claims about how its findings should be judged, so cvENGINE does not let the AI close them by itself. A person decides.";
export const CLOSE_NOTE = "Closed as a false positive on the AI host review's advice, after a person read it.";

// "The host changed. The next automatic review is due at 14:20." for a host that changed within a day of its last review; ``when`` formats the time.
export function waitingText(iso, when = (d) => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })) {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : `The host changed. Its next automatic review is due ${when(d)}; Review now runs it at once.`;
}

export const HELD_TEXT = "Text on this host tells AI what to do, so cvENGINE closed nothing and started nothing by itself. A person decides.";

// The one headline and the quiet line below it (the card's reading).
export function summary(review) {
  const c = review.counts || { real: 0, false_positive: 0, uncertain: 0, closed: 0, held: 0 };
  const n = c.real + c.false_positive + c.uncertain;
  if (!n) return { headline: "The AI read the host but gave no verdict on its findings.", detail: "" };
  let headline;
  if (c.real === n) headline = n === 1 ? "The finding looks real." : `All ${n} findings look real.`;
  else if (c.real) headline = `${c.real} of ${n} findings ${c.real === 1 ? "looks" : "look"} real.`;
  else if (c.false_positive === n) headline = n === 1 ? "The finding looks like a false positive." : `All ${n} findings look like false positives.`;
  else if (c.uncertain === n) headline = n === 1 ? "The AI could not tell whether the finding is real." : `The AI could not tell for any of the ${n} findings.`;
  else headline = "No finding looks clearly real.";
  const parts = [];
  if (c.false_positive) {
    const kept = c.false_positive - c.closed;
    const reasons = [...new Set((review.findings || []).filter((f) => f.summary === "false_positive" && f.outcome !== "closed").map(heldBecause))];
    const because = reasons.length === 1 ? ` because ${reasons[0]}` : "";
    const all = c.false_positive === n;
    let text = all ? "" : `${c.false_positive} ${c.false_positive === 1 ? "looks" : "look"} like ${c.false_positive === 1 ? "a false positive" : "false positives"}`;
    let how;
    if (c.closed && kept) how = `${c.closed} closed, ${kept} ${kept === 1 ? "stays" : "stay"} open${because}`;
    else if (c.closed) how = all ? (n === 1 ? "It was closed" : "All were closed") : (c.closed === 1 ? "closed" : "all closed");
    else how = all ? (n === 1 ? "It stays open" : "They stay open") + because : (kept === 1 ? "it stays open" : "they stay open") + because;
    parts.push(all ? how : `${text}: ${how}`);
  }
  if (c.uncertain && c.uncertain < n) parts.push(`${c.uncertain} ${c.uncertain === 1 ? "is" : "are"} unclear`);
  return { headline, detail: parts.length ? `${parts.join("; ")}.` : "" };
}

const VERDICT = { real: ["Real", "high"], false_positive: ["False positive", "ice"], uncertain: ["Unclear", "queued"] };

// One finding's compact row: the chip, the CVE or title (a link), one plain reason, and the quiet tag.
export function findingView(f) {
  const [label, tone] = VERDICT[f.summary] || VERDICT.uncertain;
  const reason = reasonText(f.reason_code);
  return {
    title: f.title || "Finding",
    link: f.link || "",
    chip: label,
    tone,
    confidence: f.confidence || "low",
    tooltip: `${label}, ${f.confidence || "low"} confidence`,
    reason,
    note: f.note || "",
    tag: outcomeTag(f),
    canClose: !!f.can_close,
    type: f.finding && f.finding.type,
    id: f.finding && f.finding.id,
  };
}

// The quiet help under the buttons: why the step was not started by itself.
export function stepHelp(step) {
  const d = String((step && step.detail) || "");
  if (!step || step.state !== "proposed") return "";
  if (/recommend only/.test(d)) return "This project only recommends steps, so nothing starts until you press Start.";
  if (/touches the host/.test(d)) return "This step scans the host, so it always waits for you.";
  if (/aimed at AI/.test(d)) return "Not started by itself: this host's text contains instructions.";
  if (/last 24 hours/.test(d)) return "Not started by itself: a step on this host ran or was dismissed in the last day.";
  if (/limit of automatic steps/.test(d)) return "Not started by itself: this project's limit of automatic steps for today is reached.";
  if (/paused/.test(d)) return "Not started by itself: scanning is paused.";
  return d ? `Not started by itself: ${d.replace(/\.+$/, "")}.` : "";
}

// The next step: its title, why, the chip, and which buttons it has.
export function stepView(step) {
  if (!step) return null;
  const name = step.target ? step.target.title : "";
  const title = (STEP_TITLES[step.action] || (() => step.description || step.action))(name);
  const why = step.note || STEP_WHY[step.reason_code] || "";
  const base = { action: step.action, title, why, help: stepHelp(step), start: false, dismiss: false, chip: "", tone: "queued", href: step.target ? step.target.link || "" : "" };
  if (step.action === "none") return { ...base, chip: "Done", tone: "success", why: why || STEP_WHY.nothing_to_do };
  if (step.action === "ask_person") {
    if (step.state === "dismissed") return { ...base, chip: "Dismissed", tone: "queued" };
    return { ...base, chip: "Needs a person", tone: "smoke", dismiss: !!step.can_dismiss, help: step.state === "done" ? "A notification was sent." : base.help };
  }
  if (step.state === "proposed") return { ...base, chip: "Waiting for you", tone: "smoke", start: !!step.can_start, dismiss: !!step.can_dismiss };
  if (step.state === "started" || step.state === "done") return { ...base, chip: step.mode === "auto" ? "Started automatically" : "Started", tone: "success", help: step.detail ? `${step.detail}` : "" };
  if (step.state === "refused") return { ...base, chip: "Could not start", tone: "high", help: step.detail ? `${step.detail.charAt(0).toUpperCase()}${step.detail.slice(1)}${/[.!?]$/.test(step.detail) ? "" : "."}` : "" };
  if (step.state === "dismissed") return { ...base, chip: "Dismissed", tone: "queued", help: step.dismissed_by ? `Dismissed by ${step.dismissed_by.username || step.dismissed_by.name || "a person"}.` : "" };
  if (step.state === "expired") return { ...base, chip: "Expired", tone: "queued", help: "Nobody acted on it, so it expired." };
  return base;
}

// What the card says when there is no review to show: a headline and a quiet line.
export function emptyText(data) {
  const state = stateOf(data);
  const review = data && data.review;
  const why = (data && data.readiness && data.readiness.reason) || "";
  const code = data && data.readiness ? data.readiness.reason_code : "";
  switch (state) {
    case "off": return { headline: code === "off" ? "AI host review is off for this project." : "AI host review is off.", detail: "" };
    case "no_provider": return { headline: "No AI provider is set up.", detail: "An administrator adds one in Settings, then the AI can review this host." };
    case "nothing": return { headline: "Nothing is open on this host.", detail: "There is nothing for the AI to review." };
    case "blocked": return { headline: "A review cannot be asked for now.", detail: why ? `${why.charAt(0).toUpperCase()}${why.slice(1)}.` : "" };
    case "running": return { headline: "The AI is reading this host.", detail: "This page updates by itself when it is done." };
    case "failed": return { headline: "The review did not finish.", detail: failureText(review) };
    case "too_large": return { headline: "This host is too large to review in one go.", detail: failureText(review) };
    case "stale": return { headline: "The host changed while the AI was reading it.", detail: "Nothing was applied. It will be reviewed again." };
    default: return { headline: "Not reviewed yet.", detail: "The AI reads every open finding of the host together, says which look real and suggests one next step." };
  }
}

// Review now: whether the button works and why not.
export function canReview(data) {
  const r = (data && data.readiness) || {};
  return { enabled: !!r.can_request, reason: r.can_request ? "" : r.reason || "" };
}

// "Reviewed 2 h ago" for the header row; ``ago`` is the page's own relative-time helper.
export function whenText(data, ago) {
  const review = data && data.review;
  const state = stateOf(data);
  if (!review) return state === "off" ? "" : "";
  const at = review.decided || review.created;
  if (state === "running") return "Running";
  if (state === "applied") return `Reviewed ${ago(at)}`;
  if (state === "failed" || state === "too_large") return `Tried ${ago(at)}`;
  if (state === "stale") return `Tried ${ago(at)}`;
  return "";
}
