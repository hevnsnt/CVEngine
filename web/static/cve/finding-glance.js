// The top of a finding's detail pane: what was found, how sure we are, and what the AI made of it, in three short cards, so the answer to
// "why is this here and do I believe it" is readable without scrolling. Everything below it (the CVE record, the history, the
// validation job, the checks) folds away under a one-line summary. Nothing here invents data: every line comes from the detail the
// server already sends; a signal that is not known says so.
import { el, badge } from "/staticfiles/cve/ui.js";
import { fmtLong, zoneLabel } from "/staticfiles/cve/prefs.js";
import { proofOf, templateSegments, textSegments } from "/staticfiles/cve/finding-glance-logic.js";

const CLASS_WORDS = {
  confirmed: "Confirmed",
  likely: "Likely",
  needs_validation: "Needs validation",
  likely_false_positive: "Likely false positive",
  not_applicable: "Not applicable",
};

// A folded section: a title, one line that says what is inside, and the content. ``body`` is what the caller appends to.
export function fold(title, sub, { open = false } = {}) {
  const root = el("details", "fold");
  if (open) root.open = true;
  const head = el("summary");
  head.append(el("b", "", title));
  if (sub) head.append(el("span", "fold-sub", sub));
  const body = el("div", "fold-body");
  root.append(head, body);
  return { root, body };
}

const step = (d, label) =>
  (d.how_found.steps || []).find((s) => s.label === label);

// A value as a sentence: words wrap at spaces, a check name is a code chip, a time is written for people (viewer's zone) with the
// exact ISO value in the tooltip.
function richValue(segs) {
  const box = document.createDocumentFragment();
  segs.forEach((s) => {
    if (s.k === "code" || s.k === "when") {
      // the lead word stays with the thing it introduces, so a line never ends on "Check:" or "Tested"
      const unit = el("span", "gl-unit");
      if (s.lead) unit.append(document.createTextNode(s.lead));
      if (s.k === "code") unit.append(el("code", "gl-code", s.v));
      else unit.append(el("time", "gl-when", fmtLong(s.iso) || s.iso, { datetime: s.iso, title: `${s.iso} (shown in ${zoneLabel()})` }));
      box.append(unit);
    } else box.append(document.createTextNode(s.v));
  });
  return box;
}

// The three states a piece of evidence can be in. "for" supports the finding being real, "against" speaks for a false alarm.
const signal = (tone, label, value, segs) => {
  const row = el("li", `sig sig-${tone}`);
  row.append(
    el("i", "sig-mark", tone === "for" ? "✓" : tone === "against" ? "✕" : "•", {
      "aria-hidden": "true",
    }),
  );
  const text = el("span", "sig-text");
  text.append(el("b", "", label), " ", richValue(segs || textSegments(value)));
  row.append(text);
  const word =
    tone === "for"
      ? "supports the finding"
      : tone === "against"
        ? "speaks against it"
        : "not decisive";
  row.title = `${label}: ${word}`;
  return row;
};

function foundCard(d) {
  const card = el("section", "gl-card gl-found");
  card.append(el("h3", "gl-h", "What was found"));
  const steps = d.how_found.steps || [];
  const first = step(d, "Observed") || step(d, "Matched at") || steps[0];
  if (first) {
    // "nginx-ui 1.31.2 (technology fingerprint of the web server)": the product and version are the headline, the rest says how it was seen
    const m = /^(.*?)\s*\(([^()]*)\)$/.exec(first.value);
    card.append(el("div", "gl-big mono", m ? m[1] : first.value));
    card.append(
      el(
        "div",
        "gl-sub",
        m
          ? m[2]
          : first.label === "Observed"
            ? "seen on this host"
            : first.label,
      ),
    );
  } else
    card.append(
      el("p", "note", "No evidence is recorded for how this was found."),
    );
  const rest = steps.filter((x) => x !== first);
  if (rest.length) {
    const list = el("dl", "gl-facts");
    rest.forEach((x) => {
      const dd = el("dd", "gl-val");
      dd.append(richValue(x.label === "Template check" ? templateSegments(x.value) : textSegments(x.value)));
      list.append(el("dt", "", x.label), dd);
    });
    card.append(list);
  }
  return card;
}

// A score from the rules, before the AI and before any check: how well the product and version on the host line up with the advisory.
function confidenceCard(d, row) {
  const card = el("section", "gl-card gl-conf");
  card.append(el("h3", "gl-h", "Confidence"));
  const score =
    d.confidence != null
      ? d.confidence
      : row && row.confidence != null
        ? row.confidence
        : null;
  if (score != null) {
    const pct = Math.round(Math.max(0, Math.min(1, Number(score))) * 100);
    const tier = pct >= 75 ? "high" : pct >= 45 ? "mid" : "low";
    card.append(el("div", `gl-big gl-pct ${tier}`, `${pct}%`));
    const meter = el("div", "meter", null, {
      role: "img",
      "aria-label": `Match score ${pct} percent`,
    });
    meter.append(el("i", tier, null, { style: `width:${pct}%` }));
    card.append(
      meter,
      el(
        "div",
        "gl-sub",
        "match score from the rules, before the AI and any check",
      ),
    );
  }
  const list = el("ul", "sigs");
  const version = step(d, "Version check");
  if (version) {
    const v = version.value;
    list.append(
      signal(
        /^inside/.test(v) ? "for" : /^outside/.test(v) ? "against" : "unk",
        "Version",
        v,
      ),
    );
  }
  const tpl = step(d, "Template check");
  if (tpl)
    list.append(
      signal(
        /^vulnerable/.test(tpl.value)
          ? "for"
          : /^no match/.test(tpl.value)
            ? "against"
            : "unk",
        "Template",
        tpl.value,
        templateSegments(tpl.value),
      ),
    );
  const dist = step(d, "Distribution");
  if (dist)
    list.append(
      signal(
        /patched/i.test(dist.value)
          ? "against"
          : /vulnerable/i.test(dist.value)
            ? "for"
            : "unk",
        "Distribution",
        dist.value,
      ),
    );
  const live = d.validation || {};
  // cvENGINE's own read of a library's served file (validation.record_library_read): a completed check, not metadata
  const bodyRead = (live.steps || []).some((s) => s.kind === "library_read" && s.result === "reaffirmed");
  const [liveTone, liveText] = bodyRead ? ["for", "the served file states an affected version"] : {
    hit: ["for", "reproduced by a check"],
    clean: ["against", "a check did not reproduce it"],
    observed: ["unk", "only metadata was observed"],
    failed: ["unk", "a check failed to run"],
    pending: ["unk", "checks are queued"],
    skipped_blocked: ["unk", "checks were not run"],
  }[live.status] || ["unk", "no check has run"];
  list.append(signal(liveTone, "Live check", liveText));
  if ((d.ai.hard_evidence || []).length)
    list.append(signal("for", "Hard evidence", d.ai.hard_evidence[0]));
  card.append(list);
  return card;
}

// Long prose is cut to a few lines with a toggle, so the card stays scannable and nothing is hidden for good.
function clamped(text, cls = "") {
  const box = el("div", `gl-clamp ${cls}`.trim());
  const p = el("p", "clamp", text);
  box.append(p);
  if (text.length > 170) {
    const more = el("button", "linkish", "Read more", {
      type: "button",
      "aria-expanded": "false",
    });
    more.onclick = () => {
      const on = p.classList.toggle("open");
      more.textContent = on ? "Show less" : "Read more";
      more.setAttribute("aria-expanded", String(on));
    };
    box.append(more);
  }
  return box;
}

const CONFIDENCE_WORDS = { high: "High", medium: "Medium", low: "Low" };

// The AI reviewer's newest verdict on this finding (cvENGINE's review, not the triage): what it thinks, how sure, why, and what the
// server did about it. The sentences come from the server; the model's own note is set as text, never as markup.
function reviewerBlock(review) {
  if (!review) return null;
  const box = el("div", "gl-reviewer");
  box.append(el("h4", "gl-h2", "AI reviewer"));
  box.append(el("p", "gl-reviewer-verdict", review.verdict_text || ""));
  const facts = [
    `Confidence: ${CONFIDENCE_WORDS[review.confidence] || "not stated"}`,
    review.reason_code ? `Reason: ${String(review.reason_code).replace(/_/g, " ")}` : null,
    review.model ? `Model: ${review.model}` : null,
  ].filter(Boolean);
  box.append(el("p", "note", facts.join(". ")));
  box.append(el("p", "", review.outcome_text || ""));
  if (review.note) box.append(el("p", "gl-reviewer-note", review.note));
  if (review.scope_text) box.append(el("p", "note", review.scope_text));
  return box;
}

function aiCard(d, aiBadge, note) {
  const card = el("section", "gl-card gl-ai");
  card.append(el("h3", "gl-h", "AI assessment"));
  const cols = el("div", "gl-ai-cols");
  const left = el("div", "gl-ai-left");
  const right = el("div", "gl-ai-right");
  const verdict = el("div", "gl-verdict");
  verdict.append(aiBadge);
  left.append(verdict);
  const reviewer = reviewerBlock(d.ai_review);
  if (reviewer) left.append(reviewer);
  if (d.ai.overridden && d.ai.model_classification) {
    const said = el("p", "gl-override");
    said.append(
      "The model said ",
      badge(
        CLASS_WORDS[d.ai.model_classification] || d.ai.model_classification,
        d.ai.model_classification === "likely_false_positive" ? "fp" : "",
      ),
    );
    left.append(said);
    const why = (d.ai.hard_evidence || [])[0];
    left.append(
      el(
        "p",
        "gl-rule",
        d.ai.classification === "confirmed" && d.ai.reason
          ? `The rules confirmed it: ${d.ai.reason}`
          : why
            ? `The rules kept it open because ${why}.`
            : "The rules decide whether a finding can be cleared.",
      ),
    );
  }
  if (d.severity && d.severity_ai) {
    const sev = el("div", "gl-sev");
    sev.append(
      el("span", "note", "Severity"),
      badge(d.severity, d.severity),
      el("span", "gl-arrow", "\u2192", { "aria-hidden": "true" }),
      badge(`AI view ${d.severity_ai}`, d.severity_ai),
    );
    left.append(sev);
  }
  const reasoning = d.ai.overridden ? d.ai.model_reason : d.ai.reason;
  if (reasoning)
    right.append(el("h4", "gl-h2", "Its reasoning"), clamped(reasoning));
  else if (!d.why_it_matters && note) right.append(el("p", "note", note));
  if (d.ai.severity_reason)
    right.append(
      el("h4", "gl-h2", "On the severity"),
      clamped(d.ai.severity_reason),
    );
  if (d.why_it_matters)
    right.append(
      el("h4", "gl-h2", "Why it matters"),
      clamped(d.why_it_matters),
    );
  cols.append(left, right);
  card.append(cols);
  if (d.ai.model)
    card.append(
      el(
        "p",
        "gl-foot",
        `${d.ai.model}${d.ai.triaged ? `, ${String(d.ai.triaged).slice(0, 10)}` : ""}`,
      ),
    );
  return card;
}

// Threat intelligence about the CVE itself, on one line: not proof about this host, which the note beside it says.
function threatLine(d) {
  const x = d.cve && d.cve.exploitation;
  if (!x) return null;
  const line = el("div", "gl-threats");
  line.append(el("span", "note", "About the CVE, not this host"));
  const chip = (text, tone) => line.append(badge(text, tone));
  const listed = (x.exploited_by || []).length || x.cisa_kev === true;
  chip(
    listed
      ? `Exploited in the wild${x.exploited_by && x.exploited_by[0] ? `: ${x.exploited_by[0].source}` : ""}`
      : x.cisa_kev === false
        ? "Not in CISA KEV"
        : "Exploitation unknown",
    listed ? "fire" : "queued",
  );
  const exploits = Object.keys(x.public_exploits || {});
  chip(
    exploits.length
      ? `Public exploit: ${exploits.join(", ")}`
      : x.exploit_db === false
        ? "No public exploit listed"
        : "Public exploit unknown",
    exploits.length ? "high" : "queued",
  );
  if (x.epss && x.epss.score != null) {
    const pct = (x.epss.score * 100).toFixed(1);
    chip(
      `EPSS ${pct}%${x.epss.percentile != null ? ` (${Math.round(x.epss.percentile * 100)}th pct)` : ""}`,
      x.epss.score >= 0.1 ? "medium" : "queued",
    );
  }
  return line;
}

// The proof, first: when a check cvENGINE ran against this host reproduced the finding, say so before anything else and show what the host answered.
// Everything underneath still folds away; this is the part a person reads to believe it. Nothing is drawn for a finding no check reproduced.
function proofCard(d) {
  const proof = proofOf(d.validation);
  if (!proof) return null;
  const card = el("section", "gl-card gl-proof");
  card.append(el("h3", "gl-h", "Proven on this host"));
  const line = el("p", "gl-proof-line");
  line.append(`Reproduced by the ${proof.label}`);
  if (proof.at) line.append(" on ", el("time", "gl-when", fmtLong(proof.at) || proof.at, { datetime: proof.at, title: `${proof.at} (shown in ${zoneLabel()})` }));
  if (proof.summary) line.append(`: ${proof.summary}`);
  card.append(line);
  if (proof.display) card.append(el("p", "note", "Repeat it yourself:"), el("pre", "banner mono", proof.display));
  proof.exchanges.forEach((e) => {
    const name = e.kind.replace(/_/g, " ");
    if (e.request) card.append(el("h4", "gl-h2", `Request (${name})`), el("pre", "banner mono gl-proof-pre", e.request));
    if (e.response) card.append(el("h4", "gl-h2", "What the host answered"), el("pre", "banner mono gl-proof-pre", e.response));
    if (e.reply) card.append(el("h4", "gl-h2", "The service replied"), el("pre", "banner mono gl-proof-pre", e.reply));
  });
  if (!proof.exchanges.length) card.append(el("p", "note", "No request or response was kept for this check."));
  return card;
}

export function glance(d, { row, aiBadge, note }) {
  const grid = el("div", "gl-grid");
  grid.append(foundCard(d), confidenceCard(d, row), aiCard(d, aiBadge, note));
  return [proofCard(d), grid, threatLine(d)].filter(Boolean);
}
