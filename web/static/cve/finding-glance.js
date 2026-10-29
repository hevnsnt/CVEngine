// The top of a finding's detail pane: what was found, how sure we are, and what the AI made of it, in three short cards, so the answer to
// "why is this here and do I believe it" is readable without scrolling. Everything below it (the CVE record, the history, the
// validation job, the checks) folds away under a one-line summary. Nothing here invents data: every line comes from the detail the
// server already sends; a signal that is not known says so.
import { el, badge } from "/staticfiles/cve/ui.js";

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

// The three states a piece of evidence can be in. "for" supports the finding being real, "against" speaks for a false alarm.
const signal = (tone, label, value) => {
  const row = el("li", `sig sig-${tone}`);
  row.append(
    el("i", "sig-mark", tone === "for" ? "✓" : tone === "against" ? "✕" : "•", {
      "aria-hidden": "true",
    }),
  );
  const text = el("span", "sig-text");
  text.append(el("b", "", label), document.createTextNode(` ${value}`));
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
    rest.forEach((x) =>
      list.append(el("dt", "", x.label), el("dd", "", x.value)),
    );
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
  const [liveTone, liveText] = {
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

function aiCard(d, aiBadge, note) {
  const card = el("section", "gl-card gl-ai");
  card.append(el("h3", "gl-h", "AI assessment"));
  const cols = el("div", "gl-ai-cols");
  const left = el("div", "gl-ai-left");
  const right = el("div", "gl-ai-right");
  const verdict = el("div", "gl-verdict");
  verdict.append(aiBadge);
  left.append(verdict);
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
        why
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

export function glance(d, { row, aiBadge, note }) {
  const grid = el("div", "gl-grid");
  grid.append(foundCard(d), confidenceCard(d, row), aiCard(d, aiBadge, note));
  return [grid, threatLine(d)].filter(Boolean);
}
