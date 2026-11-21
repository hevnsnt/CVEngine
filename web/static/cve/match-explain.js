// A match explains itself, and a host says which commands settle its matches (cveFeed/match_explain.py). The match page draws a match's
// ``explain``: what was found, how sure cvENGINE is and why, the numbered read-only steps with their commands and what each answer means, and
// the closures the evidence supports. The host page draws its ``validate_plan``: one question per package ("Is the installed httpd package
// patched?") with the commands that answer it and the matches it settles, exploited first. Every command was built by the server from an
// allow-listed package name and a validated CVE id; everything is drawn as text (el() sets textContent), and only https links open.
import { el, badge } from "/staticfiles/cve/ui.js";
import * as EX from "/staticfiles/cve/match-explain-logic.js";

const copyButton = (text) => {
  const b = el("button", "btn ghost sm", "Copy", { type: "button", "aria-label": "Copy the command" });
  b.onclick = () => navigator.clipboard && navigator.clipboard.writeText(text);
  return b;
};

const link = (url, text) => {
  const href = EX.safeHref(url);
  return href ? el("a", "mono", text || href, { href, target: "_blank", rel: "noopener noreferrer nofollow" }) : null;
};

function outcomeList(outcomes, cls = "x-outcomes") {
  const rows = EX.outcomeRows(outcomes);
  if (!rows.length) return null;
  const ul = el("ul", `guide-list ${cls}`);
  rows.forEach((r) => {
    const li = el("li");
    li.append(badge(r.label, r.tone), document.createTextNode(` ${r.text}`));
    ul.append(li);
  });
  return ul;
}

function stepItem(step) {
  const li = el("li", "x-step");
  li.append(el("p", "x-step-text", step.text || ""));
  const url = link(step.url, step.command ? "Open the advisory page" : step.url);
  if (url && !step.command) li.append(url);
  if (step.command) {
    const row = el("div", "local-check");
    const head = el("div", "tools");
    head.append(el("span", "note", step.needs || ""), copyButton(step.command));
    row.append(head, el("pre", "banner", step.command));
    li.append(row);
    if (url) {
      const line = el("p", "note");
      line.append(url);
      li.append(line);
    }
  }
  const outcomes = outcomeList(step.outcomes, "x-step-outcomes");
  if (outcomes) li.append(outcomes);
  return li;
}

function stepList(steps) {
  const ol = el("ol", "x-steps");
  (steps || []).forEach((s) => ol.append(stepItem(s)));
  return ol;
}

// One match: the card at the top of its page. ``onClose(status, note)`` starts the normal closure (the note dialog, then the status route)
// with the evidence's note filled in; without it, or for a closed match, no closure is offered.
export function explainCard(x, { status = "open", readOnly = false, onClose = null } = {}) {
  if (!x || !x.found) return null;
  const card = el("section", "gl-card gl-explain", null, { "aria-label": "What this match means" });
  card.append(el("h3", "gl-h", "What we found"), el("p", "x-found", x.found));
  const sure = el("div", "x-sure");
  sure.append(el("h3", "gl-h", "Why we show it, and how sure we are"), badge(x.confidence_label || x.confidence || "", EX.confidenceTone(x.confidence)));
  card.append(sure, el("p", "x-why", x.why || ""));
  // how the distribution's own data judged it: "Judged by Ubuntu 22.04 (jammy)'s own fixed build 1:8.9p1-3ubuntu0.10: ..."
  if (x.distro && x.distro.text) card.append(el("p", "note x-distro", x.distro.text));
  if (x.advisory && (x.advisory.advisory || x.advisory.fixed_build)) {
    const line = el("p", "note");
    line.append(document.createTextNode(`Red Hat's fix: ${[x.advisory.advisory, x.advisory.fixed_build].filter(Boolean).join(", ")} `));
    const a = link(x.advisory.url, "Open the advisory");
    if (a) line.append(a);
    card.append(line);
  }
  if ((x.steps || []).length) {
    card.append(el("h3", "gl-h", x.question ? `What to do: ${x.question.text}` : "What to do"));
    if (x.who) card.append(el("p", "note", x.who));
    card.append(stepList(x.steps));
  }
  const outcomes = outcomeList(x.outcomes);
  if (outcomes) card.append(el("h3", "gl-h", "What the answer means"), outcomes);
  const choices = onClose ? EX.closeChoices(x, status, { readOnly }) : [];
  if (choices.length) {
    const tools = el("div", "tools x-close");
    choices.forEach((c) => {
      const b = el("button", "btn ghost sm", `${c.label}…`, { type: "button", "data-close": c.status });
      b.onclick = async () => {
        b.disabled = true;
        try {
          await onClose(c.status, c.note);
        } finally {
          b.disabled = false;
        }
      };
      tools.append(b);
    });
    card.append(tools, el("p", "note", "Opens the closure note with what the commands showed filled in: add the build the command printed, then save."));
  }
  return card;
}

// One host: the questions that settle the most of its open matches, in order.
export function validatePlanCard(plan, { host = "", project = "" } = {}) {
  const groups = Array.isArray(plan) ? plan : [];
  if (!groups.length) return null;
  const box = el("div", "why validate-plan", null, { id: "validate-plan" });
  box.append(el("h3", "sec", "Settle these matches on the host"), el("p", "note", EX.planIntro(groups, host)));
  groups.forEach((g, i) => {
    const det = el("details", "x-group", null, { "data-keep-key": `plan:${g.key}` });
    if (i === 0) det.open = true;
    const sum = el("summary");
    sum.append(el("b", "", g.question || ""));
    if (g.kev) sum.append(badge("Exploited", "fire"));
    sum.append(el("span", "note", ` ${g.count} match${g.count === 1 ? "" : "es"}${g.platform_label ? ` · ${g.platform_label}` : ""}`));
    det.append(sum, stepList(g.steps));
    const outcomes = outcomeList(g.outcomes);
    if (outcomes) det.append(outcomes);
    const { shown, more } = EX.shownResolves(g.resolves);
    const list = el("p", "note x-resolves");
    list.append(document.createTextNode("Answers: "));
    shown.forEach((r, k) => {
      if (k) list.append(document.createTextNode(", "));
      list.append(project ? el("a", "mono", r.cve_id, { href: EX.matchHref(project, r.match_id), title: [r.product, r.source].filter(Boolean).join(", ") })
        : el("span", "mono", r.cve_id));
      if (r.kev) list.append(document.createTextNode(" (exploited)"));
    });
    if (more) list.append(document.createTextNode(` and ${more} more`));
    det.append(list);
    box.append(det);
  });
  return box;
}
