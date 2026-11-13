// The "AI review of this host" card of the host page (docs/AI-REVIEWER.md "Host review"): one headline, a compact verdict row for each finding, the next step
// with Start and Dismiss, Review now, and (for administrators) the project's mode in a closed disclosure. Every word from the model or the scanned host is set
// with textContent (the el() helper), never as markup. The plain words live in host-review-logic.js.
import { api, badge, el, toast } from "/staticfiles/cve/ui.js";
import { HELD_TEXT, MODES, canReview, emptyText, findingView, modeHelp, stateOf, stepView, summary, whenText } from "/staticfiles/cve/host-review-logic.js";

const POLL_MS = 5000;
const FALLBACK_AGO = (iso) => (iso ? new Date(iso).toLocaleDateString() : "never");

const settingsLink = () => document.querySelector('a[href^="/cve/settings"]'); // the rail shows Settings only to people who may open it: they are the administrators

function verdictRows(review, openFindings) {
  const views = (review.findings || []).map(findingView);
  if (!views.length) return null;
  const list = el("ul", "hr-rows", null, { "aria-label": "Verdict on each finding" });
  views.forEach((v) => {
    const row = el("li", "hr-row");
    const chip = badge(v.chip, v.tone);
    chip.setAttribute("title", v.tooltip);
    const main = el("div", "hr-main");
    const name = v.link ? el("a", "mono hr-name", v.title, { href: v.link }) : el("span", "mono hr-name", v.title);
    if (v.link) name.setAttribute("aria-label", `Open ${v.title}`);
    main.append(name);
    if (v.reason) main.append(el("span", "hr-reason", v.reason));
    if (v.note) main.append(el("span", "note hr-note", v.note, { title: v.note }));
    const tag = el("span", `note hr-tag${v.tag.tone ? ` ${v.tag.tone}` : ""}`, v.tag.text);
    row.append(chip, main, tag);
    list.append(row);
  });
  return list;
}

export function hostReviewCard({ base, hostId, isCurrent = () => true, ago = FALLBACK_AGO, poll = true }) {
  const card = el("section", "card hr-card", null, { "aria-labelledby": `host-review-h-${hostId}` });
  const path = `${base}/hosts/${hostId}/review`;
  let token = 0;
  let data = null;

  const heading = el("h3", "", "AI review of this host", { id: `host-review-h-${hostId}`, tabindex: "-1" });
  const when = el("span", "note hr-when");
  const actions = el("div", "hr-actions");
  const head = el("header", "hr-head");
  head.append(heading, when, actions);
  const body = el("div", "hr-body", null, { role: "status", "aria-live": "polite" });
  const foot = el("div", "hr-foot");
  card.append(head, body, foot);

  const refocus = () => { try { heading.focus(); } catch (_) { /* a card that is gone has no focus to give */ } };

  async function act(method, tail, payload, done) {
    try {
      const out = await api(method, `${path}${tail}`, payload);
      if (done) toast(done);
      await load(out, true);
    } catch (e) {
      toast(e.message, true);
      await load(null, true);
    }
  }

  function settingsBox() {
    foot.textContent = "";
    if (!settingsLink() || stateOf(data) === "off" && data.readiness.reason_code === "disabled") return;
    const box = el("details", "hr-settings", null, { "data-keep-key": `host-review-settings-${hostId}` });
    box.append(el("summary", "", "Settings for this project"));
    const id = `host-review-mode-${hostId}`;
    const select = el("select", "", null, { id });
    MODES.forEach(([value, text]) => {
      const o = el("option", "", text, { value });
      if (value === data.mode) o.setAttribute("selected", "");
      select.append(o);
    });
    select.value = data.mode;
    select.onchange = async () => {
      select.disabled = true;
      try {
        await api("PUT", `${base}/settings`, { host_review_mode: select.value });
        toast("Saved");
      } catch (e) {
        toast(e.message, true);
      }
      await load(null, true);
    };
    box.append(el("label", "note", "AI host review in this project", { for: id }), select,
      el("p", "note", `${modeHelp(data.mode)} This applies to every host of the project.`));
    foot.append(box);
  }

  function reviewHeader(review) {
    const ready = canReview(data);
    actions.textContent = "";
    const state = stateOf(data);
    if (state === "off") return;
    const run = el("button", "btn ghost sm", review && review.status === "applied" ? "Review again" : "Review now", { type: "button" });
    run.disabled = !ready.enabled;
    if (!ready.enabled && ready.reason) run.setAttribute("title", ready.reason);
    run.onclick = async () => {
      run.disabled = true;
      run.textContent = "Queueing…";
      await act("POST", "", {}, "Review queued");
      refocus();
    };
    actions.append(run);
  }

  function stepBlock(review) {
    const step = stepView(review.step);
    if (!step) return null;
    const box = el("div", `hr-step ${step.tone}`);
    const top = el("div", "hr-step-top");
    top.append(el("span", "hr-step-label note", "Suggested next step"), badge(step.chip, step.tone));
    box.append(top);
    box.append(step.href ? el("a", "hr-step-title", step.title, { href: step.href }) : el("p", "hr-step-title", step.title));
    if (step.why) box.append(el("p", "hr-step-why", step.why));
    if (step.start || step.dismiss) {
      const row = el("div", "hr-step-buttons");
      if (step.start) {
        const start = el("button", "btn sm", "Start", { type: "button", "aria-label": `Start: ${step.title}` });
        start.onclick = async () => {
          start.disabled = true;
          start.textContent = "Starting…";
          await act("POST", "/step", {}, "Step started");
          refocus();
        };
        row.append(start);
      }
      if (step.dismiss) {
        const dismiss = el("button", "btn ghost sm", "Dismiss", { type: "button", "aria-label": `Dismiss: ${step.title}` });
        dismiss.onclick = async () => {
          dismiss.disabled = true;
          await act("POST", "/dismiss", {}, "Dismissed");
          refocus();
        };
        row.append(dismiss);
      }
      box.append(row);
    }
    if (step.help) box.append(el("p", "note hr-step-help", step.help));
    return box;
  }

  function reading(review, into) {
    const s = summary(review);
    if (review.held_for_instructions) into.append(el("p", "msg warn hr-held", HELD_TEXT));
    into.append(el("p", "hr-headline", s.headline));
    if (s.detail) into.append(el("p", "note hr-sub", s.detail));
    if (review.host_note) into.append(el("p", "note hr-sub", review.host_note));
    const rows = verdictRows(review);
    if (rows) into.append(rows);
  }

  function draw() {
    body.textContent = "";
    const state = stateOf(data);
    const review = data.review;
    reviewHeader(review);
    when.textContent = whenText(data, ago);
    if (review && (review.decided || review.created)) when.setAttribute("title", `${new Date(review.decided || review.created).toLocaleString()}${review.model ? ` · ${review.model}` : ""}`);
    else when.removeAttribute("title");
    card.setAttribute("data-state", state);

    if (state === "applied") {
      reading(review, body);
      const step = stepBlock(review);
      if (step) body.append(step);
    } else {
      const t = emptyText(data);
      body.append(el("p", "hr-headline", t.headline));
      if (t.detail) body.append(el("p", "note hr-sub", t.detail));
      if (state === "running") body.append(badge("Running", "running"));
      if (state === "off") {
        const link = settingsLink();
        if (link && data.readiness.reason_code === "disabled") body.append(el("a", "hr-link", "Turn it on in Settings", { href: link.getAttribute("href") }));
        if (review && review.status === "applied") {
          const old = el("details", "hr-old", null, { "data-keep-key": `host-review-old-${hostId}` });
          old.append(el("summary", "", `Last review, ${ago(review.decided || review.created)} (from before it was switched off)`));
          reading(review, old);
          body.append(old);
        }
      }
    }
    settingsBox();
  }

  async function load(known, quiet) {
    const mine = ++token;
    try {
      data = known && known.status !== undefined && known.readiness ? known : await api("GET", path);
    } catch (e) {
      if (mine !== token) return;
      if (!data) {
        body.textContent = "";
        body.append(el("p", "hr-headline", "The AI review could not be read."), el("p", "note hr-sub", e.message));
        return;
      }
      if (!quiet) toast(e.message, true);
    }
    if (mine !== token || !data) return;
    draw();
    if (poll && data.review && data.review.running && stateOf(data) !== "off") {
      setTimeout(() => { if (isCurrent() && mine === token) load(null, true); }, POLL_MS);
    }
  }

  body.append(el("p", "note", "Reading the AI review of this host…"));
  load(null, false);
  return card;
}
