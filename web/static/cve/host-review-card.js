// The "AI review of this host" card of the host page (docs/AI-REVIEWER.md "Host review"): what the AI concluded about the host, each finding's verdict
// with its reason, the next step with Start and Dismiss, Review now, and the project's mode. Every word from the model or the scanned host is set with
// textContent (the el() helper), never as markup. Plain words and logic live in host-review-logic.js.
import { api, badge, el, toast } from "/staticfiles/cve/ui.js";
import { HELD_TEXT, MODES, canReview, conclusion, emptyText, failureText, findingView, heldDetail, modeHelp, stateOf, stepView } from "/staticfiles/cve/host-review-logic.js";

const POLL_MS = 5000;
const OPEN_VERDICTS = 6; // up to this many verdict lines are open by default; more sit behind the summary

function verdictList(review, project, openFindings) {
  const views = (review.findings || []).map(findingView);
  if (!views.length) return null;
  const box = el("details", "host-review-verdicts");
  if (views.length <= OPEN_VERDICTS) box.setAttribute("open", "");
  box.append(el("summary", "", `Verdict on each finding (${views.length})`));
  const list = el("ul", "host-review-list", null, { style: "list-style:none;margin:8px 0 0;padding:0;display:grid;gap:10px" });
  views.forEach((v) => {
    const item = el("li", "host-review-item");
    const head = el("div", "", null, { style: "display:flex;flex-wrap:wrap;gap:8px;align-items:center" });
    head.append(badge(v.label, v.tone), el("b", "mono", v.title, { style: "overflow-wrap:anywhere" }));
    item.append(head);
    if (v.outcome) item.append(el("p", "note", v.outcome, { style: "margin:4px 0 0" }));
    if (v.reason) item.append(el("p", "note", v.reason, { style: "margin:4px 0 0;overflow-wrap:anywhere" }));
    list.append(item);
  });
  box.append(list);
  if (openFindings) {
    const open = el("button", "btn ghost sm", "Open this host's findings", { type: "button", style: "margin-top:8px" });
    open.onclick = () => openFindings();
    box.append(open);
  }
  return box;
}

export function hostReviewCard({ base, hostId, hostName = "this host", isCurrent = () => true, openFindings = null, poll = true }) {
  const card = el("section", "why host-review", null, { "aria-labelledby": `host-review-h-${hostId}` });
  const path = `${base}/hosts/${hostId}/review`;
  let token = 0;
  let data = null;

  const heading = el("h3", "sec", "AI review of this host", { id: `host-review-h-${hostId}`, tabindex: "-1" });
  const status = el("div", "", null, { role: "status", "aria-live": "polite" });
  const modeBox = el("div", "host-review-mode", null, { style: "margin-top:12px" });
  card.append(heading, status, modeBox);

  const refocus = () => { try { heading.focus(); } catch (_) { /* a card that is gone has no focus to give */ } };

  async function act(method, tail, body, done) {
    try {
      const out = await api(method, `${path}${tail}`, body);
      if (done) toast(done);
      await load(out, true);
    } catch (e) {
      toast(e.message, true);
      await load(null, true);
    }
  }

  function drawMode() {
    modeBox.textContent = "";
    const id = `host-review-mode-${hostId}`;
    const label = el("label", "note", "AI host review in this project", { for: id });
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
    modeBox.append(label, el("br"), select, el("p", "note", `${modeHelp(data.mode)}. This applies to every host of the project.`, { style: "margin:4px 0 0" }));
  }

  function draw() {
    status.textContent = "";
    const state = stateOf(data);
    const review = data.review;
    const head = el("div", "host-assess-head");
    const now = canReview(data);
    const run = el("button", "btn sm", review && review.status === "applied" ? "Review again" : "Review now", { type: "button" });
    run.disabled = !now.enabled;
    if (!now.enabled && now.reason) run.setAttribute("title", now.reason);
    run.onclick = async () => {
      run.disabled = true;
      run.textContent = "Queueing…";
      await act("POST", "", {}, "Review queued");
      refocus();
    };
    head.append(run);
    status.append(head);

    if (state === "running") {
      status.append(el("p", "note", "The AI is reading this host's findings now. This page updates by itself when it is done.", { style: "margin:8px 0 0" }));
    } else if (state === "failed" || state === "stale") {
      status.append(badge(state === "failed" ? "Review failed" : "Host changed", state === "failed" ? "high" : "queued"), el("p", "note", failureText(review), { style: "margin:8px 0 0" }));
    } else if (state !== "applied") {
      status.append(el("p", "note", emptyText(data), { style: "margin:8px 0 0" }));
      if (state === "disabled") {
        const settings = document.querySelector('a[href^="/cve/settings"]'); // the rail shows Settings only to people who may open it
        if (settings) status.append(el("a", "", "Open Settings to turn it on", { href: `${settings.getAttribute("href")}`, style: "display:inline-block;margin-top:6px" }));
      }
      if (!now.enabled && now.reason && state === "never") status.append(el("p", "note", `Review now is not available: ${now.reason}.`));
    }

    if (state === "applied") {
      const when = review.decided || review.created;
      if (review.held_for_instructions) status.append(el("p", "msg err", HELD_TEXT, { style: "margin:8px 0" }));
      status.append(el("p", "", conclusion(review), { style: "margin:8px 0 0" }));
      if (review.host_note) status.append(el("p", "note", review.host_note, { style: "margin:4px 0 0;overflow-wrap:anywhere" }));
      status.append(el("p", "note", `Reviewed ${when ? new Date(when).toLocaleString() : ""}${review.model ? ` by ${review.model}` : ""}.`, { style: "margin:4px 0 8px" }));
      const verdicts = verdictList(review, base, openFindings);
      if (verdicts) status.append(verdicts);
      const step = stepView(review.step);
      if (step) {
        const box = el("div", "host-review-step", null, { style: "margin-top:12px" });
        box.append(el("h4", "", step.heading, { style: "margin:0 0 4px" }), badge(step.tone === "success" ? "Done" : step.tone === "high" ? "Refused" : step.start || step.dismiss ? "Waiting for you" : "Info", step.tone));
        box.append(el("p", "", step.text, { style: "margin:6px 0 0;overflow-wrap:anywhere" }));
        if (step.note) box.append(el("p", "note", step.note, { style: "margin:4px 0 0;overflow-wrap:anywhere" }));
        const held = heldDetail(review.step);
        if (held) box.append(el("p", "note", `Not started by itself: ${held}`, { style: "margin:4px 0 0" }));
        if (step.detail && step.action !== "none" && !held && !/could not be started/.test(step.text)) box.append(el("p", "note", step.detail, { style: "margin:4px 0 0" }));
        if (step.start || step.dismiss) {
          const row = el("div", "", null, { style: "display:flex;flex-wrap:wrap;gap:8px;margin-top:8px" });
          if (step.start) {
            const start = el("button", "btn sm", "Start", { type: "button", "aria-label": `Start the next step: ${step.text}` });
            start.onclick = async () => {
              start.disabled = true;
              start.textContent = "Starting…";
              await act("POST", "/step", {}, "Step started");
              refocus();
            };
            row.append(start);
          }
          if (step.dismiss) {
            const dismiss = el("button", "btn ghost sm", "Dismiss", { type: "button", "aria-label": `Dismiss the next step: ${step.text}` });
            dismiss.onclick = async () => {
              dismiss.disabled = true;
              await act("POST", "/dismiss", {}, "Dismissed");
              refocus();
            };
            row.append(dismiss);
          }
          box.append(row);
        }
        status.append(box);
      }
    }
    drawMode();
  }

  async function load(known, quiet) {
    const mine = ++token;
    try {
      data = known && known.status !== undefined && known.readiness ? known : await api("GET", path);
    } catch (e) {
      if (mine !== token) return;
      if (!data) {
        status.textContent = "";
        status.append(el("p", "note", `The AI review could not be read: ${e.message}`));
        return;
      }
      if (!quiet) toast(e.message, true);
    }
    if (mine !== token || !data) return;
    draw();
    if (poll && data.review && data.review.running) {
      setTimeout(() => { if (isCurrent() && mine === token) load(null, true); }, POLL_MS);
    }
  }

  status.append(el("p", "note", "Reading the AI review of this host…"));
  load(null, false);
  return card;
}
