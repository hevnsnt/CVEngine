// The Auto-tuning card of Settings, configMaxxing (cveFeed/autotune.py): the mode (Auto by default, Suggest, Off), the AI advisor switch, the
// last run and the tuning history with Revert and Apply. The rows of the other cards carry each setting's own badge (pinned, auto-tuned,
// suggested). Everything from the server is set with textContent or value.
import { api, ask, button, details, el, selectOf, shortDate, toast } from "/staticfiles/cve/ui.js";
import { API, cardAnchor, registerCard } from "/staticfiles/cve/config-maxxing.js";
import { historyLine } from "/staticfiles/cve/autotune-history.js";
import { AGENT_POLICIES, AGENT_POLICY_HELP, AUTOTUNE_INTRO, AUTOTUNE_MODES, AUTOTUNE_OFF_DETAIL, AUTOTUNE_OFF_HELP, decisionText, lastRunText, modeDetail, modeNotice } from "/staticfiles/cve/config-maxxing-logic.js";

const PATH = `${API}/autotune`;
const HISTORY_SHOWN = 5;  // the first screen: the newest five changes

// One entry of the History: What (with who and when), Why, What happened, and Revert or Apply where the server says it can (can_revert, can_apply).
function historyRow(d, reload, focus) {
  const line = historyLine(d);
  const row = el("li", `at-line${line.tone === "good" || line.tone === "bad" || line.tone === "wait" ? ` at-${line.tone}` : ""}${focus ? " at-focus" : ""}`);
  if (line.id != null) row.setAttribute("id", `${cardAnchor("autotune")}-line-${line.id}`);
  const text = el("div", "", null, { style: "min-width:0" });
  const what = el("p", "at-what", line.what);
  const meta = [line.who, line.when].filter(Boolean).join(" · ");
  if (meta) what.append(el("span", "at-meta", ` · ${meta}`));
  text.append(what);
  if (line.why) text.append(labelled("Why", line.why));
  if (line.happened) text.append(labelled("What happened", line.happened));
  row.append(text);
  const name = d.label || d.setting || "this setting";
  if (line.revert) {
    const revert = button("Revert", async () => {
      const sure = await ask(`${name} goes back to ${d.old_value}, and the tuner will not raise it for a day.`, { title: "Revert this change?", ok: "Revert", danger: false });
      if (!sure) return;
      await api("POST", `${PATH}/decisions/${d.id}/revert`, {});
      toast(`${name} is back to ${d.old_value}`);
      await reload();
    }, "btn ghost sm");
    revert.setAttribute("aria-label", `Revert ${name} to ${d.old_value}`);
    row.append(revert);
  } else if (line.apply) {
    const apply = button("Apply", async () => {
      await api("POST", `${PATH}/decisions/${d.id}/apply`, {});
      toast(`${name} is now ${d.new_value}`);
      await reload();
    }, "btn ghost sm");
    apply.setAttribute("aria-label", `Apply ${d.new_value} to ${name}`);
    row.append(apply);
  }
  return row;
}

function labelled(label, words) {
  const p = el("p", "");
  p.append(el("span", "at-k", `${label}: `), words);
  return p;
}

// The newest SHOWN lines, a "Show more" for the rest; a line the page was asked to point at (an alert's link) is always among those shown.
function historySection(decisions, reload, focusId) {
  const box = el("div", "", null, { style: "margin:0 0 12px" });
  box.append(el("p", "sec", "History", { style: "margin:8px 0 4px" }));
  if (!decisions.length) {
    box.append(el("p", "note", "No change yet: auto-tune writes a line here for every change it makes.", { style: "margin:0" }));
    return box;
  }
  const list = el("ol", "at-history");
  const rows = decisions.map((d) => historyRow(d, reload, focusId != null && d.id === focusId));
  const at = focusId == null ? -1 : decisions.findIndex((d) => d.id === focusId);
  let shown = Math.max(HISTORY_SHOWN, at + 1);
  const draw = () => {
    list.textContent = "";
    rows.slice(0, shown).forEach((r) => list.append(r));
  };
  draw();
  box.append(list);
  if (decisions.length > shown) {
    const hidden = decisions.length - shown;
    const more = button(`Show more (${hidden})`, async () => {
      shown = decisions.length;
      draw();
      holder.remove();
    }, "btn ghost sm");
    more.setAttribute("aria-label", `Show the ${hidden} older ${hidden === 1 ? "change" : "changes"}`);
    const holder = el("p", "at-more");
    holder.append(more);
    box.append(holder);
  }
  return box;
}

export async function build(host, ctx = {}) {
  const data = await api("GET", PATH);
  const reload = async () => (ctx.reload ? ctx.reload() : build(host, ctx));
  const card = el("div", "card", null, { style: "max-width:720px" });
  card.append(el("h2", "", "Auto-tuning", { style: "margin-bottom:8px" }));
  const notice = el("p", data.killed ? "msg err" : "note", modeNotice(data), { style: "margin:0 0 4px", role: "status" });
  card.append(notice);
  if (modeDetail(data)) card.append(details(modeDetail(data)));
  card.append(historySection(data.history || [], reload, ctx.focus == null ? null : Number(ctx.focus)));

  card.append(el("p", "note", AUTOTUNE_INTRO, { style: "margin:0 0 8px" }), el("p", "note", AUTOTUNE_OFF_HELP, { style: "margin:0 0 8px" }), details(AUTOTUNE_OFF_DETAIL));
  const id = "autotune-mode";
  const select = selectOf(AUTOTUNE_MODES, data.mode);
  select.setAttribute("id", id);
  select.disabled = !!data.killed;
  const advisor = el("input", "", null, { type: "checkbox", id: "autotune-advisor" });
  advisor.checked = !!(data.advisor && data.advisor.enabled);
  advisor.disabled = !!data.killed;
  const a = data.advisor || {};
  const advisorNote = a.provider
    ? `Every ${a.interval_hours} hours the tuner also asks your AI provider for a second opinion on the numbers it measured (numbers only, never a host or a finding). ` +
      `Used today: ${a.used_today ?? "?"} of ${a.cap} (AI spend, Auto-tuning AI advice per day).` + (a.last_error ? ` Last question: ${a.last_error}.` : "")
    : "No AI provider is set up, so the deterministic controller tunes alone (it always can).";
  const save = button("Save", async () => {
    await api("PUT", PATH, { mode: select.value, advisor: advisor.checked });
    toast(select.value === "off" ? "Auto-tuning is off" : `Auto-tuning: ${select.value}`);
    await reload();
  });
  save.disabled = !!data.killed;
  const modeRow = el("div", "field", null, { style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap" });
  modeRow.append(el("label", "", "Mode", { for: id, style: "font-weight:500" }), select);
  const advisorRow = el("div", "field", null, { style: "display:flex;gap:8px;align-items:center;margin-top:8px" });
  advisorRow.append(advisor, el("label", "", "Ask the AI advisor", { for: "autotune-advisor" }));
  card.append(modeRow, advisorRow, el("p", "note", advisorNote, { style: "margin:4px 0 0" }));
  const actions = el("div", "", null, { style: "display:flex;gap:8px;align-items:center;margin-top:12px" });
  actions.append(save);
  card.append(actions);
  const policy = selectOf(AGENT_POLICIES, data.agent_policy || "suggest");
  policy.setAttribute("id", "autotune-agent-policy");
  policy.disabled = !!data.killed;
  policy.onchange = async () => {
    await api("PUT", PATH, { agent_policy: policy.value });
    toast(`Agents: ${policy.value}`);
    await reload();
  };
  const policyRow = el("div", "field", null, { style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:16px" });
  policyRow.append(el("label", "", "AI agents", { for: "autotune-agent-policy", style: "font-weight:500" }), policy);
  card.append(policyRow, el("p", "note", AGENT_POLICY_HELP, { style: "margin:4px 0 0" }));
  if (data.changed_by) card.append(el("p", "note", `Mode last set by ${data.changed_by} on ${shortDate(data.changed_at)}`, { style: "margin:8px 0 0" }));
  card.append(el("p", "note", lastRunText(data.last_run, shortDate), { style: "margin:8px 0 0" }));
  if (data.sized_for) card.append(el("p", "note", `Sized for this machine: ${data.sized_for}.`, { style: "margin:4px 0 0" }));

  host.textContent = "";
  host.append(card);
}

registerCard({ id: "autotune", title: "Auto-tuning", build });
