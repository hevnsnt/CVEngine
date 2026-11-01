// The Auto-tuning card of Settings, configMaxxing (cveFeed/autotune.py): the mode (Auto by default, Suggest, Off), the AI advisor switch, the
// last run and the tuning history with Revert and Apply. The rows of the other cards carry each setting's own badge (pinned, auto-tuned,
// suggested). Everything from the server is set with textContent or value.
import { api, ask, button, el, selectOf, shortDate, toast } from "/staticfiles/cve/ui.js";
import { API, registerCard } from "/staticfiles/cve/config-maxxing.js";
import { AUTOTUNE_INTRO, AUTOTUNE_MODES, AUTOTUNE_OFF_HELP, decisionText, lastRunText, modeNotice } from "/staticfiles/cve/config-maxxing-logic.js";

const PATH = `${API}/autotune`;

function historyRow(d, reload) {
  const row = el("div", "", null, { style: "display:flex;gap:8px;align-items:flex-start;justify-content:space-between;padding:6px 0;border-top:1px solid var(--line, rgba(128,128,128,.25))" });
  const text = el("p", "note", `${shortDate(d.at)} · ${decisionText(d)}`, { style: "margin:0" });
  row.append(text);
  if (d.can_revert) {
    const revert = button("Revert", async () => {
      const sure = await ask(`${d.label || d.setting} goes back to ${d.old_value}, and the tuner will not raise it for a day.`, { title: "Revert this change?", ok: "Revert", danger: false });
      if (!sure) return;
      await api("POST", `${PATH}/decisions/${d.id}/revert`, {});
      toast(`${d.label || d.setting} is back to ${d.old_value}`);
      await reload();
    }, "btn ghost sm");
    revert.setAttribute("aria-label", `Revert ${d.label || d.setting} to ${d.old_value}`);
    row.append(revert);
  } else if (d.can_apply) {
    const apply = button("Apply", async () => {
      await api("POST", `${PATH}/decisions/${d.id}/apply`, {});
      toast(`${d.label || d.setting} is now ${d.new_value}`);
      await reload();
    }, "btn ghost sm");
    apply.setAttribute("aria-label", `Apply ${d.new_value} to ${d.label || d.setting}`);
    row.append(apply);
  }
  return row;
}

export async function build(host, ctx = {}) {
  const data = await api("GET", PATH);
  const reload = async () => (ctx.reload ? ctx.reload() : build(host, ctx));
  const card = el("div", "card", null, { style: "max-width:720px" });
  card.append(el("h2", "", "Auto-tuning", { style: "margin-bottom:12px" }), el("p", "note", AUTOTUNE_INTRO, { style: "margin:0 0 8px" }));
  card.append(el("p", "note", AUTOTUNE_OFF_HELP, { style: "margin:0 0 12px" }));
  const notice = el("p", data.killed ? "msg err" : "note", modeNotice(data), { style: "margin:0 0 12px", role: "status" });
  card.append(notice);

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
  if (data.changed_by) card.append(el("p", "note", `Mode last set by ${data.changed_by} on ${shortDate(data.changed_at)}`, { style: "margin:8px 0 0" }));
  card.append(el("p", "note", lastRunText(data.last_run, shortDate), { style: "margin:8px 0 0" }));
  if (data.sized_for) card.append(el("p", "note", `Sized for this machine: ${data.sized_for}.`, { style: "margin:4px 0 0" }));

  card.append(el("p", "sec", "Tuning history", { style: "margin:16px 0 4px" }));
  const decisions = data.history || [];
  if (!decisions.length) card.append(el("p", "note", "No change or recommendation yet.", { style: "margin:0" }));
  decisions.forEach((d) => card.append(historyRow(d, reload)));
  host.textContent = "";
  host.append(card);
}

registerCard({ id: "autotune", title: "Auto-tuning", build });
