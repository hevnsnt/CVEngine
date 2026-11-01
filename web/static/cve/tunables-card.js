// The cards of Settings, configMaxxing that come from the generic tunable registry (cveFeed/tunables.py): AI spend, Scan pacing ... A card is
// one group of the registry; its rows, ranges, defaults and help texts all come from the server, so a new tunable needs no change here, and a new
// group is one registerTunableGroup() line below (a test keeps these ids equal to the server's groups). Everything from the server is set with
// textContent or value.
import { api, button, el, shortDate, toast } from "/staticfiles/cve/ui.js";
import { API, registerCard } from "/staticfiles/cve/config-maxxing.js";
import { canPin, canReset, changesFrom, originLines, rangeText, runningText, softWarning, sourceLabel, usageText } from "/staticfiles/cve/config-maxxing-logic.js";

const PATH = `${API}/tunables`;
const inputId = (key) => `tn-${key.replace(/[^a-z0-9]/gi, "-")}`;

function row(field, onInput, save) {
  const wrap = el("div", "field", null, { style: "padding:10px 0;border-top:1px solid var(--line, rgba(128,128,128,.25))" });
  const id = inputId(field.key);
  const input = el("input", "", null, {
    id, type: "number", inputmode: "numeric", min: String(field.min), max: String(field.max), step: "1", style: "width:96px",
    "aria-describedby": `${id}-note`,
  });
  input.value = String(field.value);
  input.dataset.key = field.key;
  input.oninput = () => onInput();
  const reset = button("Reset to default", async () => {
    await save({ [field.key]: null }, input.id);
    toast(`${field.label} is back to its default`);
  }, "btn ghost sm");
  reset.disabled = !canReset(field);
  reset.title = canReset(field) ? "Remove the value saved here" : "Nothing is saved here for this setting";
  reset.setAttribute("aria-label", `Reset ${field.label} to default`); // the visible text is the same on every row
  const controls = el("div", "", null, { style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap" });
  controls.append(input, el("span", "note", field.unit || "", { style: "margin:0" }), reset);
  if (canPin(field)) {
    const pin = button("Save this value", async () => {
      await save({ [field.key]: field.env_value }, input.id);
      toast(`${field.label} is now saved here`);
    }, "btn ghost sm");
    pin.title = `Keep ${field.env_value} here even if ${field.env_name} changes`;
    pin.setAttribute("aria-label", `Save the current value of ${field.label} here`);
    controls.append(pin);
  }
  const top = el("div", "", null, { style: "display:flex;gap:12px;align-items:center;flex-wrap:wrap;justify-content:space-between" });
  top.append(el("label", "", field.label, { for: id, style: "font-weight:500" }), controls);
  const applies = field.applies_text || runningText(field);
  const facts = el("p", "note", [sourceLabel(field), `allowed ${rangeText(field)}`, ...originLines(field, shortDate), applies, usageText(field)].filter(Boolean).join(" · "), {
    id: `${id}-note`, style: "margin:4px 0 0",
  });
  const warning = el("p", "msg err", "", { style: "margin:4px 0 0", hidden: "", role: "status" });
  wrap.append(top, el("p", "note", field.help, { style: "margin:4px 0 0" }), facts, warning);
  return { wrap, input, warning };
}

async function build(host, groupId, focusId = "") {
  const data = await api("GET", PATH);
  const group = (data.groups || []).find((g) => g.id === groupId);
  if (!group) throw new Error(`No settings are registered for ${groupId}`);
  const fields = (data.fields || []).filter((f) => f.group === groupId);
  const card = el("div", "card", null, { style: "max-width:720px" });
  card.append(el("h2", "", group.title, { style: "margin-bottom:12px" }), el("p", "note", group.intro || "", { style: "margin:0 0 12px" }));
  const inputs = [];
  const drafts = () => Object.fromEntries(inputs.map((i) => [i.dataset.key, i.value]));
  const problem = el("p", "msg err", "", { style: "margin:8px 0 0", hidden: "", role: "alert" });
  const save = async (values, focus = "") => {
    await api("PUT", PATH, { values });
    await build(host, groupId, focus || (document.activeElement && document.activeElement.id) || "");
  };
  const saveButton = button("Save", async () => {
    const { changes, error } = changesFrom(fields, drafts());
    if (error) throw new Error(error);
    await save(changes, inputId(Object.keys(changes)[0]));
    toast("Saved. The new numbers apply within a few seconds.");
  });
  const warnings = [];
  const refresh = () => {
    const current = drafts();
    const { error, changes } = changesFrom(fields, current);
    problem.textContent = error || "";
    problem.hidden = !error; // an empty error bar must not show
    saveButton.disabled = !!error || !Object.keys(changes).length;
    fields.forEach((field, i) => {
      const text = softWarning(field, current[field.key]);
      warnings[i].textContent = text; // advice only: it never disables Save
      warnings[i].hidden = !text;
    });
  };
  fields.forEach((field) => {
    const { wrap, input, warning } = row(field, refresh, save);
    inputs.push(input);
    warnings.push(warning);
    card.append(wrap);
  });
  const actions = el("div", "", null, { style: "display:flex;gap:8px;align-items:center;margin-top:12px" });
  actions.append(saveButton);
  card.append(actions, problem);
  host.textContent = "";
  host.append(card);
  refresh();
  const again = focusId && document.getElementById && document.getElementById(focusId);
  if (again && again.focus) again.focus(); // the card was drawn again after a save: keep the person where they were
}

export function registerTunableGroup(id, title) {
  registerCard({ id, title, build: (host) => build(host, id) });
}

registerTunableGroup("ai_spend", "AI spend");
registerTunableGroup("throughput", "Scan pacing");
