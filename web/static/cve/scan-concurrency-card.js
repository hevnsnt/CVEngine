// The Scan concurrency card of Settings, configMaxxing: how many scanner runs of each kind, how many hosts are assessed at once and how many
// discovery scans are kept running. Everything from the server is set with textContent or value.
import { api, badge, button, el, shortDate, toast } from "/staticfiles/cve/ui.js";
import { API, registerCard } from "/staticfiles/cve/config-maxxing.js";
import {
  EXPLANATION_TEXT, canReset, changesFrom, checkDraft, discoveryNotice, formatMb, groupFields, memoryPlan, originLines, rangeText, runningText, sourceLabel,
} from "/staticfiles/cve/config-maxxing-logic.js";

const PATH = `${API}/scan_concurrency`;
const TONE = { applied: "success", pending: "queued", unknown: "" };
const STATE_LABEL = { applied: "Applied", pending: "Being applied", unknown: "Not confirmed" };

function fieldRow(field, data, onInput, save) {
  const row = el("div", "field", null, { style: "padding:10px 0;border-top:1px solid var(--line, rgba(128,128,128,.25))" });
  const id = `sc-${field.key.replace(/[^a-z0-9]/gi, "-")}`;
  const input = el("input", "", null, {
    id, type: "number", inputmode: "numeric", min: String(field.min), max: String(field.max), step: "1", style: "width:88px",
    "aria-describedby": `${id}-note`,
  });
  input.value = String(field.value);
  input.dataset.key = field.key;
  input.oninput = () => onInput();
  const reset = button("Reset to default", async () => {
    await save({ [field.key]: null });
    toast(`${field.label} is back to its default`);
  }, "btn ghost sm");
  reset.disabled = !canReset(field);
  reset.title = canReset(field) ? "Remove the value saved here" : "Nothing is saved here for this setting";
  const controls = el("div", "", null, { style: "display:flex;gap:8px;align-items:center" });
  controls.append(input, reset);
  const top = el("div", "", null, { style: "display:flex;gap:12px;align-items:center;flex-wrap:wrap;justify-content:space-between" });
  top.append(el("label", "", field.label, { for: id, style: "font-weight:500" }), controls);
  const facts = el("p", "note", [sourceLabel(field), `allowed ${rangeText(field)}`, ...originLines(field, shortDate), runningText(field)].join(" · "), {
    id: `${id}-note`, style: "margin:4px 0 0",
  });
  row.append(top, el("p", "note", field.help, { style: "margin:4px 0 0" }), facts);
  if (field.key === "discovery_concurrency") {
    const status = data.discovery || {};
    const line = el("p", "note", null, { style: "margin:6px 0 0" });
    line.append(badge(STATE_LABEL[status.state] || STATE_LABEL.unknown, TONE[status.state] || ""), document.createTextNode(` ${discoveryNotice(field, status)}`));
    row.append(line);
  }
  return { row, input };
}

async function build(host) {
  const data = await api("GET", PATH);
  const card = el("div", "card", null, { style: "max-width:720px" });
  card.append(el("h2", "", "Scan concurrency", { style: "margin-bottom:12px" }), el("p", "note", EXPLANATION_TEXT, { style: "margin:0 0 12px" }));
  const memory = data.memory || {};
  card.append(
    el(
      "p",
      "note",
      `Memory budget of the scanning container: ${formatMb(memory.budget_mb)}` +
        (memory.limit_mb ? ` (container limit ${formatMb(memory.limit_mb)}, set with CELERY_MEM_LIMIT)` : "") +
        (memory.budget_mb == null ? ". No worker has reported yet." : "."),
      { style: "margin:0 0 8px" },
    ),
  );
  const warnings = el("div", "", null, { role: "status", "aria-live": "polite" });
  card.append(warnings);
  const inputs = [];
  const labels = {};
  const defaults = {};
  data.fields.forEach((f) => {
    if (f.group === "heavy") {
      labels[f.key.slice(6)] = f.label;
      defaults[f.key.slice(6)] = f.default;
    }
  });
  const drafts = () => Object.fromEntries(inputs.map((i) => [i.dataset.key, i.value]));
  const refresh = () => {
    const current = drafts();
    const caps = {};
    data.fields
      .filter((f) => f.group === "heavy")
      .forEach((f) => {
        const checked = checkDraft(f, current[f.key]);
        caps[f.key.slice(6)] = checked.ok ? checked.value : f.value;
      });
    const plan = memoryPlan(caps, memory.costs_mb || {}, memory.budget_mb, defaults, labels);
    warnings.textContent = "";
    plan.warnings.forEach((w) => warnings.append(el("p", "msg err", w)));
    const { error, changes } = changesFrom(data.fields, current);
    problem.textContent = error || "";
    problem.hidden = !error; // an empty error bar must not show
    saveButton.disabled = !!error || !Object.keys(changes).length;
  };
  const save = async (values) => {
    await api("PUT", PATH, { values });
    await rebuild();
  };
  const problem = el("p", "msg err", "", { style: "margin:8px 0 0", hidden: "" });
  const saveButton = button("Save", async () => {
    const { changes, error } = changesFrom(data.fields, drafts());
    if (error) throw new Error(error);
    await save(changes);
    toast("Saved. The new limits apply within a few seconds.");
  });
  groupFields(data.fields, data.groups).forEach((group) => {
    card.append(el("p", "sec", group.title, { style: "margin:16px 0 4px" }));
    group.fields.forEach((field) => {
      const { row, input } = fieldRow(field, data, refresh, save);
      inputs.push(input);
      card.append(row);
    });
  });
  const actions = el("div", "", null, { style: "display:flex;gap:8px;align-items:center;margin-top:12px" });
  actions.append(saveButton);
  card.append(actions, problem);
  host.textContent = "";
  host.append(card);
  refresh();
  const rebuild = async () => build(host);
}

registerCard({ id: "scan_concurrency", title: "Scan concurrency", build });
