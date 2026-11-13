// Admin settings: AI, API keys, Tailscale, OpenVAS, notifications, email, scan policy, proxy. Superuser only (the API enforces it).
// DOM is built with textContent / value only; secrets are write-only (blank keeps the stored value).
import { ask, details } from "/staticfiles/cve/ui.js";
import { askScannerPlan } from "/staticfiles/cve/scanner-plan.js";
import { seedCard } from "/staticfiles/cve/seed-card.js";
import { openvasPanel } from "/staticfiles/cve/openvas-panel.js";
import { apiKeysPanel } from "/staticfiles/cve/api-keys-panel.js";
import { buildSection, cards } from "/staticfiles/cve/config-maxxing.js";
import "/staticfiles/cve/autotune-card.js"; // registers the Auto-tuning card first: the mode sits at the top of configMaxxing
import "/staticfiles/cve/scan-concurrency-card.js"; // registers its card with configMaxxing
import { FIELDS, GROUPS, anySet, applies, checkDraft, collect, effective, initialDrafts, labelOf, warnings } from "/staticfiles/cve/ai-settings-logic.js";
import { OWN_SERVER, readyToFetch, sameLabel as sameLabelOf } from "/staticfiles/cve/ai-models-logic.js";
import { autoLoad, connectionStatus, modelPicker, newSource } from "/staticfiles/cve/ai-models.js";
import "/staticfiles/cve/tunables-card.js"; // registers the cards of the generic tunable registry (AI spend, Scan pacing)
import { SECTION_ID, SECTION_LABEL, isSectionHash, parseHash, readOpen, writeOpen } from "/staticfiles/cve/config-maxxing-logic.js";

const root = document.getElementById("settings");
const csrf = root.querySelector("[name=csrfmiddlewaretoken]").value;
const API = "/cve/api/settings";

const el = (tag, cls, text, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};

async function api(method, path, body) {
  const res = await fetch(`${API}/${path}`, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try {
    data = await res.json();
  } catch (_) {
    /* empty */
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function toast(message, isError = false) {
  const t = el("div", `toast${isError ? " err" : ""}`, message, {
    role: "status",
  });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// --- tiny form kit -------------------------------------------------------------
let uid = 0;
function field(label, input, help) {
  const id = `f${(uid += 1)}`;
  input.id = id;
  const wrap = el("div", "field");
  wrap.append(el("label", "", label, { for: id }), input);
  if (help) wrap.append(el("p", "note", help, { style: "margin:6px 0 0" }));
  return wrap;
}
const text = (value = "", attrs = {}) =>
  Object.assign(el("input", "", null, attrs), { value });
const secret = (isSet, label) =>
  el("input", "", null, {
    type: "password",
    autocomplete: "new-password",
    placeholder: isSet ? "saved (leave blank to keep)" : label || "not set",
  });
function check(label, checked) {
  const box = el("input", "", null, {
    type: "checkbox",
    style: "width:auto;min-height:0",
  });
  box.checked = !!checked;
  const wrap = el("label", "", null, {
    style:
      "display:flex;gap:10px;align-items:center;margin:0 0 12px;font-weight:400",
  });
  wrap.append(box, document.createTextNode(label));
  return { wrap, box };
}
function selectOf(options, value) {
  const s = el("select");
  options.forEach(([v, t]) =>
    s.append(Object.assign(el("option", "", t), { value: v })),
  );
  s.value = value == null ? "" : value;
  return s;
}
function button(label, onClick, cls = "btn") {
  const b = el("button", cls, label, { type: "button" });
  b.onclick = async () => {
    const idle = b.textContent;
    b.disabled = true;
    b.textContent = "Working…";
    try {
      await onClick();
    } catch (err) {
      toast(err.message, true);
    }
    b.textContent = idle;
    b.disabled = false;
  };
  return b;
}
const card = (title, ...kids) => {
  const c = el("div", "card");
  c.style.maxWidth = "640px";
  c.append(el("h2", "", title), ...kids);
  c.firstChild.style.marginBottom = "12px";
  return c;
};

// The AI reviewer (docs/AI-REVIEWER.md): its own container. Its two models are chosen in "Which model does which job" with the default model;
// what is left here is when it works. Plain text everywhere; nothing here renders HTML. The page's one Save sends `body()`.
function reviewerPanel(r, markDirty) {
  const on = check("Review findings and check operations with the AI reviewer", r.enabled);
  const close = check("Close the findings it finds to be false positives (off: record its verdicts only)", r.auto_close);
  const daily = text(r.review_daily_max, { type: "number", min: "0", max: "20000" });
  const hours = text((r.ops_hours || []).join(", "), { placeholder: (r.default_ops_hours || []).join(", ") });
  // the AI host review (docs/AI-REVIEWER.md "Host review"): off until a person turns it on here, because every review is a billed AI call
  const hostOn = check("Review whole hosts with the AI (one AI call per changed host)", r.host_review_enabled);
  const hostDaily = text(r.host_review_daily_max, { type: "number", min: "0", max: "20000" });
  const status = el("p", "note");
  const waiting = el("p", "note");
  const draw = (now) => {
    const container = now.container || {};
    const inForce = now.models_in_force || {};
    status.textContent = !now.env_enabled ? "Turned off for this whole server by its administrator."
      : !container.token ? "Waiting for the server to hand the reviewer container its token."
      : `${now.working ? "Working" : "Not working (see the connection above, or a pause)"}. ${inForceText(inForce)} Reviewed today: ${now.reviews_today}. `
        + `Last call from the container: ${container.last_seen || "never"}. Last operations check: ${now.last_ops_at || "never"}.`;
    const jobs = now.ai_jobs || {};
    waiting.textContent = jobs.message || `AI jobs queued for the container: ${jobs.queued || 0}.`;
  };
  draw(r);
  const panel = card(
    "AI reviewer",
    el("p", "note", "A separate, locked-down container reviews every open finding once (again only when its host or evidence changes) and checks the server's operations a few times a day, raising admin alerts. It closes a false positive only when the server finds no hard evidence, nobody worked the finding, and no text aimed at AI agents in its evidence. It also answers the questions the AI triage queues for it; while it is off they wait. Its models are chosen above, in the table."),
    status,
    details("For the server's administrator: CVENGINE_REVIEWER=0 in the server's environment turns the reviewer off. It shows here as turned off by the administrator."),
    waiting,
    on.wrap,
    close.wrap,
    field("Findings reviewed per day at most", daily),
    field("Operations check hours (UTC, comma separated)", hours),
    el("h3", "sec", "AI review of whole hosts"),
    el("p", "note", "The AI reads every open finding of a host together, says which look real and which look like false positives, and picks one next step. It is off until you turn it on. Every review is an AI call that your AI provider bills you for (up to the daily limit below), so it stays off on a fresh install and after an update. Each project then chooses on the host page whether the AI only recommends a step (the default) or starts safe read-only steps by itself."),
    hostOn.wrap,
    field("Hosts reviewed per day at most", hostDaily),
  );
  return {
    card: panel,
    draw,
    body() {
      const list = hours.value.split(",").map((h) => h.trim()).filter(Boolean).map(Number);
      return { enabled: on.box.checked, auto_close: close.box.checked, review_daily_max: Number(daily.value), ops_hours: list,
        host_review_enabled: hostOn.box.checked, host_review_daily_max: Number(hostDaily.value) };
    },
  };
}

// "Findings are reviewed by X; operations checks use Y." from the models the server reports in force.
function inForceText(inForce) {
  if (!inForce || (!inForce.review && !inForce.ops)) return "No model is in force for the reviewer yet.";
  return `Findings are reviewed by ${inForce.review || "no model"}; operations checks use ${inForce.ops || "no model"}.`;
}

// --- sections ------------------------------------------------------------------
const sections = {
  async ai(m) {
    const [s, r] = await Promise.all([api("GET", "ai"), api("GET", "reviewer")]);
    const provider = el("select");
    const listed = new Set(s.providers);
    const grouped = GROUPS.map(([title, ids]) => [title, ids.filter((id) => listed.has(id))]);
    const named = new Set(grouped.flatMap(([, ids]) => ids));
    const others = s.providers.filter((id) => !named.has(id));
    if (others.length) grouped.push(["Other", others]);
    grouped.forEach(([title, ids]) => {
      if (!ids.length) return;
      const g = el("optgroup");
      g.label = title;
      ids.forEach((id) => g.append(Object.assign(el("option", "", labelOf(id)), { value: id })));
      provider.append(g);
    });
    provider.value = s.provider;
    const key = secret(s.has_key, "API key");
    const base = text(s.base_url, { autocomplete: "off", spellcheck: "false" });
    const keyField = field("API key", key);
    const baseField = field("Base URL", base);
    const needsUrl = s.needs_url || OWN_SERVER;
    const BASE_HINT = {
      ollama: "required, e.g. http://100.64.0.5:11434 (Tailscale or remote), or http://localhost:11434 if it runs on this server",
      vllm: "required, e.g. http://100.64.0.5:8000/v1 (vLLM) or http://localhost:8080/v1 (llama.cpp's llama-server, LiteLLM or any OpenAI-compatible server); the API key is only needed if the server asks for one",
      lmstudio: "required, e.g. http://100.64.0.5:1234/v1, or http://localhost:1234/v1 if it runs on this server (the API key is only needed when you turned on authentication in LM Studio)",
      openrouter: "optional, defaults to https://openrouter.ai/api/v1",
      openai: "optional, empty uses OpenAI (https://api.openai.com/v1); set it for a LiteLLM proxy or another OpenAI-compatible service, which then gets the key you type here",
      anthropic: "optional, empty uses Anthropic (https://api.anthropic.com); set it for a gateway or proxy, which then gets the key you type here",
    };
    // What is stored now, per job, so that a change of provider can be undone by choosing the old one again and a save can say what changed.
    const savedModels = { default: s.model || "", review: r.review_model || "", ops: r.ops_model || "", nuclei: s.nuclei_model || "" };
    let dirty = false;
    let refreshHints = () => {}; // set below, once the request settings exist
    let drawInForce = () => {};
    const source = newSource();
    const readiness = () => {
      const p = provider.value;
      return readyToFetch({ provider: p, typedKey: key.value, hasKey: s.has_key, baseUrl: base.value, keyless: s.keyless, needsUrl, sameAsSaved: p === s.provider });
    };
    const readNow = () => ({ ...readiness(), provider: provider.value, api_key: key.value.trim(), base_url: base.value.trim() });
    const context = () => {
      const ready = readiness();
      return { provider: provider.value, baseUrl: base.value, selectable: s.selectable, label: labelOf(provider.value), needsKey: !!ready.needsKey, needsAddress: !!ready.needsAddress };
    };
    const connection = connectionStatus(source, context);
    const defaultPick = modelPicker({ source, context, job: "default", saved: savedModels.default, onChange: () => markDirty() });
    const reviewPick = modelPicker({
      source, context, job: "reviewer", saved: savedModels.review, onChange: () => markDirty(),
      sameLabel: (c) => sameLabelOf(c.provider, "review", r.default_models), recommendFor: (_st, c) => (c.provider === "anthropic" ? r.default_models.review : ""),
    });
    const opsPick = modelPicker({
      source, context, job: "reviewer", saved: savedModels.ops, onChange: () => markDirty(),
      sameLabel: (c) => sameLabelOf(c.provider, "ops", r.default_models), recommendFor: (_st, c) => (c.provider === "anthropic" ? r.default_models.ops : ""),
    });
    // The Nuclei job: empty is the default, the cheapest haiku the provider lists (the server finds it in the list), else the default model.
    const nucleiPick = modelPicker({
      source, context, job: "reviewer", saved: savedModels.nuclei, onChange: () => markDirty(),
      sameLabel: () => (source.state.nucleiDefault ? `Default: ${source.state.nucleiDefault}` : "Default: same as Everything else"),
      recommendFor: (st) => st.nucleiDefault || "",
    });
    const advancedAddress = el("details", "ai-adv");
    advancedAddress.open = !!s.base_url;
    advancedAddress.append(el("summary", "", "Advanced: use a gateway or proxy address"), baseField);
    const sync = () => {
      const p = provider.value;
      const own = needsUrl.includes(p);
      key.placeholder = s.keyless.includes(p)
        ? "optional"
        : s.has_key && p === s.provider
          ? "saved (leave blank to keep)"
          : "API key";
      base.placeholder = BASE_HINT[p] || "optional";
      keyField.style.display = p === "ollama" ? "none" : "";
      // the address is part of the connection where the server is yours (required: plain box), under Advanced where a vendor has its own
      advancedAddress.classList.toggle("ai-adv-own", own);
      advancedAddress.querySelector("summary").textContent = own ? "Server address" : "Advanced: use a gateway or proxy address";
      if (own) advancedAddress.open = true;
      refreshHints();
    };
    provider.addEventListener("change", () => {
      const same = provider.value === s.provider;
      base.value = provider.value === s.provider ? (s.base_url || "") : ""; // an address belongs to the service it was saved for
      if (!same) advancedAddress.open = false;
      defaultPick.set(same ? savedModels.default : ""); // a model belongs to the provider it was chosen from
      reviewPick.set(same ? savedModels.review : "");
      opsPick.set(same ? savedModels.ops : "");
      nucleiPick.set(same ? savedModels.nuclei : "");
      sync();
      drawInForce();
    });
    // The list is fetched when the page opens, and when the provider, the key or the address changes (the source waits for typing to pause).
    const loader = autoLoad(source, readNow, [{ el: provider }, { el: key }, { el: base }]);
    // --- how a request is made: timeouts, reply limit, context window, JSON mode, reasoning, keep-alive -----------------------------------
    // An empty box follows the server's environment variable and then the provider's default; the line under each box says which one applies.
    const inputs = {};
    const hints = {};
    const wraps = {};
    const adv = el("details", "ai-adv");
    adv.open = anySet(s);
    adv.append(
      el("summary", "", "Request settings"),
      el("p", "note", "How each request to the model is made. Leave a box empty to use the provider's default (or the server's environment setting, if it has one); the line under each box says what is in force. These apply to every task the model does and to the connection test."),
    );
    const grid = el("div", "ai-adv-grid");
    const warnBox = el("div", "ai-warns", null, { role: "status" });
    FIELDS.forEach((f) => {
      const initial = initialDrafts(s)[f.key];
      const input =
        f.kind === "choice"
          ? selectOf(f.choices, initial)
          : text(initial, { autocomplete: "off", spellcheck: "false", ...(f.kind === "number" ? { inputmode: "numeric" } : { placeholder: f.placeholder || "" }) });
      const wrap = field(f.label, input, f.help);
      const hint = el("p", "note ai-hint", "", { id: `${input.id}-hint` });
      input.setAttribute("aria-describedby", hint.id);
      wrap.append(hint);
      // The hint under a box follows every keystroke; the one announced region (warnBox) is rewritten when the value is committed.
      input.addEventListener("input", () => refreshHints(false));
      input.addEventListener("change", () => refreshHints(true));
      inputs[f.key] = input;
      hints[f.key] = hint;
      wraps[f.key] = wrap;
      grid.append(wrap);
    });
    adv.append(grid, warnBox);
    const drafts = () => Object.fromEntries(FIELDS.map((f) => [f.key, inputs[f.key].value]));
    refreshHints = (announce = true) => {
      const p = provider.value;
      const now = drafts();
      const problems = [];
      FIELDS.forEach((f) => {
        wraps[f.key].style.display = applies(s, f.key, p) ? "" : "none";
        const checked = checkDraft(s, f.key, now[f.key]);
        inputs[f.key].setAttribute("aria-invalid", checked.ok ? "false" : "true");
        const eff = effective(s, f.key, p, now[f.key]);
        hints[f.key].textContent = checked.ok ? eff.text : checked.error;
        hints[f.key].className = `note ai-hint${checked.ok ? "" : " ai-hint-err"}`;
        if (!checked.ok && applies(s, f.key, p)) problems.push(`${f.label}: ${checked.error}`);
        if (f.kind === "number") inputs[f.key].placeholder = checked.ok && eff.value != null ? String(eff.value) : "default";
      });
      if (announce) {
        warnBox.replaceChildren(
          ...problems.map((w) => el("p", "note ai-warn ai-warn-err", w)),
          ...warnings(s, p, now).map((w) => el("p", "note ai-warn", w)),
        );
      }
    };
    sync();
    const enabled = check("Use this model to confirm CVE matches", s.enabled);
    const fire = check(
      "Auto-fire: on a new FIRE or SMOKE CVE, pick affected targets and test their hosts",
      s.auto_fire,
    );
    const max = text(s.auto_fire_max_scans, {
      type: "number",
      min: "1",
      max: "5000",
    });
    const planTotal = text(s.plan_daily_total, {
      type: "number",
      min: "0",
      max: "100000",
    });
    const planProject = text(s.plan_daily_per_project, {
      type: "number",
      min: "0",
      max: "100000",
    });
    const guideDaily = text(s.cve_guidance_daily, { type: "number", min: "0", max: "100000" });
    const gp = s.cve_guidance;
    const guideNote = el("p", "note", gp
      ? `${gp.cves.toLocaleString()} CVEs: guidance written by rules for ${gp.rules.toLocaleString()}, by the model for ${gp.ai.toLocaleString()}, by a person for ${gp.manual.toLocaleString()}. ${gp.local_only.toLocaleString()} are only usable from the host itself and never matched. ${gp.ai_pending.toLocaleString()} still wait for the model${gp.days_left ? `: about ${gp.days_left.toLocaleString()} day${gp.days_left === 1 ? "" : "s"} at ${gp.daily_budget.toLocaleString()} a day` : ""}. The model handled ${gp.ai_last_day.toLocaleString()} in the last day.`
      : "CVE guidance progress is not available yet.");
    const guideNow = text("200", { type: "number", min: "1", max: "5000", "aria-label": "How many CVEs to write guidance for now" });
    const guideRun = button("Write now", async () => {
      const r = await api("POST", "cve_guidance/run", { count: guideNow.value });
      guideNote.textContent = `Queued: the model writes guidance for the next ${r.queued} CVEs. Progress shows here after a refresh.`;
    }, "btn ghost sm");
    const verified = el("p", "note", "");
    const showVerified = () => {
      verified.textContent = s.verified_at
        ? `Connection verified ${new Date(s.verified_at).toLocaleString()}.`
        : "Not tested since the last change.";
    };
    showVerified();
    const status = el("p", "msg", "", { role: "status", "aria-live": "polite", hidden: "" });
    const say = (message, ok) => {
      status.hidden = !message;
      status.className = `msg ${ok ? "ok" : "err"}`;
      status.textContent = message || "";
    };
    const dirtyNote = el("p", "note ai-dirty", "", { role: "status", "aria-live": "polite" });
    const markDirty = () => {
      dirty = true;
      dirtyNote.textContent = "You have unsaved changes.";
    };
    m.addEventListener("input", (e) => { if (!e.target.closest("[data-nodirty]")) markDirty(); });
    m.addEventListener("change", (e) => { if (!e.target.closest("[data-nodirty]")) markDirty(); });
    const reviewerP = reviewerPanel(r, markDirty);
    const save = async () => {
      const { values, errors } = collect(s, drafts(), provider.value); // only what the chosen provider uses: a hidden box cannot be fixed
      const bad = FIELDS.find((f) => errors[f.key]);
      if (bad) {
        adv.open = true;
        refreshHints();
        inputs[bad.key].focus();
        const message = `${bad.label}: ${errors[bad.key]}`;
        say(message, false); // beside the toast, which goes after 3.5 seconds
        throw new Error(message);
      }
      for (const [pick, name] of [[defaultPick, "the default model"], [reviewPick, "the finding review model"], [opsPick, "the operations check model"], [nucleiPick, "the Nuclei targeting model"]]) {
        if (pick.error) {
          pick.focus();
          say(`Fix ${name}: ${pick.error}`, false);
          throw new Error(`Fix ${name}: ${pick.error}`);
        }
      }
      if (enabled.box.checked && s.selectable.includes(provider.value) && !defaultPick.value) {
        defaultPick.focus();
        const message = `${labelOf(provider.value)} serves whichever models you pick or host: choose the default model before turning confirmation on.`;
        say(message, false);
        throw new Error(message);
      }
      const saved = await api("PUT", "ai", {
        ...values,
        cve_guidance_daily: guideDaily.value,
        plan_daily_total: planTotal.value,
        plan_daily_per_project: planProject.value,
        provider: provider.value,
        model: defaultPick.value,
        nuclei_model: nucleiPick.value,
        api_key: key.value,
        base_url: base.value,
        enabled: enabled.box.checked,
        auto_fire: fire.box.checked,
        auto_fire_max_scans: max.value,
      });
      Object.assign(s, saved); // the stored provider, address and settings, so a later change of provider restores the right address
      savedModels.default = s.model || "";
      savedModels.nuclei = s.nuclei_model || "";
      key.value = "";
      key.placeholder = s.has_key ? "saved (leave blank to keep)" : "API key";
      let after;
      try {
        after = await api("PUT", "reviewer", { ...reviewerP.body(), review_model: reviewPick.value, ops_model: opsPick.value });
      } catch (err) {
        throw new Error(`The connection and the default model were saved, but the reviewer settings were not: ${err.message}`);
      }
      Object.assign(r, after);
      savedModels.review = r.review_model || "";
      savedModels.ops = r.ops_model || "";
      defaultPick.set(savedModels.default, { stored: true });
      reviewPick.set(savedModels.review, { stored: true });
      opsPick.set(savedModels.ops, { stored: true });
      nucleiPick.set(savedModels.nuclei, { stored: true });
      reviewerP.draw(r);
      showVerified();
      refreshHints();
      dirty = false;
      dirtyNote.textContent = "";
      drawInForce();
      loader.ask(true);
    };
    // What is in force, in words: the saved default, and the models the server reports for the reviewer.
    const inForce = el("p", "ai-inforce", "", { role: "status", "aria-live": "polite" });
    drawInForce = () => {
      const named = s.model || (provider.value === s.provider && source.state.recommended ? `${source.state.recommended} (the newest cheapest)` : "the newest cheapest model");
      const nuclei = s.nuclei_model || (provider.value === s.provider ? source.state.nucleiDefault || s.nuclei_model_in_force : "") || "the default model, once the list loads";
      inForce.textContent = `In force now: everything else uses ${named}${provider.value === s.provider ? "" : " once you save"}. Nuclei targeting and tag selection uses ${nuclei}. ${r.models_in_force ? inForceText(r.models_in_force) : "The reviewer has no model until a connection is saved."}`;
    };
    source.subscribe(drawInForce);
    drawInForce();
    const jobRow = (title, about, pick) => {
      const id = `ai-job-${(uid += 1)}`;
      pick.select.id = id;
      const name = el("th", "ai-job", null, { scope: "row" });
      name.append(el("label", "ai-job-name", title, { for: id }), el("p", "note ai-job-about", about));
      const cell = el("td", "ai-job-pick");
      cell.append(pick.wrap);
      const tr = el("tr");
      tr.append(name, cell);
      return tr;
    };
    const jobs = el("table", "ai-jobs", null, { "aria-label": "Which model does which job" });
    const jobsBody = el("tbody");
    jobsBody.append(
      jobRow("Everything else", "The default model. Triages every finding, confirms CVE matches, plans validation checks and Nuclei scans, and writes CVE guidance. It runs on every scan in many small requests, so this is where most of the spend goes: a cheap model is the right choice. The daily caps are under AI spend.", defaultPick),
      jobRow("Nuclei targeting and tag selection", "Chooses which detection templates apply to the software found. A smaller, faster model works well here and avoids refusals.", nucleiPick),
      jobRow("Finding review", "The AI reviewer. Reads each open finding once, and again only when its host or evidence changes, up to the daily limit below. One larger request per finding, so a stronger model costs the most here.", reviewPick),
      jobRow("Operations check", "The AI reviewer. Looks over the work queue, the scanners and the errors a few times a day (four by default) and writes an alert for each problem. A handful of small requests a day, so the cost hardly matters.", opsPick),
    );
    jobs.append(jobsBody);
    const testNote = el("p", "note", "", { role: "status", "aria-live": "polite" });
    const refreshLink = el("button", "ai-link", "Refresh list", { type: "button" });
    refreshLink.onclick = async () => {
      const ask = readNow();
      if (!ask.ok) return connection.draw();
      await loader.refresh();
    };
    const connectionCard = card(
      "Connection",
      field("Provider", provider),
      keyField,
      advancedAddress,
      connection.node,
      (() => {
        const row = el("div", "ai-actions");
        row.append(
          button("Test connection", async () => {
            if (!readNow().ok) return connection.draw();
            await loader.refresh();
          }, "btn ghost"),
        );
        return row;
      })(),
    );
    const modelsCard = card(
      "Which model does which job",
      el("p", "note", "Each job can use its own model. The lists are the models your provider offers right now. A model you choose here is used from the next request; nothing already running is changed."),
      jobs,
      inForce,
      (() => {
        const row = el("div", "ai-actions");
        row.append(refreshLink, button("Send a test message", async () => {
          if (dirty) throw new Error("Save first: the test message uses the saved settings.");
          testNote.textContent = "Sending a test message...";
          try {
            const res = await api("POST", "ai/test");
            testNote.textContent = `The model answered: ${res.reply}`;
            say(`Connection OK. The model answered: ${res.reply}`, true);
          } catch (err) {
            testNote.textContent = err.message; // stays on the page: the sentence says what to change
            say(err.message, false);
          }
          Object.assign(s, await api("GET", "ai")); // verified_at moved
          showVerified();
        }, "btn ghost"));
        return row;
      })(),
      testNote,
      verified,
    );
    modelsCard.classList.add("ai-models-card");
    const limitsCard = card(
      "Confirmation and limits",
      enabled.wrap,
      field("Validation planning requests per day, all projects", planTotal),
      field("Validation planning requests per day, one project", planProject),
      (() => {
        const f = field("CVE guidance written by the model per day (each CVE is one paid request; 0 turns it off)", guideDaily);
        f.append(guideNote);
        const row = el("div", "tools guide-now", null, { "data-nodirty": "" });
        row.append(el("span", "note", "Or, from what is left of today's budget, write the next"), guideNow, el("span", "note", "CVEs now"), guideRun);
        f.append(row);
        return f;
      })(),
      adv,
    );
    m.append(connectionCard, el("div", "", null, { style: "height:16px" }), modelsCard, el("div", "", null, { style: "height:16px" }), limitsCard);
    sync();
    loader.ask(true); // the page opens with its lists filled: nothing to press
    const seedState = await api("GET", "cve_seed");
    m.append(el("div", "", null, { style: "height:16px" }), seedCard({ el, api, toast, card, csrf, apiBase: API, initial: seedState }));
    const seedParts = [m.children[m.children.length - 2], m.lastChild]; // the seed build is not a setting: it goes below the settings, before the Save bar
    m.append(
      el("div", "", null, { style: "height:16px" }),
      card(
        "Auto-fire",
        fire.wrap,
        field("Max hosts tested per CVE", max),
      ),
      el("div", "", null, { style: "height:16px" }),
      reviewerP.card,
      ...seedParts,
    );
    const bar = el("div", "ai-savebar");
    bar.append(
      button("Save AI settings", async () => {
        say("");
        await save();
        say(`Saved. ${inForce.textContent}`, true);
        toast("Saved");
      }),
      dirtyNote,
      status,
    );
    m.append(bar);
  },

  async updates(m) {
    const host = el("div");
    const sourceHost = el("div");
    m.append(host, sourceHost);
    const when = (iso) => (iso ? new Date(iso).toLocaleString() : "never");
    const ago = (ms) => {
      const sec = Math.max(0, Math.round(ms / 1000));
      return sec < 60 ? `${sec} s` : `${Math.floor(sec / 60)} min ${String(sec % 60).padStart(2, "0")} s`;
    };
    // What happens after Approve, in order, with what to expect. `at` is the step the host is on now (1 = waiting for the host).
    const UPDATE_STEPS = [
      ["Approved", "Done."],
      ["The host picks it up", "Within a few seconds once the host updater is installed. Nothing happens until it is."],
      ["New work pauses, this server settles", "Up to a minute. Scans that run on Sentinels are not waited for: the Sentinels keep what they finish and hand it over when cvENGINE is back."],
      ["The files are updated", "About 10 seconds."],
      ["The services rebuild and restart", "2 to 5 minutes. The page greys out and comes back on its own."],
      ["Scanning resumes", "Immediately; the page reloads."],
    ];
    const SETUP_COMMAND = "cd /opt/cvengine && git pull --ff-only && sudo scripts/install-updater.sh";
    const stepAt = (s, hu) => {
      if (s.phase === "resuming" || s.phase === "done") return 5;
      if (s.phase === "applying") return /^merging/.test(s.phase_detail || "") ? 3 : 4;
      if (s.phase === "draining" && !/could not reach|local changes/.test(s.phase_detail || "")) return 2;
      return 1;
    };
    const copyButton = (value) =>
      button("Copy command", async () => {
        try {
          await navigator.clipboard.writeText(value);
          toast("Copied");
        } catch (_) {
          toast("Select the command and copy it");
        }
      }, "btn ghost");
    // Shown while no host updater is listening: say what is missing and give the one command that fixes it.
    const setupBox = (s) => {
      const box = el("div", "", null, { style: "border:1px solid var(--border,#ccc);border-radius:8px;padding:12px 14px;margin:12px 0" });
      box.append(
        el("p", "", "One-time setup on the server", { style: "font-weight:600;margin:0 0 6px" }),
        el("p", "note", "CVEngine cannot restart itself: the web app has no Docker access on purpose. A small script on the server does the update, and it is not installed or not running there, so Approve has nothing to wake. Run this once on the server, as the user that owns the CVEngine folder (adjust the folder if it is not /opt/cvengine):"),
        el("pre", "", SETUP_COMMAND, { style: "margin:8px 0;padding:8px 10px;white-space:pre-wrap;overflow-wrap:anywhere;user-select:all;font-size:13px;background:var(--surface-2,#f4f4f4);border-radius:6px" }),
        el("p", "note", s.status === "approved" ? "It pulls this version, starts the watcher, and applies the update you approved straight away. From then on every update starts within seconds of Approve and nothing more is needed on the server." : "It pulls this version and starts the watcher. After that, Approve starts an update within seconds and nothing more is needed on the server."),
        copyButton(SETUP_COMMAND),
      );
      return box;
    };
    const timeline = (s, hu) => {
      const at = stepAt(s, hu);
      const steps = UPDATE_STEPS.map((x) => x.slice());
      if (s.wait_for_scans) steps[2] = ["New scans pause, running scans finish", "As long as the longest running scan: minutes for most, up to a few hours for a deep scan."];
      const wrap = el("div", "", null, { style: "margin:12px 0" });
      const waited = s.approved_at ? Date.now() - Date.parse(s.approved_at) : 0;
      wrap.append(el("p", "", `Approved ${ago(waited)} ago. Typical total once the host is listening and no scan is running: about 3 to 6 minutes.`, { style: "margin:0 0 8px;font-weight:500" }));
      const list = el("ol", "", null, { style: "list-style:none;margin:0;padding:0" });
      steps.forEach(([title, expect], i) => {
        const blocked = i === 1 && at === 1 && !hu.alive;
        const mark = i < at ? "\u2713" : i === at ? (blocked ? "!" : "\u25CF") : "\u25CB";
        const live = i === at ? (s.phase_detail && !blocked ? ` ${s.phase_detail}.` : blocked ? " Not happening: no host updater is listening." : "") : "";
        const row = el("li", "", null, { style: `display:flex;gap:10px;padding:4px 0;${i > at ? "opacity:.55" : ""}` });
        row.append(
          el("span", "", mark, { style: "width:1.2em;flex:none;text-align:center", "aria-hidden": "true" }),
          el("span", "", null),
        );
        row.lastChild.append(el("strong", "", title), el("span", "note", ` ${i < at ? "Done." : expect}${live}`));
        list.append(row);
      });
      wrap.append(list);
      return wrap;
    };
    let timer = 0;
    const draw = (s) => {
      clearTimeout(timer);
      host.textContent = "";
      const head = {
        up_to_date: "CVEngine is up to date.",
        available: "A newer version is available.",
        dismissed: "A newer version is available (dismissed).",
        approved: "Update approved. Waiting for the host updater to apply it.",
        error: "The last check failed.",
        unknown: "Whether a newer version is available cannot be told.",
        disabled: "Update checks are turned off.",
      }[s.status];
      const kids = [el("p", "", head, { style: "font-weight:500;margin:0 0 6px" })];
      kids.push(
        el(
          "p",
          "note",
          `Installed ${s.installed_known ? s.installed : "unknown"}, latest ${s.latest || "unknown"} on ${s.repo}@${s.branch}. Last checked ${when(s.last_checked_at)}.`,
        ),
      );
      if (s.last_error) kids.push(el("p", "msg err", s.last_error));
      const hu = s.host_updater || {};
      // How updates are installed. Manual is the default: the code of this server never changes unless an administrator chose Automatic.
      const modeBox = el("fieldset", "", null, { style: "border:0;padding:0;margin:12px 0" });
      modeBox.append(el("legend", "", "How updates are installed", { style: "font-weight:600;padding:0;margin-bottom:6px" }));
      [
        ["manual", "Manual", "CVEngine tells you when a new version exists. Nothing is installed until you click Approve."],
        ["auto", "Automatic", "When the twice-daily check finds a new version, CVEngine approves it and the server installs it shortly after: scans pause and finish first, then the services restart. The code on this server changes without you being asked."],
      ].forEach(([value, label, help]) => {
        const row = el("label", "", null, { style: "display:flex;gap:10px;align-items:flex-start;margin:6px 0;cursor:pointer" });
        const radio = el("input", "", null, { type: "radio", name: "update-mode", value });
        radio.checked = (s.mode || "manual") === value;
        radio.onchange = async () => {
          try {
            draw(await api("PUT", "updates", { mode: value }));
            toast(value === "auto" ? "Updates are now installed automatically" : "Updates are now manual");
          } catch (err) {
            toast(err.message);
            draw(s);
          }
        };
        const text = el("span", "");
        text.append(el("strong", "", label), el("span", "note", ` ${help}`));
        row.append(radio, text);
        modeBox.append(row);
      });
      kids.push(modeBox);
      // An update does not wait for scans that run on Sentinels. Waiting for them is an option, off by default.
      const waitRow = el("label", "", null, { style: "display:flex;gap:10px;align-items:flex-start;margin:6px 0 12px;cursor:pointer" });
      const waitBox = el("input", "", null, { type: "checkbox", name: "update-wait-scans" });
      waitBox.checked = s.wait_for_scans === true;
      waitBox.onchange = async () => {
        try {
          draw(await api("PUT", "updates", { wait_for_scans: waitBox.checked }));
          toast(waitBox.checked ? "Updates now wait for running scans to finish" : "Updates no longer wait for scans");
        } catch (err) {
          toast(err.message);
          draw(s);
        }
      };
      const waitText = el("span", "");
      waitText.append(
        el("strong", "", "Wait for scans to finish before updating"),
        el("span", "note", " Off (the default): an update pauses new work and rebuilds within a minute. Scans that run on your Sentinels are not waited for; the Sentinels keep what they finish and hand it over when cvENGINE is back. On: the update waits for every running scan first (minutes, or hours for a deep scan), then interrupts what is left after the drain limit."),
      );
      waitRow.append(waitBox, waitText);
      kids.push(waitRow);
      // The web interface certificate renews itself 30 days before it ends (the host's renewal check); this speaks up only when it did not.
      const cert = s.certificate || {};
      if (cert.problem) kids.push(el("p", "msg err", cert.problem));
      else if (cert.known && cert.days_left != null)
        kids.push(el("p", "note", `Web interface certificate: valid for ${cert.days_left} more days, renewed automatically when fewer than 30 remain${cert.last_renewed_at ? ` (last renewed ${when(cert.last_renewed_at)})` : ""}.`));
      if (s.mode === "auto" && !hu.alive)
        kids.push(el("p", "msg err", "Automatic needs something on the server to install the update: the host updater (below), or automatic deployment (scripts/install-auto-deploy.sh). The host updater is not reporting; if this server uses automatic deployment you can ignore this."));
      if (["available", "dismissed", "approved", "up_to_date"].includes(s.status)) {
        if (hu.alive) {
          kids.push(el("p", "note", `Host updater: listening (last seen ${hu.age_seconds} s ago). An approved update starts within seconds.`));
        } else if (hu.seen) {
          kids.push(el("p", "msg err", `The host updater stopped reporting ${Math.max(1, Math.round(hu.age_seconds / 60))} minutes ago, so an approved update will not start. On the server, check that cron is running and run scripts/install-updater.sh.`));
        } else if (s.status !== "up_to_date") {
          kids.push(el("p", "msg err", "The host updater has not reported in, so Approve will not start anything yet."));
        }
        if (!hu.alive && s.status !== "up_to_date") kids.push(setupBox(s));
      }
      if (s.status === "approved") kids.push(timeline(s, hu));
      // a server with commits of its own cannot be moved forward for the administrator: say what to do, never offer Approve
      if (s.local_commits > 0 && s.behind_by > 0 && ["diverged", "dismissed"].includes(s.status))
        kids.push(el("p", "msg err", `The branch has ${s.behind_by} new commit${s.behind_by === 1 ? "" : "s"}, but this server has ${s.local_commits} of its own on top of ${s.common || "it"}, so an update cannot be applied for you (it moves the checkout forward and never merges). On the server run git fetch origin, then git merge origin/${s.branch}, then scripts/update.sh or make up.`));
      else if (s.local_commits > 0 && s.status === "up_to_date")
        kids.push(el("p", "note", `This server has ${s.local_commits} commit${s.local_commits === 1 ? "" : "s"} of its own on top of ${s.branch}; everything on the branch is included.`));
      if (s.status === "unknown" && !s.last_error)
        kids.push(el("p", "msg err", "Whether this server is behind cannot be told: GitHub has never seen the commit it was built from (commits of its own that were not pushed), and the host has not said which commit it shares with the branch. The host updater reports that within half an hour of running; if it is not installed, run scripts/install-updater.sh."));
      if (s.host_comparison) kids.push(el("p", "note", s.host_comparison));
      if (["available", "dismissed", "approved", "diverged"].includes(s.status)) {
        kids.push(
          el(
            "p",
            "",
            `${s.latest_message}${s.behind_by ? ` (${s.behind_by} commit${s.behind_by === 1 ? "" : "s"} ahead)` : ""}`,
            { style: "margin:10px 0 4px" },
          ),
        );
        if (s.commits.length) {
          const list = el("ul", "note", null, { style: "margin:0 0 10px;padding-left:18px" });
          s.commits.forEach((c) => list.append(el("li", "", `${c.sha}  ${c.message}`)));
          kids.push(list);
        }
        if (s.latest_url) kids.push(el("a", "note", "View on GitHub", { href: s.latest_url, target: "_blank", rel: "noopener noreferrer", style: "display:block;margin:0 0 14px" }));
      }
      if (s.scanner_notice) kids.push(el("p", "msg", `${s.scanner_notice.text} `, { style: "margin-top:10px", role: "status" }), el("a", "note", "Open Sentinels", { href: "/cve/sentinels/" }), document.createTextNode(" "));
      if (s.discovery_pin_notice) kids.push(el("p", "msg", s.discovery_pin_notice, { style: "margin-top:10px", role: "status" }));
      if (s.branch_warning) kids.push(el("p", "msg err", s.branch_warning, { style: "margin-top:10px" }));
      if (s.status === "approved") {
        kids.push(
          el("p", "note", s.approved_by === "automatic" ? `Approved automatically at ${when(s.approved_at)} because updates are set to Automatic.` : `Approved by ${s.approved_by} at ${when(s.approved_at)}.`, { style: "margin-top:10px" }),
          button("Cancel approval", async () => { draw(await api("POST", "updates/cancel")); toast("Approval cancelled"); }, "btn ghost"),
        );
      } else if (["available", "dismissed"].includes(s.status)) {
        // Not enough disk for this update (measured by the host): say so in plain words and keep the button off, with the reason on it
        if (s.disk && s.disk.short) kids.push(el("p", "msg err", s.disk.text, { id: "update-disk-short", role: "alert" }));
        const approveButton = button("Approve update", async () => {
            // the question worth asking first (which scanners run), asked by the server's facts; no question, no dialog: the button just updates
            const fresh = await api("GET", "updates");
            if (fresh.scanner_choice && fresh.scanner_choice.needs_choice) {
              const plan = await askScannerPlan(fresh.scanner_choice);
              if (!plan) return;
              draw(await api("POST", "updates/approve", { sentinels: plan }));
              toast("Approved");
              return;
            }
            const note = (s.branch_warning ? s.branch_warning + " " : "") + (hu.alive
              ? "Scans are paused, running ones finish, then the host rebuilds and restarts the services."
              : "The host updater is not reporting, so nothing will start until it is installed on the server (scripts/install-updater.sh).");
            if (!(await ask(note, { title: `Update CVEngine to ${s.latest}?`, ok: "Approve update", danger: false }))) return;
            draw(await api("POST", "updates/approve"));
            toast("Approved");
        });
        if (s.disk && s.disk.short) {
          approveButton.disabled = true;
          approveButton.title = s.disk.text;
          approveButton.setAttribute("aria-describedby", "update-disk-short");
        }
        kids.push(approveButton);
        if (s.status === "available")
          kids.push(document.createTextNode(" "), button("Dismiss", async () => { draw(await api("POST", "updates/dismiss")); }, "btn ghost"));
      }
      kids.push(document.createTextNode(" "), button("Check now", async () => { draw(await api("POST", "updates/check")); toast("Checked"); }, "btn ghost"));
      host.append(card("Updates", ...kids));
      if (s.status === "approved")
        timer = setTimeout(async () => {
          if (!host.isConnected) return;
          try {
            draw(await api("GET", "updates"));
          } catch (_) {
            timer = setTimeout(() => draw(s), 4000); // the services restart during an update: keep trying
          }
        }, 4000);
    };
    const drawSource = (s) => {
      const enabled = check("Check GitHub for updates twice a day", s.enabled);
      const repo = text(s.repo);
      const branch = text(s.branch);
      const token = secret(s.has_token, "only for a private repository");
      sourceHost.append(
        el("div", "", null, { style: "height:16px" }),
        card(
          "Update source",
          enabled.wrap,
          field("GitHub repository (owner/name)", repo),
          field("Branch", branch, "Changing it makes the next approved update move this server to that branch, when that is safe (it must keep every database migration that is installed). If it is not, Settings says why and nothing moves."),
          field("Access token", token, "A fine-grained token with read-only Contents access. Stored write-only."),
          button("Save", async () => {
            const changed = repo.value !== s.repo || branch.value !== s.branch;
            let next = await api("PUT", "updates", { enabled: enabled.box.checked, repo: repo.value, branch: branch.value, token: token.value });
            if (changed) next = await api("POST", "updates/check"); // a different source: look at it straight away
            draw(next);
            toast(changed ? "Saved, and checked the new source" : "Saved");
          }),
        ),
      );
    };
    const first = await api("GET", "updates");
    drawSource(first);
    draw(first);
  },

  async reset(m) {
    const s = await api("GET", "factory_reset");
    const list = el("ul", "note", null, { style: "margin:6px 0 12px;padding-left:18px" });
    [
      `${s.organizations} organization${s.organizations === 1 ? "" : "s"} and ${s.projects} project${s.projects === 1 ? "" : "s"}`,
      `${s.targets} target${s.targets === 1 ? "" : "s"}, ${s.hosts} host${s.hosts === 1 ? "" : "s"} and ${s.scans} scan${s.scans === 1 ? "" : "s"} with all their results, files and screenshots`,
      `${s.users} other user${s.users === 1 ? "" : "s"}, memberships and API tokens`,
      "the AI model settings, API keys, notification, email, proxy and report settings, IP allowlist and bans",
      "the CVE feed, matches, generated checks, AI activity, audit log, scheduled scans and update settings",
    ].forEach((t) => list.append(el("li", "", t)));
    const keep = el(
      "p",
      "note",
      "Kept: your own account (same password and two-step sign-in), the scan engines and installed tools. Afterwards you land in the setup wizard, as on a new install. This cannot be undone.",
      { style: "margin:0 0 18px" },
    );
    const phrase = text("", { placeholder: s.phrase, autocomplete: "off", spellcheck: "false" });
    const password = el("input", "", null, { type: "password", autocomplete: "current-password" });
    const force = check(
      `${s.running_scans} scan${s.running_scans === 1 ? " is" : "s are"} still running or queued: reset anyway`,
      false,
    );
    const go = button(
      "Reset to factory settings",
      async () => {
        const r = await api("POST", "factory_reset", {
          confirm: phrase.value,
          password: password.value,
          force: force.box.checked,
        });
        password.value = "";
        toast("Reset complete");
        location.href = r.redirect;
      },
      "btn danger",
    );
    const kids = [
      el("p", "", "This removes everything below and starts the instance over.", { style: "font-weight:500;margin:0" }),
      list,
      keep,
      field(`Type ${s.phrase} to confirm`, phrase),
      field("Your password", password),
    ];
    if (s.running_scans) kids.push(force.wrap);
    kids.push(go);
    m.append(card("Factory reset", ...kids));
  },

  async resources(m) {
    const host = el("div");
    m.append(host);
    const mb = (v) => (v == null ? "?" : v >= 1024 ? `${(v / 1024).toFixed(1)} GB` : `${v} MB`);
    const secs = (n) => (n >= 3600 ? `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m` : n >= 60 ? `${Math.floor(n / 60)}m ${n % 60}s` : `${n}s`);
    const list = (title, rows, empty) => {
      const wrap = el("div", "", null, { style: "margin-top:12px" });
      wrap.append(el("p", "sec", title));
      if (!rows.length) wrap.append(el("p", "note", empty));
      rows.forEach((r) => wrap.append(el("div", "find", r)));
      return wrap;
    };
    // Always shown, also when no worker has reported yet (the cards below are not drawn then).
    const pointer = () => {
      const note = el("p", "note", "Scan concurrency moved to configMaxxing: how many scans of each kind run at once, how many hosts are assessed at once and how many discovery scans are kept running. ", { style: "margin:0" });
      note.append(
        Object.assign(el("a", "", "Open configMaxxing", { href: `#${SECTION_ID}` }), {
          onclick: (event) => {
            event.preventDefault();
            open(SECTION_ID);
          },
        }),
      );
      const box = el("div", "card", null, { style: "max-width:640px;margin-bottom:16px" });
      box.append(note);
      return box;
    };
    const draw = (snap) => {
      host.textContent = "";
      host.append(pointer());
      if (!snap.containers.length) {
        host.append(card("Resources", el("p", "note", "No worker has reported yet. The celery worker publishes its memory every 30 seconds.")));
        return;
      }
      snap.containers.forEach((c) => {
        const mem = c.memory || {};
        const total = mem.total_mb || 1;
        const pct = Math.min(100, Math.round(((mem.used_mb || 0) / total) * 100));
        const bar = el("div", "", null, { style: "height:12px;border-radius:3px;background:var(--sunk);overflow:hidden;margin:8px 0" });
        const fill = el("div", "", null, { style: `height:100%;width:${pct}%;transition:width .6s ease;background:${pct > 90 ? "var(--fire)" : pct > 75 ? "var(--smoke)" : "var(--ok)"}` });
        bar.append(fill);
        const kids = [
          el("p", "", `${mb(mem.used_mb)} used of ${mb(mem.limit_mb || mem.total_mb)}${mem.limit_mb ? " (container limit)" : ""}; ${mb(mem.available_mb)} free`, { style: "margin:0;font-weight:500" }),
          bar,
          el("p", "note", `Heavy jobs (bbot, nmap, nuclei) start only while their estimated memory fits the budget of ${mb(c.budget_mb)} and ${mb(c.headroom_mb)} stays free. If free memory drops under ${mb(c.critical_mb)}, the biggest job is stopped and retried lighter, so the worker is never lost.`),
          list(
            `Running (${c.running.length})`,
            c.running.map((j) => `${j.label}: reserved ${mb(j.reserved_mb)}, using ${mb(j.rss_mb)}, ${secs(j.seconds)}`),
            "Nothing heavy is running.",
          ),
          list(
            `Waiting for memory (${c.waiting.length})`,
            c.waiting.map((j) => `${j.label}: needs ${mb(j.needs_mb)}, waiting ${secs(j.seconds)}`),
            "Nothing is waiting.",
          ),
          list(
            `Stopped for memory in the last 24 hours (${c.memory_kills.length})`,
            c.memory_kills.map((k) => `${new Date(k.t * 1000).toLocaleTimeString()}  ${k.kind} on ${k.label}: used ${mb(k.rss_mb)}, ${mb(k.available_mb)} free`),
            "None. The queue is keeping up.",
          ),
        ];
        if (c.age_seconds > 120) kids.push(el("p", "msg err", `This worker last reported ${secs(c.age_seconds)} ago.`));
        host.append(card(`Container ${c.host}`, ...kids), el("div", "", null, { style: "height:16px" }));
      });
      host.append(
        card(
          "Tuning",
          el("p", "note", "Memory reserved per job (an estimate at first, raised to what real runs needed): " +
            Object.entries(snap.costs_mb || {}).map(([k, v]) => `${k} ${mb(v)}`).join(", ") + "."),
          details(
            "For the server's administrator: container ceilings come from CELERY_MEM_LIMIT, WEB_MEM_LIMIT and BEAT_MEM_LIMIT (docker-compose, default 4g, 1g, 512m).",
            "Override the per-job estimate with HEAVY_COST_SCALE, HEAVY_MEMORY_BUDGET_MB or HEAVY_COST_<KIND>_MB in the celery environment.",
          ),
        ),
      );
    };
    let timer = null;
    const refresh = async () => {
      try {
        draw(await api("GET", "resources"));
      } catch (err) {
        host.textContent = "";
        host.append(el("p", "msg err", err.message));
      }
      if (document.body.contains(host)) timer = setTimeout(refresh, 5000);
    };
    await refresh();
  },

  async [SECTION_ID](m) {
    await buildSection(m, { card: parseHash(location.hash).card });
  },

  async tailscale(m) {
    const wrap = el("div");
    m.append(wrap);
    const lines = (box) => box.value.split(/[\s,]+/).filter(Boolean);
    const when = (iso) => (iso ? new Date(iso).toLocaleString() : "never");
    const statusBadge = (l) => {
      const cls = { ok: "", partial: "medium", error: "failed", never: "" }[l.last_status] || "";
      const word = { ok: "synced", partial: "synced with notes", error: "error", never: "not synced yet" }[l.last_status] || l.last_status;
      return el("span", `badge ${cls}`.trim(), l.enabled ? word : "off");
    };
    // one card: an existing link, or (link === null) the form that connects a tailnet to a project
    const linkCard = (link, projects, redraw) => {
      const l = link || {};
      const project = link
        ? null
        : selectOf(projects.map((p) => [p.id, p.org ? `${p.name} (${p.org})` : p.name]), projects[0] && projects[0].id);
      const kind = l.credential_kind;
      const clientId = text("", { autocomplete: "off", placeholder: kind === "oauth" ? "saved (leave blank to keep)" : "OAuth client id" });
      const clientSecret = secret(kind === "oauth", "OAuth client secret");
      const token = secret(kind === "token", "or an API access token (tskey-api-...)");
      const routing = selectOf(
        [
          ["auto", "This server's Tailscale node (the compose `tailscale` profile)"],
          ["host", "Already routed: the Docker host is on the tailnet"],
        ],
        l.routing || "auto",
      );
      const enabled = check("Keep this project's targets in step with the tailnet (sync every 15 minutes)", link ? l.enabled : true);
      const local = check("Also read this server's own Tailscale node (the compose `tailscale` profile), no credential needed", link ? l.use_local : true);
      const policy = check("Read the tailnet policy file for tailnet-wide findings (needs the policy_file:read scope)", link ? l.check_policy : true);
      const auto = check("Auto-scan: queue the normal discovery and scan pipeline for new and changed online devices", !!l.auto_scan);
      const cap = text(l.max_devices || 100, { type: "number", min: "1", max: "5000" });
      const onlyTags = text((l.only_tags || []).join(" "), { placeholder: "tag:server tag:prod (empty: any device)" });
      const skipTags = text((l.skip_tags || []).join(" "), { placeholder: "tag:printer" });
      const onlyOs = text((l.only_os || []).join(" "), { placeholder: "linux windows (empty: any)" });
      const body = () => ({
        enabled: enabled.box.checked,
        use_local: local.box.checked,
        routing: routing.value,
        check_policy: policy.box.checked,
        auto_scan: auto.box.checked,
        max_devices: cap.value,
        only_tags: lines(onlyTags),
        skip_tags: lines(skipTags),
        only_os: lines(onlyOs),
        client_id: clientId.value,
        client_secret: clientSecret.value,
        access_token: token.value,
      });
      const pid = () => (link ? l.project.id : project.value);
      const kids = [];
      if (link) {
        const status = el("div", "", null, { style: "display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px" });
        status.append(
          statusBadge(l),
          el("span", "note", `${l.tailnet || "tailnet not named yet"}: ${l.device_count} device${l.device_count === 1 ? "" : "s"} on the tailnet, ${l.imported} imported (${l.online} online, ${l.offline} offline, ${l.departed} departed). Last sync ${when(l.last_sync_at)}.`, { style: "margin:0" }),
        );
        kids.push(status);
        if (l.last_error) kids.push(el("p", "msg err", l.last_error));
        if (!l.scan_reachable) kids.push(el("p", "note", "Scans cannot reach this tailnet yet, so its devices are listed and checked but not scanned."));
        const node = l.local && l.local.backend_state ? `This server's node is ${l.local.backend_state}${l.local.self_name ? ` as ${l.local.self_name}` : ""}, running Tailscale ${l.local.version || "?"}.` : "";
        if (node) kids.push(el("p", "note", node));
      } else {
        kids.push(field("Project the tailnet's devices become targets of", project));
      }
      kids.push(
        el("p", "note", "Credentials are stored encrypted and never shown again. Create an OAuth client with only these read-only scopes: devices:core:read, devices:routes:read, policy_file:read and devices:posture_attributes:read (policy_file:read needs the other two).", { style: "margin:0 0 10px" }),
        field("OAuth client id", clientId),
        field("OAuth client secret", clientSecret),
        field("API access token (alternative to an OAuth client)", token, "An access token expires after at most 90 days; an OAuth client does not and can be revoked."),
        enabled.wrap,
        field("How scans reach the tailnet", routing, "Scanning needs a route: with the compose profile this server joins the tailnet itself. Choose Already routed only if the Docker host is on the tailnet and containers can reach 100.x addresses through it; that is taken on your word. Without a route devices are still listed and checked from API data, but never scanned."),
        local.wrap,
        policy.wrap,
        auto.wrap,
        field("Most devices one sync imports or queues for scanning", cap, "The rest follow on the next sync. Existing devices are always kept up to date."),
        field("Only devices tagged", onlyTags),
        field("Never devices tagged", skipTags),
        field("Only these operating systems", onlyOs),
        el("p", "note", "Devices shared into your tailnet from another tailnet are never imported, and neither is this server's own node. Hosts excluded for the organization are never added or scanned.", { style: "margin:0 0 12px" }),
      );
      const out = el("p", "note", "", { style: "margin:8px 0 0" });
      const actions = el("div", "", null, { style: "display:flex;gap:8px;flex-wrap:wrap" });
      actions.append(
        button(link ? "Save" : "Connect", async () => {
          if (!link && !project.value) throw new Error("Choose a project first");
          await api("PUT", `tailscale/${pid()}`, body());
          toast("Saved");
          await redraw();
        }),
        button("Test connection", async () => {
          const r = await api("POST", `tailscale/${pid()}/test`, body());
          out.className = r.ok ? "note" : "msg err";
          out.textContent = r.ok
            ? `Connected${r.tailnet ? ` to ${r.tailnet}` : ""}: ${r.devices} device${r.devices === 1 ? "" : "s"}.${r.policy ? ` Policy file: ${r.policy}.` : ""}${r.local && r.local.backend_state ? ` This server's node: ${r.local.backend_state}.` : ""}${r.local && r.local.error ? ` This server's node: ${r.local.error}.` : ""}`
            : r.error;
        }, "btn ghost"),
      );
      if (link) {
        actions.append(
          button("Sync now", async () => {
            await api("POST", `tailscale/${pid()}/sync`);
            toast("Sync queued: refresh in a minute");
          }, "btn ghost"),
          button("Disconnect", async () => {
            if (!(await ask("The project keeps its targets and findings; the devices are archived and their tailnet addresses can no longer be scanned.", { title: "Disconnect this tailnet?", ok: "Disconnect" }))) return;
            await api("DELETE", `tailscale/${pid()}`);
            toast("Disconnected");
            await redraw();
          }, "btn ghost"),
        );
      }
      return card(link ? `Tailnet of ${l.project.name}` : "Connect a tailnet", ...kids, actions, out);
    };
    const draw = async () => {
      wrap.textContent = "";
      const s = await api("GET", "tailscale");
      wrap.append(
        card(
          "Tailscale",
          el("p", "note", "Connect a tailnet to a project and its devices become targets automatically, are scanned like any other host and are checked for Tailscale-specific problems (outdated clients with known security fixes, key expiry, stale devices, broad subnet routes, an allow-all policy, broad SSH rules). Connecting is what authorises scanning the addresses of the devices it imports (100.64.0.0/10 and fd7a:115c:a1e0::/48), and nothing else in those ranges."),
          el("p", "note", "Scanning needs this server's own Tailscale node (the compose `tailscale` profile, see docs/TAILSCALE.md) or a Docker host that is already on the tailnet. Without a route, devices are still listed and checked from API data, but never scanned."),
        ),
        el("div", "", null, { style: "height:16px" }),
      );
      s.links.forEach((link) => {
        wrap.append(linkCard(link, [], draw), el("div", "", null, { style: "height:16px" }));
      });
      if (s.projects.length) wrap.append(linkCard(null, s.projects, draw));
    };
    await draw();
  },

  async openvas(m) {
    await openvasPanel(m);
  },

  async keys(m) {
    await apiKeysPanel(m);
  },

  async notifications(m) {
    const s = await api("GET", "notifications");
    const hooks = {
      slack_hook_url: secret(s.has_slack_hook_url, "Slack webhook URL"),
      discord_hook_url: secret(s.has_discord_hook_url, "Discord webhook URL"),
      lark_hook_url: secret(s.has_lark_hook_url, "Lark webhook URL"),
      telegram_bot_token: secret(
        s.has_telegram_bot_token,
        "Telegram bot token",
      ),
      telegram_bot_chat_id: secret(
        s.has_telegram_bot_chat_id,
        "Telegram chat id",
      ),
    };
    const labels = {
      slack_hook_url: "Slack webhook",
      discord_hook_url: "Discord webhook",
      lark_hook_url: "Lark webhook",
      telegram_bot_token: "Telegram bot token",
      telegram_bot_chat_id: "Telegram chat id",
    };
    const flags = {};
    const channelKits = [
      ["send_to_slack", "Send to Slack"],
      ["send_to_discord", "Send to Discord"],
      ["send_to_lark", "Send to Lark"],
      ["send_to_telegram", "Send to Telegram"],
    ].map(([f, l]) => {
      flags[f] = check(l, s[f]);
      return flags[f].wrap;
    });
    const eventKits = [
      ["send_scan_status_notif", "Scan status"],
      ["send_vuln_notif", "New vulnerabilities"],
      ["send_interesting_notif", "Interesting findings"],
      ["send_subdomain_changes_notif", "Subdomain changes"],
      ["send_scan_output_file", "Attach scan output files"],
      ["send_scan_tracebacks", "Include tracebacks"],
    ].map(([f, l]) => {
      flags[f] = check(l, s[f]);
      return flags[f].wrap;
    });
    m.append(
      card(
        "Notifications",
        el("h3", "", "Channels", { style: "font-size:14px;margin:0 0 8px" }),
        ...channelKits,
        ...Object.entries(hooks).map(([k, input]) => field(labels[k], input)),
        el("h3", "", "Send notifications for", {
          style: "font-size:14px;margin:16px 0 8px",
        }),
        el(
          "p",
          "note",
          "These channels are shared by the whole instance, not by one project. New vulnerabilities sends at most one message per feed sync for fire-level CVE matches on your hosts, one message per auto-fire run for the hosts its template tests confirmed vulnerable (batched, however many CVEs ran), and one per scan; each names a few hosts and counts the rest. A message can therefore mention hosts of several projects.",
          { style: "margin:0 0 8px" },
        ),
        ...eventKits,
        button("Save", async () => {
          const body = {};
          Object.entries(flags).forEach(([f, c]) => {
            body[f] = c.box.checked;
          });
          Object.entries(hooks).forEach(([k, input]) => {
            if (input.value) body[k] = input.value;
          });
          await api("PUT", "notifications", body);
          Object.values(hooks).forEach((i) => {
            i.value = "";
            i.placeholder = "saved (leave blank to keep)";
          });
          toast("Saved");
        }),
      ),
    );
  },

  async email(m) {
    const s = await api("GET", "email");
    const on = check(
      "Send email (people you add get an onboarding email with a link to choose their password)",
      s.enabled,
    );
    const host = text(s.host, {
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "none",
      placeholder: "smtp.example.com",
    });
    const port = text(String(s.port), { inputmode: "numeric" });
    const security = selectOf(
      [
        ["starttls", "STARTTLS (usually port 587)"],
        ["ssl", "SSL/TLS (usually port 465)"],
        ["none", "None (port 25 relay, no login)"],
      ],
      s.security,
    );
    const user = text(s.username, {
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "none",
    });
    const pass = secret(s.has_password, "not set");
    const fromAddress = text(s.from_address, {
      type: "email",
      autocomplete: "off",
      placeholder: "cvengine@example.com",
    });
    const fromName = text(s.from_name, { placeholder: "cvENGINE" });
    const verify = check(
      "Verify the server certificate (turn off only for a relay you trust that uses a private or self-signed certificate)",
      s.verify_certificate,
    );
    const linkBase = text(s.link_base, {
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "none",
      placeholder: s.link_effective,
    });
    const status = el("p", "note", "", { style: "margin:12px 0 0" });
    const showTest = (t) => {
      status.textContent = t
        ? `Last test ${t.ok ? "worked" : "failed"} (${new Date(t.at).toLocaleString()}, to ${t.to})${t.ok ? "." : `: ${t.error}`}`
        : "No test message sent yet.";
      status.className = `note${t && !t.ok ? " err" : ""}`;
    };
    showTest(s.last_test);
    const body = () => {
      const b = {
        enabled: on.box.checked,
        host: host.value,
        port: port.value,
        security: security.value,
        username: user.value,
        from_address: fromAddress.value,
        from_name: fromName.value,
        verify_certificate: verify.box.checked,
        link_base: linkBase.value,
      };
      if (pass.value) b.password = pass.value;
      return b;
    };
    const save = async () => {
      await api("PUT", "email", body());
      pass.value = "";
      pass.placeholder = "saved (leave blank to keep)";
    };
    const to = text("", {
      type: "email",
      autocomplete: "off",
      placeholder: "your own address",
    });
    m.append(
      card(
        "Email",
        el(
          "p",
          "note",
          "The mail server cvENGINE sends through. When someone is added with an email address, they receive their username and a one-time link to choose a password, so no password is handed around. With mail off, or no address on the account, you are shown a temporary password as before. The password is write-only: once saved it is never shown again.",
          { style: "margin:0 0 12px" },
        ),
        on.wrap,
        field("Mail server", host),
        field("Port", port),
        field("Security", security),
        field("User name", user, "Leave empty for a relay that needs no login."),
        field("Password", pass),
        field("From address", fromAddress),
        field("From name", fromName),
        verify.wrap,
        field(
          "Link address (optional)",
          linkBase,
          `Links in the email start with this address. Leave empty to use ${s.link_effective}, built from this server's DOMAIN_NAME. Set it when people reach cvENGINE at a different address, such as https://scanner.example.com.`,
        ),
        button("Save", async () => {
          await save();
          toast("Saved");
        }),
        el("h3", "", "Send a test message", {
          style: "font-size:14px;margin:20px 0 8px",
        }),
        field(
          "Send it to",
          to,
          "Saves the settings above first. Empty sends it to the address on your own account.",
        ),
        button(
          "Send test message",
          async () => {
            await save();
            const r = await api("POST", "email/test", { to: to.value });
            showTest(r.last_test);
            toast(
              r.ok ? `Test message sent to ${r.to}` : r.error,
              !r.ok,
            );
          },
          "btn ghost",
        ),
        status,
      ),
    );
  },

  async scan_policy(m) {
    const policy = await api("GET", "scan_policy");
    const everything = check(
      "Let scans run every Nuclei template that is installed (turn off to run only the read-only ones)",
      policy.nuclei_all_templates,
    );
    const credentials = check(
      "Allow checks that send credentials (default logins and brute force)",
      policy.allow_credential_checks,
    );
    const policyCard = card(
      "Nuclei templates",
      el(
        "p",
        "note",
        "By default scans run the whole template library Nuclei ships, including checks that send requests other than plain reads. Turn this off to run only templates that read (plain GET, HEAD or OPTIONS requests to the scanned host). Templates the AI writes always stay read-only, and Nuclei's denial-of-service templates stay excluded.",
      ),
      everything.wrap,
      el(
        "p",
        "note",
        "Off by default. Some templates try a product's default username and password against a login form. Scans never run them unless you turn this on, and the targeted pass never picks them. Turn it on only for hosts you are allowed to try logins against.",
      ),
      credentials.wrap,
      button("Save", async () => {
        await api("PUT", "scan_policy", {
          nuclei_all_templates: everything.box.checked,
          allow_credential_checks: credentials.box.checked,
        });
        toast("Saved");
      }),
    );
    policyCard.style.maxWidth = "none";
    m.append(policyCard);
    m.append(
      el(
        "p",
        "note",
        "Every scan runs the same fixed pipeline (discovery, nmap, the read-only checks, correlation, triage). There are no per-scan engines to edit: earlier versions listed editable engine configurations inherited from reNgine, but nothing ever read them, so they were removed.",
      ),
    );
  },

  async ip_allowlist(m) {
    const wrap = el("div");
    m.append(wrap);
    const draw = async () => {
      wrap.textContent = "";
      const s = await api("GET", "ip_allowlist");
      const use = check(
        `Restrict access to the IPs/CIDRs below (your current IP: ${s.your_ip})`,
        s.enabled,
      );
      const rows = el("div", "grid");
      s.entries.forEach((e) => {
        const row = el("div");
        row.append(
          el("span", "", e.label ? `${e.cidr} (${e.label})` : e.cidr),
          document.createTextNode(" "),
          button(
            "Remove",
            async () => {
              await api("DELETE", `ip_allowlist/entries/${e.id}`);
              toast("Removed");
              await draw();
            },
            "btn ghost sm",
          ),
        );
        rows.append(row);
      });
      const cidr = text("", {
        placeholder: "e.g. 203.0.113.4 or 203.0.113.0/24",
      });
      const label = text("", { placeholder: "optional label" });
      const addRow = el("div", "inline-add");
      addRow.append(
        cidr,
        label,
        button(
          "Add my current IP",
          () => {
            cidr.value = s.your_ip;
          },
          "btn ghost",
        ),
        button("Add", async () => {
          await api("POST", "ip_allowlist/entries", {
            cidr: cidr.value,
            label: label.value,
          });
          toast("Added");
          await draw();
        }),
      );
      wrap.append(
        card(
          "IP allowlist",
          el(
            "p",
            "note",
            "When enabled, every request to this app (web UI, admin, API) from an IP not listed below is blocked.",
          ),
          use.wrap,
          rows,
          addRow,
          el("div", "", null, { style: "height:8px" }),
          button("Save", async () => {
            await api("PUT", "ip_allowlist", { enabled: use.box.checked });
            toast("Saved");
            await draw();
          }),
        ),
      );
    };
    await draw();
  },

  // Settings > Sentinels: the one instance switch of "keep Sentinels on the newest version" (agentapi/sentinel_autoupdate.py). Per Sentinel, the Sentinels page has
  // "Update now" and the self-update setting (Off is the opt-out).
  async sentinels(m) {
    const v1 = async (method, body) => {
      const res = await fetch("/api/v1/sentinels/defaults", {
        method,
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
        body: body ? JSON.stringify(body) : undefined,
      });
      let data = {};
      try {
        data = await res.json();
      } catch (_) {
        /* empty */
      }
      if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
      return data;
    };
    const s = await v1("GET");
    const keep = check("Keep Sentinels on the newest version", s.keep_newest);
    keep.wrap.style.minHeight = "44px";
    keep.box.style.cssText = "width:24px;height:24px;min-height:0;flex:none";
    m.append(
      card(
        "Sentinels",
        el(
          "p",
          "note",
          "On by default. When a Sentinel runs a build behind the newest published one, cvENGINE asks it to update: at most once every 6 hours per Sentinel, never while it runs a long task, never to a build this server cannot run yet, and every request is in the audit log. The built-in scanner is updated through this server's host updater. Turn it off here for all Sentinels, or set one Sentinel's self-update to Off on the Sentinels page to keep just that one where it is.",
          { style: "margin:0 0 14px" },
        ),
        keep.wrap,
        button("Save", async () => {
          const next = await v1("PUT", { keep_newest: keep.box.checked });
          toast(next.keep_newest ? "Sentinels are kept on the newest version" : "Sentinels are no longer asked to update");
        }),
      ),
    );
  },
  async reports(m) {
    const s = await api("GET", "reports");
    const inputs = {
      company_name: text(s.company_name, { placeholder: "Acme Security" }),
      company_address: text(s.company_address),
      company_email: text(s.company_email, { type: "email" }),
      company_website: text(s.company_website, { placeholder: "https://example.com" }),
      footer_text: text(s.footer_text),
      primary_color: text(s.primary_color, { type: "color", style: "min-height:44px;padding:4px" }),
      secondary_color: text(s.secondary_color, { type: "color", style: "min-height:44px;padding:4px" }),
    };
    const summary = Object.assign(el("textarea", "", null, { rows: "7", spellcheck: "false" }), { value: s.executive_summary_description });
    const exec = check("Include an executive summary", s.show_executive_summary);
    const footer = check("Show a footer on every page", s.show_footer);
    const credit = check("Show the CVEngine credit line", s.show_banner);
    m.append(
      card(
        "Reports",
        el("p", "note", "Branding for the PDF and HTML reports you download from a scan. Nothing here is sent anywhere.", { style: "margin:0 0 14px" }),
        field("Company name", inputs.company_name),
        field("Address", inputs.company_address),
        field("Contact email", inputs.company_email),
        field("Website", inputs.company_website),
        field("Accent colour", inputs.primary_color),
        field("Heading colour", inputs.secondary_color),
        exec.wrap,
        field(
          "Executive summary text",
          summary,
          "Markdown. Placeholders: {company_name} {target_name} {scan_date} {subdomain_count} {vulnerability_count} {critical_count} {high_count} {medium_count} {low_count} {info_count}",
        ),
        footer.wrap,
        field("Footer text", inputs.footer_text),
        credit.wrap,
        button("Save", async () => {
          await api("PUT", "reports", {
            ...Object.fromEntries(Object.entries(inputs).map(([k, v]) => [k, v.value])),
            executive_summary_description: summary.value,
            show_executive_summary: exec.box.checked,
            show_footer: footer.box.checked,
            show_banner: credit.box.checked,
          });
          toast("Saved");
        }),
      ),
    );
  },

  async proxy(m) {
    const s = await api("GET", "proxy");
    const use = check(
      "Route scan traffic through the proxies below",
      s.use_proxy,
    );
    const list = Object.assign(
      el("textarea", "", null, {
        rows: "6",
        spellcheck: "false",
        placeholder: "http://127.0.0.1:8080\nsocks5://127.0.0.1:9050",
        style:
          "width:100%;font:13px/1.5 var(--mono);padding:10px 12px;border:0;border-radius:6px;box-shadow:var(--ring)",
      }),
      { value: s.proxies },
    );
    m.append(
      card(
        "Proxy",
        el(
          "p",
          "note",
          "When on, scans that run on this server send their traffic to your targets through one of these proxies, picked per request in turn: the web probes and checks, nuclei, bbot, WPScan, testssl.sh and wafw00f. If a proxy is down the request fails; it never falls back to a direct connection.",
        ),
        el(
          "p",
          "note",
          "Not covered, still sent directly from this server: nmap, naabu, the UDP sweeps, the database and RDP checks and OpenVAS, because they need raw sockets that an HTTP or SOCKS proxy cannot carry. A Sentinel runs on its own machine and keeps its own connection; it does not use this list. Calls to outside services (CVE feeds, AI providers, Shodan, GitHub and the like) are not proxied either. Do not rely on this setting for anonymity of those.",
        ),
        el(
          "p",
          "note",
          "Use http://host:port, socks5://host:port or socks5h://host:port. An https:// proxy works for the external tools only, and testssl.sh takes only an http:// proxy without a login. When no proxy suits a tool, that tool does not run. Loopback and this stack's own services are never proxied; the server's CVENGINE_PROXY_BYPASS lists more.",
        ),
        use.wrap,
        field("Proxies (one per line)", list),
        button("Save", async () => {
          await api("PUT", "proxy", {
            use_proxy: use.box.checked,
            proxies: list.value,
          });
          toast("Saved");
        }),
      ),
    );
  },
};

// --- tabs ------------------------------------------------------------------------
// Thirteen tabs never fit on one line, so they are grouped: a column beside the panel on a wide screen, wrapped rows on a narrow one.
const view = root.querySelector("#view");
view.classList.add("set-layout");
// A navigation list, not a tablist: the groups hold a collapsible heading button and a link next to the section buttons, which a tablist may not own.
// The open section is marked with aria-current.
const tabs = el("nav", "set-nav", null, {
  "aria-label": "Settings",
});
const panel = el("div", "set-panel");
view.append(tabs, panel);
// Essentials are the four things most installs ever touch; everything else is under Advanced, collapsed. OpenVAS is not in Settings: its one
// place is Administration > OpenVAS, which an organization admin can open too (the panel is the same).
const essentials = ["ai", "alerts", "reports", "updates", "sentinels"];
const advanced = ["keys", "tailscale", "scan_policy", "ip_allowlist", "proxy", "resources", "reset"];
const labels = {
  ai: "AI model",
  alerts: "Alerts",
  reports: "Reports",
  updates: "Updates",
  sentinels: "Sentinels",
  keys: "API keys",
  tailscale: "Tailscale",
  scan_policy: "Scan policy",
  ip_allowlist: "IP allowlist",
  proxy: "Proxy",
  resources: "Resources",
  reset: "Factory reset",
};
// Alerts: where this server sends notices (chat webhooks) and how it sends mail, one pane instead of two
sections.alerts = async (m) => {
  const mail = el("div");
  await sections.notifications(m);
  m.append(mail);
  await sections.email(mail);
};

// configMaxxing: the advanced tunables. A group of its own that is collapsed until opened; whether it is open is remembered per viewer.
let storage = null;
try {
  storage = window.localStorage;
} catch (_) {
  /* blocked: the group stays collapsed by default and nothing is remembered */
}
const advItems = el("div", "set-group-items", null, { id: "set-adv-items" });
const advToggle = el("button", "set-group-title set-toggle", "Advanced", { type: "button", "aria-controls": "set-adv-items" });
function setAdvOpen(isOpen) {
  advItems.hidden = !isOpen;
  advToggle.setAttribute("aria-expanded", String(isOpen));
}
const cmItems = el("div", "set-group-items", null, { id: "set-cm-items" });
const cmToggle = el("button", "set-group-title set-toggle", SECTION_LABEL, {
  type: "button",
  "aria-controls": "set-cm-items",
});
function setCmOpen(isOpen, remember = true) {
  cmItems.hidden = !isOpen;
  cmToggle.setAttribute("aria-expanded", String(isOpen));
  cmToggle.dataset.open = isOpen ? "1" : "0";
  if (remember) writeOpen(storage, isOpen);
}

async function open(name, card = "") {
  tabs
    .querySelectorAll("button[data-tab]")
    .forEach((b) =>
      b.setAttribute(
        "aria-current",
        String(b.dataset.tab === name && (!b.dataset.card || b.dataset.card === (card || b.dataset.card))),
      ),
    );
  if (name === SECTION_ID) setCmOpen(true);
  if (name === SECTION_ID || advanced.includes(name)) setAdvOpen(true); // a link into an advanced pane opens the fold around it
  panel.textContent = "";
  history.replaceState(null, "", card ? `#${name}/${card}` : `#${name}`);
  try {
    await sections[name](panel);
  } catch (err) {
    panel.append(el("p", "msg err", err.message));
  }
}
const tabButton = (name) => {
  const b = el("button", "btn ghost sm", labels[name], { "data-tab": name, "aria-current": "false" });
  b.type = "button";
  b.onclick = () => open(name);
  return b;
};
const essentialsGroup = el("div", "set-group", null, { role: "presentation" });
essentialsGroup.append(el("span", "set-group-title", "Essentials", { "aria-hidden": "true" }), ...essentials.map(tabButton));
tabs.append(essentialsGroup);
advToggle.onclick = () => setAdvOpen(advItems.hidden);
advanced.forEach((name) => advItems.append(tabButton(name)));
const cmGroup = el("div", "set-group", null, { role: "presentation" });
cmToggle.onclick = () => setCmOpen(cmItems.hidden);
cards().forEach((entry) => {
  const b = el("button", "btn ghost sm", entry.title, {
    "data-tab": SECTION_ID,
    "data-card": entry.id,
    "aria-current": "false",
  });
  b.type = "button";
  b.onclick = () => open(SECTION_ID, entry.id);
  cmItems.append(b);
});
cmGroup.append(cmToggle, cmItems);
// Timings (feed interval, discovery and nuclei limits) live in Administration; a link here so Advanced is where one looks for them
advItems.append(Object.assign(el("a", "btn ghost sm", "Timings", { href: "/cve/admin/#timings" })));
advItems.append(cmGroup);
const advGroup = el("div", "set-group", null, { role: "presentation" });
advGroup.append(advToggle, advItems);
tabs.append(advGroup);
setCmOpen(readOpen(storage), false);
setAdvOpen(false);

// an old link to #engines (the tab this replaced) opens the scan policy
const legacyTabs = { engines: "scan_policy", notifications: "alerts", email: "alerts" };
const hash = location.hash.slice(1);
if (hash === "openvas") window.location.replace("/cve/admin/#openvas"); // its one place now
const hashTab = isSectionHash(location.hash) ? SECTION_ID : legacyTabs[hash] || hash;
open(sections[hashTab] ? hashTab : "ai", isSectionHash(location.hash) ? parseHash(location.hash).card : "");
window.addEventListener("hashchange", () => {
  if (location.hash === "#openvas") window.location.replace("/cve/admin/#openvas");
  if (isSectionHash(location.hash)) open(SECTION_ID, parseHash(location.hash).card);
  else if (legacyTabs[location.hash.slice(1)]) open(legacyTabs[location.hash.slice(1)]);
  else if (sections[location.hash.slice(1)]) open(location.hash.slice(1));
});
