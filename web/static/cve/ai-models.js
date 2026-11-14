// The model drop-down shared by Settings > AI model, the setup wizard and the Connect-a-model page. One component, so a model is chosen the
// same way everywhere: a real drop-down filled from the provider's own list, the saved value always in it, and a typed name only where the
// list cannot know. The logic is in ai-models-logic.js (tested with node); this file only draws it, always with textContent.
import { OTHER, CHOOSE, buildOptions, checkModel, connectionLine, createModelSource, valueOf } from "/staticfiles/cve/ai-models-logic.js";

const node = (tag, cls, text, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};

export const csrfToken = () => (document.querySelector("[name=csrfmiddlewaretoken]") || {}).value || "";

// The request for a list. The browser sends only what was typed; with no key the server uses the one it holds for this provider and address.
export function modelsFetcher(csrf = csrfToken()) {
  return async (params, signal) => {
    const res = await fetch("/cve/api/settings/ai/models", {
      method: "POST",
      credentials: "same-origin",
      signal,
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
      body: JSON.stringify({ provider: params.provider, api_key: params.api_key || "", base_url: params.base_url || "", refresh: params.refresh === true }),
    });
    let data = {};
    try {
      data = await res.json();
    } catch (_) {
      /* empty */
    }
    if (!res.ok) throw new Error(data.error || (res.status === 403 ? "only an administrator can load the list" : `the server answered ${res.status}`));
    return data;
  };
}

export const newSource = (opts = {}) => createModelSource({ fetcher: modelsFetcher(opts.csrf), delay: opts.delay ?? 500 });

// The status line: "Connected: 13 models available" or "Could not reach Anthropic: the key was refused". Announced politely when it changes.
export function connectionStatus(source, context) {
  const line = node("p", "ai-conn", "", { role: "status", "aria-live": "polite" });
  const draw = () => {
    const c = context();
    const state = source.state;
    const { tone, text } = connectionLine({ phase: state.phase, count: state.models.length, error: state.error, label: c.label, needsKey: c.needsKey, needsAddress: c.needsAddress });
    line.className = `ai-conn ai-conn-${tone}`;
    line.textContent = text;
  };
  source.subscribe(draw);
  draw();
  return { node: line, draw };
}

// One drop-down.
//   source    the model source (newSource())
//   context   () => {provider, baseUrl, selectable, builtIn?}
//   job       "default" | "reviewer"; reviewer rows have their own empty choice and the job name for the built-in model
//   saved     the value stored now
//   onChange  () => void, called when the person changes the choice
export function modelPicker({ source, context, job = "default", reviewerJob = "", saved = "", onChange = () => {}, sameLabel = null, recommendFor = null }) {
  const select = node("select", "ai-model-select");
  const other = node("input", "ai-model-other", null, { type: "text", autocomplete: "off", spellcheck: "false", placeholder: "for example llama3.1:8b", hidden: "" });
  const problem = node("p", "note ai-model-problem", "", { hidden: "" });
  const wrap = node("div", "ai-model");
  wrap.append(select, other, problem);
  let savedValue = String(saved || "");
  let value = savedValue; // the model the row stands for
  let otherMode = false;
  const draw = () => {
    const c = context();
    const state = source.state;
    const recommended = recommendFor ? recommendFor(state, c) : state.recommended;
    const listState = state.phase === "ready" ? (state.models.length ? "ready" : "empty") : state.phase === "failed" ? "failed" : state.phase;
    const built = buildOptions({
      job, models: state.models, recommended, saved: otherMode ? savedValue : value, provider: c.provider, baseUrl: c.baseUrl, selectable: c.selectable || [],
      listState, autoLabel: sameLabel ? sameLabel(c) : "",
    });
    select.replaceChildren(...built.options.map((o) => {
      const opt = node("option", "", o.label);
      opt.value = o.value;
      if (o.disabled) opt.disabled = true;
      return opt;
    }));
    const canOther = built.options.some((o) => o.value === OTHER);
    if (!canOther) otherMode = false;
    const target = otherMode ? OTHER : built.selected;
    select.value = target;
    if (select.value !== target) select.value = built.options[0] ? built.options[0].value : "";
    select.setAttribute("aria-busy", state.phase === "loading" ? "true" : "false");
    other.hidden = !otherMode;
    const bad = otherMode ? checkModel(value) : null;
    problem.hidden = !bad;
    problem.textContent = bad || "";
    other.setAttribute("aria-invalid", bad ? "true" : "false");
  };
  select.addEventListener("change", () => {
    if (select.value === OTHER) {
      otherMode = true;
      value = other.value.trim();
      draw();
      other.hidden = false;
      other.focus();
    } else {
      otherMode = false;
      value = valueOf(select.value, "");
      draw();
    }
    onChange();
  });
  other.addEventListener("input", () => {
    value = other.value.trim();
    const bad = checkModel(value);
    problem.hidden = !bad;
    problem.textContent = bad || "";
    other.setAttribute("aria-invalid", bad ? "true" : "false");
    onChange();
  });
  source.subscribe(draw);
  draw();
  return {
    wrap, select, other,
    get value() {
      return otherMode ? other.value.trim() : valueOf(select.value, "");
    },
    get error() {
      return otherMode ? checkModel(other.value) : null;
    },
    get needsPick() {
      return select.value === CHOOSE;
    },
    // a new stored value (after a save), or '' with `keep` false when the provider changed and the old model belongs to the old provider
    set(next, { stored = false } = {}) {
      value = String(next || "");
      if (stored) savedValue = value;
      otherMode = false;
      other.value = "";
      draw();
    },
    draw,
    focus: () => (otherMode ? other : select).focus(),
  };
}

// Fetch when a provider, key or address changes (debounced by the source), when the page opens, and by hand. `read()` returns
// {provider, api_key, base_url, ok, needsKey, needsAddress}; nothing is asked for until it says ok.
export function autoLoad(source, read, elements) {
  const ask = (immediate = false) => {
    const r = read();
    if (!r.ok) {
      source.reset();
      return;
    }
    const params = { provider: r.provider, api_key: r.api_key, base_url: r.base_url };
    if (immediate) source.now(params);
    else source.request(params);
  };
  elements.forEach(({ el, immediate }) => {
    el.addEventListener("input", () => ask(false));
    el.addEventListener("change", () => ask(immediate !== false));
  });
  return { ask, refresh: () => { const r = read(); if (r.ok) return source.refresh({ provider: r.provider, api_key: r.api_key, base_url: r.base_url }); source.reset(); return null; } };
}
