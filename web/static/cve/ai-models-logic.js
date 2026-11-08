// The model drop-downs of Settings > AI model and of the setup pages: what goes in each list, and what a choice means. No DOM and no
// imports, so `node --test` can run it (tests/test_ai_models_logic.mjs). ai-models.js draws what these functions return.
//
// A row is one job that needs a model. `job` is "default" (the model every pipeline job uses, which may be empty: the server then takes the
// newest cheapest model of the provider) or "reviewer" (the reviewer's finding review or operations check, which may be empty: they then
// follow the default model, or on Anthropic the model built in for the job).

export const OTHER = "__other__"; // "Other (type a model name)..."
export const CHOOSE = "__choose__"; // a provider that needs a pick, and nothing picked yet: a prompt, never a value
export const MODEL_NAME = /^[A-Za-z0-9._:/@+-]{1,100}$/; // the server's rule for a model name (settings_api.MODEL_NAME)

// Providers that serve models a list cannot know about (your own server's), and any provider behind a gateway address.
export const OWN_SERVER = ["ollama", "vllm", "lmstudio"];

// "$0.80 per million input tokens" as the tail of an option; empty when the provider did not report a price.
export function formatPrice(price) {
  if (price == null || price === "" || !Number.isFinite(Number(price))) return "";
  const n = Number(price);
  if (n === 0) return "free";
  if (n < 0.01) return "under $0.01 per million input tokens";
  return `$${n.toFixed(2)} per million input tokens`;
}

const withPrice = (id, price) => {
  const p = formatPrice(price);
  return p ? `${id} (${p})` : id;
};

// Whether a free-text "Other" entry is offered: your own servers, a provider behind a gateway address, or a list that did not load.
export function canType({ provider, baseUrl, listState }) {
  return OWN_SERVER.includes(provider) || !!String(baseUrl || "").trim() || listState === "failed" || listState === "empty";
}

// The options of one drop-down.
//   models       [{id, price}] from the provider (may be empty)
//   recommended  the model to mark ('' for none)
//   saved        the value stored now ('' for "not set")
//   provider, baseUrl, selectable (providers that need a pick), listState: "loading" | "ready" | "failed" | "empty" | "idle"
//   defaultLabel for a reviewer row: what the empty choice is called (see sameLabel)
// Returns {options: [{value, label, kind, disabled?}], selected}. `kind`: "auto" (the empty choice), "choose", "saved", "model", "other".
export function buildOptions({ job = "default", models = [], recommended = "", saved = "", provider = "", baseUrl = "", selectable = [], listState = "ready", autoLabel = "" }) {
  const options = [];
  const needsPick = job === "default" && selectable.includes(provider);
  const savedId = String(saved || "").trim();
  const known = new Set(models.map((m) => m.id));
  if (job === "reviewer") {
    options.push({ value: "", label: autoLabel || "Same as the default model", kind: "auto" });
  } else if (!needsPick) {
    options.push({ value: "", label: recommended ? `Newest cheapest (recommended: ${recommended})` : "Newest cheapest (recommended)", kind: "auto" });
  } else if (!savedId) {
    options.push({ value: CHOOSE, label: listState === "loading" ? "Loading models..." : "Choose a model", kind: "choose", disabled: true });
  }
  if (savedId && !known.has(savedId)) {
    // never dropped silently: a saved model the provider did not list (a custom one, a retired one, or a list that failed to load)
    options.push({ value: savedId, label: `${savedId} (saved${listState === "ready" ? ", not in the provider's list" : ""})`, kind: "saved" });
  }
  for (const m of models) {
    const star = recommended && m.id === recommended ? ", recommended" : "";
    const label = withPrice(m.id, m.price);
    options.push({ value: m.id, label: star ? (label.endsWith(")") ? `${label.slice(0, -1)}${star})` : `${label} (recommended)`) : label, kind: "model" });
  }
  if (canType({ provider, baseUrl, listState })) options.push({ value: OTHER, label: "Other (type a model name)...", kind: "other" });
  const selected = savedId ? savedId : needsPick ? CHOOSE : "";
  return { options, selected };
}

// The model a row stands for, from what its drop-down and its text box show. '' is "not set here".
export function valueOf(selectValue, otherText) {
  if (selectValue === OTHER) return String(otherText || "").trim();
  if (selectValue === CHOOSE) return "";
  return selectValue || "";
}

// null when the value can be saved, else a sentence.
export function checkModel(value) {
  const v = String(value || "").trim();
  if (v === "") return null;
  return MODEL_NAME.test(v) ? null : "A model name uses letters, digits and . _ : / @ + - (at most 100 characters).";
}

// The words of the empty choice of a reviewer row. On Anthropic the reviewer has a model built in for each job; elsewhere it follows the default.
export function sameLabel(provider, job, builtIn) {
  if (provider === "anthropic" && builtIn && builtIn[job]) return `Built-in: ${builtIn[job]}`;
  return "Same as the default model";
}

// --- the connection line -----------------------------------------------------------------------------------------------------------
// state: {phase: "idle" | "loading" | "ready" | "failed", count, error, provider (label), needsKey, needsAddress}
export function connectionLine(state) {
  const name = state.label || "the provider";
  if (state.phase === "loading") return { tone: "pending", text: `Checking ${name}...` };
  if (state.phase === "ready") {
    const n = state.count || 0;
    return { tone: "ok", text: n === 0 ? `Connected: ${name} listed no models` : `Connected: ${n} ${n === 1 ? "model" : "models"} available` };
  }
  if (state.phase === "failed") return { tone: "err", text: `Could not reach ${name}: ${state.error || "it did not answer"}` };
  if (state.needsAddress) return { tone: "idle", text: `Enter the address of your ${name} server to load its models` };
  if (state.needsKey) return { tone: "idle", text: `Enter an API key to load the models of ${name}` };
  return { tone: "idle", text: "Not checked yet" };
}

// Whether the list can be asked for now: a saved key or a typed one (or a keyless provider), and an address where one is required.
export function readyToFetch({ provider, typedKey, hasKey, baseUrl, keyless = [], needsUrl = OWN_SERVER, sameAsSaved = true }) {
  if (needsUrl.includes(provider) && !String(baseUrl || "").trim()) return { ok: false, needsAddress: true };
  if (keyless.includes(provider)) return { ok: true };
  if (String(typedKey || "").trim() || (hasKey && sameAsSaved)) return { ok: true };
  return { ok: false, needsKey: true };
}

// --- one request per change, in memory --------------------------------------------------------------------------------------------
export const cacheKey = (provider, baseUrl, typedKey) => `${provider}\n${String(baseUrl || "").trim().replace(/\/+$/, "").toLowerCase()}\n${String(typedKey || "").length ? "typed:" + hashText(typedKey) : "saved"}`;

// A short hash so a typed key is never held as a key of the cache (it is a Map key in memory only, but there is no reason to keep the text).
export function hashText(text) {
  let h = 5381;
  for (let i = 0; i < text.length; i += 1) h = ((h << 5) + h + text.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}

// A source of model lists: `fetcher(params, signal)` returns {models, recommended} or throws Error(plain reason). One request at a time per
// source (a newer one aborts the older), debounced, cached for the life of the page per provider and address and key.
export function createModelSource({ fetcher, delay = 500, setTimer = setTimeout, clearTimer = clearTimeout, makeController = () => new AbortController() }) {
  const cache = new Map();
  const listeners = new Set();
  let timer = null;
  let controller = null;
  let serial = 0;
  let state = { phase: "idle", models: [], recommended: "", error: "", params: null };
  const emit = (patch) => {
    state = { ...state, ...patch };
    listeners.forEach((fn) => fn(state));
  };
  const run = async (params, { force = false } = {}) => {
    const key = cacheKey(params.provider, params.base_url, params.api_key);
    if (controller) controller.abort();
    serial += 1;
    const mine = serial;
    if (!force && cache.has(key)) {
      const hit = cache.get(key);
      emit({ phase: "ready", models: hit.models, recommended: hit.recommended, error: "", params, key });
      return state;
    }
    controller = makeController();
    const same = state.key === key; // a refresh of the list on screen keeps it; another provider or address starts empty
    emit({ phase: "loading", error: "", params, key, models: same ? state.models : [], recommended: same ? state.recommended : "" });
    try {
      const r = await fetcher({ ...params, refresh: force || undefined }, controller.signal);
      if (mine !== serial) return state; // a newer request replaced this one
      const hit = { models: r.models || [], recommended: r.recommended || "" };
      cache.set(key, hit);
      emit({ phase: "ready", ...hit, error: "", key });
    } catch (err) {
      if (mine !== serial || (err && err.name === "AbortError")) return state;
      emit({ phase: "failed", models: [], recommended: "", error: err && err.message ? err.message : "it did not answer", key });
    }
    return state;
  };
  return {
    // ask soon (debounced): for a provider, key or address that is being typed
    request(params) {
      clearTimer(timer);
      timer = setTimer(() => run(params), delay);
    },
    now: (params, opts) => {
      clearTimer(timer);
      return run(params, opts);
    },
    refresh: (params) => {
      clearTimer(timer);
      cache.delete(cacheKey(params.provider, params.base_url, params.api_key));
      return run(params, { force: true });
    },
    reset(patch = {}) {
      clearTimer(timer);
      if (controller) controller.abort();
      serial += 1;
      emit({ phase: "idle", models: [], recommended: "", error: "", ...patch });
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    get state() {
      return state;
    },
    get cacheSize() {
      return cache.size;
    },
  };
}
