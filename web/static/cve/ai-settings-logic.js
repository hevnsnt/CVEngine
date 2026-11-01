// Settings, AI model: the logic behind the request settings (timeouts, reply limit, context window, JSON mode, reasoning, keep-alive), kept free
// of the DOM and of imports so that `node --test` can run it (tests/test_ai_settings_logic.mjs). settings.js only draws what these functions
// return, always with textContent. The server (cveFeed/settings_api.py) checks every value again; these checks are for the person typing.
//
// `s` below is the answer of GET /cve/api/settings/ai: `limits` (range and unit of each number), `env` (the environment variables that are set),
// `provider_defaults` (what each provider sends when nothing is set), `applies_to` (settings only some providers use) and `choices`.

export const GROUPS = [
  ["Hosted", ["anthropic", "openai", "openrouter"]],
  ["Your own server", ["ollama", "lmstudio", "vllm"]],
];
export const LABELS = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  openrouter: "OpenRouter",
  ollama: "Ollama",
  lmstudio: "LM Studio",
  vllm: "vLLM, llama.cpp or another OpenAI-compatible server",
};
export const labelOf = (provider) => LABELS[provider] || provider;

// the environment variable behind each setting, as the page names it in a hint
export const ENV_NAMES = {
  request_timeout: "CVENGINE_AI_TIMEOUT",
  connect_timeout: "CVENGINE_AI_CONNECT_TIMEOUT",
  max_tokens: "CVENGINE_AI_MAX_TOKENS",
  context_tokens: "CVENGINE_OLLAMA_NUM_CTX",
  structured_mode: "CVENGINE_AI_STRUCTURED",
  reasoning: "CVENGINE_AI_REASONING",
};

export const FIELDS = [
  { key: "request_timeout", label: "Request timeout (seconds)", kind: "number",
    help: "How long to wait for the model's answer. A local model that loads on the first request, or a long stage on a slow machine, needs more." },
  { key: "connect_timeout", label: "Connect timeout (seconds)", kind: "number",
    help: "How long to wait to reach the server. A server that is down then fails quickly instead of after the full request timeout." },
  { key: "max_tokens", label: "Reply limit (tokens)", kind: "number",
    help: "The longest answer a request may ask for, for every task. A reasoning model spends part of it thinking, so a short limit can cut its answer off." },
  { key: "context_tokens", label: "Context window (tokens)", kind: "number",
    help: "Ollama only. How much text the model reads at once. Ollama picks it from the machine's memory (4096 tokens under 24 GiB) and cuts a longer prompt at its start without an error." },
  { key: "structured_mode", label: "JSON mode", kind: "choice",
    choices: [["", "Not set here"], ["auto", "Automatic (your own servers only)"], ["all", "Every provider"], ["off", "Off"]],
    help: "Whether a finding triage carries a JSON Schema the reply must follow. It makes a small local model reliable at the format; the reply is checked either way." },
  { key: "reasoning", label: "Reasoning", kind: "choice",
    choices: [["", "Not set here"], ["default", "Provider default (send nothing)"], ["off", "Off"], ["low", "Low"], ["medium", "Medium"], ["high", "High"], ["max", "Max"]],
    help: "How much the model thinks before it answers, where the provider has a switch for it. Thinking is paid from the reply limit." },
  { key: "keep_alive", label: "Keep the model loaded", kind: "text", placeholder: "for example 30m",
    help: "Ollama only. How long the model stays in memory after a request: 30m, 1h, 90s, 0 to unload at once, -1 to keep it loaded. Empty is the server's default (five minutes)." },
];
export const KEEP_ALIVE = /^(?:-1|0|\d{1,5}[smh])$/i;

export const applies = (s, key, provider) => {
  const only = (s.applies_to || {})[key];
  return !only || only.includes(provider);
};

// --- what is typed in a box -----------------------------------------------------------------------------------
// A draft is a string. Returns {ok: true, value} (value '' means "not set here") or {ok: false, error}.
export function checkDraft(s, key, draft) {
  const text = String(draft == null ? "" : draft).trim();
  const limit = (s.limits || {})[key];
  if (limit) {
    if (text === "") return { ok: true, value: "" };
    const range = `between ${limit.min.toLocaleString("en-US")} and ${limit.max.toLocaleString("en-US")} ${limit.unit}`;
    if (!/^\d{1,9}$/.test(text)) return { ok: false, error: `Use a whole number ${range}, or leave it empty.` };
    const n = Number(text);
    if (n < limit.min || n > limit.max) return { ok: false, error: `Use a number ${range}, or leave it empty.` };
    return { ok: true, value: String(n) };
  }
  if (key === "keep_alive") {
    if (text === "") return { ok: true, value: "" };
    return KEEP_ALIVE.test(text)
      ? { ok: true, value: text.toLowerCase() }
      : { ok: false, error: "Use a time such as 30m, 1h or 90s, 0 to unload at once, or -1 to keep it loaded." };
  }
  const allowed = (s.choices || {})[key] || [];
  if (text === "" || allowed.includes(text)) return { ok: true, value: text };
  return { ok: false, error: `Choose one of: ${allowed.join(", ")}.` };
}

// The body of the save request for the request settings, or the errors by field. `drafts` is {key: string}.
export function collect(s, drafts) {
  const values = {};
  const errors = {};
  for (const f of FIELDS) {
    const r = checkDraft(s, f.key, drafts[f.key]);
    if (r.ok) values[f.key] = r.value;
    else errors[f.key] = r.error;
  }
  return { values, errors };
}

// The drafts a page starts with: what is stored, as text.
export const initialDrafts = (s) => Object.fromEntries(FIELDS.map((f) => [f.key, s[f.key] == null ? "" : String(s[f.key])]));

// Whether a customised setting exists, to open the section when there is something in it.
export const anySet = (s) => FIELDS.some((f) => s[f.key] != null && s[f.key] !== "");

// --- the value in force, and why ---------------------------------------------------------------------------------
const num = (n) => Number(n).toLocaleString("en-US");

function envNumber(s, key) {
  const raw = (s.env || {})[key];
  const limit = (s.limits || {})[key];
  if (raw == null || raw === "" || !limit || !/^\d+$/.test(String(raw))) return null;
  const n = Number(raw);
  return n >= limit.min && n <= limit.max ? n : null;
}

// {source: 'setting' | 'env' | 'default' | 'none', text, value (a number setting that has one)} for one setting of `provider` given what is typed (`draft`).
export function effective(s, key, provider, draft) {
  const checked = checkDraft(s, key, draft);
  const typed = checked.ok ? checked.value : "";
  const defaults = (s.provider_defaults || {})[provider] || {};
  const limit = (s.limits || {})[key];
  if (!applies(s, key, provider)) return { source: "none", text: `Not used by ${labelOf(provider)}.` };
  if (limit) {
    if (typed !== "") return { source: "setting", value: Number(typed), text: `Using ${num(typed)} ${limit.unit}, set here.` };
    const fromEnv = envNumber(s, key);
    if (fromEnv != null) return { source: "env", value: fromEnv, text: `Using ${num(fromEnv)} ${limit.unit} from ${ENV_NAMES[key]} in the server's environment. A value here replaces it.` };
    const d = defaults[key];
    if (d == null) {
      return key === "max_tokens"
        ? { source: "default", text: `Nothing is sent: ${labelOf(provider)} keeps its own limit.` }
        : { source: "default", text: "Not set: the server's own default applies." };
    }
    const triage = key === "max_tokens" && defaults.triage_max_tokens ? ` (${num(defaults.triage_max_tokens)} for a finding triage)` : "";
    return { source: "default", value: d, text: `Using ${num(d)} ${limit.unit}${triage}, the default for ${labelOf(provider)}.` };
  }
  if (key === "keep_alive") {
    return typed !== ""
      ? { source: "setting", text: typed === "0" ? "Unloads the model right after each request." : typed === "-1" ? "Keeps the model loaded." : `Keeps the model loaded for ${typed}.` }
      : { source: "default", text: "Using the server's default (Ollama: five minutes)." };
  }
  if (key === "structured_mode") {
    const fromEnv = ((s.env || {}).structured_mode || "").toLowerCase();
    const mode = typed || (["auto", "all", "off"].includes(fromEnv) ? fromEnv : "auto");
    const source = typed ? "setting" : ["auto", "all", "off"].includes(fromEnv) ? "env" : "default";
    const sends = !!defaults.structured_possible && mode !== "off" && (!!defaults.structured || mode === "all");
    const via = source === "env" ? ` from ${ENV_NAMES[key]}` : source === "default" ? ", the default" : ", set here";
    return { source, text: `${mode === "auto" ? "Automatic" : mode === "all" ? "Every provider" : "Off"}${via}: ${sends ? "a JSON Schema is sent to" : "no JSON Schema is sent to"} ${labelOf(provider)}.` };
  }
  if (key === "reasoning") {
    const fromEnv = ((s.env || {}).reasoning || "").toLowerCase();
    const levels = ["off", "low", "medium", "high", "max"];
    const level = typed === "default" ? "" : typed || (levels.includes(fromEnv) ? fromEnv : "");
    const source = typed ? "setting" : levels.includes(fromEnv) ? "env" : "default";
    if (!level) {
      return { source, text: typed === "default" ? "Nothing is sent, even if the server's environment sets a level." : "Nothing is sent: the model uses its own default." };
    }
    if (defaults.reasoning_sent === false) {
      return { source, text: `${labelOf(provider)} is not sent a reasoning field: switch it on the server, or choose a model without it.` };
    }
    return { source, text: `Asks for ${level}${source === "env" ? ` (from ${ENV_NAMES[key]})` : ""}, for the models that have a switch; others are left alone.` };
  }
  return { source: "default", text: "" };
}

// Sentences worth showing next to the section, not errors.
export function warnings(s, provider, drafts) {
  const out = [];
  const cap = checkDraft(s, "max_tokens", drafts.max_tokens);
  const level = checkDraft(s, "reasoning", drafts.reasoning);
  const thinking = level.ok && level.value && level.value !== "default" && level.value !== "off";
  if (cap.ok && cap.value !== "" && Number(cap.value) < 1000) {
    out.push("A reply limit under 1,000 tokens cuts off the answer of most tasks, and of a reasoning model before it finishes thinking.");
  }
  if (thinking && cap.ok && cap.value !== "" && Number(cap.value) < 4096) {
    out.push("Reasoning is paid from the reply limit: with thinking on, give the reply limit 4,096 tokens or more.");
  }
  const timeout = checkDraft(s, "request_timeout", drafts.request_timeout);
  const connect = checkDraft(s, "connect_timeout", drafts.connect_timeout);
  if (timeout.ok && connect.ok && timeout.value !== "" && connect.value !== "" && Number(connect.value) > Number(timeout.value)) {
    out.push("The connect timeout is longer than the request timeout.");
  }
  return out;
}
