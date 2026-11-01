// configMaxxing: the logic behind Settings, configMaxxing and its Scan concurrency card, kept free of the DOM and of imports so that
// `node --test` can run it (tests/test_config_maxxing.mjs). The page code (config-maxxing.js, scan-concurrency-card.js) only draws what
// these functions return, always with textContent.

export const SECTION_ID = "configmaxxing";
export const SECTION_LABEL = "configMaxxing";
export const STORAGE_KEY = "cve.settings.configmaxxing.open";
export const WARNING_TEXT =
  "Advanced settings for people who like to tune things. The defaults are safe. Changing these can make scans slower, use more memory or send more traffic to your targets.";
export const EXPLANATION_TEXT =
  "More at once scans faster but needs more CPU and memory. The memory gate still holds work back when the container is short on memory. " +
  "Scanning on a second machine (a Sentinel) is the best way to scale.";

// --- whether the section is open: remembered per viewer, never required ---------------------------------------
export function readOpen(storage) {
  try {
    return storage.getItem(STORAGE_KEY) === "1";
  } catch (_) {
    return false; // blocked storage, a private window: collapsed, the default
  }
}
export function writeOpen(storage, open) {
  try {
    storage.setItem(STORAGE_KEY, open ? "1" : "0");
    return true;
  } catch (_) {
    return false;
  }
}

// #configmaxxing, and #configmaxxing/<card id> to land on one card
export function parseHash(hash) {
  const [section, card = ""] = String(hash || "").replace(/^#/, "").split("/");
  return { section, card };
}
export const isSectionHash = (hash) => parseHash(hash).section === SECTION_ID;

// --- numbers -------------------------------------------------------------------------------------------------
// A draft is what is typed in a box. Returns {ok, value} or {ok: false, error}. An empty box means "no change" to the caller, not a value.
export function checkDraft(field, draft) {
  const raw = String(draft ?? "").trim();
  if (!/^\d+$/.test(raw)) return { ok: false, error: `${field.label} must be a whole number from ${field.min} to ${field.max}` };
  const value = Number(raw);
  if (value < field.min || value > field.max) return { ok: false, error: `${field.label} must be from ${field.min} to ${field.max}` };
  return { ok: true, value };
}

// {key: number} for the boxes that differ from what is in effect now, and the first problem if one is invalid.
export function changesFrom(fields, drafts) {
  const changes = {};
  let error = null;
  fields.forEach((field) => {
    if (!(field.key in drafts)) return;
    const checked = checkDraft(field, drafts[field.key]);
    if (!checked.ok) {
      error = error || checked.error;
      return;
    }
    if (checked.value !== field.value) changes[field.key] = checked.value;
  });
  return { changes, error };
}

// --- what a row says about where its number comes from ---------------------------------------------------------
export function sourceLabel(field) {
  if (field.source === "admin") return "Saved here";
  if (field.source === "environment") return `From the environment (${field.env_name}=${field.env_value})`;
  return "Built-in default";
}
export function originLines(field, formatDate = (x) => x) {
  const lines = [`Default ${field.default}`];
  lines.push(field.env_value == null ? `${field.env_name} is not set` : `${field.env_name}=${field.env_value}`);
  if (field.source === "admin") {
    const when = field.set_at ? ` on ${formatDate(field.set_at)}` : "";
    lines.push(`Set by ${field.set_by || "an administrator"}${when}`);
  }
  return lines;
}
export const canReset = (field) => field.source === "admin";
export const rangeText = (field) => `${field.min} to ${field.max}`;

export function groupFields(fields, groups) {
  return groups.map((g) => ({ ...g, fields: fields.filter((f) => f.group === g.id) })).filter((g) => g.fields.length);
}

// --- memory ----------------------------------------------------------------------------------------------------
export function formatMb(mb) {
  if (mb == null) return "unknown";
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`;
}

// Mirrors cveFeed.scan_concurrency.memory_plan, so the warning follows the boxes while they are typed in. `caps` {kind: limit}. The worst case
// (every kind at its limit at once) may be OVERCOMMIT times the budget before it warns, because the kinds rarely peak together.
export const OVERCOMMIT = 2;
export function memoryPlan(caps, costs, budget, defaults, labels = {}) {
  const kinds = Object.keys(caps);
  const cost = (k) => costs[k] ?? 500;
  const total = kinds.reduce((sum, k) => sum + cost(k) * caps[k], 0);
  const defaultTotal = kinds.reduce((sum, k) => sum + cost(k) * (defaults[k] ?? caps[k]), 0);
  const warnings = [];
  if (budget) {
    kinds.forEach((k) => {
      const alone = cost(k) * caps[k];
      if (caps[k] > (defaults[k] ?? caps[k]) && alone > budget) {
        warnings.push(`${labels[k] || k} at ${caps[k]} could want ${alone} MB by itself, more than the ${budget} MB budget of the scanning container: the extra runs will only wait for memory.`);
      }
    });
    if (total > budget * OVERCOMMIT && total > defaultTotal) {
      warnings.push(
        `With every scanner at its limit at the same time, up to ${total} MB could be wanted, more than ${OVERCOMMIT} times the ${budget} MB budget of the scanning container. ` +
          "The memory gate will hold runs back, so raising these further will not scan faster until the container has more memory (CELERY_MEM_LIMIT) or you scan on a second machine.",
      );
    }
  }
  return { total, defaultTotal, budget, warnings };
}

// The discovery pool is the one number a running process cannot simply re-read. Say exactly what is known.
export function discoveryNotice(field, status) {
  if (!field) return "";
  if (status && status.message) return status.message;
  return field.running == null ? "What the discovery worker's ceiling is now is not known." : `The discovery worker's ceiling is ${field.running}.`;
}
export function runningText(field) {
  if (field.applies === "restart") return "Applies after the next restart";
  if (field.applies !== "pool") return "Applies within a few seconds, with no restart";
  if (field.running == null) return "Worker ceiling now: not reported yet";
  return `Worker ceiling now: ${field.running}`;
}
