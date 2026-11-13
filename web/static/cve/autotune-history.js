// The History of the Auto-tuning card (Settings, configMaxxing): one line per change in the shape a person reads, in plain words:
//   What      "Hosts assessed at once 12 → 14"
//   Why       one sentence from the decision's reason
//   Happened  "oldest waiting assessment 52 → 9 min, no memory pressure; kept" | "made it worse: ...; undone" | "being checked, result at 14:30" | "not judged: a person changed it"
//   Who       auto-tune, an agent (named), the AI, a person
// Pure functions over a decision as cveFeed/autotune.py ``serialize`` sends it (every field may be missing or null: a value the server did not send
// is left out of the sentence, never printed as "undefined", "null", "NaN" or a bare "?"). The card (autotune-card.js) only draws what these return.
import { fmtTime } from "/staticfiles/cve/prefs.js";

const isNum = (v) => typeof v === "number" && Number.isFinite(v);
const clean = (v) => (typeof v === "string" ? v.replace(/\s+/g, " ").trim() : "");
const sentence = (text) => {
  const t = clean(text);
  return t ? t[0].toUpperCase() + t.slice(1) : "";
};
const cut = (text, n) => (text.length > n ? `${text.slice(0, n - 1).trimEnd()}…` : text);
const number = (v) => (isNum(v) ? String(Math.round(v * 100) / 100) : "");

// Who made the change, in words. A source this version does not know is shown as itself, in plain words ("by x").
export function whoText(d) {
  const named = clean(d && d.actor);
  switch (d && d.source) {
    case "controller": return "auto-tune";
    case "ai": return "the AI";
    case "person": return named || "a person";
    case "agent": return clean(d.agent_name) ? `an agent (${clean(d.agent_name)})` : named ? `an agent (${named})` : "an agent";
    default: return clean(d && d.source) || "auto-tune";
  }
}

// "5 min ago", "3 h ago", "2 days ago": the same words and rounding as the scans list (app.js).
export function ago(iso, now = Date.now()) {
  const t = Date.parse(iso || "");
  if (!isNum(t)) return "";
  const mins = Math.max(0, Math.round((now - t) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  return mins < 2880 ? `${Math.round(mins / 60)} h ago` : `${Math.round(mins / 1440)} days ago`;
}

export function whatText(d) {
  const label = clean(d && d.label) || clean(d && d.setting) || "A setting";
  const [from, to] = [number(d && d.old_value), number(d && d.new_value)];
  if (d && d.action === "release") return `${label} handed back to auto-tune${to ? ` at ${to}` : ""}`;
  if (d && d.action === "pause") return `${label} paused for ${to || "a few"} hours`;
  if (d && d.action === "revert") return from && to ? `${label} put back ${from} → ${to}` : `${label} put back`;
  if (from && to) return `${label} ${from} → ${to}`;
  return to ? `${label} set to ${to}` : label;
}

const PHASE_WHY = {
  aim_high: "Aimed at what this machine can carry",
  back_off: "Backed off because of trouble",
  cap: "Brought down to what this machine can carry",
  probe: "Probed up one step: the last hours were healthy and work was waiting",
  emergency: "Backed off while the database did not answer",
  recover: "Restored after the database came back",
  verify: "Undone because the change before it made things worse",
};

// One plain sentence: the decision's own reason, cut at the first colon-led tail the controller adds ("...: probed 12 to 14") and at 160 characters.
export function whyText(d) {
  if (d && d.action === "revert" && d.source === "person") return `${whoText(d)} chose to undo the earlier change`;
  if (d && d.action === "revert") return PHASE_WHY.verify;  // the tuner's own revert: its reason is a technical line with the time of the change it undid
  if (d && d.action === "release") return "A person gave this number back to auto-tune";
  if (d && d.action === "apply") return "A person applied the recommendation";
  let reason = clean(d && d.reason);
  if (reason) {
    reason = reason.replace(/:\s*(probed|backed off|lowered|lengthened|restored|aimed)\b[^:]*$/i, "");
    return cut(sentence(reason), 160);
  }
  return PHASE_WHY[d && d.phase] || (d && d.applied === false ? "Auto-tune recommends this change" : "");
}

// The measurement a change was judged by (cveFeed/autotune_policy.py METRICS), as a phrase with its unit. share: 0 to 1 shown as a percent.
const METRIC = {
  wait_share: { text: "runs waiting for their turn", share: true },
  discovery_queue: { text: "scans waiting in the queue", unit: "" },
  assess_oldest_s: { text: "oldest waiting assessment", seconds: true },
  conductor_saturated_share: { text: "checks held back by the conductor", share: true },
  conductor_idle_share: { text: "checks with nothing due", share: true },
  sentinel_idle_share: { text: "Sentinel slots idle", share: true },
};
const amount = (m, v) => {
  if (!isNum(v)) return "";
  if (m.share) return `${Math.round(v * 100)}%`;
  if (m.seconds) return v >= 5400 ? `${Math.round(v / 360) / 10} h` : `${Math.round(v / 60)} min`;
  return number(v);
};

// "oldest waiting assessment 52 → 9 min", or "" when the numbers are not there (the server's own sentence is used then).
export function measurementText(d) {
  const base = d && d.baseline && typeof d.baseline === "object" ? d.baseline : null;
  const after = base && base.after && typeof base.after === "object" ? base.after : null;
  const m = base && METRIC[base.metric];
  if (base && base.metric === "trouble" && after && after.metric === "trouble" && isNum(base.value) && isNum(after.value)) {  // a back-off: judged by whether the trouble stopped
    return after.value ? "the trouble is still there" : base.value ? "the trouble is gone" : "no trouble";
  }
  if (!m || !after || after.metric !== base.metric || !isNum(base.value) || !isNum(after.value)) return "";
  const [a, b] = [amount(m, base.value), amount(m, after.value)];
  if (m.seconds) {
    const unit = a.endsWith(" min") && b.endsWith(" min") ? " min" : "";
    return unit ? `${m.text} ${a.slice(0, -4)} → ${b.slice(0, -4)} min` : `${m.text} ${a} → ${b}`;
  }
  return `${m.text} ${a} → ${b}`;
}

function pressureText(d) {
  const after = d && d.baseline && d.baseline.after;
  if (!after || typeof after !== "object") return "";
  const kills = (isNum(after.kills) ? after.kills : 0) + (isNum(after.oom) && isNum(d.baseline.oom) && after.oom > d.baseline.oom ? after.oom - d.baseline.oom : 0);
  if (kills > 0) return `${kills} memory kill${kills === 1 ? "" : "s"}`;
  if (after.trouble === 1) return "trouble for this setting";
  return after.trouble === 0 ? "no memory pressure" : "";
}

// The server's own sentence without its "so it was not judged" tail, which the line says up front.
// "2 memory kill(s)" (what an older server wrote) reads "2 memory kills"; "1 memory kill(s)" reads "1 memory kill".
const plainCount = (text) => text.replace(/\b(\d+)\s([^,;]*)/g, (all, n, rest) => (rest.includes("(s)") ? `${n} ${rest.replace(/\(s\)/g, n === "1" ? "" : "s")}` : all));
const plainDetail = (text) => plainCount(clean(text)).replace(/^undid decision \d+:\s*/i, "").replace(/,?\s+so (?:it|the change) (?:was|is) not judged\.?$/i, "").replace(/\.$/, "");

// What happened after the change: {text, tone}. tone: good | bad | neutral | wait.
export function happenedText(d, now = Date.now()) {
  if (!d) return { text: "", tone: "neutral" };
  const numbers = measurementText(d);
  const detail = plainDetail(d.outcome_detail);
  const facts = [numbers || detail, numbers ? pressureText(d) : ""].filter(Boolean).join(", ");
  if (d.applied === false) {
    if (d.resolution === "applied") return { text: "applied by a person", tone: "neutral" };
    if (d.resolution === "superseded") return { text: "replaced by a newer recommendation", tone: "neutral" };
    return { text: "nothing has changed yet: apply it to make the change", tone: "wait" };
  }
  if (d.action === "revert") {
    if (d.source === "person") return { text: `undone by ${whoText(d)}`, tone: "neutral" };
    return { text: facts ? `put back: ${facts}` : "put back", tone: "neutral" };
  }
  if (d.action === "release") return { text: "auto-tune manages this number again", tone: "neutral" };
  switch (d.outcome) {
    case "helped": return { text: `${facts || "it helped"}; kept`, tone: "good" };
    case "no_effect": return { text: `${facts ? `${facts}; ` : ""}no effect, kept`, tone: "neutral" };
    case "regressed": return { text: `made it worse${facts ? `: ${facts}` : ""}; ${d.resolution === "reverted" ? "undone" : "kept"}`, tone: "bad" };
    case "unknown": return { text: `not judged${facts ? `: ${facts}` : ""}`, tone: "neutral" };
    case "reverted": return { text: "undone", tone: "neutral" };
    default: break;
  }
  if (d.resolution === "reverted") return { text: "undone by a person", tone: "neutral" };
  if (d.verify_at) {
    const t = Date.parse(d.verify_at);
    return { text: isNum(t) && t > now ? `being checked, result at ${fmtTime(d.verify_at, false)}` : "being checked, result due now", tone: "wait" };
  }
  return { text: d.source === "person" ? "not judged: a person changed it" : "not judged: this kind of change is not measured", tone: "neutral" };
}

// The whole line, for the card to draw and the tests to read.
export function historyLine(d, now = Date.now()) {
  const happened = happenedText(d, now);
  return {
    id: d && isNum(d.id) ? d.id : null,
    what: whatText(d), why: whyText(d), happened: happened.text, tone: happened.tone, who: whoText(d), when: ago(d && d.at, now),
    revert: !!(d && d.can_revert && d.resolution !== "reverted" && d.action !== "revert" && d.action !== "release"), apply: !!(d && d.can_apply), undone: !!(d && d.resolution === "reverted"),
  };
}
