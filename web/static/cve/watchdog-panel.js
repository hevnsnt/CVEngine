// The watchdog panel (Administration, Watchdog tab; App Admin only): the answer to "is something watching this for me, and what did it do?"
//   /cve/api/admin/watchdog    each rule in words, what it changed and its last 20 actions (docs/WATCHDOG.md)
// It polls every 30 s while its tab is open and draws through renderKeepingState, so nothing you opened closes. Text is set with textContent only.
import { api, ask, el, button, couldNotRead, details, table, waiting } from "/staticfiles/cve/ui.js";
import { renderKeepingState } from "/staticfiles/cve/keep-state.js";
import { fmtDateTime, zoneLabel } from "/staticfiles/cve/prefs.js";
import { localTimes } from "/staticfiles/cve/watchdog-text.js";

const EVERY_MS = 30000;

const WD_WORD = { ok: ["Fine", "success"], watching: ["Watching", "medium"], acting: ["Acting", "medium"], standing_down: ["Standing aside", "medium"], held: ["Held", "medium"],
  problem: ["Needs you", "critical"], unknown: ["Not known", "info"], off: ["Off", "info"] };
function wdRule(wdRoot, rule) {
  const [word, cls] = WD_WORD[rule.status] || WD_WORD.unknown;
  const li = el("li", `wd-rule wd-${rule.color}`);
  const head = el("div", "wd-rule-head");
  head.append(el("span", `badge ${cls}`, word), el("strong", "", `${rule.code} ${rule.title}`));
  const toggle = button(rule.enabled ? "Switch off" : "Switch on", async () => {
    // switching a safety rule off asks first and says what stops being watched; switching it on needs no question
    if (rule.enabled && !(await ask(
      `${rule.does} While it is off, the watchdog stops doing this and tells you nothing about it. You can switch it on again here at any time.`,
      { title: `Stop watching: ${rule.title}?`, ok: "Switch it off" },
    ))) return;
    paintWatchdog(wdRoot, await api("POST", "/cve/api/admin/watchdog", { rule: rule.code, enabled: !rule.enabled }), true);
  }, "btn ghost sm");
  head.append(toggle);
  li.append(head, el("p", "note wd-does", rule.does), el("p", "note", localTimes(rule.text)));
  return li;
}

function paintWatchdog(wdRoot, w, force = false) {
  const head = el("div", "wd-head", null, { "data-keep-key": "wd-head" });
  head.append(el("h2", "", "Watchdog"));
  let state = ["Watching this server", "success"];
  if (w.env_off) state = ["Switched off by the server's administrator", "info"];
  else if (!w.enabled) state = ["Switched off in Settings", "info"];
  else if (!w.running) state = ["Not running", "critical"];
  head.append(el("span", `badge ${state[1]}`, state[0]));
  head.append(el("span", "note", w.tick_age_seconds == null ? "No pass yet." : `Last pass ${w.tick_age_seconds} s ago.`));
  if (!w.env_off) {
    head.append(button(w.enabled ? "Switch off" : "Switch on", async () => {
      if (w.enabled && !(await ask(
        "Every rule stops: nothing restarts what has gone quiet, nothing stands aside for an update and nothing tells you when something could not be fixed. You can switch it on again here at any time.",
        { title: "Stop watching this server?", ok: "Switch it off" },
      ))) return;
      paintWatchdog(wdRoot, await api("POST", "/cve/api/admin/watchdog", { enabled: !w.enabled }), true);
    }, "btn ghost sm"));
  }
  if (w.env_off) head.append(details("For the server's administrator: CVENGINE_WATCHDOG=0 in the server's environment turns the watchdog off. Remove it and restart to switch it on again."));
  const intro = el("p", "note", "It runs outside the workers, so it keeps working when they stop. It restarts what has gone quiet, stands aside while an update runs, checks two minutes later that it worked, and tells you when it could not fix something.");
  const rules = el("ul", "wd-rules", null, { "data-keep-key": "wd-rules" });
  w.rules.forEach((r) => rules.append(wdRule(wdRoot, r)));
  const changed = el("div", "wd-changed", null, { "data-keep-key": "wd-changed" });
  changed.append(el("h3", "", "What the watchdog changed"));
  if (!w.changes.length) changed.append(el("p", "note", "Nothing. It has changed no setting that is still in force."));
  w.changes.forEach((c) => {
    const row = el("p", "wd-change");
    row.append(el("strong", "", localTimes(c.what)), el("span", "note", ` Since ${fmtDateTime(c.since)} ${zoneLabel()}. ${c.undo}`));
    changed.append(row);
  });
  const actions = el("div", "wd-actions", null, { "data-keep-key": "wd-actions" });
  actions.append(el("h3", "", `Last ${Math.min(20, w.events.length) || ""} actions`.replace("  ", " ")));
  if (!w.events.length) actions.append(el("p", "note", "Nothing yet: it has had nothing to do."));
  else actions.append(table([
    { label: `When (${zoneLabel()})`, render: (e) => fmtDateTime(e.at), cls: "wd-when" },
    { label: "Rule", render: (e) => e.rule },
    { label: "What happened", render: (e) => localTimes([e.observation, e.action && `Did: ${e.action}.`, e.result].filter(Boolean).join(" ")) },
  ], w.events));
  intro.setAttribute("data-keep-key", "wd-intro");
  renderKeepingState(wdRoot, () => [head, intro, rules, changed, actions], { force });
}

async function loadWatchdog(wdRoot) {
  try {
    paintWatchdog(wdRoot, await api("GET", "/cve/api/admin/watchdog"));
  } catch (err) {
    const again = couldNotRead("The watchdog", () => { loadWatchdog(wdRoot); }, err.message);
    again.setAttribute("data-keep-key", "wd-err");
    renderKeepingState(wdRoot, () => [el("h2", "", "Watchdog", { "data-keep-key": "wd-title" }), again]);
  }
}

// Mounted by the Administration tabs: draws now, then every 30 s for as long as this panel is on the page.
export async function watchdogPanel(mount) {
  const root = el("section", "card watchdog", null, { id: "watchdog", "aria-live": "polite" });
  root.append(el("h2", "", "Watchdog"), waiting("Checking the watchdog"));
  mount.append(root);
  const tick = async () => {
    if (!root.isConnected) return;  // another tab was opened: stop polling
    await loadWatchdog(root);
    setTimeout(tick, EVERY_MS);
  };
  await tick();
}
