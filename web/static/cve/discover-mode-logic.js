// Targets page: the discovery mode a target is discovered in. Kept free of the DOM and of imports so that `node --test` can run it
// (tests/test_discover_mode_logic.mjs); app.js only draws what these functions return. The server checks every value again.
//
// A target's stored mode (`discovery_mode`) is what every automatic scan uses: standard, deep, passive, or manual ("just add them, do not
// scan yet": nothing automatic scans it). Discover runs in the mode chosen next to the button; the one picked there is kept on the target, so
// the work conductor's next rescan uses it too (the server does that, POST targets/<id>/discover with `mode`). A manual only target has no
// mode to run: its choice starts empty and Discover waits until one is picked, so one click never turns it into a scanned target.

export const RUNNABLE = [
  ["standard", "Standard"],
  ["deep", "Deep"],
  ["passive", "Passive (public sources only)"],
];
export const MANUAL = "manual";
export const MANUAL_LABEL = "Manual only (never scanned automatically)";
export const PLACEHOLDER = ["", "Choose a mode…"];

// the choices of the Discovery column: the three modes and manual only
export const STORED = [...RUNNABLE, [MANUAL, MANUAL_LABEL]];

export const isRunnable = (mode) => RUNNABLE.some(([value]) => value === mode);
const isStored = (mode) => STORED.some(([value]) => value === mode);

// what the Discovery column of the all-projects view says
export const modeText = (mode) => (mode === MANUAL ? "manual only" : isRunnable(mode) ? mode : "standard");

// The options next to Discover: the three modes, and for a manual only target an empty "Choose a mode" first.
export const discoverOptions = (stored) => (isRunnable(stored) ? RUNNABLE : [PLACEHOLDER, ...RUNNABLE]);

// What the choice shows first: the stored mode; for a manual only target nothing (the placeholder).
export const defaultChoice = (stored) => (isRunnable(stored) ? stored : "");

// Discover can be pressed once a mode to run is chosen.
export const canDiscover = (picked) => isRunnable(picked);

// The request body for Discover. Without `mode` the server runs the stored mode, so that is what is sent whenever the choice is the stored
// mode; a manual only target always names one (the server refuses to guess for it).
export const discoverBody = (stored, picked) => (isRunnable(picked) && (picked !== stored || !isRunnable(stored)) ? { mode: picked } : {});

// The mode the target has after Discover: what the server says it stored (it keeps the old one for an internal target, and may for others),
// else the stored one. The page shows this, never what it asked for.
export const modeAfter = (response, stored) => (response && isStored(response.discovery_mode) ? response.discovery_mode : stored);

// A sentence for the tooltip of the choice next to Discover, so it is clear the choice is kept.
export function discoverHint(stored) {
  if (!isRunnable(stored)) {
    return "This target is manual only. Choose a mode, then press Discover: it is scanned once in that mode and the mode is kept, so the work conductor rescans it in that mode from then on.";
  }
  return `Discover runs in the mode chosen here (${modeText(stored)} is this target's own). Another mode is kept for this target, and the work conductor rescans it in that mode from then on.`;
}

// The toast after Discover started, from the server's answer: the scan and the mode it runs in, and what the target's mode is now.
export function startedText(response, stored) {
  const after = modeAfter(response, stored);
  if (response.internal) return `Internal scan #${response.scan_id} queued for a Sentinel (discovery modes do not apply to it; the target stays ${modeText(after)})`;
  const ran = response.scan_mode || after;
  let text = `Discovery #${response.scan_id} started (${ran})`;
  if (ran !== after) text += `; it was already going in ${ran}, and ${modeText(after)} is now this target's mode`;
  else if (after !== stored) text += `; ${modeText(after)} is now this target's mode`;
  return text;
}
