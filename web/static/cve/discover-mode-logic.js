// Targets page: the discovery mode a target is discovered in. Kept free of the DOM and of imports so that `node --test` can run it
// (tests/test_discover_mode_logic.mjs); app.js only draws what these functions return. The server checks every value again.
//
// A target's stored mode (`discovery_mode`) is what every automatic scan uses: standard, deep, passive, or manual ("just add them, do not
// scan yet": nothing automatic scans it). Discover runs in the mode chosen next to the button; the one picked there is kept on the target, so
// the work conductor's next rescan uses it too (the server does that, POST targets/<id>/discover with `mode`).

export const RUNNABLE = [
  ["standard", "Standard"],
  ["deep", "Deep"],
  ["passive", "Passive (public sources only)"],
];
export const MANUAL = "manual";
export const MANUAL_LABEL = "Manual only (never scanned automatically)";

// the choices of the Discovery column: the three modes and manual only
export const STORED = [...RUNNABLE, [MANUAL, MANUAL_LABEL]];

export const isRunnable = (mode) => RUNNABLE.some(([value]) => value === mode);

// what the Discovery column of the all-projects view says
export const modeText = (mode) => (mode === MANUAL ? "manual only" : isRunnable(mode) ? mode : "standard");

// The mode Discover offers first: the stored one. A manual only target has no mode to run, so standard is offered, and
// choosing to run it is what ends manual only.
export const defaultChoice = (stored) => (isRunnable(stored) ? stored : "standard");

// The request body for Discover. Without `mode` the server runs the stored mode, so that is what is sent whenever the choice is the stored
// mode; a manual only target always names one (the server refuses to guess for it).
export const discoverBody = (stored, picked) => (isRunnable(picked) && (picked !== stored || !isRunnable(stored)) ? { mode: picked } : {});

// The mode the target has after Discover, as the server keeps it: the picked one, else the stored one.
export const modeAfter = (stored, picked) => (isRunnable(picked) ? picked : stored);

// A sentence for the tooltip of the choice next to Discover, so it is clear the choice is kept.
export function discoverHint(stored) {
  if (!isRunnable(stored)) {
    return "This target is manual only. Choosing a mode and pressing Discover scans it once and keeps that mode: the work conductor rescans it in that mode from then on.";
  }
  return `Discover runs in the mode chosen here (${modeText(stored)} is this target's own). Another mode is kept for this target, and the work conductor rescans it in that mode from then on.`;
}

// The toast after Discover started: names the mode, and says so when it replaced the stored one.
export function startedText(scanId, stored, picked) {
  const after = modeAfter(stored, picked);
  const changed = after !== stored;
  return `Discovery #${scanId} started (${after})${changed ? `; ${after} is now this target's mode` : ""}`;
}
