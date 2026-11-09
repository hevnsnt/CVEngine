// How the dashboard loads its numbers: each tile on its own, from what the server last stored, never blocked by another tile.
//
// Each tile has its own poller and its own request (stats, graph, discovery ...): none awaits another, so a slow answer holds back only its own tile.
//
// The server answers the headline numbers from the stored per-project snapshots at once (cveFeed/dashboard_snapshot.py) and says how old they are
// (``snapshot.as_of``) and whether a project has none yet (``snapshot.partial``, ``snapshot.ready``). This module holds the page-side half:
// the pure functions the page and tests/test_tile_loader.mjs share. No DOM, no network, no timers of its own.

export const STALE_AFTER_MS = 120000; // older than this and the page says how old ("as of 5 minutes ago")

/** "as of 5 minutes ago" for a snapshot older than two minutes, else "" (a fresh one needs no remark). */
export function ageText(asOf, now = Date.now()) {
  const at = asOf ? Date.parse(asOf) : NaN;
  if (!Number.isFinite(at)) return "";
  const ms = Math.max(0, now - at);
  if (ms < STALE_AFTER_MS) return "";
  const min = Math.floor(ms / 60000);
  if (min < 60) return `as of ${min} minute${min === 1 ? "" : "s"} ago`;
  const hours = Math.floor(min / 60);
  if (hours < 48) return `as of ${hours} hour${hours === 1 ? "" : "s"} ago`;
  return `as of ${Math.floor(hours / 24)} days ago`;
}

/**
 * What the tiles show for an answer: "pending" (nothing stored yet and nothing remembered: a skeleton, never dashes), "updating" (a number is shown but
 * a newer one is on its way: some project has no snapshot yet, the snapshot is old, or the number is the one remembered from the last visit) or
 * "fresh". ``remembered`` says the values on screen came from this browser's last visit, not from the server.
 */
export function tileState(snapshot, { remembered = false, now = Date.now() } = {}) {
  if (remembered && !snapshot) return "updating";
  if (!snapshot || snapshot.ready === false) return remembered ? "updating" : "pending";
  if (snapshot.partial || snapshot.stale) return "updating";
  const at = snapshot.as_of ? Date.parse(snapshot.as_of) : NaN;
  return Number.isFinite(at) && now - at > STALE_AFTER_MS ? "updating" : "fresh";
}

/** The last answer this browser saw for ``key`` (``{at, value}``), or null. Safe with no storage, a full one, or text that is not JSON. */
export function lastKnown(storage, key) {
  try {
    const raw = storage && storage.getItem(key);
    const parsed = raw ? JSON.parse(raw) : null;
    return parsed && typeof parsed === "object" && "value" in parsed ? parsed : null;
  } catch (_) {
    return null;
  }
}

export function remember(storage, key, value, now = Date.now()) {
  try {
    if (storage) storage.setItem(key, JSON.stringify({ at: now, value }));
  } catch (_) {
    /* the page works without a memory */
  }
}

/**
 * Starts the pollers that are not needed for the first paint one after another, once the browser is idle (or after ``timeout`` ms), ``gap`` ms apart,
 * so the page asks for the few things the numbers need first and the rest as the browser has time. ``starts`` are functions; ``idle(fn, {timeout})``
 * and ``later(fn, ms)`` default to requestIdleCallback and setTimeout. Returns the number of starts scheduled.
 */
export function startWhenIdle(starts, { idle = globalThis.requestIdleCallback && ((fn, o) => globalThis.requestIdleCallback(fn, o)), later = (fn, ms) => setTimeout(fn, ms), gap = 150, timeout = 1500 } = {}) {
  const run = () => starts.forEach((start, i) => later(start, i * gap));
  if (idle) idle(run, { timeout });
  else later(run, 0);
  return starts.length;
}
