// What the status strip (statusstrip.js) shows, without the page: which items are drawn and how many notices the line says there are.
// Kept apart so tests/test_statusstrip_logic.mjs can run it under node.

// entries: [{items: [{kind, text, rank, dismissible?}], count?}], one per source (the scanners, the alerts). gone: the texts the viewer dismissed
// in this browser session; only a dismissible item is taken away by it.
export function visibleItems(entries, gone) {
  return entries
    .flatMap((e) => e.items || [])
    .filter((i) => !(i.dismissible && gone.includes(i.text)))
    .sort((a, b) => a.rank - b.rank);
}

// How many notices the strip says there are. A source that knows how many it stands for gives ``count`` (the alerts: every open alert, also
// the ones folded behind "7 more alerts. Show all."); otherwise each of its items that is a notice counts once. An item of kind "more" is a
// button that unfolds the list, never a notice of its own.
export function noticeCount(entries, gone) {
  let total = 0;
  for (const e of entries) {
    const items = e.items || [];
    const kept = items.filter((i) => !(i.dismissible && gone.includes(i.text)));
    if (Number.isFinite(e.count)) total += Math.max(0, e.count - (items.length - kept.length));
    else total += kept.filter((i) => i.kind !== "more").length;
  }
  return total;
}

// The alerts the strip lists after a poll: those the server sent, less the ones dismissed here whose dismissal the poll may not have seen yet
// (the poll began before the dismissal was stored: its answer is older than the click). dismissedAt: alert id -> the time the dismissal was
// stored (Infinity while the request is on its way); started: when the poll began, on the same clock.
export function afterPoll(alerts, dismissedAt, started) {
  return alerts.filter((a) => !(dismissedAt.has(a.id) && dismissedAt.get(a.id) >= started));
}
