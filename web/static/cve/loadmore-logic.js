// "Load more" under a list: the words and the arithmetic, kept free of the DOM and of imports so that `node --test` can run them
// (tests/test_loadmore_logic.mjs). createList (app.js) draws what these return.
//
// Phases of the button under the rows: `idle` (a button saying how many are left), `busy` (the same button, disabled and aria-busy,
// saying how many are on the way), `error` (the rows stay; a retry is offered) and `done` (the button is replaced by a plain
// "All N shown", but only after the reader asked for more at least once: a list that fits on its first page says nothing).

// rows shown after `page` pages of `size`, never more than `total`
export const shownCount = (total, page, size) => Math.max(0, Math.min(total, page * size));
export const leftCount = (total, page, size) => Math.max(0, total - shownCount(total, page, size));
// how many rows the next request adds
export const nextCount = (left, size) => Math.max(0, Math.min(left, size));

export const moreLabel = (left) => `Load more (${left} left)`;
export const busyLabel = (n) => `Loading ${n} more...`;
export const doneLabel = (total) => `All ${total} shown`;

const word = (n, noun, plural) => (n === 1 ? noun : plural);
// the polite live-region message after a page arrived
export const loadedMessage = (added, shown, total, noun = "item", plural = "items") => `Loaded ${added} more ${word(added, noun, plural)}, ${shown} of ${total} shown`;

// What the row under the list shows: {kind: "button"|"done"|"none", label, busy, disabled}.
// `phase` is what the reader started (idle|busy); `page` is the page number the rows on screen came from.
export function moreView({ phase = "idle", total, page, size }) {
  const left = leftCount(total, page, size);
  if (left <= 0) return page > 1 ? { kind: "done", label: doneLabel(total), busy: false, disabled: false } : { kind: "none", label: "", busy: false, disabled: false };
  if (phase === "busy") return { kind: "button", label: busyLabel(nextCount(left, size)), busy: true, disabled: true };
  return { kind: "button", label: moreLabel(left), busy: false, disabled: false };
}
