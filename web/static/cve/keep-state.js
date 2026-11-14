// Re-render a polled region without taking away what the person is doing in it.
//
// A page that refreshes itself every few seconds used to empty its container and build everything again. The new elements come up with their
// default state, so every <details> the person had opened snapped shut at the next refresh, a list they had scrolled went back to the top, the
// field they were typing in lost its text and focus, and a half-made text selection vanished. This module is the one place that fixes that, for every
// polling page:
//
//   renderKeepingState(container, () => [node, node, ...])
//
// The function builds the NEW blocks (the container's top-level children) exactly as the page always did. Then:
//   * a block with the same key (data-keep-key, else tag + class + position) whose markup did not change is not touched at all: the same node stays,
//     so a refresh with nothing new moves nothing (the open state of a <details> is not part of the markup that is compared);
//   * (a block marked data-keep-fresh is the exception: its handlers close over data its markup does not show, so it is always replaced; a kept block
//     keeps its handlers, so a block's handlers must depend only on what its markup says)
//   * a block that changed is replaced, and what the person did inside the old one is put on the new one: the open state of every <details> (by
//     data-keep-key, else the summary text with its numbers blanked and its position among equals), the scroll position of every scrolled element,
//     the value, checked state and caret of the fields they changed, and the focused element;
//   * a block that is gone is removed, a block that is new appears as the page built it (a new section starts closed);
//   * the container's own scroll and the page scroll are put back.
// It also refuses to redraw while the person is using the region: a pointer press or a key in the last two seconds inside it, a focused <select> they
// just used, an open dialog, popover or menu, or a text selection inside it. The newest build waits and runs when the person is done.
//
// Give every disclosure a stable data-keep-key (the summary text changes with its count: "Not due (33)"), and every top-level block of a polled
// container one too. Nothing here reads the network or the page: tests/test_keep_state.mjs drives it with a small fake DOM, and
// tests/e2e_keep_open.py with a real browser.

export const KEEP_KEY = "data-keep-key";
export const IGNORE = "data-keep-ignore"; // an element (a canvas, an orb, a moved widget) that is not part of what "changed" means
export const FRESH = "data-keep-fresh"; // a top-level block that is always replaced, never kept: its event handlers close over data the markup does not show
export const IDLE_MS = 2000;
const SELECT_MS = 15000; // a <select> keeps its focus after its menu closed: it only holds a redraw back for this long after the last touch

const POPOVER_SELECTORS = ["dialog[open]", ":popover-open", '[aria-haspopup][aria-expanded="true"]', '[data-keep-popover="open"]', "details[data-keep-popover][open]"];

const guards = new WeakMap(); // container -> {last, pending, timer}
const signatures = new WeakMap(); // block node -> the normalised markup it was drawn from

const all = (root, selector) => {
  try {
    return Array.from(root.querySelectorAll(selector));
  } catch (_) {
    return []; // a selector this browser does not know (":popover-open" before 2023)
  }
};

/** The markup of ``node`` as compared between refreshes: no ignored subtree, no ``open`` (the person owns it), no live-moved state. */
export function signature(node) {
  if (node.nodeType === 3) return `#text:${node.textContent}`;
  if (node.nodeType !== 1) return "";
  const copy = node.cloneNode(true);
  all(copy, `[${IGNORE}]`).forEach((n) => n.parentNode && n.parentNode.removeChild(n));
  if (copy.tagName === "DETAILS") copy.removeAttribute("open");
  all(copy, "details").forEach((d) => d.removeAttribute("open"));
  return copy.outerHTML;
}

const tagOf = (el) => (el.tagName || "").toLowerCase();
const attr = (el, name) => (el.getAttribute ? el.getAttribute(name) : null);

// the text a <summary> is known by: the numbers blanked, because "Not due (33)" becomes "Not due (34)"
const summaryText = (details) => {
  const s = all(details, "summary").find((n) => n.parentNode === details) || null;
  return s ? String(s.textContent || "").replace(/\d[\d,.]*/g, "#").trim() : "";
};

// what an element is called inside one block: its data-keep-key, else its id, name or summary, else its tag and first class
function baseKey(el) {
  const keep = attr(el, KEEP_KEY);
  if (keep) return `k:${keep}`;
  const id = attr(el, "id");
  if (id) return `#${id}`;
  if (tagOf(el) === "details") return `details:${summaryText(el)}`;
  const name = attr(el, "name");
  if (name) return `${tagOf(el)}[${name}]`;
  const cls = String(attr(el, "class") || "").split(/\s+/)[0];
  return `${tagOf(el)}.${cls}`;
}

// every element of a block with a key that is the same on the old and on the new copy: the base, then which of its equals it is
function keyed(root, selector) {
  const seen = new Map();
  const out = [];
  const list = selector === "*" ? [root, ...all(root, "*")] : [...(root.matches && root.matches(selector) ? [root] : []), ...all(root, selector)];
  for (const el of list) {
    const base = baseKey(el);
    const n = seen.get(base) || 0;
    seen.set(base, n + 1);
    out.push([`${base}~${n}`, el]);
  }
  return out;
}

const isField = (el) => ["input", "textarea", "select"].includes(tagOf(el)) && !["file", "password"].includes(String(el.type || "").toLowerCase());

function fieldDefault(el) {
  if (tagOf(el) === "select") {
    const options = Array.from(el.options || []);
    const chosen = options.find((o) => o.defaultSelected) || options[0];
    return chosen ? chosen.value : "";
  }
  return el.defaultValue ?? "";
}

/** What the person did inside ``root``: opened sections, scrolled elements, edited fields, the focused element. */
export function capture(root, activeElement = null) {
  const state = { open: new Map(), scroll: new Map(), fields: new Map(), focus: null };
  for (const [key, d] of keyed(root, "details")) state.open.set(key, !!d.open);
  for (const [key, el] of keyed(root, "*")) {
    if (el.scrollTop > 0 || el.scrollLeft > 0) state.scroll.set(key, { top: el.scrollTop, left: el.scrollLeft });
  }
  for (const [key, el] of keyed(root, "input, textarea, select")) {
    if (!isField(el)) continue;
    const type = String(el.type || "").toLowerCase();
    const edited = type === "checkbox" || type === "radio" ? el.checked !== el.defaultChecked : String(el.value) !== String(fieldDefault(el));
    const focused = el === activeElement;
    if (edited || focused) {
      state.fields.set(key, { value: el.value, checked: el.checked, type, start: focused ? el.selectionStart : null, end: focused ? el.selectionEnd : null });
    }
  }
  if (activeElement && root.contains && root.contains(activeElement)) {
    const hit = keyed(root, "*").find(([, el]) => el === activeElement);
    if (hit) state.focus = hit[0];
  }
  return state;
}

/** Put what ``capture`` found onto ``root`` (a new copy of the same block, already in the page so that scroll can be set). */
export function restore(root, state) {
  for (const [key, d] of keyed(root, "details")) if (state.open.has(key) && d.open !== state.open.get(key)) d.open = state.open.get(key);
  for (const [key, el] of keyed(root, "*")) {
    const at = state.scroll.get(key);
    if (at) {
      el.scrollTop = at.top;
      el.scrollLeft = at.left;
    }
  }
  for (const [key, el] of keyed(root, "input, textarea, select")) {
    const was = state.fields.get(key);
    if (!was || !isField(el)) continue;
    if (was.type === "checkbox" || was.type === "radio") el.checked = was.checked;
    else el.value = was.value;
  }
  if (state.focus) {
    const hit = keyed(root, "*").find(([key]) => key === state.focus);
    if (hit && hit[1].focus) {
      hit[1].focus({ preventScroll: true });
      const was = state.fields.get(state.focus);
      if (was && was.start != null && hit[1].setSelectionRange) {
        try {
          hit[1].setSelectionRange(was.start, was.end);
        } catch (_) {
          /* a field type with no caret */
        }
      }
    }
  }
}

const asNodes = (built) => {
  if (!built) return [];
  if (Array.isArray(built)) return built.flat().filter(Boolean);
  if (built.nodeType === 11) return Array.from(built.childNodes);
  return [built];
};

// the key of a top-level block: its data-keep-key, else tag and first class and which of its equals it is
function blockKeys(nodes) {
  const seen = new Map();
  return nodes.map((node) => {
    const base = node.nodeType === 1 ? attr(node, KEEP_KEY) || `${tagOf(node)}.${String(attr(node, "class") || "").split(/\s+/)[0]}` : "#text";
    const n = seen.get(base) || 0;
    seen.set(base, n + 1);
    return `${base}~${n}`;
  });
}

function reconcile(container, nextNodes, doc) {
  const active = doc ? doc.activeElement : null;
  const olds = Array.from(container.childNodes);
  const oldKeys = blockKeys(olds);
  const byKey = new Map(olds.map((n, i) => [oldKeys[i], n]));
  const nextKeys = blockKeys(nextNodes);
  const outcome = { kept: 0, replaced: 0, added: 0, removed: 0 };
  const settled = [];
  const swaps = [];
  nextNodes.forEach((next, i) => {
    const old = byKey.get(nextKeys[i]);
    const sig = signature(next);
    if (old && signatures.get(old) === sig && !(next.nodeType === 1 && next.hasAttribute(FRESH))) {
      settled.push(old);
      byKey.delete(nextKeys[i]);
      outcome.kept += 1;
      return;
    }
    signatures.set(next, sig);
    settled.push(next);
    if (old && old.nodeType === 1 && next.nodeType === 1) {
      swaps.push([old, next, capture(old, active)]);
      byKey.delete(nextKeys[i]);
      outcome.replaced += 1;
    } else outcome.added += 1;
  });
  for (const [old, next] of swaps) container.replaceChild(next, old);
  for (const left of byKey.values()) {
    container.removeChild(left);
    outcome.removed += 1;
  }
  let cursor = container.firstChild;
  for (const node of settled) {
    if (node === cursor) cursor = cursor.nextSibling;
    else container.insertBefore(node, cursor);
  }
  for (const [, next, state] of swaps) restore(next, state);
  return outcome;
}

function guardOf(container, doc, now) {
  let g = guards.get(container);
  if (g) return g;
  g = { last: -Infinity, pending: null, timer: 0 };
  guards.set(container, g);
  const touch = () => {
    g.last = now();
  };
  if (container.addEventListener) for (const type of ["pointerdown", "mousedown", "touchstart", "keydown", "input", "focusin"]) container.addEventListener(type, touch, true);
  return g;
}

/** True while the person is using ``container``: recent pointer or key, a used <select>, an open popover, or a selection inside. */
export function interacting(container, { doc = globalThis.document, now = () => Date.now(), idleMs = IDLE_MS } = {}) {
  const g = guardOf(container, doc, now);
  const age = now() - g.last;
  if (age < idleMs) return true;
  const active = doc ? doc.activeElement : null;
  if (active && container.contains && container.contains(active) && tagOf(active) === "select" && age < SELECT_MS) return true;
  if (POPOVER_SELECTORS.some((s) => all(container, s).length)) return true;
  const sel = doc && doc.defaultView && doc.defaultView.getSelection ? doc.defaultView.getSelection() : null;
  if (sel && !sel.isCollapsed && sel.anchorNode && container.contains && container.contains(sel.anchorNode)) return true;
  return false;
}

/**
 * Redraw ``container`` with the blocks ``build()`` returns (an array of nodes or a fragment), keeping what the person opened, scrolled, typed or
 * selected. Returns ``{status: "rendered", kept, replaced, added, removed}`` or ``{status: "deferred"}`` when the person is using the region (the
 * newest build is drawn when they stop). ``force`` draws at once (a person's own action, such as a button they pressed, is not a poll).
 * ``after(outcome)`` runs once the blocks are in place, whether the draw was at once or later. ``timers`` and ``now`` are for tests.
 */
export function renderKeepingState(container, build, { force = false, doc = globalThis.document, now = () => Date.now(), timers, idleMs = IDLE_MS, after } = {}) {
  const set = timers ? timers.set : (f, d) => setTimeout(f, d);
  const clear = timers ? timers.clear : (t) => clearTimeout(t);
  const g = guardOf(container, doc, now);
  if (!force && interacting(container, { doc, now, idleMs })) {
    g.pending = build;
    clear(g.timer);
    g.timer = set(() => {
      const later = g.pending;
      g.timer = 0;
      if (later) renderKeepingState(container, later, { doc, now, timers, idleMs, after });
    }, Math.max(250, idleMs - (now() - g.last) + 50));
    return { status: "deferred" };
  }
  g.pending = null;
  clear(g.timer);
  g.timer = 0;
  const top = container.scrollTop;
  const left = container.scrollLeft;
  const view = doc && doc.defaultView;
  const pageX = view ? view.scrollX : 0;
  const pageY = view ? view.scrollY : 0;
  const outcome = reconcile(container, asNodes(build()), doc);
  if (container.scrollTop !== top) container.scrollTop = top;
  if (container.scrollLeft !== left) container.scrollLeft = left;
  if (view && view.scrollTo && (view.scrollX !== pageX || view.scrollY !== pageY)) view.scrollTo(pageX, pageY);
  if (after) after(outcome);
  return { status: "rendered", ...outcome };
}
