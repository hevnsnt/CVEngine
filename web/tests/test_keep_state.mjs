import assert from 'node:assert/strict';
import {test} from 'node:test';

import {IDLE_MS, interacting, renderKeepingState, signature} from '../static/cve/keep-state.js';
import {doc, el, fakeTimers} from './fake_dom.mjs';

// What a polled page does: build the blocks from the newest data. ``deferred`` is what the Sentinels page did before keep-state.js: empty the container
// and build again, which is the bug these tests are about.
const mountOf = () => el('div', {id: 'mount'});
const naive = (mount, build) => {
  mount.childNodes.splice(0).forEach((c) => (c.parentNode = null));
  build().forEach((n) => mount.appendChild(n));
};
const clock = (start = 100000) => {
  let t = start;
  const now = () => t;
  now.advance = (ms) => (t += ms);
  return now;
};
const draw = (mount, build, extra = {}) => renderKeepingState(mount, build, {doc, now: clock(), ...extra});

const queue = (n, rows = 3) => () => [
  el('section', {'data-keep-key': 'queue'},
    el('h3', {}, 'OpenVAS queue'),
    el('details', {'data-keep-key': 'not-due'}, el('summary', {}, `Not due (${n})`), el('ul', {'data-keep-key': 'not-due-list'}, ...Array.from({length: rows}, (_, i) => el('li', {}, `host ${i}`))),
      el('p', {}, `Showing ${rows} of ${n} not due hosts.`))),
];
const openIt = (mount, key) => {
  const d = mount.querySelectorAll('details').find((x) => x.getAttribute('data-keep-key') === key);
  d.open = true;
  return d;
};

test('the old behaviour closed every opened section at the next refresh (the bug)', () => {
  const mount = mountOf();
  naive(mount, queue(33));
  openIt(mount, 'not-due');
  naive(mount, queue(33));
  assert.equal(mount.querySelectorAll('details')[0].open, false);
});

test('an opened section stays open when the refresh brings changed markup (its count moved)', () => {
  const mount = mountOf();
  draw(mount, queue(33));
  openIt(mount, 'not-due');
  const out = draw(mount, queue(34));
  assert.equal(out.status, 'rendered');
  assert.equal(out.replaced, 1);
  const d = mount.querySelectorAll('details')[0];
  assert.equal(d.open, true);
  assert.match(d.textContent, /Not due \(34\)/);
  assert.match(d.textContent, /Showing 3 of 34 not due hosts/);
});

test('an opened section stays open, and its node is the same one, when the refresh brings the same markup', () => {
  const mount = mountOf();
  draw(mount, queue(33));
  const d = openIt(mount, 'not-due');
  const block = mount.firstChild;
  const out = draw(mount, queue(33));
  assert.deepEqual([out.kept, out.replaced, out.added, out.removed], [1, 0, 0, 0]);
  assert.equal(mount.firstChild, block);
  assert.equal(mount.querySelectorAll('details')[0], d);
  assert.equal(d.open, true);
});

test('a section the person left closed stays closed', () => {
  const mount = mountOf();
  draw(mount, queue(33));
  draw(mount, queue(34));
  assert.equal(mount.querySelectorAll('details')[0].open, false);
});

test('open state follows the key, not the position: a block inserted before it, or a reorder, does not move it', () => {
  const page = (n, lead) => () => [...(lead ? [el('p', {'data-keep-key': 'lead'}, 'new notice')] : []), ...queue(n)()];
  const mount = mountOf();
  draw(mount, page(33, false));
  openIt(mount, 'not-due');
  draw(mount, page(34, true));
  assert.equal(mount.childNodes.length, 2);
  assert.equal(mount.querySelectorAll('details')[0].open, true);
  const two = () => [
    el('details', {'data-keep-key': 'a'}, el('summary', {}, 'A (1)')),
    el('details', {'data-keep-key': 'b'}, el('summary', {}, 'B (1)')),
  ];
  const swapped = () => two().reverse();
  const m2 = mountOf();
  draw(m2, two);
  m2.querySelectorAll('details').find((d) => d.getAttribute('data-keep-key') === 'b').open = true;
  draw(m2, swapped);
  assert.deepEqual(m2.querySelectorAll('details').map((d) => [d.getAttribute('data-keep-key'), d.open]), [['b', true], ['a', false]]);
});

test('a section with no data-keep-key is found by its summary text with the numbers blanked, and by its place among equals', () => {
  const page = (a, b) => () => [el('div', {class: 'card'}, el('details', {}, el('summary', {}, `Daily usage (${a})`)), el('details', {}, el('summary', {}, `Daily usage (${b})`)))];
  const mount = mountOf();
  draw(mount, page(3, 4));
  mount.querySelectorAll('details')[1].open = true;
  draw(mount, page(5, 6));
  assert.deepEqual(mount.querySelectorAll('details').map((d) => d.open), [false, true]);
});

test('a new section appears closed, a removed one vanishes', () => {
  const mount = mountOf();
  draw(mount, () => [el('details', {'data-keep-key': 'one'}, el('summary', {}, 'One')), el('details', {'data-keep-key': 'two'}, el('summary', {}, 'Two'))]);
  mount.querySelectorAll('details').forEach((d) => (d.open = true));
  const out = draw(mount, () => [el('details', {'data-keep-key': 'two'}, el('summary', {}, 'Two (changed)')), el('details', {'data-keep-key': 'three'}, el('summary', {}, 'Three'))]);
  assert.deepEqual(mount.querySelectorAll('details').map((d) => [d.getAttribute('data-keep-key'), d.open]), [['two', true], ['three', false]]);
  assert.equal(out.removed, 1);
  assert.equal(out.added, 1);
});

test('a block that did not change keeps its node while its changed neighbour is replaced', () => {
  const page = (n) => () => [el('p', {'data-keep-key': 'still'}, 'static text'), el('p', {'data-keep-key': 'moving'}, `count ${n}`)];
  const mount = mountOf();
  draw(mount, page(1));
  const [still, moving] = mount.childNodes;
  draw(mount, page(2));
  assert.equal(mount.childNodes[0], still);
  assert.notEqual(mount.childNodes[1], moving);
  assert.equal(mount.childNodes[1].textContent, 'count 2');
});

test('whether a <details> is open is not part of what "changed" means; an ignored subtree is not either', () => {
  const a = el('details', {}, el('summary', {}, 'x'), el('b', {'data-keep-ignore': ''}, 'orb 1'));
  const b = a.cloneNode(true);
  b.open = true;
  b.querySelectorAll('b')[0].childNodes[0].data = 'orb 2';
  assert.equal(signature(a), signature(b));
  b.querySelectorAll('summary')[0].childNodes[0].data = 'y';
  assert.notEqual(signature(a), signature(b));
});

test('scroll position inside a list and of the container survives a redraw that changed the list', () => {
  const page = (n) => () => [el('div', {'data-keep-key': 'box'}, el('ul', {'data-keep-key': 'list'}, ...Array.from({length: n}, (_, i) => el('li', {}, `row ${i}`))))];
  const mount = mountOf();
  draw(mount, page(40));
  const list = mount.querySelectorAll('ul')[0];
  list.scrollTop = 180;
  list.scrollLeft = 7;
  mount.scrollTop = 25;
  draw(mount, page(41));
  const fresh = mount.querySelectorAll('ul')[0];
  assert.notEqual(fresh, list);
  assert.equal(fresh.childNodes.length, 41);
  assert.deepEqual([fresh.scrollTop, fresh.scrollLeft, mount.scrollTop], [180, 7, 25]);
});

test('typed text, a ticked box and the caret survive a redraw; a field the person did not touch takes the server value', () => {
  const page = (note) => () => [el('form', {'data-keep-key': 'form'},
    el('input', {name: 'model', type: 'text', value: 'default-model'}),
    el('input', {name: 'untouched', type: 'text', value: note}),
    el('input', {name: 'agree', type: 'checkbox'}),
    el('textarea', {name: 'why'}, ''))];
  const mount = mountOf();
  draw(mount, page('v1'));
  const [model, untouched, agree, why] = mount.querySelectorAll('input, textarea');
  model.value = 'typed-by-person';
  agree.checked = true;
  why.value = 'a long reason';
  model.focus();
  model.setSelectionRange(3, 7);
  draw(mount, page('v2'));
  const [m2, u2, a2, w2] = mount.querySelectorAll('input, textarea');
  assert.notEqual(m2, model);
  assert.equal(m2.value, 'typed-by-person');
  assert.equal(a2.checked, true);
  assert.equal(w2.value, 'a long reason');
  assert.equal(u2.value, 'v2');
  assert.equal(doc.activeElement, m2);
  assert.deepEqual([m2.selectionStart, m2.selectionEnd], [3, 7]);
});

test('a refresh waits while the person presses a key or a pointer in the region, then the newest build is drawn', () => {
  const mount = mountOf();
  const now = clock();
  const timers = fakeTimers();
  const opts = {doc, now, timers};
  draw(mount, queue(33), opts);
  mount.fire('keydown');
  assert.equal(renderKeepingState(mount, queue(34), opts).status, 'deferred');
  assert.equal(renderKeepingState(mount, queue(35), opts).status, 'deferred');
  assert.match(mount.textContent, /Not due \(33\)/);
  assert.equal(timers.queue.length, 1);
  now.advance(IDLE_MS + 100);
  timers.runAll();
  assert.match(mount.textContent, /Not due \(35\)/);
  mount.fire('pointerdown');
  assert.equal(renderKeepingState(mount, queue(36), opts).status, 'deferred');
  assert.equal(renderKeepingState(mount, queue(36), {...opts, force: true}).status, 'rendered');
});

test('a refresh waits while a dialog, popover or menu is open in the region, or a select was just used', () => {
  const now = clock();
  const opts = {doc, now};
  const menu = mountOf();
  draw(menu, () => [el('div', {'data-keep-key': 'm'}, el('button', {'aria-haspopup': 'menu', 'aria-expanded': 'true'}, 'Actions'))], opts);
  now.advance(IDLE_MS + 100);
  assert.equal(interacting(menu, opts), true);
  const dialog = mountOf();
  draw(dialog, () => [el('dialog', {open: ''}, 'x')], opts);
  assert.equal(interacting(dialog, opts), true);
  const pick = mountOf();
  draw(pick, () => [el('select', {name: 'days'}, el('option', {value: '1'}, 'a'))], opts);
  pick.fire('pointerdown');
  now.advance(IDLE_MS + 100);
  pick.querySelectorAll('select')[0].focus();
  assert.equal(interacting(pick, opts), true);
  now.advance(20000);
  assert.equal(interacting(pick, opts), false);
  const quiet = mountOf();
  draw(quiet, queue(1), opts);
  now.advance(IDLE_MS + 100);
  assert.equal(interacting(quiet, opts), false);
});

test('a text selection inside the region holds the refresh back', () => {
  const mount = mountOf();
  const now = clock();
  draw(mount, queue(33), {doc, now});
  now.advance(IDLE_MS + 100);
  const text = mount.querySelectorAll('h3')[0].childNodes[0];
  const view = {...doc.defaultView, getSelection: () => ({isCollapsed: false, anchorNode: text})};
  assert.equal(interacting(mount, {doc: {...doc, defaultView: view}, now}), true);
});
