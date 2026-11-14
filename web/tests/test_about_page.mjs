import assert from 'node:assert/strict';
import {test} from 'node:test';

// "About this page" (static/cve/about-page.js): the button beside a page's head that opens the whole purpose sentence. It must show exactly when the
// sentence is cut or not drawn, open and close by keyboard, and never invent text of its own: the panel holds the page's own `.sub` text.
globalThis.document = undefined;
globalThis.window = {addEventListener() {}};
const {mountAbout, sentenceHidden} = await import('../static/cve/about-page.js');

const box = (w, h) => ({getBoundingClientRect: () => ({width: w, height: h})});
const sub = (text, scroll, client, scrollH = 20, clientH = 20) => ({textContent: text, scrollWidth: scroll, clientWidth: client, scrollHeight: scrollH, clientHeight: clientH});

test('a head that is not drawn (a phone clips it to one pixel) hides its sentence', () => {
  assert.equal(sentenceHidden(box(1, 1), sub('Some sentence.', 100, 100)), true);
});

test('a sentence cut at the end of its line is hidden, one that fits is not', () => {
  assert.equal(sentenceHidden(box(800, 40), sub('A long sentence that does not fit.', 640, 300)), true);
  assert.equal(sentenceHidden(box(800, 40), sub('Short.', 120, 300)), false);
  assert.equal(sentenceHidden(box(800, 40), sub('Wrapped.', 300, 300, 60, 40)), true); // clipped in height
});

// a page with just enough DOM for the module: the head, its sentence, and `after` that records what is put next to the head
function page(headBox, subBox, text) {
  const made = [];
  const node = (tag) => {
    const attrs = {};
    const listeners = {};
    return {tag, attrs, listeners, hidden: false, className: '', textContent: '', id: '', type: '', focused: false,
      setAttribute(k, v) { attrs[k] = String(v); }, getAttribute: (k) => attrs[k],
      addEventListener(ev, fn) { (listeners[ev] ||= []).push(fn); },
      fire(ev, e = {}) { (listeners[ev] || []).forEach((fn) => fn({preventDefault() {}, ...e})); },
      focus() { this.focused = true; }};
  };
  const subNode = {...subBox, textContent: text};
  const head = {...headBox, querySelector: (s) => (s === '.sub' ? subNode : null), parentElement: {querySelector: () => null},
    after(...nodes) { made.push(...nodes); }};
  const doc = {querySelector: (s) => (s === 'main .page-head' ? head : null), createElement: (t) => node(t)};
  return {doc, made, subNode};
}

test('the button is hidden while the sentence fits and shown when it is cut', () => {
  const fits = page(box(800, 40), sub('x', 100, 300), 'What this page is for.');
  const a = mountAbout(fits.doc);
  assert.equal(a.button.hidden, true);
  const cut = page(box(800, 40), sub('x', 900, 300), 'What this page is for, in a sentence that is far too long for the line.');
  const b = mountAbout(cut.doc);
  assert.equal(b.button.hidden, false);
  assert.equal(b.panel.textContent, 'What this page is for, in a sentence that is far too long for the line.');
});

test('the button opens and closes the panel, and says so to a screen reader', () => {
  const p = page(box(1, 1), sub('x', 1, 1), 'The whole   sentence.');
  const a = mountAbout(p.doc);
  assert.equal(a.button.hidden, false);
  assert.equal(a.button.getAttribute('aria-expanded'), 'false');
  assert.equal(a.button.getAttribute('aria-controls'), a.panel.id);
  assert.equal(a.panel.hidden, true);
  a.button.fire('click');
  assert.equal(a.panel.hidden, false);
  assert.equal(a.button.getAttribute('aria-expanded'), 'true');
  assert.equal(a.panel.textContent, 'The whole sentence.');
  a.button.fire('click');
  assert.equal(a.panel.hidden, true);
});

test('Escape closes the panel and returns the focus to the button', () => {
  const p = page(box(1, 1), sub('x', 1, 1), 'The whole sentence.');
  const a = mountAbout(p.doc);
  a.button.fire('click');
  a.panel.fire('keydown', {key: 'Escape'});
  assert.equal(a.panel.hidden, true);
  assert.equal(a.button.getAttribute('aria-expanded'), 'false');
  assert.equal(a.button.focused, true);
});

test('a page with no purpose sentence gets nothing', () => {
  const doc = {querySelector: () => null, createElement: () => ({})};
  assert.equal(mountAbout(doc), null);
});
