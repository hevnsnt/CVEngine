import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {register} from 'node:module';
import {test} from 'node:test';

// The "Your API keys" list (static/cve/api-keys-list.js): newest first, Created and Last used in local time, an access badge, only 4 + 2 characters of a token, revoke with a confirm.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this._text = ''; this.className = ''; this.listeners = {}; this.isConnected = true; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  fire(type) { (this.listeners[type] || []).forEach((fn) => fn({target: this})); }
  showModal() { this.open = true; }
  close() { if (this.open) { this.open = false; this.fire('close'); } }
  focus() {}
  remove() {}
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
globalThis.Node = Node;
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };
const body = new Node('body');
globalThis.document = {createElement: (t) => new Node(t), createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}), querySelector: () => null, querySelectorAll: () => [], body, cookie: ''};
globalThis.localStorage = {getItem: () => null, setItem() {}};
globalThis.setTimeout = (fn) => 0;

const {keyHint, sortTokens, accessWords, renderTokenList, revokeQuestion} = await import('../static/cve/api-keys-list.js');
const {fmtDateTime} = await import('../static/cve/prefs.js');

const tok = (over = {}) => ({id: 1, name: 'agent', prefix: 'cve_', suffix: 'xY', scope: 'full', project: null, read_only: false, created: '2026-11-01T10:00:00+00:00', last_used: null, revoked: false, ...over});

test('a token shows its first 4 and last 2 characters and never more, whatever the server sent', () => {
  assert.equal(keyHint(tok()), 'cve_...xY');
  assert.equal(keyHint(tok({suffix: ''})), 'cve_...');  // a key made before the ending was kept
  assert.equal(keyHint(tok({prefix: 'cve_AbCdEfGh', suffix: 'abcdefgh'})), 'cve_...gh');
  const shown = keyHint({prefix: 'cve_AbCdEfGh', suffix: 'abcdefgh'});
  assert.ok(shown.length <= 4 + 3 + 2);
});

test('newest first, a tie broken by id, revoked keys left out', () => {
  const list = sortTokens([
    tok({id: 1, name: 'old', created: '2026-10-01T00:00:00+00:00'}),
    tok({id: 3, name: 'same-second-b', created: '2026-11-05T00:00:00+00:00'}),
    tok({id: 2, name: 'same-second-a', created: '2026-11-05T00:00:00+00:00'}),
    tok({id: 4, name: 'gone', created: '2026-11-07T00:00:00+00:00', revoked: true}),
    tok({id: 5, name: 'newest', created: '2026-11-06T00:00:00+00:00'}),
  ]);
  assert.deepEqual(list.map((t) => t.name), ['newest', 'same-second-b', 'same-second-a', 'old']);
});

test('old duplicates stay readable: two keys with one name are two rows, told apart by key and date', () => {
  const root = new Node('div');
  const n = renderTokenList(root, [tok({id: 1, suffix: 'aa', created: '2026-10-01T00:00:00+00:00'}), tok({id: 2, suffix: 'bb', created: '2026-11-01T00:00:00+00:00'})], async () => {});
  assert.equal(n, 2);
  const rows = find(root, (x) => x.tag === 'tr').slice(1);
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /agent.*cve_\.\.\.bb/);
  assert.match(rows[1].textContent, /agent.*cve_\.\.\.aa/);
});

test('the columns: Name, Key, Access, Created in local time, Last used, and Revoke', () => {
  const root = new Node('div');
  renderTokenList(root, [tok({last_used: '2026-11-03T08:30:00+00:00'})], async () => {});
  const heads = find(root, (x) => x.tag === 'th').map((h) => h.textContent);
  assert.deepEqual(heads, ['Name', 'Key', 'Access', 'Created', 'Last used', '']);
  const text = find(root, (x) => x.tag === 'tr')[1].textContent;
  assert.ok(text.includes(fmtDateTime('2026-11-01T10:00:00+00:00')), text);  // the shared helper: the person's time zone
  assert.ok(text.includes(fmtDateTime('2026-11-03T08:30:00+00:00')), text);
  assert.ok(!text.includes('T10:00'), text);
  const never = new Node('div');
  renderTokenList(never, [tok()], async () => {});
  assert.match(never.textContent, /never used/);
});

test('a read-only key carries a read only badge, a full one says full access, a host reporter says which project', () => {
  assert.equal(accessWords(tok({read_only: true})), 'read only');
  assert.equal(accessWords(tok()), 'full access');
  assert.equal(accessWords(tok({scope: 'inventory', project: 'acme'})), 'host reporter for acme');
  const root = new Node('div');
  renderTokenList(root, [tok({read_only: true})], async () => {});
  assert.equal(find(root, (x) => x.className.startsWith('badge'))[0].textContent, 'read only');
});

test('revoke asks first: Cancel changes nothing, Revoke in the dialog does it', async () => {
  const root = new Node('div');
  const revoked = [];
  renderTokenList(root, [tok({id: 7, name: 'ci-key'})], async (t) => { revoked.push(t.id); });
  const revoke = find(root, (x) => x.tag === 'button' && x.textContent === 'Revoke')[0];
  const pending = revoke.onclick();
  const dlg = find(body, (x) => x.tag === 'dialog').at(-1);
  assert.ok(dlg.open);
  assert.match(dlg.textContent, /Revoke "ci-key" \(cve_\.\.\.xY, made .+\)\? Anything using this key stops working at once\. This cannot be undone\./);
  find(dlg, (x) => x.tag === 'button' && x.textContent === 'Cancel')[0].onclick();
  await pending;
  assert.deepEqual(revoked, []);
  const again = revoke.onclick();
  const dlg2 = find(body, (x) => x.tag === 'dialog').at(-1);
  find(dlg2, (x) => x.tag === 'button' && x.textContent === 'Revoke')[0].onclick();
  await again;
  assert.deepEqual(revoked, [7]);
});

test('an empty list draws nothing and says so by returning 0; no wording has a long dash', () => {
  const root = new Node('div');
  assert.equal(renderTokenList(root, [tok({revoked: true})], async () => {}), 0);
  assert.equal(root.children.length, 0);
  const source = readFileSync(new URL('../static/cve/api-keys-list.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /[\u2013\u2014]/);
  assert.match(revokeQuestion(tok()), /^Revoke "agent"/);
});
