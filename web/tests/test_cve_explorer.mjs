import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The CVE explorer's browser-free logic (static/cve/explorer-logic.js) and the "Search CVEs" row it adds to the Ctrl+K palette.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
// palette-search.js imports ui.js, which imports prefs.js: enough of a page for them to load
globalThis.document = {querySelector: () => null, querySelectorAll: () => [], getElementById: () => null, addEventListener() {},
  documentElement: {dataset: {}, setAttribute() {}, getAttribute: () => null}, cookie: ''};
globalThis.window = globalThis.window || {addEventListener() {}, matchMedia: () => ({matches: false, addEventListener() {}})};
globalThis.localStorage = globalThis.localStorage || {getItem: () => null, setItem() {}, removeItem() {}};

const logic = await import('../static/cve/explorer-logic.js');
const {suggestions} = await import('../static/cve/palette-search.js');

test('what counts as a CVE id matches the server rule', () => {
  for (const q of ['CVE-2024-6387', 'cve-2024-6387', '2024-6387', 'CVE-2024', '2024-', '6387', 'cve-']) assert.ok(logic.looksLikeId(q), q);
  for (const q of ['ssh', 'php', '123', '8.1', 'openssh 9', 'log4j', '']) assert.ok(!logic.looksLikeId(q), q);
});

test('the address round-trips and keeps only what differs from the defaults', () => {
  const s = logic.stateFrom('?q=ssh&severity=high&kev=1&page=3&id=cve-2024-6387');
  assert.deepEqual(s, {q: 'ssh', severity: 'high', kev: true, page: 3, id: 'CVE-2024-6387'});
  assert.equal(logic.queryString(s), '?q=ssh&severity=high&kev=1&page=3&id=CVE-2024-6387');
  assert.equal(logic.apiUrl(s), '/cve/api/cves?q=ssh&severity=high&kev=1&page=3');
  assert.equal(logic.queryString(logic.stateFrom('')), '');
  assert.deepEqual(logic.stateFrom('?severity=bogus&page=-2&id=<x>&kev=yes'), {q: '', severity: '', kev: false, page: 1, id: ''});
  assert.equal(logic.detailUrl('CVE-2024-6387'), '/cve/api/cves/CVE-2024-6387');
  assert.equal(logic.explorerHref(' apache tomcat '), '/cve/cves/?q=apache+tomcat');
});

test('the palette offers Search CVEs for a bare word or id, never for a host filter', () => {
  const ssh = suggestions('ssh');
  assert.equal(ssh.at(-1).label, 'Search CVEs for “ssh”');
  assert.equal(ssh.at(-1).href, '/cve/cves/?q=ssh');
  const id = suggestions('2024-6387');
  assert.equal(id[0].href, '/cve/cves/?q=2024-6387');  // an id goes first
  const po = suggestions('po');
  assert.equal(po[0].label, 'port:');  // filter completions keep their place
  assert.equal(po.at(-1).href, '/cve/cves/?q=po');
  for (const q of ['port:22', '-host:www', '"apache tomcat"', 'x', '']) {
    assert.ok(!suggestions(q).some((r) => r.href && r.href.startsWith('/cve/cves/')), q);
  }
});

test('formatters', () => {
  assert.equal(logic.rangeText({introduced: '8.5p1', fixed: '9.8p1'}), '8.5p1 to before 9.8p1');
  assert.equal(logic.rangeText({introduced: '0', fixed: '2.1'}), 'before 2.1');
  assert.equal(logic.rangeText({lastAffected: '9.7p1'}), 'up to 9.7p1');
  assert.equal(logic.rangeText({introduced: '2.0'}), 'from 2.0');
  assert.equal(logic.rangeText({}), 'every version');
  assert.equal(logic.productName({vendor: 'OpenBSD', product: 'OpenSSH'}), 'OpenBSD OpenSSH');
  assert.equal(logic.productName({package: 'php'}), 'php');
  assert.equal(logic.epssText(0.43), 'EPSS 43%');
  assert.equal(logic.epssText(0.004), 'EPSS 0.40%');
  assert.equal(logic.hostsText(0), 'None of your hosts');
  assert.equal(logic.hostsText(1), '1 of your host');
  assert.equal(logic.hostsText(3), '3 of your hosts');
});
