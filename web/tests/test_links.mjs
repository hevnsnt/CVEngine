import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// links.js is the one place that says where a hostname, an IP address, a CVE id and a "Needs validation" label point. It builds
// DOM nodes, so a minimal stand-in for `document` is enough to read what it produced.
class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.dataset = {}; this.className = ''; this.title = ''; this._text = ''; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  append(...kids) { this.children.push(...kids); }
  set textContent(v) { this._text = String(v); }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
globalThis.document = {
  createElement: (tag) => new Node_(tag),
  createTextNode: (text) => Object.assign(new Node_('#text'), {_text: String(text)}),
};
const source = readFileSync(new URL('../static/cve/links.js', import.meta.url), 'utf8');
const links = await import(`data:text/javascript,${encodeURIComponent(source)}`);

const render = (text, project = 'p', opts) => {
  const box = new Node_('span');
  links.linkify(box, text, project, opts);
  return box.children.map((c) => (c.tag === 'a' ? {a: c.textContent, href: c.attrs.href} : c.textContent));
};

test('addresses point where the records are', () => {
  assert.equal(links.hostHref('p', 'a b.test'), '/cve/p/hosts/?host=a%20b.test');
  assert.equal(links.ipHref('p', '10.0.0.1'), '/cve/p/hosts/?q=ip%3A10.0.0.1');
  assert.equal(links.matchHref('p', 7), '/cve/p/matches/#7');
  assert.equal(links.cveHref('p', 'CVE-2026-1', 7), '/cve/p/matches/#7');
  assert.equal(links.cveHref('p', 'CVE-2026-1', null), '/cve/p/matches/?cve=CVE-2026-1');
  assert.equal(links.cveHref('p', 'CVE-2026-1', null, 'h.test'), '/cve/p/matches/?cve=CVE-2026-1&host=h.test');
  assert.equal(links.validateHref('p', 7), '/cve/p/matches/#7&validate');
  assert.equal(links.findingHref('p', 'vulnerability', 3), '/cve/p/vulns/#vulnerability-3');
  assert.equal(links.findingHref('p', 'hygiene', 4), '/cve/p/vulns/#hygiene-4');
  assert.equal(links.findingHref('p', 'match', 3), '/cve/p/matches/#3');
});

test('a project slug cannot break out of the path', () => {
  assert.equal(links.hostHref('a/../b', 'h.test'), '/cve/a%2F..%2Fb/hosts/?host=h.test');
});

test('free text: hosts, addresses and CVE ids become links', () => {
  const out = render('Nuclei confirmed X on www.example.com (192.0.2.7) for CVE-2026-0001.');
  const anchors = out.filter((x) => typeof x === 'object');
  assert.deepEqual(anchors.map((x) => x.a), ['www.example.com', '192.0.2.7', 'CVE-2026-0001']);
  assert.equal(anchors[0].href, '/cve/p/hosts/?host=www.example.com');
  assert.equal(anchors[1].href, '/cve/p/hosts/?q=ip%3A192.0.2.7');
  // the line names exactly one host, so its CVE goes to that host's match
  assert.equal(anchors[2].href, '/cve/p/matches/?cve=CVE-2026-0001&host=www.example.com');
  assert.equal(out.map((x) => (typeof x === 'object' ? x.a : x)).join(''), 'Nuclei confirmed X on www.example.com (192.0.2.7) for CVE-2026-0001.');
});

test('a line that names two hosts does not guess which one a CVE belongs to', () => {
  const anchors = render('CVE-2026-0001 on a.example.com and b.example.com').filter((x) => typeof x === 'object');
  assert.equal(anchors.find((x) => x.a === 'CVE-2026-0001').href, '/cve/p/matches/?cve=CVE-2026-0001');
});

test('not hosts: files, products, bad addresses, versions', () => {
  const out = render('Loaded template cve.yaml and nuclei.json; read the cve.now feed; ASP.NET 4.8.1; 999.1.1.1; github.com');
  // a product named like a host (ASP.NET) is still linked in free text: the Hosts page then finds nothing. Callers that print
  // products pass `kinds` (next test).
  assert.deepEqual(out.filter((x) => typeof x === 'object').map((x) => x.a), ['ASP.NET']);
});

test('kinds narrows what is linked (a change line names products too)', () => {
  const out = render('port opened 192.0.2.9:443 ASP.NET', 'p', {kinds: ['ip']});
  assert.deepEqual(out.filter((x) => typeof x === 'object').map((x) => x.a), ['192.0.2.9']);
});

test('with no project there is nowhere to link to', () => {
  assert.deepEqual(render('CVE-2026-1 on a.example.com', null), ['CVE-2026-1 on a.example.com']);
});

test('text is never parsed as markup', () => {
  const out = render('<img src=x onerror=alert(1)> a.example.com');
  assert.equal(out[0], '<img src=x onerror=alert(1)> ');
  assert.equal(out[1].a, 'a.example.com');
});

test('"Needs validation" on a match presses Validate now; on any other finding it opens that finding', () => {
  const m = links.needsValidation('p', 'match', 5);
  assert.equal(m.textContent, 'Needs validation');
  assert.equal(m.attrs.href, '/cve/p/matches/#5&validate');
  assert.equal(m.dataset.kind, 'match');
  const v = links.needsValidation('p', 'vulnerability', 9);
  assert.equal(v.attrs.href, '/cve/p/vulns/#vulnerability-9');
  assert.ok(m.className.includes('needs-validation'));
});
