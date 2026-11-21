import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {register} from 'node:module';
import {test} from 'node:test';

// A match explains itself (match-explain-logic.js and match-explain.js): the words and choices the match page and the host page draw from a
// match's ``explain`` and a host's ``validate_plan``, drawn against a tiny DOM. Everything is text, only https links open, and a closure starts
// from the server's evidence note.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this._text = ''; this.className = ''; this.disabled = false; this.open = false; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };
globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  querySelector: () => null,
  querySelectorAll: () => [],
  documentElement: new Node('html'),
  cookie: '',
};
globalThis.localStorage = {getItem: () => null, setItem() {}};

const logic = await import('../static/cve/match-explain-logic.js');
const {explainCard, validatePlanCard} = await import('../static/cve/match-explain.js');

const EXPLAIN = {
  found: 'The web server says it is Apache httpd 2.4.37 on Red Hat. CVE-2024-38475 affects Apache httpd before 2.4.60.',
  why: 'This is based only on the version in the Server header. Not confirmed: cvENGINE did not test for the flaw itself.',
  confidence: 'not_confirmed', confidence_label: 'Not confirmed',
  question: {key: 'rhel:httpd', text: 'Is the installed httpd package patched?'},
  who: 'Someone with a shell on gecmedia.zebra.com can run these.',
  steps: [
    {text: 'See whether the installed httpd package carries Red Hat\'s fix.', command: 'rpm -q --changelog httpd | grep -F -e CVE-2024-38475',
     needs: 'A shell on the host', read_only: true, outcomes: {cant_tell: 'No line.', fixed: 'A line names CVE-2024-38475.'}},
    {text: 'Ask the package manager.', command: 'dnf updateinfo list cves | grep -F -e CVE-2024-38475', needs: 'A shell', read_only: true,
     outcomes: {affected: 'A line names it.'}, url: 'javascript:alert(1)'},
  ],
  outcomes: {affected: 'Still open.', fixed: 'Fix installed.', cant_tell: 'Unknown.'},
  close: [{status: 'fixed', label: 'Close as fixed', note: 'Checked on gecmedia.zebra.com: `rpm -q --changelog httpd | grep -F -e CVE-2024-38475` names it.'},
          {status: 'false_positive', label: 'Close as false positive', note: 'Not affected: backported.'},
          {status: 'open', label: 'Reopen', note: 'x'}],
};

test('the outcomes read fixed first, then still affected, then can\'t tell, and only those given', () => {
  assert.deepEqual(logic.outcomeRows({cant_tell: 'c', fixed: 'f'}).map((r) => [r.key, r.label, r.tone]),
                   [['fixed', 'Fixed', 'success'], ['cant_tell', "Can't tell", 'smoke']]);
  assert.deepEqual(logic.outcomeRows(null), []);
});

test('a closure is offered only on an open match outside a read-only view, and only as fixed or false positive', () => {
  assert.deepEqual(logic.closeChoices(EXPLAIN, 'open').map((c) => c.status), ['fixed', 'false_positive']);
  assert.deepEqual(logic.closeChoices(EXPLAIN, 'in_progress').map((c) => c.status), ['fixed', 'false_positive']);
  for (const closed of ['fixed', 'accepted_risk', 'false_positive']) assert.deepEqual(logic.closeChoices(EXPLAIN, closed), []);
  assert.deepEqual(logic.closeChoices(EXPLAIN, 'open', {readOnly: true}), []);
  assert.deepEqual(logic.closeChoices({}, 'open'), []);
});

test('only an https link opens, and the plan reads in plain words', () => {
  assert.equal(logic.safeHref('javascript:alert(1)'), '');
  assert.equal(logic.safeHref('http://example.com'), '');
  assert.equal(logic.safeHref('https://access.redhat.com/security/cve/CVE-2024-38475'), 'https://access.redhat.com/security/cve/CVE-2024-38475');
  assert.equal(logic.matchHref('zebra project', 7), '/cve/zebra%20project/matches/#7');
  assert.equal(logic.planIntro([{count: 70}, {count: 4}], 'gecmedia.zebra.com'),
               '2 questions on gecmedia.zebra.com settle 74 open matches. Someone with a shell on the host can answer them; every command only reads. Start at the top: exploited CVEs come first.');
  assert.equal(logic.planIntro([], 'h'), '');
  assert.deepEqual(logic.shownResolves([1, 2, 3], 2), {shown: [1, 2], more: 1});
  assert.equal(logic.groupSummary({question: 'Is the installed httpd package patched?', count: 70, kev: true}),
               'Is the installed httpd package patched? · 70 matches · listed as exploited');
});

test('the match card says what was found, how sure, the numbered steps with their commands, and closes with the evidence note', async () => {
  const closes = [];
  const card = explainCard(EXPLAIN, {status: 'open', onClose: async (status, note) => closes.push([status, note])});
  const text = card.textContent;
  assert.match(text, /What we found/);
  assert.match(text, /The web server says it is Apache httpd 2\.4\.37 on Red Hat\./);
  assert.match(text, /Not confirmed/);
  assert.match(text, /What to do: Is the installed httpd package patched\?/);
  const commands = find(card, (n) => n.tag === 'pre').map((n) => n.textContent);
  assert.deepEqual(commands, ['rpm -q --changelog httpd | grep -F -e CVE-2024-38475', 'dnf updateinfo list cves | grep -F -e CVE-2024-38475']);
  assert.equal(find(card, (n) => n.tag === 'ol')[0].children.length, 2);
  assert.equal(find(card, (n) => n.tag === 'a').length, 0, 'a javascript: link is never drawn');
  const buttons = find(card, (n) => n.tag === 'button' && n.attrs['data-close']);
  assert.deepEqual(buttons.map((b) => b.attrs['data-close']), ['fixed', 'false_positive']);
  await buttons[0].onclick();
  assert.deepEqual(closes, [['fixed', EXPLAIN.close[0].note]]);
  // closed, or with nowhere to save: no closure
  assert.equal(find(explainCard(EXPLAIN, {status: 'fixed', onClose: () => {}}), (n) => n.attrs['data-close']).length, 0);
  assert.equal(find(explainCard(EXPLAIN, {status: 'open'}), (n) => n.attrs['data-close']).length, 0);
  assert.equal(explainCard(null), null);
});

test('the host plan draws one question per package with its commands and the matches it answers', () => {
  const plan = [{key: 'rhel:httpd', question: 'Is the installed httpd package patched?', kev: true, count: 3, platform_label: 'Red Hat Enterprise Linux',
                 steps: [{text: 'See which of these CVEs...', command: 'rpm -q --changelog httpd | grep -o -F -e CVE-2024-38475 | sort -u', needs: 'A shell', read_only: true, outcomes: {fixed: 'Each CVE printed is fixed.'}}],
                 outcomes: {fixed: 'Close them.'},
                 resolves: [{match_id: 5, cve_id: 'CVE-2024-38475', kev: true, product: 'Apache httpd', source: 'tech'},
                            {match_id: 6, cve_id: 'CVE-2024-38476', kev: false, product: 'Apache httpd', source: 'openvas'}]},
                {key: 'rhel:openssl', question: 'Is the installed openssl package patched?', kev: false, count: 1, steps: [], resolves: []}];
  const box = validatePlanCard(plan, {host: 'gecmedia.zebra.com', project: 'zebra'});
  assert.match(box.textContent, /Settle these matches on the host/);
  const groups = find(box, (n) => n.tag === 'details');
  assert.equal(groups.length, 2);
  assert.equal(groups[0].open, true);
  assert.equal(groups[1].open, false);
  assert.match(groups[0].textContent, /Is the installed httpd package patched\?Exploited 3 matches · Red Hat Enterprise Linux/);
  const links = find(groups[0], (n) => n.tag === 'a').map((a) => [a.textContent, a.attrs.href]);
  assert.deepEqual(links, [['CVE-2024-38475', '/cve/zebra/matches/#5'], ['CVE-2024-38476', '/cve/zebra/matches/#6']]);
  assert.equal(validatePlanCard([], {}), null);
});

test('the modules build the DOM with text only', () => {
  for (const name of ['match-explain.js', 'match-explain-logic.js']) {
    const src = readFileSync(new URL(`../static/cve/${name}`, import.meta.url), 'utf8');
    assert.doesNotMatch(src, /innerHTML|insertAdjacentHTML|outerHTML\s*=/, name);
  }
});
