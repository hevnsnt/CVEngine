import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// secret-detail-logic.js is pure: the sentences, counts and buttons of the secret panel. No value ever reaches it.
const read = (name) => readFileSync(new URL(`../static/cve/${name}`, import.meta.url), 'utf8');
const logic = await import(`data:text/javascript,${encodeURIComponent(read('secret-detail-logic.js'))}`);

test('the three decisions are the ones the owner asked for, in order', () => {
  assert.deepEqual(logic.decisionButtons('unverified').map((b) => [b.status, b.label]), [
    ['public_by_design', 'Mark as intended public key'],
    ['false_positive', 'Mark false positive'],
    ['accepted', 'Accept risk'],
  ]);
});

test('a decided secret shows its decision and can be reopened; an open one cannot', () => {
  const buttons = logic.decisionButtons('false_positive');
  assert.equal(buttons.find((b) => b.status === 'false_positive').current, true);
  assert.equal(buttons.at(-1).status, 'unverified');
  assert.equal(buttons.at(-1).label, 'Reopen');
  assert.equal(logic.decisionButtons('live').some((b) => b.label === 'Reopen'), false);
  logic.decisionButtons('accepted').forEach((b) => assert.ok(b.help.length > 20));
});

test('other places are counted from the places served now', () => {
  assert.equal(logic.otherPlaces({occurrences: 1, hosts: 1}), 'Served in one place only.');
  assert.equal(logic.otherPlaces({occurrences: 2, hosts: 1}), 'Also found in 1 other place, 1 host in all.');
  assert.equal(logic.otherPlaces({occurrences: 6, hosts: 3}), 'Also found in 5 other places, 3 hosts in all.');
  assert.match(logic.otherPlaces({occurrences: 0, hosts: 0}), /Not served anywhere now/);
});

test('a place says its full URL and its line', () => {
  assert.equal(logic.whereLine({url: 'https://example.com/', line: 1270}), 'https://example.com/ (line 1270)');
  assert.equal(logic.whereLine({url: 'https://example.com/a.js', line: null}), 'https://example.com/a.js');
});

test('a place with no context says why, and one with context shows only that', () => {
  assert.deepEqual(logic.contextView({context: "k='AIza…ghij'", context_note: ''}), {text: "k='AIza…ghij'", note: ''});
  assert.deepEqual(logic.contextView({context: '', context_note: 'Context not stored, rescan to capture.'}), {text: '', note: 'Context not stored, rescan to capture.'});
  assert.match(logic.contextView({context: ''}).note, /Context not stored, rescan to capture/);
});

test('only an http or https address can be opened', () => {
  assert.equal(logic.openableUrl('https://example.com/a.js'), 'https://example.com/a.js');
  assert.equal(logic.openableUrl('http://example.com/'), 'http://example.com/');
  for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', '', null, 'not a url']) assert.equal(logic.openableUrl(bad), null);
});

test('validation is said in words, from the server sentence when there is one', () => {
  assert.equal(logic.validationWords({explain: {validated: {words: 'Not validated: x.'}}}), 'Not validated: x.');
  assert.equal(logic.validationWords({validation: {outcome: 'verified_active'}}), 'Validated: verified_active.');
  assert.equal(logic.validationWords({}), 'Not validated.');
});

test('the panel is built with textContent only and opens pages in a new tab without the opener', () => {
  const src = read('secret-panel.js');
  assert.doesNotMatch(src, /innerHTML|insertAdjacentHTML|outerHTML/);
  assert.match(src, /rel: "noopener noreferrer"/);
  assert.match(src, /openableUrl\(o\.url\)/, 'a stored URL is opened only when it is http or https');
  assert.match(src, /aria-labelledby/);
  assert.match(src, /target\.focus\(\)/, 'focus goes back to where it was when the panel closes, even when a redrawn list replaced the button');
  assert.match(src, /aria-pressed/);
});

test('the list opens the panel, shows where each secret is served, and a score line opens it in place', () => {
  assert.match(read('secrets.js'), /openSecret\(s\.project \|\| slug, s\.id/);
  assert.match(read('secrets.js'), /label: "Found at"/);
  assert.match(read('dashboard.js'), /openSecret\(project, l\.ref\.id\)/);
  assert.match(read('app.js'), /openSecret\(projectOf\(h\), l\.ref\.id\)/);
});
