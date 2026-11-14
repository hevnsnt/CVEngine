import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// score-detail-logic.js is pure: it turns the lines cveFeed/scoring.py stores into what the dashboard dialog and the host page show.
const source = readFileSync(new URL('../static/cve/score-detail-logic.js', import.meta.url), 'utf8');
const {refHref, scoreLines, totalNote, evidenceWord} = await import(`data:text/javascript,${encodeURIComponent(source)}`);
const ctx = {slug: 'acme web', host: 'a.example.com'};

test('every kind of evidence has a link target, and an unknown kind has none', () => {
  assert.equal(refHref({type: 'match', id: 7}, ctx), '/cve/acme%20web/matches/#7');
  assert.equal(refHref({type: 'match'}, ctx), '/cve/acme%20web/matches/?host=a.example.com');
  assert.equal(refHref({type: 'matches'}, ctx), '/cve/acme%20web/matches/?host=a.example.com');
  assert.equal(refHref({type: 'vulnerability', id: 9}, ctx), '/cve/acme%20web/vulns/#vulnerability-9');
  assert.equal(refHref({type: 'hygiene', id: 3}, ctx), '/cve/acme%20web/vulns/#hygiene-3');
  assert.equal(refHref({type: 'hygiene_list'}, ctx), '/cve/acme%20web/hygiene/');
  assert.equal(refHref({type: 'secret', id: 4}, ctx), '/cve/acme%20web/secrets/?open=4');
  assert.equal(refHref({type: 'host_tab', tab: 'web'}, ctx), '/cve/acme%20web/hosts/?host=a.example.com&tab=web');
  assert.equal(refHref({type: 'nonsense'}, ctx), null);
  assert.equal(refHref(null, ctx), null);
  assert.equal(refHref({type: 'secret', id: 4}, {host: 'h'}), null); // no project, no link
});

test('an id is a positive integer: anything else cannot build a path', () => {
  assert.equal(refHref({type: 'secret', id: '4/../x'}, ctx), '/cve/acme%20web/secrets/');
  assert.equal(refHref({type: 'match', id: -1}, ctx), '/cve/acme%20web/matches/?host=a.example.com');
  assert.equal(refHref({type: 'host_tab', tab: 'web&x=1#'}, ctx), '/cve/acme%20web/hosts/?host=a.example.com&tab=web%26x%3D1%23');
});

const parts = [
  {label: 'Fire CVE match CVE-2026-1', points: 40, kind: 'cve', text: 'A sentence.', ref: {type: 'match', id: 5}},
  {label: 'Server credential served on /', points: 10, kind: 'secret', text: 'Another.', ref: {type: 'secret', id: 4}},
  {label: 'Public IP observed', points: 10, kind: 'exposure', text: 'x', ref: {type: 'host_tab', tab: 'services'}},
  {label: 'old line stored before sentences', points: 3},
];

test('all the lines are listed and they add up to the total', () => {
  const view = scoreLines(parts, ctx);
  assert.equal(view.lines.length, 4);
  assert.equal(view.sum, 63);
  assert.equal(view.total, 63);
  assert.equal(view.capped, false);
  assert.equal(view.hidden, null);
  assert.equal(view.lines[1].href, '/cve/acme%20web/secrets/?open=4');
  assert.equal(view.lines[3].href, null); // an old line has a label and points and nothing to open
  assert.equal(view.lines[3].text, '');
});

test('a fold has its own total, and the visible lines plus the fold are the whole sum', () => {
  const view = scoreLines(parts, ctx, {limit: 2});
  assert.equal(view.lines.length, 2);
  assert.deepEqual([view.hidden.count, view.hidden.points], [2, 13]);
  assert.equal(view.lines.reduce((n, l) => n + l.points, 0) + view.hidden.points, view.sum);
});

test('a sum over 100 is shown as 100 and says so', () => {
  const view = scoreLines([{label: 'a', points: 60}, {label: 'b', points: 60}], ctx);
  assert.deepEqual([view.sum, view.total, view.capped], [120, 100, true]);
  assert.match(totalNote(view, 100), /add up to 120, and a score stops at 100/);
});

test('a score that differs from its lines is said, never hidden', () => {
  const view = scoreLines(parts, ctx);
  assert.match(totalNote(view, 43), /add up to 63, but the score of 43/);
  assert.equal(totalNote(view, 63), 'the sum of the lines above.');
});

test('bad input is read as no lines', () => {
  assert.deepEqual(scoreLines(null, ctx).lines, []);
  assert.deepEqual(scoreLines([null, 3, 'x', {label: 'ok', points: 'NaN'}], ctx).lines.map((l) => l.points), [0]);
  assert.equal(evidenceWord({type: 'secret'}), 'Open the secret');
  assert.equal(evidenceWord(null), '');
});

const read = (name) => readFileSync(new URL(`../static/cve/${name}`, import.meta.url), 'utf8');

test('the dashboard tile explains its score in a dialog and the host page lists every line with its evidence', () => {
  const dash = read('dashboard.js');
  assert.match(dash, /import \{ scoreList \} from "\/staticfiles\/cve\/score-detail\.js"/);
  assert.match(dash, /openScore\(cell\)/);
  assert.match(dash, /e\.metaKey \|\| e\.ctrlKey/, 'a new-tab click still goes to the host');
  assert.doesNotMatch(dash, /info\.score_parts \|\| \[\]\)\.slice\(0, 8\)/, 'the tile payload is not cut at eight lines');
  const app = read('app.js');
  assert.match(app, /scoreList\(h\.score_detail/);
  assert.match(app, /get\("tab"\)/, 'a score line can open a tab of the host page');
});

test('the score list is built with textContent only and every link is a real link', () => {
  const src = read('score-detail.js');
  assert.doesNotMatch(src, /innerHTML|insertAdjacentHTML|outerHTML/);
  assert.match(src, /el\("a", "score-label"/);
  assert.match(src, /el\("ol", "score-lines"/, 'an ordered list, so a screen reader announces the line count');
});

test('the hosts-scanned tile says how many hosts the denominator leaves out', () => {
  const page = readFileSync(new URL('../cveFeed/templates/cveFeed/dashboard.html', import.meta.url), 'utf8');
  assert.match(page, /id="s-coverage_note"/);
  assert.match(read('dashboard.js'), /more with no address to scan/);
});
