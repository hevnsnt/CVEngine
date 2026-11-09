import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import {test} from 'node:test';

// Contract: a page that refreshes itself must not redraw a region that holds something the person opened (a <details>), scrolled or typed in by emptying
// the container and building it again, because the new elements come up in their default state and every <details> snaps shut at the next refresh. The
// one way to redraw a polled region is renderKeepingState (static/cve/keep-state.js, tested in test_keep_state.mjs; the browser proof is
// tests/e2e_keep_open.py). This grep guard fails when a polling file grows a redraw that does not go through it, and when a disclosure has no stable key.

const DIR = new URL('../static/cve/', import.meta.url);
const files = readdirSync(DIR).filter((f) => f.endsWith('.js'));
const read = (f) => readFileSync(new URL(f, DIR), 'utf8');

const POLLS = /setInterval\(|from "\/staticfiles\/cve\/poll\.js"|setTimeout\((?:loop|tick|poll)\b/;
const REDRAW = /\.replaceChildren\(|\.innerHTML\s*=[^=]|\.textContent\s*=\s*""/g;
const count = (text, re) => (text.match(re) || []).length;

// Polling files and how many redraws they may still make without the helper, each with the reason it is safe. A number here may only go DOWN: a new
// redraw in a polling file has to go through renderKeepingState, or be added here with its reason in review.
const ALLOWED_REDRAWS = {
  'addtargets.js': [1, 'the one-second "working" ticker of a dialog: it holds a spinner line, no disclosure, no field'],
  'app.js': [32, 'person-triggered panel and pane draws (a click or a route change is not a poll, and a tick of the live lists goes through createList -> renderKeepingState); '
    + 'the 5 s scan-control and live-tick pollers write text into existing nodes'],
  'bounty.js': [17, 'person-triggered tab panels; the 8 s workbench poll (renderWorkbench) goes through renderKeepingState'],
  'dashboard.js': [11, 'the Live page counters, tiles, legend and ticker: no disclosure and no field in them; the activity feed adds lines, it does not rebuild'],
  'graph.js': [2, 'a canvas and its legend'],
  'scanners.js': [1, 'the error line shown when the health page could not be read: nothing to keep in it'],
  'seed-card.js': [1, 'a result block of download links that exists only while a seed file is being built'],
};

test('every polling file redraws through renderKeepingState, or is on the allowlist with a reason', () => {
  const polling = files.filter((f) => POLLS.test(read(f)));
  assert.ok(polling.includes('ai-usage.js') && polling.includes('sentinel-live.js') && polling.includes('dashboard.js'), `found: ${polling}`);
  const bad = [];
  for (const f of polling) {
    const found = count(read(f), REDRAW);
    const [allowed] = ALLOWED_REDRAWS[f] || [0];
    if (found > allowed) bad.push(`${f}: ${found} redraws by replaceChildren, innerHTML or textContent = "" (allowed ${allowed}). Draw through renderKeepingState (static/cve/keep-state.js) or add the file to ALLOWED_REDRAWS with the reason`);
  }
  assert.deepEqual(bad, []);
  Object.entries(ALLOWED_REDRAWS).forEach(([f, [, why]]) => assert.ok(why.length > 20 && polling.includes(f), `${f} is allowlisted without a reason or does not poll`));
});

test('the pages that were reported (AI usage, Sentinels) and the other polled regions use the helper', () => {
  for (const f of ['ai-usage.js', 'sentinel-live.js', 'statusstrip.js', 'scanners.js', 'bounty.js', 'app.js']) {
    assert.match(read(f), /import \{ renderKeepingState \} from "\/staticfiles\/cve\/keep-state\.js";/, `${f} imports the helper`);
    assert.match(read(f), /renderKeepingState\(/, `${f} draws through the helper`);
  }
  assert.doesNotMatch(read('ai-usage.js'), /output\.textContent\s*=\s*""/);
  assert.doesNotMatch(read('sentinel-live.js'), /mount\.textContent\s*=\s*""/);
});

// A disclosure needs a stable key: its summary carries a count that changes ("Not due (33)"), so the words cannot be what identifies it. These files
// build disclosures that are not inside a polled region (a one-off panel, a dialog, a settings tab) or whose summary is stable text plus a position,
// which keep-state.js falls back to; each is allowed with the reason.
const UNKEYED_DISCLOSURES = {
  'admin.js': 'an administration list row, drawn once per page load',
  'app.js': 'the confirm dialogs (a dialog is not redrawn by a poll)',
  'explorer.js': 'the CVE explorer detail pane, drawn when a CVE is opened',
  'finding-glance.js': 'a fold inside a finding row; its summary is a fixed phrase and keep-state.js matches it by that text and position',
  'score-detail.js': 'the score detail pane, drawn when a finding is opened',
  'secret-panel.js': 'the secret detail pane, drawn when a secret is opened',
  'settings.js': 'Settings tabs, drawn once when the tab opens',
  'suppliers.js': 'a supplier row, drawn once per page load',
};

test('every <details> is built with a data-keep-key, except where the file is allowlisted with a reason', () => {
  const bad = [];
  for (const f of files) {
    const text = read(f);
    const lines = text.split('\n');
    lines.forEach((line, i) => {
      if (!/el\("details"/.test(line)) return;
      if (/data-keep-key/.test(line)) return;
      if (UNKEYED_DISCLOSURES[f]) {
        // inside an allowlisted file only the listed ones may stay unkeyed: new ones in app.js must be keyed
        if (f !== 'app.js' || /confirm-more|confirm-generic/.test(line)) return;
      }
      bad.push(`${f}:${i + 1}: ${line.trim()}`);
    });
  }
  assert.deepEqual(bad, [], 'give the disclosure a data-keep-key (see keep-state.js) or allowlist its file with a reason');
});

test('the helper module has no dependency and nothing runs at import', () => {
  const text = read('keep-state.js');
  assert.doesNotMatch(text, /^import /m);
  assert.doesNotMatch(text, /setInterval/);
});
