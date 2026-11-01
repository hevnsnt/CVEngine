import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as L from '../static/cve/discover-mode-logic.js';

const app = readFileSync(new URL('../static/cve/app.js', import.meta.url), 'utf8');

const answer = (extra = {}) => ({scan_id: 7, status: 'started', discovery_mode: 'standard', scan_mode: 'standard', ...extra});

test('Discover offers the stored mode first, and for a manual only target nothing until one is chosen', () => {
  for (const mode of ['standard', 'deep', 'passive']) assert.equal(L.defaultChoice(mode), mode);
  assert.equal(L.defaultChoice('manual'), '');
  assert.equal(L.defaultChoice(undefined), '');
  assert.equal(L.defaultChoice('something-else'), '');
});

test('a manual only target gets a "Choose a mode" placeholder, the others do not', () => {
  assert.deepEqual(L.discoverOptions('manual').map(([v]) => v), ['', 'standard', 'deep', 'passive']);
  assert.match(L.discoverOptions('manual')[0][1], /Choose a mode/);
  for (const mode of ['standard', 'deep', 'passive']) assert.deepEqual(L.discoverOptions(mode).map(([v]) => v), ['standard', 'deep', 'passive']);
});

test('Discover stays disabled until a mode to run is chosen, so one click never promotes a manual only target', () => {
  assert.equal(L.canDiscover(L.defaultChoice('manual')), false);
  assert.equal(L.canDiscover(''), false);
  assert.equal(L.canDiscover('manual'), false);
  assert.equal(L.canDiscover(undefined), false);
  for (const mode of ['standard', 'deep', 'passive']) {
    assert.equal(L.canDiscover(mode), true);
    assert.equal(L.canDiscover(L.defaultChoice(mode)), true); // a target with a mode can be discovered at once
  }
});

test('Discover never offers manual as a mode to run, the Discovery column does', () => {
  assert.deepEqual(L.RUNNABLE.map(([v]) => v), ['standard', 'deep', 'passive']);
  assert.deepEqual(L.STORED.map(([v]) => v), ['standard', 'deep', 'passive', 'manual']);
});

test('the stored mode is sent as no mode, so the server runs the target\'s own', () => {
  for (const mode of ['standard', 'deep', 'passive']) assert.deepEqual(L.discoverBody(mode, mode), {});
});

test('another mode is named, and a passive target is never run in standard unless that is picked', () => {
  assert.deepEqual(L.discoverBody('passive', 'standard'), {mode: 'standard'});
  assert.deepEqual(L.discoverBody('standard', 'deep'), {mode: 'deep'});
  assert.deepEqual(L.discoverBody('deep', 'passive'), {mode: 'passive'});
  assert.deepEqual(L.discoverBody('passive', L.defaultChoice('passive')), {}); // untouched choice: still passive
});

test('a manual only target always names a mode, since the server refuses to guess for it', () => {
  assert.deepEqual(L.discoverBody('manual', 'standard'), {mode: 'standard'});
  assert.deepEqual(L.discoverBody('manual', 'passive'), {mode: 'passive'});
  assert.deepEqual(L.discoverBody('manual', L.defaultChoice('manual')), {}); // nothing chosen: nothing is sent (and the button is disabled)
});

test('a value that is not a mode to run is never sent', () => {
  assert.deepEqual(L.discoverBody('passive', 'manual'), {});
  assert.deepEqual(L.discoverBody('passive', ''), {});
  assert.deepEqual(L.discoverBody('passive', undefined), {});
});

test('the page shows the mode the server stored, never the one it asked for', () => {
  assert.equal(L.modeAfter(answer({discovery_mode: 'passive'}), 'manual'), 'passive');
  assert.equal(L.modeAfter(answer({discovery_mode: 'deep'}), 'standard'), 'deep');
  // an internal target keeps its mode whatever was picked: the server says so
  assert.equal(L.modeAfter(answer({discovery_mode: 'manual', scan_mode: '', internal: true}), 'manual'), 'manual');
  assert.equal(L.modeAfter(answer({discovery_mode: 'passive', scan_mode: '', internal: true}), 'passive'), 'passive');
  // an answer with no usable mode (an older server) leaves the stored one
  assert.equal(L.modeAfter({scan_id: 3}, 'passive'), 'passive');
  assert.equal(L.modeAfter(undefined, 'deep'), 'deep');
  assert.equal(L.modeAfter(answer({discovery_mode: 'bogus'}), 'deep'), 'deep');
});

test('the toast names the mode the scan runs in and says when it changed the target\'s', () => {
  assert.equal(L.startedText(answer(), 'standard'), 'Discovery #7 started (standard)');
  assert.match(L.startedText(answer({discovery_mode: 'deep', scan_mode: 'deep'}), 'passive'), /deep is now this target's mode/);
  assert.match(L.startedText(answer({discovery_mode: 'passive', scan_mode: 'passive'}), 'manual'), /passive is now this target's mode/);
});

test('a scan that was already going keeps its mode, and the toast says which is which', () => {
  const text = L.startedText(answer({discovery_mode: 'deep', scan_mode: 'standard'}), 'standard');
  assert.match(text, /started \(standard\)/);
  assert.match(text, /already going in standard/);
  assert.match(text, /deep is now this target's mode/);
});

test('an internal target says its scan goes to a Sentinel and that its mode did not change', () => {
  const text = L.startedText(answer({discovery_mode: 'manual', scan_mode: '', internal: true, status: 'queued'}), 'manual');
  assert.match(text, /Internal scan #7/);
  assert.match(text, /stays manual only/);
});

test('the hint says the choice is kept, and what manual only means', () => {
  assert.match(L.discoverHint('passive'), /kept for this target/);
  assert.match(L.discoverHint('manual'), /manual only/);
  assert.match(L.discoverHint('manual'), /Choose a mode/);
});

test('the all-projects view words each mode, and a row from before the mode existed is standard', () => {
  assert.equal(L.modeText('manual'), 'manual only');
  assert.equal(L.modeText('passive'), 'passive');
  assert.equal(L.modeText(undefined), 'standard');
});

test('the Targets page sends the chosen mode with Discover instead of an empty body', () => {
  assert.doesNotMatch(app, /post\(`targets\/\$\{t\.id\}\/discover`, \{\}\)/, 'Discover posts an empty body again');
  assert.match(app, /post\(`targets\/\$\{t\.id\}\/discover`, discoverBody\(stored, how\.value\)\)/);
  assert.match(app, /t\.discovery_mode = modeAfter\(r, stored\)/, 'the page shows what it asked for, not what the server stored');
  assert.match(app, /discover\.disabled = busy \|\| !canDiscover\(how\.value\)/, 'Discover is not held until a mode is chosen');
  assert.match(app, /\/staticfiles\/cve\/discover-mode-logic\.js/);
});
