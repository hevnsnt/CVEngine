import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as L from '../static/cve/discover-mode-logic.js';

const app = readFileSync(new URL('../static/cve/app.js', import.meta.url), 'utf8');

test('Discover offers the stored mode first, and standard for a manual only target', () => {
  for (const mode of ['standard', 'deep', 'passive']) assert.equal(L.defaultChoice(mode), mode);
  assert.equal(L.defaultChoice('manual'), 'standard');
  assert.equal(L.defaultChoice(undefined), 'standard');
  assert.equal(L.defaultChoice('something-else'), 'standard');
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
  assert.deepEqual(L.discoverBody('manual', L.defaultChoice('manual')), {mode: 'standard'});
});

test('a value that is not a mode to run is never sent', () => {
  assert.deepEqual(L.discoverBody('passive', 'manual'), {});
  assert.deepEqual(L.discoverBody('passive', ''), {});
  assert.deepEqual(L.discoverBody('passive', undefined), {});
});

test('the mode after Discover is the picked one, the stored one when nothing runnable was picked', () => {
  assert.equal(L.modeAfter('manual', 'passive'), 'passive');
  assert.equal(L.modeAfter('passive', 'standard'), 'standard');
  assert.equal(L.modeAfter('passive', 'passive'), 'passive');
  assert.equal(L.modeAfter('passive', 'manual'), 'passive');
});

test('the toast names the mode and says when it replaced the stored one', () => {
  assert.equal(L.startedText(7, 'standard', 'standard'), 'Discovery #7 started (standard)');
  assert.match(L.startedText(7, 'passive', 'deep'), /deep is now this target's mode/);
  assert.match(L.startedText(7, 'manual', 'passive'), /passive is now this target's mode/);
});

test('the hint says the choice is kept, and what manual only means', () => {
  assert.match(L.discoverHint('passive'), /kept for this target/);
  assert.match(L.discoverHint('manual'), /manual only/);
  assert.match(L.discoverHint('manual'), /keeps that mode/);
});

test('the all-projects view words each mode, and a row from before the mode existed is standard', () => {
  assert.equal(L.modeText('manual'), 'manual only');
  assert.equal(L.modeText('passive'), 'passive');
  assert.equal(L.modeText(undefined), 'standard');
});

test('the Targets page sends the chosen mode with Discover instead of an empty body', () => {
  assert.doesNotMatch(app, /post\(`targets\/\$\{t\.id\}\/discover`, \{\}\)/, 'Discover posts an empty body again');
  assert.match(app, /post\(`targets\/\$\{t\.id\}\/discover`, discoverBody\(stored, how\.value\)\)/);
  assert.match(app, /\/staticfiles\/cve\/discover-mode-logic\.js/);
});
