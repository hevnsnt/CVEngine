import assert from 'node:assert/strict';
import {test} from 'node:test';

import {dedupeNotes, sameNote} from '../static/cve/finding-glance-logic.js';

// The AI card drew the same note two or three times: the reviewer restating the triage, or one sentence stored in two fields. The clearest is kept, the rest folded.
const triage = 'testssl.sh reports likely VULNERABLE for CCS injection, a heuristic; a load balancer or CDN may answer the probe with a 0x00 byte, so the finding needs validation against the origin server.';
const reviewer = 'testssl.sh reports likely vulnerable for CCS injection, which is only a heuristic. A load balancer or CDN often answers the probe with a 0x00 byte, so it needs validation against the origin server.';

test('the same text and a close paraphrase are the same note, different notes are not', () => {
  assert.equal(sameNote(triage, triage), true);
  assert.equal(sameNote(triage, reviewer), true);
  assert.equal(sameNote('Upgrade OpenSSL to 1.0.1h or later and restart the service.', triage), false);
  assert.equal(sameNote('', triage), false);
  assert.equal(sameNote(null, undefined), false);
});

test('a repeat is folded, the longer of the two is drawn, and nothing is lost', () => {
  const {shown, repeats} = dedupeNotes([
    {key: 'reviewer', label: "the AI reviewer's note", text: reviewer},
    {key: 'reasoning', label: "the AI's reasoning", text: triage},
    {key: 'impact', label: 'why it matters', text: 'An attacker on the network path can force weak keys and read traffic.'},
  ]);
  assert.deepEqual(shown.map((n) => n.key), ['reviewer', 'impact']);
  assert.equal(shown[0].text, reviewer);
  assert.equal(repeats.length, 1);
  assert.equal(repeats[0].key, 'reasoning');
  assert.equal(repeats[0].text, triage);

  const longer = dedupeNotes([
    {key: 'reviewer', label: 'reviewer', text: 'Needs validation against the origin server.'},
    {key: 'reasoning', label: 'reasoning', text: 'Needs validation against the origin server, because a load balancer answers.'},
  ]);
  assert.deepEqual(longer.shown.map((n) => n.key), ['reasoning']);
  assert.deepEqual(longer.repeats.map((n) => n.key), ['reviewer']);
});

test('empty and missing notes are skipped', () => {
  const {shown, repeats} = dedupeNotes([{key: 'a', label: 'a', text: ''}, {key: 'b', label: 'b', text: undefined}, null, {key: 'c', label: 'c', text: 'One note.'}]);
  assert.deepEqual(shown.map((n) => n.key), ['c']);
  assert.deepEqual(repeats, []);
});
