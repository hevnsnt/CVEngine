import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// finding-glance-logic.js is pure: the evidence strings of the glance cards become sentence segments. No DOM.
const read = (name) => readFileSync(new URL(`../static/cve/${name}`, import.meta.url), 'utf8');
const logic = await import(`data:text/javascript,${encodeURIComponent(read('finding-glance-logic.js'))}`);
const fmt = (iso) => `<${iso.slice(0, 16)}>`;
const ISO = '2026-11-07T00:31:37.378808+00:00';

test('a template result reads as a sentence with the check name apart', () => {
  const segs = logic.templateSegments(`vulnerable (testssl:secure_client_renego), tested ${ISO}`);
  assert.equal(logic.segmentsText(segs, fmt), 'Vulnerable. Check: testssl:secure_client_renego Tested <2026-11-07T00:31>');
  const code = segs.find((s) => s.k === 'code');
  assert.equal(code.v, 'testssl:secure_client_renego');
  assert.equal(code.lead, 'Check: ');
  assert.equal(segs.find((s) => s.k === 'when').iso, ISO);
});

test('a template result without a time or a check keeps its words', () => {
  assert.equal(logic.segmentsText(logic.templateSegments('no match (nuclei:cve-2024-1)'), fmt), 'No match. Check: nuclei:cve-2024-1');
  assert.equal(logic.segmentsText(logic.templateSegments('not tested'), fmt), 'not tested');
  assert.equal(logic.segmentsText(logic.templateSegments('vulnerable'), fmt), 'vulnerable');
  assert.equal(logic.segmentsText(logic.templateSegments(''), fmt), '');
  assert.equal(logic.segmentsText(logic.templateSegments(null), fmt), '');
});

test('a time inside any other value is marked, the words around it stay', () => {
  const segs = logic.textSegments(`library body read, ${ISO}`);
  assert.deepEqual(segs.map((s) => s.k), ['text', 'when']);
  assert.equal(logic.segmentsText(segs, fmt), 'library body read, <2026-11-07T00:31>');
  assert.equal(logic.segmentsText(logic.textSegments('inside the affected range'), fmt), 'inside the affected range');
  assert.equal(logic.segmentsText(logic.textSegments('seen 2026-11-07T00:31:37Z and 2026-11-08T01:02:03+02:00.'), fmt), 'seen <2026-11-07T00:31> and <2026-11-08T01:02>.');
});

test('a date that is not a time is left alone', () => {
  assert.equal(logic.segmentsText(logic.textSegments('inventory report of 2026-11-07'), fmt), 'inventory report of 2026-11-07');
});

test('an unreadable time falls back to the text the server sent', () => {
  assert.equal(logic.segmentsText(logic.textSegments('x 2026-13-45T99:99 y'), () => ''), 'x 2026-13-45T99:99 y');
});

test('the prefs formatter writes "Nov 7, 2026 12:31 AM" in the chosen zone', async () => {
  const src = read('prefs.js').split('// The account-menu button')[0];
  globalThis.localStorage = {getItem: () => 'utc'};
  const prefs = await import(`data:text/javascript,${encodeURIComponent(src)}`);
  assert.equal(prefs.fmtLong(ISO), 'Nov 7, 2026 12:31 AM');
  assert.equal(prefs.fmtLong('2026-11-07T15:05:00Z'), 'Nov 7, 2026 3:05 PM');
  assert.equal(prefs.fmtLong('2026-01-01T12:00:00Z'), 'Jan 1, 2026 12:00 PM');
  assert.equal(prefs.fmtLong('2026-01-01T00:00:00Z'), 'Jan 1, 2026 12:00 AM');
  assert.equal(prefs.fmtLong('nonsense'), '');
  assert.equal(prefs.fmtLong(''), '');
});

test('a check that reproduced it is proof, with the latest hit and what the host answered', () => {
  const proof = logic.proofOf({
    status: 'hit',
    steps: [
      {kind: 'fact_probe', label: 'banner probe', result: 'no_match', ran_at: '2026-11-08T10:00:00Z'},
      {kind: 'nuclei_template', label: 'nuclei check', display: 'nuclei -t cve-2024-1 -u https://a.example.com', result: 'hit', ran_at: '2026-11-08T11:00:00Z', summary: 'matched'},
      {kind: 'fact_probe', label: 'second probe', result: 'hit', ran_at: '2026-11-09T09:00:00Z', summary: 'version 1.2'},
    ],
    evidence: {nuclei_template: {request: 'GET /x', response: 'HTTP/1.1 200 OK'}, fact_probe: {}},
  });
  assert.equal(proof.label, 'second probe');
  assert.equal(proof.at, '2026-11-09T09:00:00Z');
  assert.equal(proof.checks, 2);
  assert.deepEqual(proof.exchanges, [{kind: 'nuclei_template', request: 'GET /x', response: 'HTTP/1.1 200 OK', reply: ''}]);
});

test('no proof unless a check reproduced it', () => {
  assert.equal(logic.proofOf(null), null);
  assert.equal(logic.proofOf({status: 'clean', steps: [{result: 'no_match'}]}), null);
  assert.equal(logic.proofOf({status: 'observed', steps: [{result: 'observed'}]}), null);
  assert.equal(logic.proofOf({status: 'hit', steps: []}), null);  // a hit with no step is not shown as proof
  const bare = logic.proofOf({status: 'hit', steps: [{kind: 'script_read', result: 'hit', ran_at: '2026-11-09T09:00:00Z'}], evidence: {}});
  assert.equal(bare.label, 'script_read');
  assert.deepEqual(bare.exchanges, []);  // still says which check, and the card says nothing was kept
});
