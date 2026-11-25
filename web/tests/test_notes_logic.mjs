import assert from 'node:assert/strict';
import {test} from 'node:test';

import {OBSERVATIONS, noteView, notesList, notesSummary} from '../static/cve/notes-logic.js';

// The operator notes of a finding or a host (static/cve/notes-logic.js): the badge of each observation, who wrote it and through what, and that
// every field becomes text, never markup.
class Node {
  constructor(tag, cls = '', text = '') { this.tag = tag; this.className = cls; this.children = []; this._text = text == null ? '' : String(text); }
  append(...kids) { this.children.push(...kids); }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const el = (tag, cls, text) => new Node(tag, cls, text);
const badge = (t, cls) => new Node('span', `badge ${cls}`.trim(), t);
const date = (iso) => iso.slice(0, 10);

test('every observation has a badge and an unknown one reads as a comment', () => {
  assert.deepEqual(Object.keys(OBSERVATIONS), ['confirmed', 'not_reproduced', 'false_positive', 'fixed_verified', 'needs_more_info', 'info']);
  assert.equal(noteView({text: 'x', observation: null, created: '2026-01-02T00:00:00Z'}, date).label, 'Comment');
  assert.equal(noteView({text: 'x', observation: 'needs_more_info', created: '2026-01-02T00:00:00Z'}, date).tone, 'smoke');
});

test('the line says who wrote it, through what and when', () => {
  const v = noteView({text: 'seen', observation: 'confirmed', author: {username: 'ana'}, source: 'mcp', via: 'ci-agent', created: '2026-03-04T10:00:00Z'}, date);
  assert.equal(v.meta, 'ana · MCP (ci-agent) · 2026-03-04');
});

test('the list is text: a note with markup stays text, its evidence is preformatted', () => {
  const box = notesList([{text: '<img src=x onerror=alert(1)>', evidence: 'curl -I', observation: 'false_positive', source: 'ui', created: '2026-03-04T10:00:00Z'}], el, badge, date);
  const all = box.textContent;
  assert.ok(all.includes('<img src=x onerror=alert(1)>'));
  assert.ok(box.children.some((n) => n.tag === 'pre' && n.textContent === 'curl -I'));
  assert.ok(box.children[0].children[0].className.includes('ice'));
  assert.match(notesSummary([1, 2]), /^2 notes/);
});
