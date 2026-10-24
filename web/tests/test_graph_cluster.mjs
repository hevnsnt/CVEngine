import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// Load the browser module without a DOM; clusterGraph is deliberately a pure
// transform so shared asset relationships and project boundaries can be tested.
const source = readFileSync(new URL('../static/cve/graph.js', import.meta.url), 'utf8');
const {clusterGraph} = await import(`data:text/javascript,${encodeURIComponent(source)}`);

test('groups original bubbles by project and root, with scoped copies of shared IPs', () => {
  const data = {
    nodes: [
      {id: 'dom:1', kind: 'domain', label: 'example.co.uk', project: 'north', project_name: 'North', root: 'example.co.uk'},
      {id: 'dom:2', kind: 'domain', label: 'other.example.co.uk', project: 'north', project_name: 'North', root: 'example.co.uk'},
      {id: 'dom:3', kind: 'domain', label: 'secret.test', project: 'south', project_name: 'South', root: 'secret.test'},
      {id: 'sub:1', kind: 'subdomain', label: 'a.example.co.uk'},
      {id: 'sub:2', kind: 'subdomain', label: 'b.secret.test'},
      {id: 'ip:1', kind: 'ip', label: '192.0.2.5'},
    ],
    edges: [
      {from: 'dom:1', to: 'sub:1'}, {from: 'dom:3', to: 'sub:2'},
      {from: 'sub:1', to: 'ip:1'}, {from: 'sub:2', to: 'ip:1'},
    ],
  };
  const view = clusterGraph(data, {columns: 1});
  assert.equal(view.nodes.filter(n => n.kind === 'project').length, 2);
  assert.equal(view.nodes.filter(n => n.kind === 'root').length, 2);
  assert.ok(view.edges.some(e => e.from === '__root:north:example.co.uk' && e.to === 'dom:1'));
  assert.ok(view.edges.some(e => e.from === '__root:north:example.co.uk' && e.to === 'dom:2'));
  const ips = view.nodes.filter(n => n.kind === 'ip');
  assert.deepEqual(new Set(ips.map(n => n.detail_id)), new Set(['ip:1']));
  assert.equal(ips.length, 2);
  assert.notEqual(ips[0].id, ips[1].id);
  assert.ok(view.edges.some(e => e.from === 'sub:1' && e.to === 'ip:1@north:example.co.uk'));
  assert.ok(view.edges.some(e => e.from === 'sub:2' && e.to === 'ip:1@south:secret.test'));
  assert.equal(data.nodes.length, 6); // transform does not alter the API payload
});

test('a single-domain view retains the original nodes and edges', () => {
  const data = {nodes: [{id: 'dom:1', kind: 'domain', label: 'example.org'}], edges: []};
  const view = clusterGraph(data);
  assert.deepEqual(view, data);
});
