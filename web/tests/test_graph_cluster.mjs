import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// Load the browser module without a DOM; clusterGraph is deliberately a pure
// transform so shared asset relationships and project boundaries can be tested.
const source = readFileSync(new URL('../static/cve/graph.js', import.meta.url), 'utf8');
const {clusterGraph, cloudProjects, CLOUD_HOSTS} = await import(`data:text/javascript,${encodeURIComponent(source)}`);

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

function bigProject(hosts, vulnerable) {
  const nodes = [{id: 'dom:1', kind: 'domain', label: 'big.example', project: 'big', project_name: 'Big', root: 'big.example'},
    {id: 'dom:2', kind: 'domain', label: 'small.example', project: 'small', project_name: 'Small', root: 'small.example'},
    {id: 'sub:small', kind: 'subdomain', label: 'a.small.example', project: 'small', status: 'scanned'},
    {id: 'ip:shared', kind: 'ip', label: '192.0.2.1'}, {id: 'ip:big', kind: 'ip', label: '192.0.2.2'}, {id: 'cve:1', kind: 'cve', label: 'CVE-2024-1'}];
  const edges = [{from: 'dom:2', to: 'sub:small'}, {from: 'sub:small', to: 'ip:shared'}];
  for (let i = 0; i < hosts; i++) {
    nodes.push({id: `sub:${i}`, kind: 'subdomain', label: `h${i}.big.example`, project: 'big', status: i < vulnerable ? 'vulnerable' : 'scanned'});
    edges.push({from: 'dom:1', to: `sub:${i}`}, {from: `sub:${i}`, to: i ? 'ip:big' : 'ip:shared'}, {from: `sub:${i}`, to: 'cve:1'});
  }
  return {nodes, edges};
}

test('a project over the cloud threshold becomes one cloud with its vulnerable hosts as dots', () => {
  const data = bigProject(CLOUD_HOSTS + 1, 3);
  const view = cloudProjects(data);
  const cloud = view.nodes.find(n => n.kind === 'cloud');
  assert.deepEqual([cloud.id, cloud.label, cloud.hosts, cloud.findings], ['__cloud:big', 'Big', CLOUD_HOSTS + 1, 3]);
  const dots = view.nodes.filter(n => n.cloud === 'big');
  assert.deepEqual(dots.map(n => n.id), ['sub:0', 'sub:1', 'sub:2']);
  assert.deepEqual(view.edges.filter(e => e.from === '__cloud:big').map(e => e.to), ['sub:0', 'sub:1', 'sub:2']);
  const ids = new Set(view.nodes.map(n => n.id));
  assert.ok(!ids.has('dom:1') && !ids.has('sub:3') && !ids.has('ip:big') && !ids.has('cve:1')); // only the clouded hosts used these
  assert.ok(ids.has('dom:2') && ids.has('sub:small') && ids.has('ip:shared')); // another project is drawn as before
  assert.ok(view.edges.every(e => ids.has(e.from) && ids.has(e.to)));
  assert.equal(data.nodes.length, CLOUD_HOSTS + 7); // the payload is left alone
});

test('a project at the threshold is drawn host by host', () => {
  const data = bigProject(CLOUD_HOSTS, 3);
  assert.equal(cloudProjects(data), data);
});

test('a cloud takes a slot in the clustered project grid, anchored', () => {
  const view = clusterGraph(cloudProjects(bigProject(CLOUD_HOSTS + 1, 2)), {columns: 2});
  const cloud = view.nodes.find(n => n.kind === 'cloud');
  assert.ok(cloud.anchored && Number.isFinite(cloud.seed_x));
  assert.ok(!view.nodes.some(n => n.id === '__project:big'));
  assert.ok(view.nodes.some(n => n.id === '__project:small'));
  assert.ok(Number.isFinite(view.nodes.find(n => n.id === 'sub:0').seed_x));
});
