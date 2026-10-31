import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// Load the browser module without a DOM; clusterGraph is deliberately a pure
// transform so shared asset relationships and project boundaries can be tested.
const source = readFileSync(new URL('../static/cve/graph.js', import.meta.url), 'utf8');
const {clusterGraph, cloudProjects, focusProject, CLOUD_HOSTS} = await import(`data:text/javascript,${encodeURIComponent(source)}`);

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

const HEAT = ['fire', 'smoke', 'ice'];
// big: `hosts` hosts, the first `hot` of them hot (fire, smoke, ice in turn); small: one host on fire. `alone` leaves small out.
function bigProject(hosts, hot, {alone = false} = {}) {
  const nodes = [{id: 'dom:1', kind: 'domain', label: 'big.example', project: 'big', project_name: 'Big', root: 'big.example'},
    {id: 'ip:shared', kind: 'ip', label: '192.0.2.1'}, {id: 'ip:big', kind: 'ip', label: '192.0.2.2'}, {id: 'cve:1', kind: 'cve', label: 'CVE-2024-1'}];
  const edges = [];
  if (!alone) {
    nodes.push({id: 'dom:2', kind: 'domain', label: 'small.example', project: 'small', project_name: 'Small', root: 'small.example'},
      {id: 'sub:small', kind: 'subdomain', label: 'a.small.example', project: 'small', status: 'vulnerable', heat: 'fire'});
    edges.push({from: 'dom:2', to: 'sub:small'}, {from: 'sub:small', to: 'ip:shared'});
  }
  for (let i = 0; i < hosts; i++) {
    nodes.push({id: `sub:${i}`, kind: 'subdomain', label: `h${i}.big.example`, project: 'big',
      status: i < hot ? 'vulnerable' : 'scanned', heat: i < hot ? HEAT[i % 3] : 'clean'});
    edges.push({from: 'dom:1', to: `sub:${i}`}, {from: `sub:${i}`, to: i ? 'ip:big' : 'ip:shared'}, {from: `sub:${i}`, to: 'cve:1'});
  }
  return {nodes, edges};
}
const tiersOf = (view, slug) => Object.fromEntries(view.nodes.filter(n => n.kind === 'tier' && n.project === slug).map(n => [n.tier, n.count]));

test('with several projects on the picture every project is a cloud, with its fire, smoke, ice and hygiene hanging off it', () => {
  const data = bigProject(40, 7);
  data.projects = {big: {name: 'Big', hygiene: 4}, small: {name: 'Small', hygiene: 0}};
  const view = cloudProjects(data);
  const clouds = view.nodes.filter(n => n.kind === 'cloud');
  assert.deepEqual(clouds.map(c => [c.id, c.label, c.hosts, c.findings, c.hygiene]),
    [['__cloud:big', 'Big', 40, 7, 4], ['__cloud:small', 'Small', 1, 1, 0]]);
  assert.deepEqual(tiersOf(view, 'big'), {fire: 3, smoke: 2, ice: 2, hygiene: 4});
  assert.deepEqual(tiersOf(view, 'small'), {fire: 1}); // a tier with nothing in it is not drawn
  assert.deepEqual(view.edges.filter(e => e.from === '__cloud:big').map(e => e.to),
    ['__tier:big:fire', '__tier:big:smoke', '__tier:big:ice', '__tier:big:hygiene']);
  assert.ok(!view.nodes.some(n => ['subdomain', 'domain'].includes(n.kind))); // every host and target is inside a cloud
  assert.ok(!view.nodes.some(n => ['ip', 'cve'].includes(n.kind))); // and so is what only they used
  const ids = new Set(view.nodes.map(n => n.id));
  assert.ok(view.edges.every(e => ids.has(e.from) && ids.has(e.to)));
  assert.equal(data.nodes.length, 46); // the payload is left alone
});

test('a project the payload cap cut short is counted by the server total', () => {
  const data = bigProject(CLOUD_HOSTS - 100, 2);
  data.hosts = {drawn: CLOUD_HOSTS - 99, total: 10000, projects: {big: 10000}};
  assert.equal(cloudProjects(data).nodes.find(n => n.id === '__cloud:big').hosts, 10000);
});

test('one project alone is drawn host by host up to the threshold, and clouded past it', () => {
  const data = bigProject(CLOUD_HOSTS, 3, {alone: true});
  assert.equal(cloudProjects(data), data);
  data.hosts = {drawn: CLOUD_HOSTS, total: CLOUD_HOSTS, projects: {big: CLOUD_HOSTS}};
  assert.equal(cloudProjects(data), data); // a total no larger than what is drawn changes nothing
  const over = bigProject(CLOUD_HOSTS + 1, 3, {alone: true});
  const view = cloudProjects(over);
  assert.deepEqual(view.nodes.filter(n => n.kind === 'cloud').map(n => n.hosts), [CLOUD_HOSTS + 1]);
  assert.deepEqual(tiersOf(view, 'big'), {fire: 1, smoke: 1, ice: 1});
});

test('every cloud takes a slot in the clustered project grid, anchored, with its bubbles around it', () => {
  const view = clusterGraph(cloudProjects(bigProject(30, 2)), {columns: 2});
  const clouds = view.nodes.filter(n => n.kind === 'cloud');
  assert.equal(clouds.length, 2);
  assert.ok(clouds.every(c => c.anchored && Number.isFinite(c.seed_x)));
  assert.ok(!view.nodes.some(n => n.kind === 'project'));
  assert.ok(Number.isFinite(view.nodes.find(n => n.id === '__tier:big:fire').seed_x));
});

test('opening a cloud draws only that project, host by host, with shared addresses kept', () => {
  const data = bigProject(CLOUD_HOSTS + 1, 3);
  const view = focusProject(data, 'big');
  const ids = new Set(view.nodes.map(n => n.id));
  assert.equal(view.nodes.filter(n => n.kind === 'subdomain').length, CLOUD_HOSTS + 1);
  assert.ok(ids.has('dom:1') && ids.has('cve:1'));
  assert.ok(ids.has('ip:big')); // shared by many hosts: kept
  assert.ok(!ids.has('ip:shared')); // only one of this project's hosts uses it
  assert.ok(!ids.has('dom:2') && !ids.has('sub:small')); // another project is not drawn
  assert.ok(view.edges.every(e => ids.has(e.from) && ids.has(e.to)));
});
