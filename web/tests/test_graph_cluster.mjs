import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// Load the browser module without a DOM; clusterGraph is deliberately a pure
// transform so shared asset relationships and project boundaries can be tested.
const source = readFileSync(new URL('../static/cve/graph.js', import.meta.url), 'utf8');
const {clusterGraph, cloudProjects, cloudRadius, cloudShape, focusProject, byTarget, showNodeDetails, CLOUD_HOSTS} = await import(`data:text/javascript,${encodeURIComponent(source)}`);

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

// many projects of very different sizes, each with some heat and hygiene
function manyProjects(sizes) {
  const nodes = [], edges = [], projects = {};
  sizes.forEach((hosts, p) => {
    const slug = `p${p}`;
    projects[slug] = {name: `Project ${p}`, hygiene: p % 3 ? 5 * p : 0};
    nodes.push({id: `dom:${slug}`, kind: 'domain', label: `${slug}.example`, project: slug, project_name: `Project ${p}`, root: `${slug}.example`});
    for (let i = 0; i < hosts; i++) {
      nodes.push({id: `sub:${slug}:${i}`, kind: 'subdomain', label: `h${i}.${slug}.example`, project: slug, heat: i < 3 ? HEAT[(i + p) % 3] : 'clean'});
      edges.push({from: `dom:${slug}`, to: `sub:${slug}:${i}`});
    }
  });
  return {nodes, edges, projects};
}

test('clouds are sized by their hosts and packed with the biggest in the middle, none overlapping, the same on every refresh', () => {
  const data = manyProjects([2, 810, 46, 32, 26, 22, 20, 9, 6, 5, 4, 3]);
  const view = cloudProjects(data, {aspect: 3});
  const clouds = view.nodes.filter(n => n.kind === 'cloud');
  assert.ok(cloudRadius(clouds.find(c => c.project === 'p1')) > cloudRadius(clouds.find(c => c.project === 'p0')));
  const centre = [clouds.reduce((s, c) => s + c.seed_x, 0) / clouds.length, clouds.reduce((s, c) => s + c.seed_y, 0) / clouds.length];
  const away = (c) => Math.hypot(c.seed_x - centre[0], c.seed_y - centre[1]);
  assert.equal(clouds.find(c => c.order === 0).project, 'p1');
  assert.ok(away(clouds.find(c => c.project === 'p1')) < Math.min(...clouds.filter(c => c.project !== 'p1').map(away)));
  for (const a of clouds) for (const b of clouds) {
    if (a !== b) assert.ok(Math.hypot(a.seed_x - b.seed_x, a.seed_y - b.seed_y) > cloudRadius(a) + cloudRadius(b), `${a.project} overlaps ${b.project}`);
  }
  const xs = clouds.map(c => c.seed_x), ys = clouds.map(c => c.seed_y);
  assert.ok(Math.max(...xs) - Math.min(...xs) > Math.max(...ys) - Math.min(...ys)); // a wide drawing gets a wide picture
  const again = cloudProjects(manyProjects([2, 810, 46, 32, 26, 22, 20, 9, 6, 5, 4, 3]), {aspect: 3});
  assert.deepEqual(again.nodes.filter(n => ['cloud', 'tier'].includes(n.kind)).map(n => [n.id, n.seed_x, n.seed_y]),
    view.nodes.filter(n => ['cloud', 'tier'].includes(n.kind)).map(n => [n.id, n.seed_x, n.seed_y]));
  // every bubble hangs nearer its own cloud than any other cloud's core
  for (const t of view.nodes.filter(n => n.kind === 'tier')) {
    const gap = (c) => Math.hypot(t.seed_x - c.seed_x, t.seed_y - c.seed_y) - cloudRadius(c);
    const own = clouds.find(c => c.project === t.project);
    assert.ok(clouds.every(c => c === own || gap(c) > 0), `${t.id} sits inside another cloud`);
    assert.ok(gap(own) > 0);
  }
  // a cloud's aura is its worst heat
  const calm = cloudProjects(bigProject(30, 0)).nodes;
  assert.deepEqual(['__cloud:big', '__cloud:small'].map(id => calm.find(n => n.id === id).hot), ['calm', 'fire']);
});

test('a cloud is made of its targets, and its shape follows them: no two projects alike, the same one alike every time', () => {
  const data = manyProjects([0, 0]);
  const add = (slug, target, hosts, hot) => {
    for (let i = 0; i < hosts; i++) data.nodes.push({id: `sub:${slug}:${target}:${i}`, kind: 'subdomain', label: `h${i}.${target}`, project: slug, target, heat: i < hot ? 'fire' : 'clean'});
  };
  add('p0', 'one.example', 30, 2);
  ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'].forEach((t, i) => add('p1', `${t}.example`, 12 - i, i === 3 ? 4 : 0));
  const clouds = Object.fromEntries(cloudProjects(data).nodes.filter(n => n.kind === 'cloud').map(c => [c.project, c]));
  assert.deepEqual(clouds.p0.parts, [{name: 'one.example', hosts: 30, findings: 2, fire: 2, smoke: 0, ice: 0}]);
  assert.equal(clouds.p1.parts.length, 8); // the smallest targets fold into one
  assert.deepEqual(clouds.p1.parts.at(-1), {name: '3 more targets', hosts: 12, findings: 0, fire: 0, smoke: 0, ice: 0});
  assert.deepEqual(clouds.p1.parts[3], {name: 'd.example', hosts: 9, findings: 4, fire: 4, smoke: 0, ice: 0});
  const shape = (c) => cloudShape(c, 100);
  const one = shape(clouds.p0), many = shape(clouds.p1);
  assert.ok(new Set(many.map(p => p.part)).size === 8 && one.every(p => p.part === 0)); // a puff for each target
  assert.ok(many.length > one.length);
  const width = (s) => Math.max(...s.map(p => p.x + p.r)) - Math.min(...s.map(p => p.x - p.r));
  const height = (s) => Math.max(...s.map(p => p.y + p.r)) - Math.min(...s.map(p => p.y - p.r));
  for (const s of [one, many]) assert.ok(width(s) <= 231 && height(s) <= 176 && (width(s) > 229 || height(s) > 174)); // fits the cloud's room
  assert.notDeepEqual(one, many);
  assert.deepEqual(shape(clouds.p1), many);
});

test('with every project a cloud nothing is clustered: the clouds keep their packed places, side by side', () => {
  const packed = cloudProjects(manyProjects([810, 46, 32, 26, 22, 9]), {aspect: 1.6});
  const view = clusterGraph(packed, {columns: 3});
  const at = (v) => Object.fromEntries(v.nodes.filter(n => ['cloud', 'tier'].includes(n.kind)).map(n => [n.id, [n.seed_x, n.seed_y]]));
  assert.equal(view.nodes.filter(n => n.kind === 'cloud').length, 6);
  assert.deepEqual(at(view), at(packed)); // where cloudProjects packed them, not a slot each in the cluster grid (1100 apart)
  const xs = view.nodes.filter(n => n.kind === 'cloud').map(c => c.seed_x);
  assert.ok(Math.max(...xs) - Math.min(...xs) < 1100);
});

test('every cloud is anchored in the clustered view, with its bubbles around it', () => {
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

// One project on the picture: a constellation for each registered root. acme has two domains (30 and 10 hosts), three address targets (one host
// each, root "IP assets") and two hosts with no domain edge and no target. The fourth item of a target is its root (default: its name).
function oneProject({targets = [['a.example', 30, 3], ['b.example', 10, 1], ['10.0.0.1', 1, 1, 'IP assets'], ['10.0.0.2', 1, 0, 'IP assets'], ['10.0.0.3', 1, 0, 'IP assets']], loose = 2} = {}) {
  const nodes = [], edges = [];
  targets.forEach(([name, hosts, hot, root], t) => {
    nodes.push({id: `dom:${t}`, kind: 'domain', label: name, project: 'acme', project_name: 'Acme', root: root || name});
    for (let i = 0; i < hosts; i++) {
      nodes.push({id: `sub:${t}:${i}`, kind: 'subdomain', label: `h${i}.${name}`, project: 'acme', target: name, heat: i < hot ? HEAT[i % 3] : 'clean'});
      edges.push({from: `dom:${t}`, to: `sub:${t}:${i}`});
    }
  });
  for (let i = 0; i < loose; i++) nodes.push({id: `sub:x:${i}`, kind: 'subdomain', label: `loose${i}.example`, project: 'acme', target: '', heat: i ? 'clean' : 'fire'});
  return {nodes, edges, projects: {acme: {name: 'Acme', hygiene: 4}, other: {name: 'Other', hygiene: 1}}};
}
const cloudsOf = (view) => view.nodes.filter(n => n.kind === 'cloud');

test('a single project is one constellation per registered root: address targets fold into one "IP assets"', () => {
  const data = oneProject();
  const view = cloudProjects(byTarget(data));
  assert.deepEqual(cloudsOf(view).map(c => [c.label, c.hosts, c.findings, c.slug, c.target]),
    [['a.example', 30, 3, 'acme', 'a.example'], ['b.example', 10, 1, 'acme', 'b.example'], ['IP assets', 3, 1, 'acme', 'IP assets'], ['Acme', 2, 1, 'acme', 'Acme']]);
  const a = cloudsOf(view).find(c => c.label === 'a.example');
  assert.deepEqual(tiersOf(view, a.project), {fire: 1, smoke: 1, ice: 1}); // its own hosts only, and no hygiene (that is known per project)
  assert.ok(cloudsOf(view).every(c => c.hygiene === 0));
  assert.deepEqual(cloudsOf(view).find(c => c.label === 'IP assets').parts.map(p => p.name).sort(), ['10.0.0.1', '10.0.0.2', '10.0.0.3']);
  assert.ok(!view.nodes.some(n => ['subdomain', 'domain'].includes(n.kind)));
  assert.equal(data.nodes.length, 30 + 10 + 3 + 5 + 2); // the payload is left alone
  assert.ok(data.nodes.every(n => n.project === 'acme'));
});

test('two domains with different roots stay apart, and two with one root are one constellation', () => {
  const apart = cloudProjects(byTarget(oneProject({targets: [['a.example', 3, 0], ['b.example', 4, 0]], loose: 0})));
  assert.deepEqual(cloudsOf(apart).map(c => [c.label, c.hosts]), [['b.example', 4], ['a.example', 3]]);
  const one = cloudProjects(byTarget(oneProject({targets: [['www.a.example', 3, 0, 'a.example'], ['api.a.example', 4, 0, 'a.example']], loose: 0})));
  assert.deepEqual(cloudsOf(one).map(c => [c.label, c.hosts]), [['a.example', 7]]);
});

test('a project with one target is one constellation', () => {
  const view = cloudProjects(byTarget(oneProject({targets: [['only.example', 12, 2]], loose: 0})));
  assert.deepEqual(cloudsOf(view).map(c => [c.label, c.hosts, c.findings]), [['only.example', 12, 2]]);
  const few = cloudProjects(byTarget(oneProject({targets: [['tiny.example', 3, 0]], loose: 0})));
  assert.equal(cloudsOf(few).length, 1); // however few hosts: it is a constellation, not a handful of dots
});

test('two projects stay one constellation per project', () => {
  const data = bigProject(40, 7);
  assert.equal(byTarget(data), data);
  assert.deepEqual(cloudsOf(cloudProjects(byTarget(data))).map(c => c.id), ['__cloud:big', '__cloud:small']);
});

test('a capped payload is one constellation for the project with the true total', () => {
  const data = oneProject();
  data.hosts = {drawn: 46, total: 9000, projects: {acme: 9000}};
  const view = cloudProjects(byTarget(data));
  assert.deepEqual(cloudsOf(view).map(c => [c.id, c.hosts, c.project, c.slug]), [['__cloud:acme', 9000, 'acme', 'acme']]);
});

test('diving into a root draws only that root\'s hosts', () => {
  const data = byTarget(oneProject());
  const ip = cloudsOf(cloudProjects(data)).find(c => c.label === 'IP assets');
  const inside = focusProject(data, ip.project);
  assert.deepEqual(inside.nodes.filter(n => n.kind === 'subdomain').map(n => n.target).sort(), ['10.0.0.1', '10.0.0.2', '10.0.0.3']);
  assert.equal(inside.nodes.filter(n => n.kind === 'domain').length, 3);
  const b = cloudsOf(cloudProjects(data)).find(c => c.label === 'b.example');
  const view = focusProject(data, b.project);
  assert.equal(view.nodes.filter(n => n.kind === 'subdomain').length, 10);
  assert.ok(view.nodes.filter(n => n.kind === 'subdomain').every(n => n.target === 'b.example'));
  assert.deepEqual(view.nodes.filter(n => n.kind === 'domain').map(n => n.label), ['b.example']);
  assert.ok(view.nodes.every(n => n.project === undefined || n.project === b.project));
});

test('a constellation knows its hosts and targets so a scan on them can light it', () => {
  const view = cloudProjects(byTarget(oneProject()));
  const b = cloudsOf(view).find(c => c.label === 'b.example');
  assert.equal(b.host_names.length, 10);
  assert.ok(b.host_names.includes('h0.b.example'));
  assert.deepEqual(b.domain_ids, ['1']);
});

test('no synthetic key reaches a link, a request or an event the details build', async () => {
  const hrefs = [], urls = [], opened = [];
  const make = (tag) => ({tag, kids: [], attrs: {}, className: '', textContent: '',
    append(...k) { this.kids.push(...k); }, setAttribute(k, v) { this.attrs[k] = v; if (k === 'href') hrefs.push(v); },
    addEventListener(type, fn) { if (type === 'click') this.click = fn; }});
  const walk = (n, out = []) => { out.push(n); (n.kids || []).forEach(k => walk(k, out)); return out; };
  globalThis.document = {createElement: make, createTextNode: (t) => ({text: t}), dispatchEvent: (e) => opened.push(e.detail)};
  globalThis.CustomEvent = class { constructor(type, init) { this.detail = init.detail; } };
  const rows = ['h0.b.example', 'h5.zzz'].map(host => ({host, heat: 'fire', score: 9, heat_reasons: []}));
  globalThis.fetch = async (url) => { urls.push(String(url)); return {ok: true, json: async () => ({count: 2, results: rows})}; };
  const view = cloudProjects(byTarget(oneProject()));
  for (const node of view.nodes.filter(n => ['cloud', 'tier'].includes(n.kind))) {
    const box = make('div');
    await showNodeDetails(box, node);
    walk(box).filter(n => n.click).forEach(n => n.click());
  }
  assert.ok(hrefs.length && urls.length);
  assert.ok([...hrefs, ...urls].every(u => !u.includes('acme%7C') && !u.includes('acme|')), [...hrefs, ...urls].join('\n'));
  assert.ok([...hrefs, ...urls].every(u => u.startsWith('/cve/acme/') || u.startsWith('/api/v1/projects/acme/')));
  assert.ok(opened.length && opened.every(k => view.nodes.some(n => n.kind === 'cloud' && n.project === k))); // Open dives into a drawn constellation
  delete globalThis.document; delete globalThis.fetch; delete globalThis.CustomEvent;
});
