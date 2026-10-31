// Shared VivaGraphJS asset graph (loaded after vivagraph.min.js): labelled nodes, click for details.
// Colors come from the page's CSS variables, read when a node is drawn, so the graph follows the theme (light by default).
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const mixed = (name, pct) => `color-mix(in srgb, ${css(name)} ${pct}%, transparent)`;
const COLORS = {
  get domain() { return css("--ink"); },
  get subdomain() { return css("--ink"); },
  get ip() { return css("--graph-ip"); },
};
const CVE_COLORS = {
  get fire() { return css("--fire"); },
  get smoke() { return css("--smoke"); },
  get ice() { return css("--ice"); },
};
// A subdomain's fill tracks how far along it is, not just what kind of node it is: hollow (no fill, just
// the usual blue outline) means CVEngine knows about it but nothing has scanned it yet; filled green means
// scanned and clean; filled red means it has an open, non-informational finding or an unresolved CVE match.
const STATUS_FILL = {
  unscanned: "none",
  get scanned() { return css("--clean"); },
  get vulnerable() { return css("--fire"); },
};
// Hosts have three looks: an empty gray circle (nuclei has not looked at it), a green outline (nuclei ran and found nothing),
// a red outline with a faint red fill (it has vulnerabilities, whatever their temperature).
const HOST_LOOK = {
  unscanned: { fill: "none", get stroke() { return css("--graph-ip"); }, width: "1.5" },
  clean: { get fill() { return css("--surface"); }, get stroke() { return css("--ok"); }, width: "2" },
  vulnerable: { get fill() { return mixed("--fire", 14); }, get stroke() { return css("--fire"); }, width: "2" },
};
const hostState = (d) => {
  if (["fire", "smoke", "ice"].includes(d.heat) || d.status === "vulnerable") return "vulnerable";
  if (d.heat === "clean" || d.status === "scanned") return "clean";
  return "unscanned";
};
function styleHost(circle, d) {
  const look = HOST_LOOK[hostState(d)];
  circle.setAttribute("fill", look.fill);
  circle.setAttribute("stroke", look.stroke);
  circle.setAttribute("stroke-width", look.width);
}

// the host's worst threat temperature, when the API says (see cveFeed.views.host_heat)
const SIZES = { project: 26, root: 20, domain: 16, subdomain: 11, ip: 8, cve: 10 };
const NS = "http://www.w3.org/2000/svg";
const MAX_LABEL = 28;
const CELL_W = 120; // a label owns a 120 x 14 px cell of the screen; a second label in the same cell is not drawn
const CELL_H = 14;
const HUB_LINKS = 3; // an IP with this many hosts is a hub: its label always shows
const MIN_LABEL_SCALE = 0.45; // below this zoom only hubs and hovered nodes are labelled
const DRAG_PX = 4; // a pointer that moves less than this is a click
// Shows or hides an SVG node. An empty display attribute is an invalid CSS value Firefox logs once per node, so showing removes it.
const showSvg = (node, on) => on ? node.removeAttribute("display") : node.setAttribute("display", "none");

const colorOf = (d) =>
  d.kind === "cve" ? CVE_COLORS[d.tier] || css("--ice") : COLORS[d.kind] || css("--muted");
const shorten = (text) =>
  text.length > MAX_LABEL ? `${text.slice(0, MAX_LABEL - 1)}…` : text;
// Under its target a host reads as its leftmost part: app.stg.example.com -> teleport.stg40.
// The full name stays in the tooltip and on the detail card.
export const shortLabel = (d) => {
  const label = d.label || "";
  const target = (d.target || "").toLowerCase();
  if (d.kind === "subdomain" && target && label.toLowerCase().endsWith(`.${target}`))
    return label.slice(0, label.length - target.length - 1);
  return label;
};

const readPins = (key) => {
  try {
    return JSON.parse(localStorage.getItem(key) || "{}") || {};
  } catch (_) {
    return {};
  }
};
const writePins = (key, pins) => {
  try {
    localStorage.setItem(key, JSON.stringify(pins));
  } catch (_) {
    /* private mode or blocked storage: pins last until reload */
  }
};

const stableAngle = (value) => {
  let hash = 2166136261;
  for (const letter of String(value)) hash = Math.imul(hash ^ letter.charCodeAt(0), 16777619);
  return ((hash >>> 0) % 3600) * Math.PI / 1800;
};

// Clouds. With more than one project on the picture, every project is drawn as one cloud of drifting bubbles with its host count, and
// what needs attention hangs off it: a bubble each for its fire, smoke and ice hosts and its open hygiene findings, sized by how many.
// Hundreds of hosts, targets, IPs and CVEs from several projects made one unreadable haze; the cloud says how big a project is and the
// bubbles say where the trouble is. Double-click a cloud (or Open on its card) to go inside, host by host. With one project on the
// picture it is drawn host by host straight away, unless it has more than CLOUD_HOSTS hosts (the force layout and the SVG both crawl).
export const CLOUD_HOSTS = 500;
const CLOUD_R = 84;
const HEATS = ["fire", "smoke", "ice"];
export const TIERS = [...HEATS, "hygiene"];
const TIER_NAMES = { fire: "Fire", smoke: "Smoke", ice: "Ice", hygiene: "Hygiene" };
// A cloud's make-up: its targets, biggest first, the smallest past CLOUD_PARTS folded into one
const CLOUD_PARTS = 8;
function cloudParts(parts) {
  parts.sort((a, b) => b.hosts - a.hosts || a.name.localeCompare(b.name));
  if (parts.length <= CLOUD_PARTS) return parts;
  const rest = parts.slice(CLOUD_PARTS - 1);
  return [...parts.slice(0, CLOUD_PARTS - 1), { name: `${rest.length} more targets`, hosts: rest.reduce((s, p) => s + p.hosts, 0), findings: rest.reduce((s, p) => s + p.findings, 0) }];
}
// A cloud's size says how big the project is: from a few hosts to thousands, on a log scale so a small project is still a cloud.
export const cloudRadius = (d) => Math.round(Math.min(128, Math.max(58, 58 + 22 * Math.log10((d.hosts || 0) + 1))));
// Where a cloud's bubbles hang: slots around it that keep clear of its name above and its counts below (degrees, 0 is right).
const TIER_SLOTS = [-48, 205, 18, 160, 58, 122, -12, 232];
const TIER_REACH = 34; // from the cloud's rim to a bubble's rim
const CLOUD_GAP = 6;
const CLOUD_SNUG = 0.86; // neighbours' outer rings may overlap a little: a cloud's bubbles only take some of its ring
// The clouds are packed like soap bubbles, biggest in the middle and the rest spiralling out, pushed apart until none touch and
// pulled toward an ellipse the shape of the drawing (``aspect``: its width over its height). Nothing random goes in, so the same
// projects come out in the same places on every refresh. A force layout let clouds overlap and bubbles drift to the wrong cloud;
// a grid read as a spreadsheet.
function packClouds(clouds, feet, aspect) {
  const golden = Math.PI * (3 - Math.sqrt(5));
  const squash = Math.max(1, Math.min(aspect, 5));
  const items = clouds.map((c, i) => {
    const step = Math.sqrt(i) * (feet.get(c) + CLOUD_GAP) * 1.1;
    return { c, x: Math.cos(i * golden) * step * Math.sqrt(squash), y: Math.sin(i * golden) * step / Math.sqrt(squash) };
  });
  for (let round = 0; round < 260; round++) {
    const pull = 0.04 * (1 - round / 320);
    for (const p of items) {
      p.x -= p.x * pull / squash;
      p.y -= p.y * pull * squash;
    }
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const a = items[i], b = items[j];
        let dx = b.x - a.x, dy = b.y - a.y, dist = Math.hypot(dx, dy);
        const need = (feet.get(a.c) + feet.get(b.c)) * CLOUD_SNUG + CLOUD_GAP;
        if (dist >= need) continue;
        if (dist < 0.01) [dx, dy, dist] = [Math.cos(i + j), Math.sin(i + j), 1];
        const push = (need - dist) / 2, ux = dx / dist, uy = dy / dist;
        a.x -= ux * push;
        a.y -= uy * push;
        b.x += ux * push;
        b.y += uy * push;
      }
    }
  }
  return items;
}
export function cloudProjects(data, { aspect = 1.6 } = {}) {
  const counts = new Map();
  for (const n of data.nodes) {
    if (!n.project || !["subdomain", "domain"].includes(n.kind)) continue;
    counts.set(n.project, (counts.get(n.project) || 0) + (n.kind === "subdomain" ? 1 : 0));
  }
  // the payload is capped, so a big project's drawn hosts are only some of them: the server's own per-project total is the count
  const totals = (data.hosts && data.hosts.projects) || {};
  for (const [slug, n] of Object.entries(totals)) if (counts.has(slug) && n > counts.get(slug)) counts.set(slug, n);
  const big = new Set(counts.size > 1 ? counts.keys() : [...counts].filter(([, n]) => n > CLOUD_HOSTS).map(([slug]) => slug));
  if (!big.size) return data;
  const about = data.projects || {};
  const names = new Map();
  const heat = new Map(); // project -> {fire, smoke, ice}: hosts by their worst temperature
  const made = new Map(); // project -> target -> {name, hosts, findings}: what the cloud is made of
  const clouded = new Set(); // every host and target of a clouded project: they are inside it
  for (const n of data.nodes) {
    if (!big.has(n.project) || !["subdomain", "domain"].includes(n.kind)) continue;
    clouded.add(n.id);
    if (n.kind === "domain") names.set(n.project, n.project_name || n.project);
    else {
      const parts = made.get(n.project) || new Map();
      const name = n.target || n.project;
      const part = parts.get(name) || { name, hosts: 0, findings: 0 };
      part.hosts += 1;
      part.findings += HEATS.includes(n.heat) ? 1 : 0;
      parts.set(name, part);
      made.set(n.project, parts);
    }
    if (n.kind === "subdomain" && HEATS.includes(n.heat)) {
      const t = heat.get(n.project) || { fire: 0, smoke: 0, ice: 0 };
      t[n.heat] += 1;
      heat.set(n.project, t);
    }
  }
  const edges = data.edges.filter((e) => !clouded.has(e.from) && !clouded.has(e.to));
  const linked = new Set(edges.flatMap((e) => [e.from, e.to]));
  const clouds = [], tiers = [];
  for (const slug of big) {
    const t = { fire: 0, smoke: 0, ice: 0, ...heat.get(slug), hygiene: (about[slug] && about[slug].hygiene) || 0 };
    const cloud = { id: `__cloud:${slug}`, kind: "cloud", label: names.get(slug) || (about[slug] && about[slug].name) || slug, project: slug,
      hosts: counts.get(slug), findings: t.fire + t.smoke + t.ice, hygiene: t.hygiene,
      hot: t.fire ? "fire" : t.smoke ? "smoke" : t.ice ? "ice" : "calm", // its aura: the worst heat among its hosts
      parts: cloudParts([...(made.get(slug) || new Map()).values()]) };
    clouds.push(cloud);
    for (const tier of TIERS) {
      if (!t[tier]) continue;
      tiers.push({ id: `__tier:${slug}:${tier}`, kind: "tier", tier, label: TIER_NAMES[tier], count: t[tier], project: slug, project_name: cloud.label });
      edges.push({ from: cloud.id, to: `__tier:${slug}:${tier}` });
    }
  }
  clouds.sort((a, b) => b.hosts - a.hosts || a.label.localeCompare(b.label));
  const feet = new Map(clouds.map((cloud) => { // a cloud and the ring its bubbles hang in
    const own = tiers.filter((t) => t.project === cloud.project);
    return [cloud, cloudRadius(cloud) + (own.length ? TIER_REACH + 10 + 2 * Math.max(...own.map(tierRadius)) + 14 : 34)];
  }));
  packClouds(clouds, feet, aspect).forEach(({ c: cloud, x, y }, i) => {
    Object.assign(cloud, { seed_x: x, seed_y: y, anchored: true, order: i });
    const r = cloudRadius(cloud);
    const start = Math.floor(unit(cloud.project) * TIER_SLOTS.length); // each cloud wears its bubbles its own way round
    tiers.filter((t) => t.project === cloud.project).forEach((t, j) => {
      const a = TIER_SLOTS[(start + j * 3) % TIER_SLOTS.length] * Math.PI / 180;
      const reach = r + TIER_REACH + tierRadius(t) + (j % 2) * 10;
      Object.assign(t, { seed_x: x + Math.cos(a) * reach, seed_y: y + Math.sin(a) * reach, anchored: true, order: i, slot: j });
    });
  });
  // an IP or CVE that only clouded hosts pointed at goes with them
  const nodes = data.nodes.filter((n) => !clouded.has(n.id) && (!["ip", "cve"].includes(n.kind) || linked.has(n.id)));
  return { ...data, nodes: [...nodes, ...clouds, ...tiers], edges };
}

// Diving into a cloud: one project's own hosts, targets and CVEs, drawn host by host whatever its size. An address only one host uses
// is left to that host's card (at this size they would double the dots); an address several hosts share stays, it is the structure.
export function focusProject(data, slug) {
  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const own = new Set(data.nodes.filter((n) => n.project === slug && ["subdomain", "domain"].includes(n.kind)).map((n) => n.id));
  const users = new Map();
  for (const e of data.edges) if (own.has(e.from) && byId.get(e.to)?.kind === "ip") users.set(e.to, (users.get(e.to) || 0) + 1);
  const edges = data.edges.filter((e) => (own.has(e.from) || own.has(e.to)) && !(byId.get(e.to)?.kind === "ip" && users.get(e.to) < 2));
  const keep = new Set([...own, ...edges.flatMap((e) => [e.from, e.to])]);
  return { ...data, nodes: data.nodes.filter((n) => keep.has(n.id)), edges: edges.filter((e) => keep.has(e.from) && keep.has(e.to)) };
}

// Retain the original bubbles and discovery links. Invisible force anchors are
// replaced by visible project/root-domain bubbles when showing all domains.
// A shared IP/CVE gets one visual copy per root so a CDN does not pull two
// unrelated tenants into the same cluster; each copy opens the same detail ID.
export function clusterGraph(data, {columns: requestedColumns} = {}) {
  const originals = new Map(data.nodes.map(node => [node.id, node]));
  const domains = data.nodes.filter(node => node.kind === 'domain' && node.project && node.root);
  const clouds = data.nodes.filter(node => node.kind === 'cloud');
  if (!domains.length && !clouds.length) return {nodes: data.nodes, edges: data.edges};
  const projects = new Map(clouds.map(cloud => [cloud.project, {slug: cloud.project, name: cloud.label, cloud, roots: new Map()}]));
  for (const domain of domains) {
    const project = projects.get(domain.project) ||
      {slug: domain.project, name: domain.project_name || domain.project, roots: new Map()};
    if (!projects.has(domain.project)) projects.set(domain.project, project);
    const roots = project.roots.get(domain.root) || [];
    if (!project.roots.has(domain.root)) project.roots.set(domain.root, roots);
    roots.push(domain);
  }
  const ordered = [...projects.values()].sort((a, b) => a.name.localeCompare(b.name));
  const anchored = new Set();
  const columns = Math.max(1, requestedColumns || Math.ceil(Math.sqrt(ordered.length * 1.5)));
  const added = [], links = [];
  const positions = new Map();
  const groupForSub = new Map();
  const domainForSub = new Map();
  for (const edge of data.edges) {
    const domain = originals.get(edge.from), sub = originals.get(edge.to);
    if (domain?.kind === 'domain' && sub?.kind === 'subdomain') {
      groupForSub.set(sub.id, `${domain.project}:${domain.root}`);
      domainForSub.set(sub.id, domain.id);
    }
  }
  ordered.forEach((project, index) => {
    const x = (index % columns) * 1100;
    const y = Math.floor(index / columns) * 1050;
    if (project.cloud) { // the cloud is the project: it holds the slot, and its red dots ring it
      positions.set(project.cloud.id, [x, y]);
      anchored.add(project.cloud.id);
      data.edges.filter(edge => edge.from === project.cloud.id).forEach(edge => {
        const tier = originals.get(edge.to), angle = stableAngle(edge.to);
        positions.set(edge.to, Number.isFinite(tier?.seed_x) ? [x + tier.seed_x - project.cloud.seed_x, y + tier.seed_y - project.cloud.seed_y]
          : [x + Math.cos(angle) * (CLOUD_R + 60), y + Math.sin(angle) * (CLOUD_R + 60)]);
      });
      return;
    }
    const projectId = `__project:${project.slug}`;
    added.push({id: projectId, kind: 'project', label: project.name, seed_x: x, seed_y: y, anchored: true});
    const roots = [...project.roots.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    roots.forEach(([root, members], rootIndex) => {
      const angle = 2 * Math.PI * rootIndex / roots.length - Math.PI / 2;
      const distance = roots.length === 1 ? 220 : 290 + Math.max(0, roots.length - 3) * 25;
      const rx = x + Math.cos(angle) * distance;
      const ry = y + Math.sin(angle) * distance;
      const rootId = `__root:${project.slug}:${root}`;
      added.push({id: rootId, kind: 'root', label: root, seed_x: rx, seed_y: ry, anchored: true});
      links.push({from: projectId, to: rootId});
      members.sort((a, b) => a.id.localeCompare(b.id)).forEach((domain, domainIndex) => {
        const direction = 2 * Math.PI * domainIndex / members.length + stableAngle(domain.id) / 8;
        const dx = rx + Math.cos(direction) * (members.length === 1 ? 95 : 115);
        const dy = ry + Math.sin(direction) * (members.length === 1 ? 95 : 115);
        positions.set(domain.id, [dx, dy]);
        links.push({from: rootId, to: domain.id});
      });
    });
  });
  for (const [subId, domainId] of domainForSub) {
    const parent = positions.get(domainId);
    if (!parent) continue;
    const angle = stableAngle(subId);
    positions.set(subId, [parent[0] + Math.cos(angle) * 130, parent[1] + Math.sin(angle) * 130]);
  }
  const clones = new Map();
  for (const edge of data.edges) {
    const to = originals.get(edge.to);
    const group = groupForSub.get(edge.from);
    if (!group || !['ip', 'cve'].includes(to?.kind)) {
      const otherGroup = groupForSub.get(edge.to);
      links.push({...edge, crossCluster: !!(group && otherGroup && group !== otherGroup)});
      continue;
    }
    const id = `${to.id}@${group}`;
    if (!clones.has(id)) {
      const parent = positions.get(edge.from) || [0, 0];
      const angle = stableAngle(id);
      clones.set(id, {...to, id, detail_id: to.id,
        seed_x: parent[0] + Math.cos(angle) * 55, seed_y: parent[1] + Math.sin(angle) * 55});
    }
    links.push({from: edge.from, to: id});
  }
  const originalNodes = data.nodes.filter(node => !['ip', 'cve'].includes(node.kind) ||
    links.some(edge => edge.to === node.id || edge.from === node.id));
  return {nodes: [...originalNodes.map(node => positions.has(node.id) ?
    {...node, seed_x: positions.get(node.id)[0], seed_y: positions.get(node.id)[1], anchored: anchored.has(node.id) || node.anchored} : node),
    ...clones.values(), ...added], edges: links};
}

// pinKey(): localStorage key for where nodes were dropped (evaluated on every read and write, so it can follow the scan).
// CVE pods. A host can carry dozens of CVEs, and drawing each as a dot turns a busy graph into a haze of specks. Instead the CVEs of a
// host are folded into the host itself: its bubble grows with how many there are and wears a ring split by temperature (fire, smoke,
// ice). Double-click a host to open its pod and see the individual CVEs; double-click again to fold them back.
const TIER_KEYS = ["fire", "smoke", "ice"];
export function collapsePods(view, expanded) {
  const byId = new Map(view.nodes.map((n) => [n.id, n]));
  const pods = new Map();
  const keep = new Set();
  const edges = [];
  view.edges.forEach((e) => {
    const from = byId.get(e.from);
    const to = byId.get(e.to);
    if (from && from.kind === "subdomain" && to && to.kind === "cve") {
      const pod = pods.get(from.id) || { fire: 0, smoke: 0, ice: 0, total: 0 };
      pod[TIER_KEYS.includes(to.tier) ? to.tier : "ice"] += 1;
      pod.total += 1;
      pods.set(from.id, pod);
      if (expanded.has(from.id)) {
        keep.add(to.id);
        edges.push(e);
      }
      return;
    }
    edges.push(e);
  });
  const nodes = view.nodes
    .filter((n) => n.kind !== "cve" || keep.has(n.id))
    .map((n) => (pods.has(n.id) ? { ...n, pod: pods.get(n.id), expanded: expanded.has(n.id) } : n));
  return { nodes, edges };
}

// Orbit. The CVEs of a host also circle it as little moons, each on its own dotted orbit and at its own speed, colored by temperature
// (at most MOON_CAP of them, in proportion to fire, smoke and ice). A host whose pod is open shows its real CVE nodes instead.
const MOON_CAP = 14;
function decorateMoons(g, d, r) {
  g.querySelector(".moons")?.remove();
  if (!d.pod || !d.pod.total || d.expanded) return;
  const moons = document.createElementNS(NS, "g");
  moons.setAttribute("class", "moons");
  const n = Math.min(MOON_CAP, d.pod.total);
  const order = [];
  TIER_KEYS.forEach((tier) => {
    const share = Math.max(d.pod[tier] ? 1 : 0, Math.round((d.pod[tier] / d.pod.total) * n));
    for (let i = 0; i < share; i += 1) order.push(tier);
  });
  [0, 1, 2].forEach((lane) => {
    const path = document.createElementNS(NS, "circle");
    path.setAttribute("class", "moon-orbit");
    path.setAttribute("r", r + 9 + lane * 8);
    path.setAttribute("fill", "none");
    moons.append(path);
  });
  order.slice(0, n).forEach((tier, i) => {
    const lane = i % 3;
    const spin = document.createElementNS(NS, "g");
    spin.setAttribute("class", "moon");
    spin.style.animationDuration = `${6 + ((i * 7) % 11) * 1.6 + lane * 4}s`;
    spin.style.animationDelay = `${-((i * 3.7) % 13)}s`;
    if (i % 2) spin.style.animationDirection = "reverse";
    const dot = document.createElementNS(NS, "circle");
    dot.setAttribute("cx", r + 9 + lane * 8);
    dot.setAttribute("r", tier === "fire" ? 3.6 : 3);
    dot.setAttribute("fill", CVE_COLORS[tier]);
    spin.append(dot);
    moons.append(spin);
  });
  g.append(moons);
}
const tierRadius = (d) => Math.min(30, 12 + 3 * Math.sqrt(d.count || 0));
const hostRadius = (d) => (d.pod && d.pod.total ? Math.min(34, 11 + 3.2 * Math.sqrt(d.pod.total)) : SIZES.subdomain);
// A cloud's look: a real cloud, puffs heaped into one billowing outline, glowing in its aura, and inside it the project as a living
// network: hosts as nodes, each tied to its nearest neighbours, packets running along the links, and a red node for each share of its
// hosts with findings. Placed and timed from the cloud's id, so a redraw looks the same; CSS does every motion (and stops it for reduced
// motion). ``under`` goes beneath the body (the hit area), ``over`` above it.
const CLOUD_SPARKS = 9;
let cloudSeq = 0;
const svgEl = (tag, attrs = {}, cls = "") => {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (cls) el.setAttribute("class", cls);
  return el;
};
const unit = (seed) => stableAngle(seed) / (2 * Math.PI); // a stable 0..1 from a string
// The cloud's shape is its make-up: a puff for each target, as big as its share of the hosts, heaped from the biggest out, low and
// wide like a cumulus, and each puff knobbled with more lumps the more hosts it holds. A project with one target is one lumpy cloud,
// one with many sprawls; no two come out alike, and the same project comes out the same on every refresh. Scaled to fit the radius.
export function cloudShape(d, R) {
  const parts = d.parts && d.parts.length ? d.parts : [{ name: d.project || d.id, hosts: d.hosts || 0, findings: 0 }];
  const total = parts.reduce((s, p) => s + Math.max(1, p.hosts), 0);
  const cores = [];
  parts.forEach((part, i) => {
    const r = Math.max(0.22, Math.sqrt(Math.max(1, part.hosts) / total));
    let at = [0, 0];
    if (cores.length) {
      let best = Infinity;
      for (const q of cores) {
        for (let s = 0; s <= 14; s++) {
          const a = (-200 + s * 15) * Math.PI / 180, reach = (q.r + r) * 0.7;
          const x = q.x + Math.cos(a) * reach, y = q.y + Math.sin(a) * reach;
          if (cores.some((c) => Math.hypot(c.x - x, c.y - y) < (c.r + r) * 0.62)) continue;
          const score = Math.hypot(x * 0.55, y) + (y + r > cores[0].r ? 4 : 0) + unit(`${d.id}:${part.name}:${s}`) * 0.18;
          if (score < best) [best, at] = [score, [x, y]];
        }
      }
    }
    cores.push({ x: at[0], y: at[1], r, part: i });
  });
  const puffs = [...cores];
  for (const core of cores) {
    const name = parts[core.part].name, lumps = 2 + Math.min(5, Math.round(Math.log2(parts[core.part].hosts + 1)));
    for (let k = 0; k < lumps; k++) {
      const a = -Math.PI * (0.08 + 0.84 * unit(`${d.id}:${name}:l${k}`)), lr = core.r * (0.38 + 0.3 * unit(`${d.id}:${name}:l${k}:r`));
      puffs.push({ x: core.x + Math.cos(a) * core.r * 0.72, y: core.y + Math.sin(a) * core.r * 0.72, r: lr, part: core.part });
    }
  }
  const left = Math.min(...puffs.map((p) => p.x - p.r)), right = Math.max(...puffs.map((p) => p.x + p.r));
  const top = Math.min(...puffs.map((p) => p.y - p.r)), bottom = Math.max(...puffs.map((p) => p.y + p.r));
  const k = R / Math.max((right - left) / 2.3, (bottom - top) / 1.75);
  const cx = (left + right) / 2, cy = (top + bottom) / 2;
  return puffs.map((p) => ({ x: (p.x - cx) * k, y: (p.y - cy) * k, r: p.r * k, part: p.part }));
}
// the network inside: each target's hosts as nodes in its own puffs (red for its share with findings), each tied to its two nearest,
// and each target bridged to the nearest one heaped before it
function cloudNetwork(d, R, puffs) {
  const parts = d.parts && d.parts.length ? d.parts : [{ name: d.project || d.id, hosts: d.hosts || 0, findings: 0 }];
  const total = parts.reduce((s, p) => s + Math.max(1, p.hosts), 0);
  const want = Math.round(Math.min(30, 12 + 5 * Math.log10((d.hosts || 0) + 1)));
  const nodes = [], links = new Map();
  const link = (i, j) => links.set(i < j ? `${i}-${j}` : `${j}-${i}`, [Math.min(i, j), Math.max(i, j)]);
  parts.forEach((part, pi) => {
    const own = puffs.filter((p) => p.part === pi);
    const n = Math.max(2, Math.round(want * Math.max(1, part.hosts) / total));
    const hot = part.findings ? Math.min(Math.ceil(n * 0.5), Math.max(1, Math.round(part.findings / Math.max(part.hosts, 1) * n * 3))) : 0;
    const first = nodes.length;
    for (let k = 0; k < 300 && nodes.length - first < n; k++) {
      const p = own[Math.floor(unit(`${d.id}:${pi}:n${k}:p`) * own.length)];
      const a = unit(`${d.id}:${pi}:n${k}:a`) * 2 * Math.PI, reach = p.r * 0.7 * Math.sqrt(unit(`${d.id}:${pi}:n${k}:r`));
      const x = p.x + Math.cos(a) * reach, y = p.y + Math.sin(a) * reach;
      if (Math.abs(x) < R * 0.36 && Math.abs(y - R * 0.04) < R * 0.24) continue; // the count sits here
      if (nodes.every((m) => Math.hypot(m.x - x, m.y - y) > R * 0.13)) nodes.push({ x, y, k: `${pi}:${k}`, part: pi, hot: nodes.length - first < hot });
    }
    const mine = nodes.map((m, i) => [m, i]).filter(([m]) => m.part === pi);
    for (const [m, i] of mine) {
      mine.filter(([, j]) => j !== i).map(([o, j]) => [Math.hypot(o.x - m.x, o.y - m.y), j]).sort((a, b) => a[0] - b[0]).slice(0, 2).forEach(([, j]) => link(i, j));
    }
    const before = nodes.map((m, i) => [m, i]).filter(([m]) => m.part < pi);
    if (mine.length && before.length) { // the bridge to the rest of the cloud
      let best = null;
      for (const [m, i] of mine) {
        for (const [o, j] of before) {
          const gap = Math.hypot(o.x - m.x, o.y - m.y);
          if (!best || gap < best[0]) best = [gap, i, j];
        }
      }
      link(best[1], best[2]);
    }
  });
  return { nodes, links: [...links.values()] };
}
function cloudArt(d) {
  const id = `cloud${++cloudSeq}`;
  const R = cloudRadius(d);
  const puffs = cloudShape(d, R);
  const under = svgEl("g", {}, "cloud-under");
  const defs = svgEl("defs");
  // one shading across every puff, lit from the top left, so the heap reads as one cloud
  const body = svgEl("radialGradient", { id: `${id}-body`, gradientUnits: "userSpaceOnUse", cx: -R * 0.3, cy: -R * 0.55, r: R * 1.6 });
  body.append(svgEl("stop", { offset: "0%" }, "cg-body-in"), svgEl("stop", { offset: "55%" }, "cg-body-mid"), svgEl("stop", { offset: "100%" }, "cg-body-out"));
  defs.append(body);
  const halo = svgEl("g", {}, "cloud-halo"); // the aura: the cloud's own shape, blurred, breathing
  const edge = svgEl("g", {}, "cloud-edge"); // every puff with an outline, then every puff without on top: only the outer edge shows
  const fill = svgEl("g", {}, "cloud-fill");
  puffs.forEach((p, i) => {
    const at = { cx: p.x.toFixed(1), cy: p.y.toFixed(1) };
    const delay = `-${(unit(`${d.id}:p${i}:d`) * 7).toFixed(1)}s`, duration = `${(5 + unit(`${d.id}:p${i}:t`) * 4).toFixed(1)}s`;
    halo.append(svgEl("circle", { ...at, r: (p.r * 1.08).toFixed(1) }));
    for (const [layer, cls] of [[edge, "cloud-puff"], [fill, "cloud-puff"]]) {
      const c = svgEl("circle", { ...at, r: p.r.toFixed(1), fill: `url(#${id}-body)` }, cls);
      c.style.animationDelay = delay; // both layers billow together, so the outline never shows through
      c.style.animationDuration = duration;
      layer.append(c);
    }
  });
  under.append(defs, halo, edge, fill);

  const over = svgEl("g", {}, "cloud-over");
  const net = svgEl("g", {}, "cloud-bubbles cloud-net");
  const { nodes, links } = cloudNetwork(d, R, puffs);
  for (const [i, j] of links) {
    const a = nodes[i], b = nodes[j];
    const at = { x1: a.x.toFixed(1), y1: a.y.toFixed(1), x2: b.x.toFixed(1), y2: b.y.toFixed(1) };
    const hot = a.hot || b.hot;
    net.append(svgEl("line", at, hot ? "cloud-link cloud-link-hot" : "cloud-link"));
    if (unit(`${d.id}:l${i}-${j}`) < 0.55) { // a packet on its way
      const packet = svgEl("line", { ...at, pathLength: 100 }, hot ? "cloud-packet cloud-packet-hot" : "cloud-packet");
      packet.style.animationDuration = `${(1.4 + unit(`${d.id}:l${i}-${j}:t`) * 2.4).toFixed(1)}s`;
      packet.style.animationDelay = `-${(unit(`${d.id}:l${i}-${j}:d`) * 4).toFixed(1)}s`;
      if (unit(`${d.id}:l${i}-${j}:w`) < 0.5) packet.style.animationDirection = "reverse";
      net.append(packet);
    }
  }
  nodes.forEach((n) => {
    const c = svgEl("circle", { cx: n.x.toFixed(1), cy: n.y.toFixed(1), r: (n.hot ? 3.4 : 2.2 + unit(`${d.id}:n${n.k}:s`) * 1.6).toFixed(1) },
      n.hot ? "cloud-node cloud-node-hot" : "cloud-node");
    c.style.animationDelay = `-${(unit(`${d.id}:n${n.k}:d`) * 5).toFixed(1)}s`;
    net.append(c);
  });
  if (d.hot === "fire") { // a cloud with hosts on fire throws sparks off its top
    const tops = puffs.filter((p) => p.y < 0);
    for (let i = 0; i < CLOUD_SPARKS; i++) {
      const p = tops[i % tops.length], a = (-150 + unit(`${d.id}:fl${i}`) * 120) * Math.PI / 180;
      const c = svgEl("circle", { cx: (p.x + Math.cos(a) * p.r).toFixed(1), cy: (p.y + Math.sin(a) * p.r).toFixed(1), r: (1.4 + unit(`${d.id}:fl${i}:s`) * 1.8).toFixed(1) }, "cloud-spark");
      c.style.animationDuration = `${(1.8 + unit(`${d.id}:fl${i}:t`) * 1.6).toFixed(1)}s`;
      c.style.animationDelay = `-${(unit(`${d.id}:fl${i}:d`) * 3).toFixed(1)}s`;
      net.append(c);
    }
  }
  const count = svgEl("text", { y: Math.round(R * 0.1), "text-anchor": "middle" }, "cloud-n");
  count.style.fontSize = `${Math.round(R * 0.38)}px`;
  count.textContent = Number(d.hosts || 0).toLocaleString();
  const unitText = svgEl("text", { y: Math.round(R * 0.1) + 18, "text-anchor": "middle" }, "cloud-u");
  unitText.textContent = "hosts";
  const base = Math.max(...puffs.map((p) => p.y + p.r)); // the bottom of the heap
  const found = svgEl("text", { y: Math.round(base + 18), "text-anchor": "middle" }, "cloud-f");
  found.textContent = d.findings ? `${d.findings} with findings` : "no findings";
  found.classList.toggle("cloud-calm", !d.findings);
  const hint = svgEl("text", { y: Math.round(base + 33), "text-anchor": "middle" }, "cloud-hint");
  hint.textContent = "double-click to open";
  over.append(net, count, unitText, found, hint);
  return { under, over, fill: "transparent" };
}
function refreshCloud(ui, d) {
  const n = ui.querySelector(".cloud-n");
  if (n) n.textContent = Number(d.hosts || 0).toLocaleString();
  const f = ui.querySelector(".cloud-f");
  if (f) {
    f.textContent = d.findings ? `${d.findings} with findings` : "no findings";
    f.classList.toggle("cloud-calm", !d.findings);
  }
  const t = ui.querySelector("title");
  if (t) t.textContent = [`${d.label}: ${d.hosts} hosts, ${d.findings} with findings. Double-click to open it.`,
    ...(d.parts || []).map((p) => `${p.name}: ${p.hosts} hosts${p.findings ? `, ${p.findings} with findings` : ""}`)].join("\n");
}
const TIER_TIPS = { fire: "hosts on fire", smoke: "hosts in smoke", ice: "hosts on ice", hygiene: "open hygiene findings" };
// What a bubble does: fire flickers and throws sparks, smoke puffs, ice wears a turning ring of frost, hygiene a sweeping scan.
// Placed and timed from its id like a cloud's, and all of it CSS, so reduced motion stops it.
function tierWeather(d, r) {
  const fx = svgEl("g", {}, "tier-fx");
  const timed = (el, key, base, spread) => {
    el.style.animationDuration = `${(base + unit(`${d.id}:${key}:t`) * spread).toFixed(2)}s`;
    el.style.animationDelay = `-${(unit(`${d.id}:${key}:d`) * (base + spread)).toFixed(2)}s`;
    return el;
  };
  if (d.tier === "fire") {
    fx.append(svgEl("circle", { r: r + 7 }, "tier-flare"));
    for (let i = 0; i < 7; i++) {
      const x = (unit(`${d.id}:s${i}`) - 0.5) * r * 1.3;
      fx.append(timed(svgEl("circle", { cx: x.toFixed(1), cy: (-r * 0.55).toFixed(1), r: (1.3 + unit(`${d.id}:s${i}:r`) * 1.6).toFixed(1) }, "tier-spark"), `s${i}`, 1.2, 1.3));
    }
  } else if (d.tier === "smoke") {
    for (let i = 0; i < 3; i++) {
      const x = (unit(`${d.id}:w${i}`) - 0.5) * r;
      fx.append(timed(svgEl("circle", { cx: x.toFixed(1), cy: (-r * 0.6).toFixed(1), r: (r * 0.42).toFixed(1) }, "tier-wisp"), `w${i}`, 3.2, 2));
    }
  } else if (d.tier === "ice") {
    fx.append(svgEl("circle", { r: r + 6 }, "tier-frost"), svgEl("circle", { r: r + 11 }, "tier-frost tier-frost-2"));
  } else if (d.tier === "hygiene") {
    const sweep = svgEl("circle", { r: r + 6 }, "tier-sweep");
    sweep.setAttribute("stroke-dasharray", `${(2 * Math.PI * (r + 6) * 0.22).toFixed(1)} ${(2 * Math.PI * (r + 6)).toFixed(1)}`);
    fx.append(sweep);
  }
  return fx;
}
function refreshTier(ui, d) {
  const n = ui.querySelector(".tier-n");
  if (n) n.textContent = Number(d.count || 0).toLocaleString();
  const r = tierRadius(d);
  ui.querySelector("circle:not(.ring)")?.setAttribute("r", r);
  ui.querySelector(".ring")?.setAttribute("r", r + 5);
  const label = ui.querySelector("text");
  label?.setAttribute("x", 0);
  label?.setAttribute("y", r + 16);
  label?.setAttribute("text-anchor", "middle");
  ui.querySelector(".tier-fx")?.remove();
  ui.querySelector(".tier-body")?.before(tierWeather(d, r));
  const t = ui.querySelector("title");
  if (t) t.textContent = `${d.project_name}: ${d.count} ${TIER_TIPS[d.tier]}. Click for the list, double-click to open the project.`;
}
const arc = (r, len, offset, color) => {
  const c = document.createElementNS(NS, "circle");
  const circumference = 2 * Math.PI * r;
  c.setAttribute("r", r);
  c.setAttribute("fill", "none");
  c.setAttribute("stroke", color);
  c.setAttribute("stroke-width", "4.5");
  c.setAttribute("stroke-dasharray", `${Math.max(0, len * circumference - 1.2)} ${circumference}`);
  c.setAttribute("stroke-dashoffset", String(-offset * circumference));
  c.setAttribute("transform", "rotate(-90)");
  return c;
};
// (Re)build the ring and the count of a host's bubble; safe to call again when the pod changes.
function decoratePod(g, d, r) {
  g.querySelector(".pod")?.remove();
  g.classList.toggle("has-pod", Boolean(d.pod && d.pod.total));
  if (!d.pod || !d.pod.total) return;
  const pod = document.createElementNS(NS, "g");
  pod.setAttribute("class", "pod");
  const track = document.createElementNS(NS, "circle");
  track.setAttribute("r", r + 4);
  track.setAttribute("fill", "none");
  track.setAttribute("stroke", css("--line-2"));
  track.setAttribute("stroke-width", "4.5");
  track.setAttribute("stroke-opacity", "0.55");
  pod.append(track);
  let offset = 0;
  TIER_KEYS.forEach((tier) => {
    if (!d.pod[tier]) return;
    const share = d.pod[tier] / d.pod.total;
    pod.append(arc(r + 4, share, offset, CVE_COLORS[tier]));
    offset += share;
  });
  if (r >= 16) {
    const n = document.createElementNS(NS, "text");
    n.setAttribute("class", "pod-n");
    n.setAttribute("text-anchor", "middle");
    n.setAttribute("dy", "0.35em");
    n.style.fontSize = `${Math.min(15, Math.max(10, r * 0.62))}px`;
    n.textContent = String(d.pod.total);
    pod.append(n);
  }
  g.append(pod);
}
function refreshHost(ui, d) {
  const r = hostRadius(d);
  const dot = ui.querySelector("circle:not(.ring):not(.pod circle)");
  if (dot) dot.setAttribute("r", r);
  const ring = ui.querySelector(".ring");
  if (ring) ring.setAttribute("r", r + (d.pod && d.pod.total ? 9 : 5));
  const text = ui.querySelector("text:not(.pod-n)");
  if (text) text.setAttribute("x", r + (d.pod && d.pod.total ? 8 : 4));
  const title = ui.querySelector("title");
  if (title) title.textContent = d.pod && d.pod.total ? `${d.label}\n${d.pod.total} CVE${d.pod.total === 1 ? "" : "s"} (${d.pod.fire} fire, ${d.pod.smoke} smoke, ${d.pod.ice} ice). Double-click to ${d.expanded ? "fold them back" : "open the pod"}.` : d.label;
  decoratePod(ui, d, r);
  decorateMoons(ui, d, r);
}

export function mountGraph(container, { onSelect, pinKey, pods: podsOn = true } = {}) {
  const graph = Viva.Graph.graph();
  let clustered = false;
  let pods = podsOn;
  const expanded = new Set(); // hosts whose pod is open
  let lastData = null;
  const layout = Viva.Graph.Layout.forceDirected(graph, {
    springLength: 80,
    springCoeff: 0.0008,
    gravity: -2.6,
    dragCoeff: 0.12, // more damping: with a few hundred nodes the old 0.05 never stopped jittering
    // leaves that share an IP get extra room, and a hub's links are long, so clusters fan out instead of stacking
    springTransform(link, spring) {
      if (link.fromId.startsWith('__project:')) { spring.length = 190; return; }
      if (link.fromId.startsWith('__cloud:')) { spring.length = CLOUD_R + 70; return; }
      if (link.fromId.startsWith('__root:')) { spring.length = 105; return; }
      if (link.data?.crossCluster) { spring.length = 550; return; }
      const ip = graph.getNode(link.toId);
      const shared = ip && ip.data && ip.data.kind === "ip" ? Math.min((ip.links || []).length, 14) : 0;
      spring.length = link.fromId === "__hub" ? 140 : 80 + shared * 5;
    },
  });
  const graphics = Viva.Graph.View.svgGraphics();
  // Use the room: a force layout comes out roughly round but these cards are wide, so what is drawn is stretched along the short side
  // (per axis, at draw time; the layout and the saved positions stay in their own round coordinates). fit() sets it.
  const spread = { x: 1, y: 1 };
  let selected = null; // the node whose card is open
  const group = new Set(); // ids of the nodes in the multi-selection
  let hovered = null;
  const uis = new Map();
  const pins = readPins(pinKey ? pinKey() : "");

  const ringOf = (id) => {
    const ui = uis.get(id);
    return ui && ui.querySelector(".ring");
  };
  const mark = (id, on) => {
    const ui = uis.get(id);
    if (ui) ui.classList.toggle("sel", on);
  };
  const markGroup = (id, on) => {
    const ring = ringOf(id);
    if (ring) showSvg(ring, on);
  };
  function clearGroup() {
    group.forEach((id) => markGroup(id, false));
    group.clear();
  }
  function addToGroup(ids) {
    ids.forEach((id) => {
      group.add(id);
      markGroup(id, true);
    });
  }
  function select(node) {
    if (selected) mark(selected, false);
    selected = node ? node.id : null;
    if (node) mark(node.id, true);
    if (onSelect) onSelect(node ? node.data : null);
  }
  const savePins = () => writePins(pinKey ? pinKey() : "", pins);
  function pin(id, x, y) {
    const node = graph.getNode(id);
    if (!node) return;
    layout.setNodePosition(id, x, y);
    layout.pinNode(node, true);
    pins[id] = [Math.round(x), Math.round(y)];
  }
  function unpin(id) {
    const node = graph.getNode(id);
    if (node) layout.pinNode(node, false);
    delete pins[id];
    savePins();
  }
  const neighbourhood = (node) => {
    const ids = [node.id];
    graph.forEachLinkedNode(node.id, (other) => {
      if (other.id !== "__hub") ids.push(other.id);
    });
    return ids;
  };

  // Live scan highlighting (SOC mode and the plain page alike): the domains and hosts a scan is working on right now carry a
  // pulsing ring. Domains are matched by id, hosts by lower-cased name, so it holds in the clustered view too.
  const active = { domains: new Set(), hosts: new Set(), labels: new Set() };
  const isActive = (node) => {
    const d = node.data || {};
    if (d.kind === "domain") return active.domains.has(String(d.detail_id || node.id).replace(/^dom:/, ""));
    if (d.kind === "subdomain" && active.hosts.has(String(d.label || "").toLowerCase())) return true;
    // an address or name a running job names (for example "Background full port scan of 198.51.100.34")
    return active.labels.size > 0 && ["ip", "subdomain", "domain"].includes(d.kind) && active.labels.has(String(d.label || "").toLowerCase());
  };
  function applyActive() {
    let any = false;
    graph.forEachNode((n) => {
      const ui = uis.get(n.id);
      if (!ui || (n.data && n.data.kind === "hub")) return;
      const on = isActive(n);
      any = any || on;
      ui.classList.toggle("gn-live", on);
    });
    container.classList.toggle("has-live", any);
  }

  // Float. Every bubble drifts a few pixels on slow, unequal cycles, so the graph feels like it hangs in space. The drift is drawn on top of
  // the layout (the layout, the fit and the saved positions never see it), it is a fixed few pixels on screen at any zoom, and the bubble
  // under the pointer or in the open card holds still. It is bounded, so nothing can float out of view.
  const FLOAT_PX = 5;
  const floatOn = !(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  let zoomK = 1;
  const readZoom = () => {
    const root = container.querySelector("svg > g");
    const m = root && /matrix\(([^)]+)\)/.exec(root.getAttribute("transform") || "");
    zoomK = Math.max(Number(m ? m[1].split(/[ ,]+/)[0] : 1) || 1, 0.02);
  };
  const zoomTimer = setInterval(() => {
    if (!document.hidden) readZoom();
  }, 250);
  const driftOf = (ui, id) => {
    if (!floatOn || id === hovered || id === selected || group.has(id)) return [0, 0];
    if (ui.__p === undefined) ui.__p = [stableAngle(id), stableAngle(`${id}~`), 0.8 + (stableAngle(`${id}#`) / 6.283) * 0.5];
    const [p1, p2, f] = ui.__p;
    const t = performance.now() * 0.001 * f;
    const a = FLOAT_PX / zoomK / 1.5;
    return [a * (Math.sin(t * 0.45 + p1) + 0.5 * Math.sin(t * 0.91 + p2)), a * (Math.cos(t * 0.38 + p2) + 0.5 * Math.sin(t * 0.83 + p1))];
  };
  const nodePoint = (id) => {
    const p = layout.getNodePosition(id);
    const ui = uis.get(id);
    if (!p || !ui) return null;
    const [dx, dy] = driftOf(ui, id);
    return { x: p.x * spread.x + dx, y: p.y * spread.y + dy };
  };
  function placeNodeUi(ui, pos) {
    const id = ui.__gid;
    const [dx, dy] = id === undefined ? [0, 0] : driftOf(ui, id);
    ui.setAttribute("transform", `translate(${pos.x * spread.x + dx},${pos.y * spread.y + dy})`);
  }
  function placeLinkUi(ui, from, to) {
    const a = ui.__from !== undefined && uis.get(ui.__from);
    const b = ui.__to !== undefined && uis.get(ui.__to);
    const [ax, ay] = a ? driftOf(a, ui.__from) : [0, 0];
    const [bx, by] = b ? driftOf(b, ui.__to) : [0, 0];
    ui.setAttribute("x1", from.x * spread.x + ax);
    ui.setAttribute("y1", from.y * spread.y + ay);
    ui.setAttribute("x2", to.x * spread.x + bx);
    ui.setAttribute("y2", to.y * spread.y + by);
  }
  // While the layout rests (the renderer is paused) nothing repaints, so the drift repaints by itself, about 30 times a second, and only
  // while the graph is on screen. While the layout runs the renderer repaints every frame and applies the drift itself.
  const linkUis = new Map();
  let floatRaf = 0;
  let floatLast = 0;
  let onScreen = true;
  function floatFrame(now) {
    floatRaf = 0;
    if (!resting || !floatOn || !onScreen || document.hidden) return;
    if (now - floatLast >= 33) {
      floatLast = now;
      graph.forEachNode((n) => {
        const ui = uis.get(n.id);
        const pt = ui && n.data && n.data.kind !== "hub" ? nodePoint(n.id) : null;
        if (pt) ui.setAttribute("transform", `translate(${pt.x},${pt.y})`);
      });
      graph.forEachLink((l) => {
        const ui = linkUis.get(l.id);
        const a = nodePoint(l.fromId);
        const b = nodePoint(l.toId);
        if (!ui || !a || !b) return;
        ui.setAttribute("x1", a.x);
        ui.setAttribute("y1", a.y);
        ui.setAttribute("x2", b.x);
        ui.setAttribute("y2", b.y);
      });
    }
    floatRaf = requestAnimationFrame(floatFrame);
  }
  const startFloat = () => {
    if (!floatRaf && floatOn) floatRaf = requestAnimationFrame(floatFrame);
  };
  new IntersectionObserver((entries) => {
    onScreen = entries.some((e) => e.isIntersecting);
    if (onScreen) startFloat();
  }).observe(container);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) startFloat();
  });

  graphics
    .node((node) => {
      const d = node.data || {};
      const g = document.createElementNS(NS, "g");
      if (d.kind === "hub") {
        g.setAttribute("display", "none");
        uis.set(node.id, g);
        return g;
      }
      g.setAttribute("class", `gn gn-${d.kind}${isActive(node) ? " gn-live" : ""}`);
      g.setAttribute("role", "button");
      g.setAttribute("tabindex", "0");
      g.dataset.heat = d.heat || d.tier || "";
      if (d.kind === "cloud") g.dataset.hot = d.hot || "calm";
      if (d.kind === "cloud" || d.kind === "tier") { // they arrive one cloud at a time, biggest first, each followed by its bubbles
        g.style.setProperty("--i", d.order || 0);
        g.style.setProperty("--j", d.slot || 0);
      }
      g.dataset.k = d.kind;
      g.style.touchAction = "none";
      g.setAttribute(
        "aria-label",
        d.kind === "subdomain"
          ? `${d.label}, ${d.status || "unscanned"}`
          : `${d.kind} ${d.label}`,
      );
      const r = d.kind === "cloud" ? cloudRadius(d) : d.kind === "tier" ? tierRadius(d) : d.kind === "subdomain" ? hostRadius(d) : SIZES[d.kind] || 6;
      const ring = document.createElementNS(NS, "circle");
      ring.setAttribute("class", "ring");
      ring.setAttribute("r", r + 5);
      ring.setAttribute("fill", "none");
      ring.setAttribute("display", "none");
      const c = document.createElementNS(NS, "circle");
      c.setAttribute("r", r);
      if (d.kind === "subdomain") {
        styleHost(c, d);
      } else if (d.kind === "cloud") {
        c.setAttribute("class", "cloud-body");
      } else if (d.kind === "tier") {
        c.setAttribute("class", "tier-body");
      } else if (d.kind === "project" || d.kind === "root") {
        c.setAttribute("fill", d.kind === "project" ? css("--graph-project-bg") : css("--graph-node-bg"));
        c.setAttribute("stroke", css("--graph-node-border"));
        c.setAttribute("stroke-width", d.kind === "project" ? "3" : "2");
      } else if (d.kind === "domain") {
        // the target itself: a heavy ring rather than a solid black disc, so it never reads as a host that is scanned
        c.setAttribute("fill", css("--surface"));
        c.setAttribute("stroke", css("--ink"));
        c.setAttribute("stroke-width", "3");
      } else {
        c.setAttribute("fill", colorOf(d));
      }
      const t = document.createElementNS(NS, "text");
      const above = ['project', 'root', 'cloud'].includes(d.kind);
      t.setAttribute("x", above ? 0 : r + 4);
      t.setAttribute("y", d.kind === "cloud" ? -Math.round(r * 0.88 + 12) : above ? -(r + 8) : 3.5); // a cloud's name sits on its top
      if (above) t.setAttribute('text-anchor', 'middle');
      t.textContent = shorten(shortLabel(d));
      const title = document.createElementNS(NS, "title");
      title.textContent = d.label;
      g.append(ring, c, t, title);
      if (d.kind === "cloud") { // the name label stays the group's first text: relabel() finds it there
        const art = cloudArt(d);
        c.setAttribute("fill", art.fill);
        g.insertBefore(art.under, c);
        g.append(art.over);
        refreshCloud(g, d);
      }
      if (d.kind === "tier") { // its count sits inside it; the name label stays the group's first text
        g.append(svgEl("text", { y: 4, "text-anchor": "middle" }, "tier-n"));
        refreshTier(g, d);
      }
      if (d.kind === "subdomain" && d.internal) {
        // a host inside a network its project declared internal (only a Sentinel there scans it): a dashed outer boundary marks it
        const boundary = document.createElementNS(NS, "circle");
        boundary.setAttribute("class", "boundary");
        boundary.setAttribute("r", r + 9);
        boundary.setAttribute("fill", "none");
        g.insertBefore(boundary, ring);
        g.classList.add("gn-internal");
        title.textContent = `${d.label} (internal${d.network ? `, ${d.network}` : ""})`;
        g.setAttribute("aria-label", `${g.getAttribute("aria-label")}, internal${d.network ? ` network ${d.network}` : ""}`);
      }
      if (d.kind === "subdomain") refreshHost(g, d);
      attachPointer(g, node);
      g.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          select(node);
        }
      });
      g.addEventListener("mouseenter", () => {
        hovered = node.id;
        relabel();
      });
      g.addEventListener("mouseleave", () => {
        hovered = null;
        relabel();
      });
      g.addEventListener("dblclick", (e) => {
        e.stopPropagation();
        if (d.kind === "cloud" || d.kind === "tier") {
          dive(`__cloud:${d.project}`, d.project);
          return;
        }
        unpin(node.id);
        if (node.data && node.data.pod && node.data.pod.total) {
          if (expanded.has(node.id)) expanded.delete(node.id);
          else expanded.add(node.id);
          resync();
        }
      });
      g.__gid = node.id;
      uis.set(node.id, g);
      return g;
    })
    .placeNode((ui, pos) => placeNodeUi(ui, pos))
    .placeLink((ui, from, to) => placeLinkUi(ui, from, to));
  graphics.link((link) => {
    const l = Viva.Graph.svg("line");
    if (link.fromId === "__hub") l.setAttribute("visibility", "hidden");
    l.setAttribute("stroke", link.fromId.startsWith('__project:') || link.fromId.startsWith('__root:') ? css('--graph-link-hi') : css('--line-2'));
    l.setAttribute("stroke-width", link.fromId.startsWith('__project:') ? '1.8' : '1');
    if (link.data?.crossCluster) l.setAttribute('stroke-dasharray', '4 4');
    if (link.toId.startsWith('__tier:')) { // a bubble hangs off its cloud on a tether that flows with its colour
      const tier = graph.getNode(link.toId)?.data || {};
      l.setAttribute('class', 'gl-tether');
      l.dataset.heat = tier.tier || '';
      l.style.setProperty('--i', tier.order || 0);
      l.style.setProperty('--j', tier.slot || 0);
    }
    l.__from = link.fromId;
    l.__to = link.toId;
    linkUis.set(link.id, l);
    return l;
  });

  // Our own pointer handling on a node, instead of a plain click: the force layout keeps moving the node under the pointer, so
  // the browser often never fires "click" (the press and the release land on different elements). A press that barely moves
  // is the click; a press that moves drags the node (and the whole selection, when it is in one), and pins it where it is dropped.
  let renderer = null;
  // The svg renderer keeps the pan and zoom in one matrix(k,0,0,k,tx,ty) on its root group; undo it to get graph coordinates.
  function clientToGraph(cx, cy) {
    const svg = container.querySelector("svg");
    const root = svg && svg.querySelector("g");
    const m = root && /matrix\(([^)]+)\)/.exec(root.getAttribute("transform") || "");
    const [k, , , , tx, ty] = m ? m[1].split(/[ ,]+/).map(Number) : [1, 0, 0, 1, 0, 0];
    const box = svg.getBoundingClientRect();
    return { x: (cx - box.left - tx) / k / spread.x, y: (cy - box.top - ty) / k / spread.y };
  }
  function attachPointer(g, node) {
    const stopViva = (e) => e.stopPropagation(); // the renderer pans the canvas on mousedown/touchstart; a node press is not a pan
    g.addEventListener("mousedown", stopViva);
    g.addEventListener("touchstart", stopViva, { passive: true });
    g.addEventListener("pointerdown", (e) => {
      if (e.button != null && e.button !== 0) return;
      e.stopPropagation();
      auto = false; // the user is working with the graph: stop refitting it under their pointer
      const start = { x: e.clientX, y: e.clientY };
      let dragging = false;
      let held = false;
      let moved = [];
      const timer = setTimeout(() => {
        if (!dragging) {
          held = true; // a long press selects the node and everything one hop from it
          clearGroup();
          addToGroup(neighbourhood(node));
          select(node);
        }
      }, 550);
      try {
        g.setPointerCapture(e.pointerId);
      } catch (_) {
        /* capture is best effort */
      }
      const toGraph = (ev) => clientToGraph(ev.clientX, ev.clientY);
      const origin = toGraph(e);
      const move = (ev) => {
        if (!dragging && Math.hypot(ev.clientX - start.x, ev.clientY - start.y) < DRAG_PX) return;
        if (!dragging) {
          dragging = true;
          clearTimeout(timer);
          const ids = group.has(node.id) ? [...group] : [node.id];
          moved = ids.map((id) => ({ id, from: layout.getNodePosition(id) })).filter((m) => m.from);
          moved.forEach((m) => (m.from = { x: m.from.x, y: m.from.y }));
        }
        const now = toGraph(ev);
        moved.forEach((m) => pin(m.id, m.from.x + now.x - origin.x, m.from.y + now.y - origin.y));
        if (renderer) renderer.rerender();
      };
      const up = (ev) => {
        clearTimeout(timer);
        g.removeEventListener("pointermove", move);
        g.removeEventListener("pointerup", up);
        g.removeEventListener("pointercancel", up);
        try {
          g.releasePointerCapture(ev.pointerId);
        } catch (_) {
          /* already released */
        }
        if (dragging) {
          savePins();
          justDragged = true;
          setTimeout(() => (justDragged = false), 0);
        } else if (!held) {
          if (ev.altKey) {
            clearGroup();
            addToGroup(neighbourhood(node));
          }
          select(node);
        }
        ev.stopPropagation();
      };
      g.addEventListener("pointermove", move);
      g.addEventListener("pointerup", up);
      g.addEventListener("pointercancel", up);
    });
    g.addEventListener("click", (e) => e.stopPropagation());
  }
  let justDragged = false;

  // Shift-drag a rectangle on empty canvas to select several nodes (desktop). Registered before the renderer so it sees
  // the press first and keeps the canvas from panning.
  const band = document.createElement("div");
  band.className = "graph-band";
  band.hidden = true;
  container.style.position = container.style.position || "relative";
  container.append(band);
  container.addEventListener(
    "mousedown",
    (e) => {
      if (!e.shiftKey || e.button !== 0) return;
      e.stopImmediatePropagation();
      e.preventDefault();
      const box = container.getBoundingClientRect();
      const x0 = e.clientX - box.left;
      const y0 = e.clientY - box.top;
      const rect = (ev) => {
        const x = ev.clientX - box.left;
        const y = ev.clientY - box.top;
        return { l: Math.min(x, x0), t: Math.min(y, y0), r: Math.max(x, x0), b: Math.max(y, y0) };
      };
      const draw = (ev) => {
        const q = rect(ev);
        band.hidden = false;
        Object.assign(band.style, { left: `${q.l}px`, top: `${q.t}px`, width: `${q.r - q.l}px`, height: `${q.b - q.t}px` });
      };
      const finish = (ev) => {
        document.removeEventListener("mousemove", draw);
        document.removeEventListener("mouseup", finish);
        band.hidden = true;
        const q = rect(ev);
        justDragged = true;
        setTimeout(() => (justDragged = false), 0);
        if (!ev.shiftKey && !(q.r - q.l > 3)) return;
        const ids = [];
        graph.forEachNode((n) => {
          const ui = uis.get(n.id);
          if (!ui || (n.data && n.data.kind === "hub")) return;
          const p = ui.getBoundingClientRect();
          const cx = p.left + p.width / 2 - box.left;
          const cy = p.top + p.height / 2 - box.top;
          if (cx >= q.l && cx <= q.r && cy >= q.t && cy <= q.b) ids.push(n.id);
        });
        addToGroup(ids);
      };
      document.addEventListener("mousemove", draw);
      document.addEventListener("mouseup", finish);
    },
    true,
  );

  // Mouse-wheel zoom, around the pointer. VivaGraph's own wheel zoom does not fire in Chromium browsers (Edge, Chrome), so the
  // graph handles the wheel itself in every browser. It is registered before the renderer so it runs first and keeps Viva's own
  // handler from zooming a second time (Firefox). The page does not scroll while the pointer is over the graph.
  const MIN_ZOOM = 0.04;
  const MAX_ZOOM = 6;
  container.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      e.stopImmediatePropagation();
      const svg = container.querySelector("svg");
      const root = svg && svg.querySelector("g");
      const m = root && /matrix\(([^)]+)\)/.exec(root.getAttribute("transform") || "");
      const k = m ? Number(m[1].split(/[ ,]+/)[0]) || 1 : 1;
      const lines = e.deltaMode === 1 ? 0.05 : e.deltaMode === 2 ? 1 : 0.0015;
      const factor = Math.min(Math.max(Math.exp(-e.deltaY * lines), 0.5), 2);
      const next = Math.min(Math.max(k * factor, MIN_ZOOM), MAX_ZOOM);
      if (next === k) return;
      const box = container.getBoundingClientRect();
      graphics.scale(next / k, { x: e.clientX - box.left, y: e.clientY - box.top });
      auto = false; // the user is in control of the view now (the Fit button or a double-click hands it back)
    },
    { passive: false },
  );
  renderer = Viva.Graph.View.renderer(graph, {
    container,
    graphics,
    layout,
  });
  renderer.run();

  // Let the layout rest. A force layout with hundreds of nodes keeps a small jitter forever; once the nodes have barely moved for a
  // moment (or ten seconds have passed since the graph last changed) the animation is paused, and any change to the graph, or a
  // press on the canvas, wakes it again.
  let lastChange = Date.now();
  let resting = false;
  const wake = () => {
    lastChange = Date.now();
    if (resting) {
      resting = false;
      renderer.resume();
    }
  };
  graph.on("changed", wake);
  container.addEventListener("pointerdown", wake);
  const lastPos = new Map();
  const settleTimer = setInterval(() => {
    if (resting || document.hidden) return;
    let moved = 0;
    let counted = 0;
    graph.forEachNode((node) => {
      const p = layout.getNodePosition(node.id);
      const q = lastPos.get(node.id);
      if (q) {
        moved += Math.hypot(p.x - q.x, p.y - q.y);
        counted += 1;
      }
      lastPos.set(node.id, { x: p.x, y: p.y });
    });
    const quiet = Date.now() - lastChange;
    const still = counted > 0 && moved / counted < 1.2;
    if ((still && quiet > 2500) || quiet > 10000) {
      renderer.pause();
      resting = true;
      startFloat();
    }
  }, 500);
  container.addEventListener("click", () => {
    if (justDragged) return;
    clearGroup();
    select(null);
  });
  const onKey = (e) => {
    if (e.key === "Escape") {
      if (focus && !selected && !group.size) surface();
      clearGroup();
      select(null);
    }
  };
  document.addEventListener("keydown", onKey);

  // Labels: only the leftmost part of a name, and only where there is room. Hubs (targets and IPs with several hosts), the
  // hovered node and the selection are always labelled; every other label is drawn only if no label already took its
  // 120 x 14 px cell this pass, and not at all when zoomed far out.
  const scaleNow = () => {
    const root = container.querySelector("svg > g");
    const m = root && /matrix\(([-\d.e]+)/.exec(root.getAttribute("transform") || "");
    return m ? Number(m[1]) : 1;
  };
  const isHub = (n) => {
    const d = n.data || {};
    return ['project', 'root', 'domain', 'cloud', 'tier'].includes(d.kind) ||
      (d.kind === "ip" && (n.links || []).filter((l) => l.fromId !== "__hub").length >= HUB_LINKS);
  };
  function relabel() {
    const box = container.getBoundingClientRect();
    const scale = scaleNow();
    const zoomedOut = scale < MIN_LABEL_SCALE;
    const items = [];
    graph.forEachNode((n) => {
      const ui = uis.get(n.id);
      if (!ui || (n.data && n.data.kind === "hub")) return;
      const p = ui.getBoundingClientRect();
      const kind = n.data?.kind;
      const rank = n.id === hovered || n.id === selected ? 0 :
        clustered && ['project', 'cloud'].includes(kind) ? 1 : clustered && kind === 'root' ? 2 :
        isHub(n) ? 3 : 4;
      items.push({ n, ui, rank, picked: group.has(n.id), x: p.left - box.left, y: p.top - box.top });
    });
    items.sort((a, b) => a.rank - b.rank);
    const taken = new Set();
    items.forEach(({ n, ui, rank, picked, x, y }) => {
      const text = ui.querySelector("text");
      if (!text) return;
      if (clustered && ['project', 'root'].includes(n.data?.kind)) {
        const project = n.data.kind === 'project';
        const radius = Math.max(SIZES[n.data.kind], (project ? 13 : 10) / Math.max(scale, 0.05));
        ui.querySelector('circle:not(.ring)')?.setAttribute('r', radius);
        ui.querySelector('.ring')?.setAttribute('r', radius + 6);
        text.style.fontSize = `${Math.max(project ? 22 : 17, (project ? 14 : 12) / Math.max(scale, 0.05))}px`;
        if (project && box.width < 600) {
          text.setAttribute('text-anchor', 'start');
          text.setAttribute('x', radius + 8 / Math.max(scale, 0.05));
          text.setAttribute('y', 4 / Math.max(scale, 0.05));
        } else {
          text.setAttribute('text-anchor', 'middle');
          text.setAttribute('x', 0);
          text.setAttribute('y', -(radius + 12 / Math.max(scale, 0.05)));
        }
      }
      showSvg(text, true);
      const label = text.getBoundingClientRect();
      const left = Math.floor((label.left - box.left) / CELL_W);
      const right = Math.floor((label.right - box.left) / CELL_W);
      const top = Math.floor((label.top - box.top) / CELL_H);
      const bottom = Math.floor((label.bottom - box.top) / CELL_H);
      const cells = [];
      for (let cx = left; cx <= right; cx++) for (let cy = top; cy <= bottom; cy++) cells.push(`${cx}:${cy}`);
      const free = cells.every(cell => !taken.has(cell));
      const kind = n.data?.kind;
      const live = ui.classList.contains("gn-live");
      const show = live || (clustered ?
        rank === 0 || (['project', 'cloud'].includes(kind) && free) ||
        (kind === 'root' && scale >= 0.16 && free) ||
        ((!zoomedOut || picked) && rank >= 3 && free) :
        rank === 0 || rank === 3 || ((!zoomedOut || picked) && free));
      if (show) cells.forEach(cell => taken.add(cell));
      showSvg(text, show);
    });
  }
  // Labels are laid out from the bubbles' on-screen boxes, which forces a layout of every node: skip it in a hidden tab, and while the
  // layout rests unless the view (pan, zoom), the selection, the picked group or the node count changed since the last pass.
  let labelSig = "";
  const labelTimer = setInterval(() => {
    if (document.hidden) return;
    const root = container.querySelector("svg > g");
    const sig = [root && root.getAttribute("transform"), selected, group.size, clustered, graph.getNodesCount()].join("|");
    if (resting && sig === labelSig) return;
    labelSig = sig;
    relabel();
  }, 500);

  // Keep the whole graph in view: refit as the layout settles and nodes arrive, until the user pans,
  // zooms or drags (then they are in control; the Fit button or double-click hands it back).
  let auto = true;
  let lastBox = "";
  function fit() {
    if (!graph.getNodesCount()) return;
    let x1 = Infinity,
      y1 = Infinity,
      x2 = -Infinity,
      y2 = -Infinity;
    graph.forEachNode((n) => {
      if (clustered && !['project', 'root'].includes(n.data?.kind)) return;
      const p = layout.getNodePosition(n.id);
      x1 = Math.min(x1, p.x);
      y1 = Math.min(y1, p.y);
      x2 = Math.max(x2, p.x);
      y2 = Math.max(y2, p.y);
    });
    if (!Number.isFinite(x1)) return;
    const w = container.clientWidth,
      h = container.clientHeight;
    if (!w || !h) return;
    // fit by screen margin instead of a fixed padding in graph units, so the picture uses the room it is given; a clustered
    // graph also needs space for each root's host bubbles and labels around it
    const margin = 26;
    const room = clustered ? 260 : 14; // graph units around the outermost node centers (node radius, label)
    // spread the short side so the picture matches the card's shape (a little rounder than the card, for the labels). The padding
    // around the outermost nodes does not stretch, so it is solved for: (bw*sx + 2*room) / (bh*sy + 2*room) = the wanted ratio.
    const bw0 = Math.max(x2 - x1, 1);
    const bh0 = Math.max(y2 - y1, 1);
    const want = Math.max((w - margin * 2) / Math.max(h - margin * 2, 1), 0.2) * 0.9;
    let sx = 1;
    let sy = 1;
    if (!clustered && graph.getNodesCount() >= 4) {
      if ((bw0 + room * 2) / (bh0 + room * 2) < want) sx = Math.min(Math.max((want * (bh0 + room * 2) - room * 2) / bw0, 1), 4);
      else sy = Math.min(Math.max(((bw0 + room * 2) / want - room * 2) / bh0, 1), 4);
    }
    if (Math.abs(sx - spread.x) > 0.04 || Math.abs(sy - spread.y) > 0.04) {
      spread.x = sx;
      spread.y = sy;
      renderer.rerender();
    }
    const bw = bw0 * spread.x + room * 2,
      bh = bh0 * spread.y + room * 2;
    const k = Math.min((w - margin * 2) / bw, (h - margin * 2) / bh, clustered ? 1.8 : 3);
    const key = [x1, y1, x2, y2, w, h, spread.x, spread.y].map((v) => Math.round(v / 6)).join();
    if (key === lastBox) return;
    lastBox = key;
    graphics.resetScale();
    renderer.moveTo(((x1 + x2) / 2) * spread.x, ((y1 + y2) / 2) * spread.y);
    graphics.scale(k, { x: w / 2, y: h / 2 });
  }
  const stop = () => {
    auto = false;
  };
  ["wheel", "pointerdown"].forEach((ev) =>
    container.addEventListener(ev, stop, { passive: true }),
  );
  container.addEventListener("dblclick", () => {
    auto = true;
    lastBox = "";
    fit();
  });
  const timer = setInterval(() => {
    if (auto && !document.hidden) fit();
  }, 700);

  function resync() {
    if (lastData) api.sync(lastData);
    wake();
  }

  // Diving into a cloud. Double-clicking a cloud bursts its bubbles and zooms into that one project, drawn host by host with its hosts
  // flying out from the middle; a bar on top names it and leads back (so does Escape). Polls keep the dive until the user leaves it.
  let focus = null; // the project slug of the open cloud
  let burst = false; // the next sync seeds new nodes at the center, so the exploded view grows out of where the cloud was
  const bar = document.createElement("div");
  bar.className = "graph-focus";
  bar.hidden = true;
  const back = Object.assign(document.createElement("button"), { type: "button", className: "btn sm graph-focus-back", textContent: "← All projects" });
  const where = Object.assign(document.createElement("span"), { className: "graph-focus-name" });
  bar.append(back, where);
  ["pointerdown", "click", "dblclick", "wheel"].forEach((ev) => bar.addEventListener(ev, (e) => e.stopPropagation(), { passive: ev === "wheel" }));
  back.addEventListener("click", () => surface());
  container.append(bar);
  const onOpenCloud = (e) => api.focus(e.detail); // the cloud's card has an Open button (a double-click is awkward on a phone)
  document.addEventListener("cve:open-cloud", onOpenCloud);
  function reset() {
    graph.clear();
    uis.clear();
    group.clear();
    selected = null;
    if (onSelect) onSelect(null);
    auto = true;
    lastBox = "";
    spread.x = spread.y = 1;
  }
  function transition(cls, then) {
    if (!floatOn) return then();
    container.classList.add(cls);
    setTimeout(() => {
      container.classList.remove(cls);
      then();
      container.classList.add(`${cls}-in`);
      setTimeout(() => container.classList.remove(`${cls}-in`), 520);
    }, 420);
  }
  function dive(cloudId, slug) {
    if (focus) return;
    const cloud = graph.getNode(cloudId);
    const d = (cloud && cloud.data) || {};
    uis.get(cloudId)?.classList.add("cloud-opening");
    if (cloud) { // zoom toward the cloud while it opens
      const p = layout.getNodePosition(cloudId);
      auto = false;
      renderer.moveTo(p.x * spread.x, p.y * spread.y);
    }
    transition("graph-diving", () => {
      focus = slug;
      burst = true;
      where.textContent = `${d.label || slug} · ${Number(d.hosts || 0).toLocaleString()} hosts${d.findings ? ` · ${d.findings} with findings` : ""}`;
      bar.hidden = false;
      container.classList.add("graph-focused");
      reset();
      resync();
    });
  }
  function surface() {
    if (!focus) return;
    transition("graph-surfacing", () => {
      focus = null;
      bar.hidden = true;
      container.classList.remove("graph-focused");
      reset();
      resync();
    });
  }

  const api = {
    setClustered(value) { clustered = Boolean(value); },
    deselect() {
      clearGroup();
      select(null);
    },
    // fold every host's CVEs into its bubble (the default), or draw each CVE as its own dot
    setPods(on) {
      pods = Boolean(on);
      expanded.clear();
      resync();
    },
    hasPods() { return pods; },
    // the domain ids and host names a scan is working on now; call again with what is true next poll
    setActive(domains = [], hosts = [], labels = []) {
      active.domains = new Set(domains.map(String));
      active.hosts = new Set(hosts.map((h) => String(h).toLowerCase()));
      active.labels = new Set(labels.map((l) => String(l).toLowerCase()));
      applyActive();
    },
    // whether a node with this name or address is on the graph (the "scanning now" chips only list what can be shown)
    hasLabel(label) {
      const want = String(label || "").toLowerCase();
      let found = false;
      graph.forEachNode((n) => {
        if (!found && String((n.data && n.data.label) || "").toLowerCase() === want) found = true;
      });
      return found;
    },
    // Pan and zoom to a node by its name or address (the "scanning now" chips use it); returns whether it was found.
    locate(label) {
      const want = String(label || "").toLowerCase();
      let found = null;
      graph.forEachNode((n) => {
        if (!found && String((n.data && n.data.label) || "").toLowerCase() === want) found = n;
      });
      if (!found) return false;
      const p = layout.getNodePosition(found.id);
      const w = container.clientWidth;
      const h = container.clientHeight;
      auto = false;
      graphics.resetScale();
      renderer.moveTo(p.x * spread.x, p.y * spread.y);
      graphics.scale(1.4, { x: w / 2, y: h / 2 });
      return true;
    },
    fit() {
      auto = true;
      lastBox = "";
      fit();
    },
    destroy() {
      clearInterval(timer);
      clearInterval(labelTimer);
      clearInterval(settleTimer);
      clearInterval(zoomTimer);
      cancelAnimationFrame(floatRaf);
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("cve:open-cloud", onOpenCloud);
    },
    clear() {
      auto = true;
      lastBox = "";
      graph.clear();
      uis.clear();
      group.clear();
      selected = null;
      if (onSelect) onSelect(null);
    },
    // test and debugging hooks: where a node is on screen, and what is pinned or selected
    inspect() {
      return { pins: { ...pins }, group: [...group], selected, nodes: graph.getNodesCount(), focus };
    },
    // open a cloud by its project, or leave the open one (null)
    focus(slug) {
      if (!slug) return surface();
      const id = `__cloud:${slug}`;
      if (graph.getNode(id)) dive(id, slug);
    },
    sync(data) {
      const width = container.clientWidth;
      const columns = width < 600 ? 1 : width < 1000 ? 2 : undefined;
      lastData = data;
      if (focus && !data.nodes.some((n) => n.project === focus)) { // the project is gone (moved, deleted): back to the whole graph
        focus = null;
        bar.hidden = true;
        container.classList.remove("graph-focused");
      }
      const clouded = focus ? focusProject(data, focus) : cloudProjects(data, { aspect: width / Math.max(container.clientHeight, 1) });
      const seeding = burst;
      burst = false;
      const base = clustered ? clusterGraph(clouded, {columns}) : clouded;
      const view = pods ? collapsePods(base, expanded) : base;
      const ids = new Set();
      view.nodes.forEach((n) => {
        ids.add(n.id);
        const existing = graph.getNode(n.id);
        if (!existing) {
          graph.addNode(n.id, n);
          if (pins[n.id]) pin(n.id, pins[n.id][0], pins[n.id][1]); // dropped here last time: stays here
          else if (seeding) { // a cloud just opened: everything starts in a small knot and the layout blows it apart
            const a = stableAngle(n.id), reach = 6 + (a % 1) * 24;
            layout.setNodePosition(n.id, Math.cos(a) * reach, Math.sin(a) * reach);
          } else if (n.kind === "cve" && expanded.size) {
            // a pod just opened: its CVEs start on a ring around their host and fan out from there
            const host = view.edges.find((e) => e.to === n.id && expanded.has(e.from));
            const at = host && layout.getNodePosition(host.from);
            if (at) layout.setNodePosition(n.id, at.x + Math.cos(stableAngle(n.id)) * 40, at.y + Math.sin(stableAngle(n.id)) * 40);
          } else if (Number.isFinite(n.seed_x) && Number.isFinite(n.seed_y)) {
            layout.setNodePosition(n.id, n.seed_x, n.seed_y);
            if (n.anchored) layout.pinNode(graph.getNode(n.id), true);
          }
        } else if (n.kind === "cloud" && (existing.data.hosts !== n.hosts || existing.data.findings !== n.findings)) {
          existing.data = n;
          const ui = uis.get(n.id);
          if (ui) refreshCloud(ui, n);
        } else if (n.kind === "tier" && existing.data.count !== n.count) {
          existing.data = n;
          const ui = uis.get(n.id);
          if (ui) refreshTier(ui, n);
        } else if (n.kind === "subdomain" && (existing.data.heat !== n.heat || existing.data.status !== n.status || existing.data.score !== n.score || JSON.stringify(existing.data.pod) !== JSON.stringify(n.pod) || existing.data.expanded !== n.expanded)) {
          existing.data = n; // a scan finished or found something: the host changes look without a reload
          const ui = uis.get(n.id);
          const dot = ui && ui.querySelector("circle:not(.ring):not(.pod circle)");
          if (dot) styleHost(dot, n);
          if (ui) refreshHost(ui, n);
        }
      });
      view.edges.forEach((e) => {
        if (
          !graph.hasLink(e.from, e.to) &&
          graph.getNode(e.from) &&
          graph.getNode(e.to)
        )
          graph.addLink(e.from, e.to, e);
      });
      // Domains are separate components, which the force layout flings apart. A hidden hub that every
      // domain links to keeps them in one compact cluster so the whole graph fits the window.
      if (!clustered) {
        if (!graph.getNode("__hub")) graph.addNode("__hub", { id: "__hub", kind: "hub" });
        clouded.nodes.forEach((n) => {
          if ((n.kind === "domain" || n.kind === "cloud") && !graph.hasLink("__hub", n.id)) graph.addLink("__hub", n.id);
        });
        ids.add("__hub");
      }
      const stale = [];
      graph.forEachNode((n) => {
        if (!ids.has(n.id)) stale.push(n.id);
      });
      stale.forEach((id) => {
        graph.removeNode(id);
        uis.delete(id);
        group.delete(id);
        if (selected === id) selected = null;
      });
      applyActive();
      return { nodes: data.nodes.length, edges: data.edges.length };
    },
  };
  return api;
}

// Fetch and draw a node's details into `box` (DOM built with textContent only).
// The detail drawer: what was clicked on the graph slides out from the right edge, over the page, so the graph keeps its room
// and the card is never off below the fold. Its X, Escape or a click on empty graph closes it (``onClose`` clears the selection).
export function detailDrawer({ onClose } = {}) {
  const aside = Object.assign(document.createElement("aside"), { className: "drawer", inert: true });
  aside.setAttribute("aria-labelledby", "drawer-h");
  const head = Object.assign(document.createElement("div"), { className: "drawer-head" });
  const title = Object.assign(document.createElement("h2"), { id: "drawer-h", textContent: "Details" });
  const close = Object.assign(document.createElement("button"), { type: "button", className: "btn ghost sm drawer-x", textContent: "Close" });
  close.setAttribute("aria-label", "Close the details");
  const body = Object.assign(document.createElement("div"), { className: "node-card drawer-body" });
  body.setAttribute("aria-live", "polite");
  head.append(title, close);
  aside.append(head, body);
  document.body.append(aside);
  let shown = 0;
  function hide() {
    shown += 1;
    aside.classList.remove("open");
    aside.inert = true;
  }
  close.addEventListener("click", () => {
    hide();
    if (onClose) onClose();
  });
  return {
    hide,
    async show(data) {
      if (!data) return hide();
      const mine = ++shown;
      aside.inert = false;
      aside.classList.add("open");
      const box = document.createElement("div"); // filled off the page, so a slow answer never lands over a newer click
      await showNodeDetails(box, data);
      if (mine === shown) body.replaceChildren(...box.childNodes);
    },
  };
}

export async function showNodeDetails(box, data) {
  box.textContent = "";
  if (!data) return;
  if (data.kind === 'cloud') {
    const heading = Object.assign(document.createElement('strong'), { className: 'cve-id', textContent: data.label });
    const note = Object.assign(document.createElement('p'), { className: 'note',
      textContent: `${data.hosts} hosts, ${data.findings} with findings${data.hygiene ? `, ${data.hygiene} open hygiene findings` : ""}. Open it (or double-click it) to see every host.` });
    const open = Object.assign(document.createElement('button'), { type: 'button', className: 'btn sm', textContent: 'Open the cloud' });
    open.addEventListener('click', () => document.dispatchEvent(new CustomEvent('cve:open-cloud', { detail: data.project })));
    const link = Object.assign(document.createElement('a'), { className: 'btn ghost sm', href: `/cve/${encodeURIComponent(data.project)}/hosts/`, textContent: 'Every host' });
    const actions = Object.assign(document.createElement('div'), { className: 'cloud-actions' });
    actions.append(open, link);
    box.append(heading, note, actions);
    return;
  }
  if (data.kind === 'tier') {
    const slug = encodeURIComponent(data.project);
    const heading = Object.assign(document.createElement('strong'), { className: 'cve-id', textContent: `${data.project_name}: ${data.label}` });
    const what = { fire: 'Their worst is a CVE that is exploited in the wild, has a public exploit or scores 9 or more, or a critical or high finding.',
      smoke: 'Their worst is a CVE scoring 7 or more or likely to be exploited, or a medium finding.',
      ice: 'Their worst is a lower-risk CVE or a low finding.', hygiene: 'Certificates, email authentication, headers, exposed storage and the like.' }[data.tier];
    const note = Object.assign(document.createElement('p'), { className: 'note', textContent: `${data.count} ${TIER_TIPS[data.tier]}. ${what}` });
    const list = Object.assign(document.createElement('a'), { className: 'btn sm',
      href: data.tier === 'hygiene' ? `/cve/${slug}/hygiene/` : `/cve/${slug}/hosts/?heat=${data.tier}`, textContent: data.tier === 'hygiene' ? 'See the findings' : 'See the hosts' });
    const open = Object.assign(document.createElement('button'), { type: 'button', className: 'btn ghost sm', textContent: 'Open the project' });
    open.addEventListener('click', () => document.dispatchEvent(new CustomEvent('cve:open-cloud', { detail: data.project })));
    const actions = Object.assign(document.createElement('div'), { className: 'cloud-actions' });
    actions.append(list, open);
    box.append(heading, note, actions);
    return;
  }
  if (data.kind === 'project' || data.kind === 'root') {
    const heading = document.createElement('strong');
    heading.className = 'cve-id';
    heading.textContent = data.label;
    const note = document.createElement('p');
    note.className = 'note';
    note.textContent = data.kind === 'project' ? 'Project cluster. Zoom in to inspect its registered domains and assets.' :
      'Registered-domain cluster. Connected bubbles retain their individual host, IP and CVE details.';
    box.append(heading, note);
    return;
  }
  let detail;
  try {
    const res = await fetch(`/cve/api/node?id=${encodeURIComponent(data.detail_id || data.id)}`, {
      credentials: "same-origin",
    });
    if (!res.ok) throw new Error(res.status);
    detail = await res.json();
  } catch (_) {
    box.append(
      Object.assign(document.createElement("p"), {
        className: "msg err",
        textContent: "Could not load details for that node.",
      }),
    );
    return;
  }
  const head = document.createElement("div");
  head.className = "node-head";
  const kind = Object.assign(document.createElement("span"), {
    className: "kind",
    textContent: detail.kind,
  });
  const title = detail.link
    ? Object.assign(document.createElement("a"), { className: "cve-id node-title", href: detail.link, textContent: detail.title })
    : Object.assign(document.createElement("strong"), { className: "cve-id", textContent: detail.title });
  head.append(kind, title);
  const list = document.createElement("dl");
  list.className = "node-rows";
  detail.rows.forEach((r) => {
    const dd = document.createElement("dd");
    if (Array.isArray(r.links) && r.links.length) {
      // each item names a record (a host, an address, a match): it links there when it has an address
      r.links.forEach((item, i) => {
        if (i) dd.append(document.createTextNode(", "));
        if (item.href && item.href.startsWith("/cve/")) {
          dd.append(Object.assign(document.createElement("a"), { className: "host-link", href: item.href, textContent: item.text }));
        } else dd.append(document.createTextNode(item.text));
      });
    } else dd.textContent = String(r.v);
    list.append(Object.assign(document.createElement("dt"), { textContent: r.k }), dd);
  });
  if (detail.heat) {
    head.append(
      Object.assign(document.createElement("span"), {
        className: `badge ${detail.heat === "fire" ? "failed" : detail.heat === "clean" ? "success" : ""}`,
        textContent: detail.heat,
      }),
    );
  }
  box.append(head, list);
  if (detail.link) {
    box.append(
      Object.assign(document.createElement("a"), {
        className: "btn ghost sm",
        href: detail.link,
        textContent: detail.link_label || "Open the host page",
        style: "display:inline-flex;margin-top:10px;text-decoration:none",
      }),
    );
  }
}
