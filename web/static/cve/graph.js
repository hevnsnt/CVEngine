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

// Retain the original bubbles and discovery links. Invisible force anchors are
// replaced by visible project/root-domain bubbles when showing all domains.
// A shared IP/CVE gets one visual copy per root so a CDN does not pull two
// unrelated tenants into the same cluster; each copy opens the same detail ID.
export function clusterGraph(data, {columns: requestedColumns} = {}) {
  const originals = new Map(data.nodes.map(node => [node.id, node]));
  const domains = data.nodes.filter(node => node.kind === 'domain' && node.project && node.root);
  if (!domains.length) return {nodes: data.nodes, edges: data.edges};
  const projects = new Map();
  for (const domain of domains) {
    const project = projects.get(domain.project) ||
      {slug: domain.project, name: domain.project_name || domain.project, roots: new Map()};
    if (!projects.has(domain.project)) projects.set(domain.project, project);
    const roots = project.roots.get(domain.root) || [];
    if (!project.roots.has(domain.root)) project.roots.set(domain.root, roots);
    roots.push(domain);
  }
  const ordered = [...projects.values()].sort((a, b) => a.name.localeCompare(b.name));
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
    {...node, seed_x: positions.get(node.id)[0], seed_y: positions.get(node.id)[1]} : node),
    ...clones.values(), ...added], edges: links};
}

// pinKey(): localStorage key for where nodes were dropped (evaluated on every read and write, so it can follow the scan).
export function mountGraph(container, { onSelect, pinKey } = {}) {
  const graph = Viva.Graph.graph();
  let clustered = false;
  const layout = Viva.Graph.Layout.forceDirected(graph, {
    springLength: 80,
    springCoeff: 0.0008,
    gravity: -2.6,
    dragCoeff: 0.05,
    // leaves that share an IP get extra room, and a hub's links are long, so clusters fan out instead of stacking
    springTransform(link, spring) {
      if (link.fromId.startsWith('__project:')) { spring.length = 190; return; }
      if (link.fromId.startsWith('__root:')) { spring.length = 105; return; }
      if (link.data?.crossCluster) { spring.length = 550; return; }
      const ip = graph.getNode(link.toId);
      const shared = ip && ip.data && ip.data.kind === "ip" ? Math.min((ip.links || []).length, 14) : 0;
      spring.length = link.fromId === "__hub" ? 140 : 80 + shared * 5;
    },
  });
  const graphics = Viva.Graph.View.svgGraphics();
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
    if (ring) ring.setAttribute("display", on ? "" : "none");
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

  graphics
    .node((node) => {
      const d = node.data || {};
      const g = document.createElementNS(NS, "g");
      if (d.kind === "hub") {
        g.setAttribute("display", "none");
        uis.set(node.id, g);
        return g;
      }
      g.setAttribute("class", `gn gn-${d.kind}`);
      g.setAttribute("role", "button");
      g.setAttribute("tabindex", "0");
      g.style.touchAction = "none";
      g.setAttribute(
        "aria-label",
        d.kind === "subdomain"
          ? `${d.label}, ${d.status || "unscanned"}`
          : `${d.kind} ${d.label}`,
      );
      const r = SIZES[d.kind] || 6;
      const ring = document.createElementNS(NS, "circle");
      ring.setAttribute("class", "ring");
      ring.setAttribute("r", r + 5);
      ring.setAttribute("fill", "none");
      ring.setAttribute("display", "none");
      const c = document.createElementNS(NS, "circle");
      c.setAttribute("r", r);
      if (d.kind === "subdomain") {
        styleHost(c, d);
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
      t.setAttribute("x", ['project', 'root'].includes(d.kind) ? 0 : r + 4);
      t.setAttribute("y", ['project', 'root'].includes(d.kind) ? -(r + 8) : 3.5);
      if (['project', 'root'].includes(d.kind)) t.setAttribute('text-anchor', 'middle');
      t.textContent = shorten(shortLabel(d));
      const title = document.createElementNS(NS, "title");
      title.textContent = d.label;
      g.append(ring, c, t, title);
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
        unpin(node.id);
      });
      uis.set(node.id, g);
      return g;
    })
    .placeNode((ui, pos) => {
      ui.setAttribute("transform", `translate(${pos.x},${pos.y})`);
    });
  graphics.link((link) => {
    const l = Viva.Graph.svg("line");
    if (link.fromId === "__hub") l.setAttribute("visibility", "hidden");
    l.setAttribute("stroke", link.fromId.startsWith('__project:') || link.fromId.startsWith('__root:') ? css('--graph-link-hi') : css('--line-2'));
    l.setAttribute("stroke-width", link.fromId.startsWith('__project:') ? '1.8' : '1');
    if (link.data?.crossCluster) l.setAttribute('stroke-dasharray', '4 4');
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
    return { x: (cx - box.left - tx) / k, y: (cy - box.top - ty) / k };
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

  renderer = Viva.Graph.View.renderer(graph, {
    container,
    graphics,
    layout,
  });
  renderer.run();
  container.addEventListener("click", () => {
    if (justDragged) return;
    clearGroup();
    select(null);
  });
  const onKey = (e) => {
    if (e.key === "Escape") {
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
    return ['project', 'root', 'domain'].includes(d.kind) ||
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
        clustered && kind === 'project' ? 1 : clustered && kind === 'root' ? 2 :
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
      text.setAttribute('display', '');
      const label = text.getBoundingClientRect();
      const left = Math.floor((label.left - box.left) / CELL_W);
      const right = Math.floor((label.right - box.left) / CELL_W);
      const top = Math.floor((label.top - box.top) / CELL_H);
      const bottom = Math.floor((label.bottom - box.top) / CELL_H);
      const cells = [];
      for (let cx = left; cx <= right; cx++) for (let cy = top; cy <= bottom; cy++) cells.push(`${cx}:${cy}`);
      const free = cells.every(cell => !taken.has(cell));
      const kind = n.data?.kind;
      const show = clustered ?
        rank === 0 || (kind === 'project' && free) ||
        (kind === 'root' && scale >= 0.16 && free) ||
        ((!zoomedOut || picked) && rank >= 3 && free) :
        rank === 0 || rank === 3 || ((!zoomedOut || picked) && free);
      if (show) cells.forEach(cell => taken.add(cell));
      text.setAttribute("display", show ? "" : "none");
    });
  }
  const labelTimer = setInterval(relabel, 500);

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
    const pad = clustered ? 440 : 70; // room for each root's host bubbles and labels
    const bw = Math.max(x2 - x1, 1) + pad * 2,
      bh = Math.max(y2 - y1, 1) + pad;
    const k = Math.min(w / bw, h / bh, 1.4);
    const key = [x1, y1, x2, y2, w, h].map((v) => Math.round(v / 6)).join();
    if (key === lastBox) return;
    lastBox = key;
    graphics.resetScale();
    renderer.moveTo((x1 + x2) / 2, (y1 + y2) / 2);
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
    if (auto) fit();
  }, 700);

  return {
    setClustered(value) { clustered = Boolean(value); },
    fit() {
      auto = true;
      lastBox = "";
      fit();
    },
    destroy() {
      clearInterval(timer);
      clearInterval(labelTimer);
      document.removeEventListener("keydown", onKey);
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
      return { pins: { ...pins }, group: [...group], selected, nodes: graph.getNodesCount() };
    },
    sync(data) {
      const width = container.clientWidth;
      const columns = width < 600 ? 1 : width < 1000 ? 2 : undefined;
      const view = clustered ? clusterGraph(data, {columns}) : data;
      const ids = new Set();
      view.nodes.forEach((n) => {
        ids.add(n.id);
        const existing = graph.getNode(n.id);
        if (!existing) {
          graph.addNode(n.id, n);
          if (pins[n.id]) pin(n.id, pins[n.id][0], pins[n.id][1]); // dropped here last time: stays here
          else if (Number.isFinite(n.seed_x) && Number.isFinite(n.seed_y)) {
            layout.setNodePosition(n.id, n.seed_x, n.seed_y);
            if (n.anchored) layout.pinNode(graph.getNode(n.id), true);
          }
        } else if (n.kind === "subdomain" && (existing.data.heat !== n.heat || existing.data.status !== n.status || existing.data.score !== n.score)) {
          existing.data = n; // a scan finished or found something: the host changes look without a reload
          const ui = uis.get(n.id);
          const dot = ui && ui.querySelector("circle:not(.ring)");
          if (dot) styleHost(dot, n);
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
        data.nodes.forEach((n) => {
          if (n.kind === "domain" && !graph.hasLink("__hub", n.id)) graph.addLink("__hub", n.id);
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
      return { nodes: data.nodes.length, edges: data.edges.length };
    },
  };
}

// Fetch and draw a node's details into `box` (DOM built with textContent only).
export async function showNodeDetails(box, data) {
  box.textContent = "";
  if (!data) return;
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
