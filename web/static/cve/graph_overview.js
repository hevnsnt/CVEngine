// Project → registrable domain → host. All text comes through textContent.
const make = (tag, className, value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
};

const tally = (n, singular, plural = `${singular}s`) => `${n} ${n === 1 ? singular : plural}`;

export function mountOverview(container, search) {
  let generation = 0;
  let lastKey = null;
  let lastResult = null;
  let lastFingerprint = null;
  let lastLoad = 0;

  function render(data) {
    const needle = search.value.trim().toLowerCase();
    const opened = new Set(Array.from(container.querySelectorAll(".graph-root[open]"),
      card => card.dataset.group));
    const fragment = document.createDocumentFragment();
    let visible = 0;
    for (const project of data.projects) {
      const roots = project.roots.filter(group =>
        !needle || project.name.toLowerCase().includes(needle) || group.root.toLowerCase().includes(needle));
      if (!roots.length) continue;
      visible += 1;
      const section = make("section", "graph-project");
      section.setAttribute("aria-label", `${project.name} asset graph`);
      const heading = make("div", "graph-project-node");
      heading.append(make("span", "graph-node-kind", "PROJECT"));
      heading.append(make("h2", "graph-project-name", project.name));
      heading.append(make("span", "graph-project-count", `${tally(roots.length, "domain group")} · ${tally(project.hosts, "host")}`));
      section.append(heading);
      const grid = make("div", "graph-groups-grid");
      for (const group of roots) {
        const card = make("details", "graph-root graph-domain-node");
        card.dataset.group = `${project.slug}:${group.root}`;
        if (opened.has(card.dataset.group)) card.open = true;
        const summary = make("summary");
        const title = make("span", "graph-root-title", group.root);
        const stats = make("span", "graph-root-stats");
        summary.append(make("span", "graph-node-kind", "ROOT DOMAIN"));
        stats.append(make("strong", "", tally(group.hosts, "host")));
        stats.append(make("span", "", `${group.live} live`));
        stats.append(make("span", "", `${group.assessed} assessed`));
        if (group.findings || group.cve_candidates)
          stats.append(make("span", "graph-attention", `${group.findings} finding hosts · ${group.cve_candidates} CVE candidate hosts`));
        summary.append(title, stats);
        const body = make("div", "graph-root-body");
        const filter = make("input", "graph-host-search");
        filter.type = "search";
        filter.placeholder = "Find a host in this domain";
        filter.setAttribute("aria-label", `Find a host in ${group.root}`);
        filter.addEventListener("input", () => {
          clearTimeout(filter._searchTimer);
          filter._searchTimer = setTimeout(() => loadHosts(project.slug, group.root, body, 1, filter.value), 180);
        });
        body.append(filter, make("div", "graph-host-results"));
        card.append(summary, body);
        card.addEventListener("toggle", () => {
          if (card.open && !body.dataset.loaded) loadHosts(project.slug, group.root, body, 1, filter.value);
        });
        grid.append(card);
      }
      section.append(grid);
      const edges = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      edges.classList.add("graph-edges");
      edges.setAttribute("aria-hidden", "true");
      section.prepend(edges);
      fragment.append(section);
    }
    if (!visible) fragment.append(make("p", "note", needle ? "No matching project or domain group." : "No targets are visible yet."));
    container.replaceChildren(fragment);
    requestAnimationFrame(drawEdges);
    for (const card of container.querySelectorAll(".graph-root[open]")) {
      const body = card.querySelector(".graph-root-body");
      const [project, ...root] = card.dataset.group.split(":");
      loadHosts(project, root.join(":"), body, 1, body.querySelector("input")?.value || "");
    }
  }

  function drawEdges() {
    for (const section of container.querySelectorAll(".graph-project")) {
      const svg = section.querySelector(".graph-edges");
      const box = section.getBoundingClientRect();
      const hub = section.querySelector(".graph-project-node").getBoundingClientRect();
      svg.setAttribute("viewBox", `0 0 ${box.width} ${box.height}`);
      svg.replaceChildren();
      const horizontal = section.clientWidth > 720;
      const sx = (horizontal ? hub.right : hub.left + hub.width / 2) - box.left;
      const sy = (horizontal ? hub.top + hub.height / 2 : hub.bottom) - box.top;
      for (const node of section.querySelectorAll(".graph-domain-node")) {
        const target = node.getBoundingClientRect();
        const tx = (horizontal ? target.left : target.left + target.width / 2) - box.left;
        const ty = (horizontal ? target.top + Math.min(target.height, 100) / 2 : target.top) - box.top;
        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        const bend = horizontal ? `C ${sx + 30} ${sy}, ${tx - 30} ${ty}` : `C ${sx} ${sy + 22}, ${tx} ${ty - 22}`;
        path.setAttribute("d", `M ${sx} ${sy} ${bend}, ${tx} ${ty}`);
        svg.append(path);
      }
    }
  }

  window.addEventListener("resize", () => requestAnimationFrame(drawEdges));
  container.addEventListener("toggle", () => requestAnimationFrame(drawEdges), true);

  async function loadHosts(project, root, body, page = 1, q = "") {
    if (page > 1 && body.dataset.loading) return;
    const sequence = Number(body.dataset.sequence || "0") + 1;
    body.dataset.sequence = String(sequence);
    body.dataset.loading = "1";
    const requestId = generation;
    const results = body.querySelector(".graph-host-results");
    if (page === 1) results.textContent = "Loading hosts…";
    else results.querySelector("button")?.setAttribute("disabled", "");
    try {
      const params = new URLSearchParams({ owner: project, root, page, q,
        project: document.body.dataset.slug || "_all" });
      const response = await fetch(`/cve/api/graph-hosts?${params}`, { credentials: "same-origin" });
      if (!response.ok) throw new Error("Could not load hosts");
      const data = await response.json();
      if (requestId !== generation || Number(body.dataset.sequence) !== sequence || !body.isConnected) return;
      const list = make("div", "graph-host-list");
      for (const host of data.results) {
        const link = make("a", "graph-host-row");
        link.href = `/cve/${encodeURIComponent(project)}/hosts/?host=${encodeURIComponent(host.host)}`;
        link.append(make("strong", "", host.host));
        link.append(make("span", "graph-host-meta", `${host.status === "attention" ? "Needs review" : host.status === "assessed" ? "Assessed" : "Not assessed"}${host.archived ? " · Archived" : ""} · ${tally(host.ip_count, "IP")} · ${tally(host.service_count, "service")}`));
        list.append(link);
      }
      if (!data.results.length) list.append(make("p", "note", "No discovered hosts in this group yet."));
      if (data.has_more) {
        const more = make("button", "btn sm", "Load more hosts");
        more.type = "button";
        more.addEventListener("click", () => loadHosts(project, root, body, page + 1, q));
        list.append(more);
      }
      if (page === 1) results.replaceChildren(list);
      else {
        const old = results.querySelector(".graph-host-list");
        old?.querySelector("button")?.remove();
        for (const item of Array.from(list.children)) old?.append(item);
      }
      body.dataset.loaded = "1";
    } catch (_) {
      if (requestId === generation && Number(body.dataset.sequence) === sequence) {
        if (page === 1) results.textContent = "Hosts could not be loaded. Close and reopen this group to retry.";
        else results.querySelector("button")?.removeAttribute("disabled");
      }
      delete body.dataset.loaded;
    } finally {
      if (Number(body.dataset.sequence) === sequence) delete body.dataset.loading;
    }
  }

  search.addEventListener("input", () => { if (lastResult) render(lastResult); });
  return {
    async load(project) {
      const key = project || "_all";
      if (key !== lastKey) { generation += 1; lastKey = key; lastResult = null; lastFingerprint = null; }
      if (!lastResult || Date.now() - lastLoad > 30000) {
        const requestId = generation;
        const response = await fetch(`/cve/api/graph-overview?project=${encodeURIComponent(key)}`, { credentials: "same-origin" });
        if (!response.ok) throw new Error("Could not load graph overview");
        const data = await response.json();
        if (requestId === generation) {
          const fingerprint = JSON.stringify(data);
          lastResult = data;
          lastLoad = Date.now();
          if (fingerprint !== lastFingerprint) { lastFingerprint = fingerprint; render(data); }
        }
      }
      return { projects: lastResult?.projects.length || 0, targets: lastResult?.targets || 0, hosts: lastResult?.hosts || 0 };
    },
  };
}
