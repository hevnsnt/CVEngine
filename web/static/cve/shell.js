import { hostRow, previewHosts, suggestions, syntaxHelp } from "/staticfiles/cve/palette-search.js";

// App shell behaviour: project switcher, mobile "More" sheet, account menu, and the jump palette (Ctrl/Cmd+K or "/").
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const SECTIONS = ["targets", "scans", "hosts", "changes", "activity", "vulns", "matches", "hygiene", "suppliers"];

// Where the switcher sends you when the project changes. On the dashboard it stays on the dashboard
// (bare /cve/ for the combined view, ?project= for one project); on a section page it keeps the section.
function projectHref(value, here) {
  if (here === "bounty") return `/cve/bounty/?project=${encodeURIComponent(value && value !== "_all" ? value : "")}`;
  if (here === "dashboard") return value && value !== "_all" ? `/cve/?project=${encodeURIComponent(value)}` : "/cve/";
  return `/cve/${value}/${SECTIONS.includes(here) ? here : "hosts"}/`;
}

// --- organization switcher: shown when the caller's projects span two or more organizations -----------------------
const readJson = (id) => {
  const node = document.getElementById(id);
  try {
    return node ? JSON.parse(node.textContent) : [];
  } catch (_) {
    return [];
  }
};
const SWITCH_PROJECTS = readJson("switch-projects");
const SWITCH_ORGS = readJson("switch-orgs");
const LAST_KEY = "cve.org.last.v1";
const lastByOrg = () => {
  try {
    return JSON.parse(localStorage.getItem(LAST_KEY) || "{}");
  } catch (_) {
    return {};
  }
};
// The project to open when an organization is chosen: the one last used in it, else its first.
const projectForOrg = (orgSlug) => {
  const inOrg = SWITCH_PROJECTS.filter((p) => p.org_slug === orgSlug);
  const last = lastByOrg()[orgSlug];
  return (inOrg.find((p) => p.slug === last) || inOrg[0] || {}).slug;
};
const currentProject = document.getElementById("project");
if (SWITCH_ORGS.length && currentProject && currentProject.value && currentProject.value !== "_all") {
  const mine = SWITCH_PROJECTS.find((p) => p.slug === currentProject.value);
  if (mine) {
    try {
      localStorage.setItem(LAST_KEY, JSON.stringify({ ...lastByOrg(), [mine.org_slug]: mine.slug }));
    } catch (_) {
      /* private window: the org switch just opens its first project */
    }
  }
}
$$("select.org-switch").forEach((sel) => {
  sel.addEventListener("change", () => {
    const slug = projectForOrg(sel.value);
    // Only a project slug may become part of the address (the same rule as the project switcher below): the list comes from page data.
    if (slug && /^[-\w]+$/.test(slug)) window.location.href = projectHref(slug, sel.dataset.section);
  });
});

// --- project switcher (sidebar and sheet) -------------------------------------------------
$$("select.proj").forEach((sel) => {
  sel.addEventListener("change", () => {
    // Only a project slug (or the reserved "_all") may become part of the address.
    if (sel.value && !/^[-\w]+$/.test(sel.value)) return;
    window.location.href = projectHref(sel.value, sel.dataset.section);
  });
});

// --- account menu: close on outside click and Escape --------------------------------------
const acct = $(".acct");
if (acct) {
  document.addEventListener("click", (e) => {
    if (acct.open && !acct.contains(e.target)) acct.open = false;
  });
  acct.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      acct.open = false;
      $("summary", acct).focus();
    }
  });
}

// --- mobile sheets: "More" (pages) and "Account" (the desktop account menu) -----------------------
const scrim = $("#sheet-scrim");
const sheets = [[$("#sheet"), $("#more-btn")], [$("#acct-sheet"), $("#acct-btn")]].filter(([s, b]) => s && b);
let openSheet = null;
function setSheet(pair, open) {
  sheets.forEach(([s, b]) => {
    const on = open && pair && s === pair[0];
    s.hidden = !on;
    b.setAttribute("aria-expanded", String(on));
  });
  scrim.hidden = !open;
  document.body.classList.toggle("noscroll", open);
  const was = openSheet;
  openSheet = open ? pair : null;
  if (open) $("a, select, button", pair[0]).focus();
  else if (was) was[1].focus();
}
sheets.forEach((pair) => pair[1].addEventListener("click", () => setSheet(pair, openSheet !== pair)));
if (scrim) {
  scrim.addEventListener("click", () => setSheet(null, false));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && openSheet) setSheet(null, false);
  });
}

// --- palette ------------------------------------------------------------------------------
// Jump to a page, project or action, or search hosts the Shodan way (filter:value, "phrases", -negation). Pages and actions
// are filtered here; the search itself is the server's (the same query the Hosts page runs), previewed six hosts at a time.
const palette = $("#palette");
const list = $("#palette-list");
const input = $("#palette-q");
const none = $("#palette-empty");
let items = [];
let shown = [];
let optionEls = [];
let cursor = 0;
let hits = []; // preview hosts for the query in the box
let hitCount = null;
let searching = false;
let searchError = "";
let searchSeq = 0;
let searchTimer = null;

const slugNow = () => {
  const sel = $("#project");
  return sel && sel.value ? sel.value : "";
};

function collect() {
  const seen = new Set();
  const out = [];
  $$("[data-nav]").forEach((a) => {
    const label = a.dataset.nav;
    if (seen.has(a.getAttribute("href"))) return;
    seen.add(a.getAttribute("href"));
    out.push({ label, hint: "Go to", href: a.getAttribute("href"), section: "Go to" });
  });
  if ($("[data-add-targets]")) out.push({ label: "Add targets", hint: "Action", run: () => $("[data-add-targets]").click(), section: "Go to" });
  // commands registered by page scripts (keys.js, saved views): { label, hint, run, when? }
  (window.cveCommands || []).forEach((c) => {
    if (!c.when || c.when()) out.push({ label: c.label, hint: c.hint || "Action", run: c.run, section: "Go to" });
  });
  const current = $("#project");
  if (current) {
    const here = current.dataset.section;
    const multi = SWITCH_ORGS.length > 0;
    const orgName = (slug) => (SWITCH_ORGS.find((o) => o.slug === slug) || {}).name;
    if (multi) {
      const mine = SWITCH_PROJECTS.find((p) => p.slug === current.value);
      SWITCH_ORGS.forEach((o) => {
        const target = projectForOrg(o.slug);
        if (target && (!mine || mine.org_slug !== o.slug))
          out.push({ label: `Switch to ${o.name}`, hint: "Organization", href: projectHref(target, here), section: "Go to" });
      });
      SWITCH_PROJECTS.forEach((p) => {
        if (p.slug !== current.value)
          out.push({ label: `Switch to ${p.name}`, sub: orgName(p.org_slug), hint: "Project", href: projectHref(p.slug, here), section: "Go to" });
      });
    } else {
      [...current.options].forEach((o) => {
        if (o.value !== current.value) out.push({ label: `Switch to ${o.textContent}`, hint: "Project", href: projectHref(o.value, here), section: "Go to" });
      });
    }
  }
  return out;
}

const helpRow = { label: "Search syntax", sub: "port:443 product:nginx -host:test", hint: "Help", run: syntaxHelp, section: "Help" };

// Everything the palette lists for what is typed, in order, each row tagged with the section it belongs to.
function rowsFor(raw) {
  const q = raw.trim();
  const ql = q.toLowerCase();
  const local = items.filter((i) => !ql || i.label.toLowerCase().includes(ql));
  if (!q) return [...local, helpRow];
  const slug = slugNow();
  const searchRow =
    q.length >= 2 && slug
      ? {
          label: `Search hosts for \u201c${q}\u201d`,
          sub: searchError || (hitCount === 0 ? "No host matches. Try a bare word or one filter." : ""),
          error: Boolean(searchError),
          hint: searching ? "searching" : hitCount != null ? `${hitCount.toLocaleString()} host${hitCount === 1 ? "" : "s"}` : "hosts",
          href: `/cve/${encodeURIComponent(slug)}/hosts/?q=${encodeURIComponent(q)}`,
          section: "Search",
        }
      : null;
  const pagesFirst = local.length > 0 && local[0].label.toLowerCase().startsWith(ql);
  return [
    ...suggestions(raw),
    ...(pagesFirst ? local : []),
    ...(searchRow ? [searchRow] : []),
    ...(searchRow && !searchError ? hits : []),
    ...(pagesFirst ? [] : local),
    helpRow,
  ];
}

function draw() {
  shown = rowsFor(input.value);
  cursor = Math.min(cursor, Math.max(shown.length - 1, 0));
  list.textContent = "";
  optionEls = [];
  let section = null;
  shown.forEach((item, idx) => {
    if (item.section && item.section !== section) {
      section = item.section;
      const head = document.createElement("li");
      head.className = "palette-sec";
      head.setAttribute("role", "presentation");
      head.textContent = section;
      list.append(head);
    }
    const li = document.createElement("li");
    li.setAttribute("role", "option");
    li.setAttribute("aria-selected", String(idx === cursor));
    const main = document.createElement("span");
    main.className = "palette-main";
    const name = document.createElement("span");
    name.className = "palette-name";
    name.textContent = item.label;
    main.append(name);
    if (item.sub) {
      const sub = document.createElement("span");
      sub.className = `palette-sub${item.error ? " err" : ""}`;
      sub.textContent = item.sub;
      main.append(sub);
    }
    const hint = document.createElement("span");
    hint.className = `palette-hint${item.heat ? ` heat-${item.heat}` : ""}`;
    hint.textContent = item.hint || "";
    li.append(main, hint);
    li.addEventListener("click", () => choose(item));
    li.addEventListener("mousemove", () => {
      if (cursor !== idx) {
        cursor = idx;
        mark();
      }
    });
    list.append(li);
    optionEls.push(li);
  });
  none.hidden = shown.length > 0;
}
function mark() {
  optionEls.forEach((li, i) => li.setAttribute("aria-selected", String(i === cursor)));
  const cur = optionEls[cursor];
  if (cur) cur.scrollIntoView({ block: "nearest" });
}
function choose(item) {
  if (item.insert !== undefined) {
    // a filter suggestion completes what is being typed; the palette stays open
    input.value = input.value.slice(0, item.start) + item.insert;
    input.focus();
    onInput();
    return;
  }
  palette.close();
  if (item.run) item.run();
  else if (item.href) window.location.href = item.href;
}

function scheduleSearch() {
  clearTimeout(searchTimer);
  const q = input.value.trim();
  const slug = slugNow();
  if (q.length < 2 || !slug) {
    hits = [];
    hitCount = null;
    searching = false;
    searchError = "";
    return;
  }
  searching = true;
  searchTimer = setTimeout(async () => {
    const seq = (searchSeq += 1);
    try {
      const data = await previewHosts(slug, q);
      if (seq !== searchSeq) return; // a newer query is already on its way
      hits = (data.results || []).map((h) => hostRow(slug, h));
      hitCount = data.count;
      searchError = "";
    } catch (err) {
      if (seq !== searchSeq) return;
      hits = [];
      hitCount = null;
      searchError = err.message;
    }
    searching = false;
    draw();
  }, 220);
}
function onInput() {
  cursor = 0;
  scheduleSearch();
  draw();
}

function openPalette() {
  if (!palette || palette.open) return;
  items = collect();
  input.value = "";
  cursor = 0;
  hits = [];
  hitCount = null;
  searchError = "";
  searching = false;
  draw();
  palette.showModal();
  input.focus();
}
if (palette) {
  $("#jump").addEventListener("click", openPalette);
  input.addEventListener("input", onInput);
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      cursor = Math.min(cursor + 1, shown.length - 1);
      mark();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      cursor = Math.max(cursor - 1, 0);
      mark();
    } else if (e.key === "Tab" && shown[cursor] && shown[cursor].insert !== undefined) {
      e.preventDefault();
      choose(shown[cursor]);
    } else if (e.key === "Enter" && shown[cursor]) {
      e.preventDefault();
      choose(shown[cursor]);
    }
  });
  palette.addEventListener("click", (e) => {
    if (e.target === palette) palette.close();
  });
  document.addEventListener("keydown", (e) => {
    const typing = /^(input|textarea|select)$/i.test(document.activeElement && document.activeElement.tagName);
    if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey)) {
      e.preventDefault();
      openPalette();
    }
  });
  // show the right modifier on this platform
  const key = $(".jump-key");
  if (key && /Mac|iPhone|iPad/.test(navigator.platform)) key.textContent = "⌘ K";
}
