// App shell behaviour: project switcher, mobile "More" sheet, account menu, and the jump palette (Ctrl/Cmd+K or "/").
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const SECTIONS = ["targets", "scans", "hosts", "changes", "activity", "vulns", "matches"];

// Where the switcher sends you when the project changes. On the dashboard it stays on the dashboard
// (bare /cve/ for the combined view, ?project= for one project); on a section page it keeps the section.
function projectHref(value, here) {
  if (here === "bounty") return `/cve/bounty/?project=${encodeURIComponent(value && value !== "_all" ? value : "")}`;
  if (here === "dashboard") return value && value !== "_all" ? `/cve/?project=${encodeURIComponent(value)}` : "/cve/";
  return `/cve/${value}/${SECTIONS.includes(here) ? here : "hosts"}/`;
}

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
const palette = $("#palette");
const list = $("#palette-list");
const input = $("#palette-q");
const none = $("#palette-empty");
let items = [];
let shown = [];
let cursor = 0;

function collect() {
  const seen = new Set();
  const out = [];
  $$("[data-nav]").forEach((a) => {
    const label = a.dataset.nav;
    if (seen.has(a.getAttribute("href"))) return;
    seen.add(a.getAttribute("href"));
    out.push({ label, hint: "Go to", href: a.getAttribute("href") });
  });
  if ($("[data-add-targets]")) out.push({ label: "Add targets", hint: "Action", run: () => $("[data-add-targets]").click() });
  // commands registered by page scripts (keys.js, saved views): { label, hint, run, when? }
  (window.cveCommands || []).forEach((c) => {
    if (!c.when || c.when()) out.push({ label: c.label, hint: c.hint || "Action", run: c.run });
  });
  const current = $("#project");
  if (current) {
    const here = current.dataset.section;
    [...current.options].forEach((o) => {
      if (o.value !== current.value) {
        out.push({ label: `Switch to ${o.textContent}`, hint: "Project", href: projectHref(o.value, here) });
      }
    });
  }
  return out;
}

function draw() {
  const q = input.value.trim().toLowerCase();
  shown = items.filter((i) => !q || i.label.toLowerCase().includes(q));
  cursor = Math.min(cursor, Math.max(shown.length - 1, 0));
  list.textContent = "";
  shown.forEach((item, idx) => {
    const li = document.createElement("li");
    li.setAttribute("role", "option");
    li.setAttribute("aria-selected", String(idx === cursor));
    const name = document.createElement("span");
    name.textContent = item.label;
    const hint = document.createElement("span");
    hint.className = "palette-hint";
    hint.textContent = item.hint;
    li.append(name, hint);
    li.addEventListener("click", () => choose(item));
    li.addEventListener("mousemove", () => {
      if (cursor !== idx) {
        cursor = idx;
        mark();
      }
    });
    list.append(li);
  });
  none.hidden = shown.length > 0;
}
function mark() {
  [...list.children].forEach((li, i) => li.setAttribute("aria-selected", String(i === cursor)));
  const cur = list.children[cursor];
  if (cur) cur.scrollIntoView({ block: "nearest" });
}
function choose(item) {
  palette.close();
  if (item.run) item.run();
  else if (item.href) window.location.href = item.href;
}
function openPalette() {
  if (!palette || palette.open) return;
  items = collect();
  input.value = "";
  cursor = 0;
  draw();
  palette.showModal();
  input.focus();
}
if (palette) {
  $("#jump").addEventListener("click", openPalette);
  input.addEventListener("input", () => {
    cursor = 0;
    draw();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      cursor = Math.min(cursor + 1, shown.length - 1);
      mark();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      cursor = Math.max(cursor - 1, 0);
      mark();
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
