// Keyboard layer: vim-style movement through lists, tab and detail shortcuts, "g" then a letter to jump between pages, and a
// "?" cheat sheet. Everything is off while typing in a field or while a dialog is open, and with Ctrl, Alt or Cmd held, so it never
// fights the browser, a screen reader or the existing palette (Ctrl/Cmd+K and "/").
import { dialog, el } from "/staticfiles/cve/ui.js";

const GO_LETTERS = {
  Live: "l",
  "Asset graph": "a",
  Hosts: "h",
  Changes: "c",
  Activity: "v",
  "CVE matches": "m",
  Findings: "f",
  Hygiene: "y",
  Targets: "t",
  Scans: "s",
  "API keys": "k",
  "Bug bounty": "b",
};
const OPEN_DELAY_MS = 220; // moving with j/k opens the row after a pause, so holding a key does not fetch every row it passes
const GO_WINDOW_MS = 1200;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const typing = () => {
  const a = document.activeElement;
  return Boolean(
    a && (/^(input|textarea|select)$/i.test(a.tagName) || a.isContentEditable),
  );
};
const dialogOpen = () => Boolean($("dialog[open]"));
const visibleRows = () => $$(".host-rows .host-row:not([hidden])");
const currentRow = () => {
  const focused =
    document.activeElement &&
    document.activeElement.closest &&
    document.activeElement.closest(".host-row");
  return focused || $(".host-rows .host-row.sel:not([hidden])");
};

let openTimer = null;
function moveRow(delta) {
  const rows = visibleRows();
  if (!rows.length) return false;
  const at = rows.indexOf(currentRow());
  const next =
    rows[
      Math.max(
        0,
        Math.min(
          rows.length - 1,
          at < 0 ? (delta > 0 ? 0 : rows.length - 1) : at + delta,
        ),
      )
    ];
  next.focus();
  next.scrollIntoView({ block: "nearest" });
  clearTimeout(openTimer);
  const selecting = $(".bulk-toggle[aria-pressed='true']");
  if (!selecting) openTimer = setTimeout(() => next.click(), OPEN_DELAY_MS);
  return true;
}

function toggleSelectOn(row) {
  const toggle = $(".bulk-toggle");
  if (!toggle) return;
  if (toggle.getAttribute("aria-pressed") !== "true") toggle.click();
  const box = row && $(".row-check", row);
  if (box) {
    box.click();
    row.focus();
  }
}

function goTo(letter) {
  const link = $$("[data-nav]").find(
    (a) => GO_LETTERS[a.dataset.nav] === letter && a.getAttribute("href"),
  );
  if (link) window.location.href = link.getAttribute("href");
}

const SHEET = [
  [
    "Go to (press g, then)",
    () =>
      $$("[data-nav]")
        .filter((a) => GO_LETTERS[a.dataset.nav])
        .map((a) => [`g ${GO_LETTERS[a.dataset.nav]}`, a.dataset.nav]),
  ],
  [
    "Lists",
    () => [
      ["j or k", "Next and previous row; the row opens after a short pause"],
      ["Enter", "Open the focused row"],
      ["x", "Select the row (starts selection mode)"],
      ["Esc", "Leave selection mode"],
      ["f", "Focus the filter or search box"],
      [".", "Open the actions menu of the focused row"],
    ],
  ],
  [
    "On a host or finding",
    () => [
      [
        "1 to 6",
        "Switch tab: Overview, Services, Web, Findings, History, Manage",
      ],
      ["y", "Copy the name (the link, on a finding)"],
      ["Y", "Copy the link"],
      ["e", "Change the remediation status of a CVE match"],
    ],
  ],
  [
    "Anywhere",
    () => [
      ["/ or Ctrl K", "Jump to a page, project or action"],
      ["?", "This list"],
    ],
  ],
];

function cheatSheet() {
  dialog("Keyboard shortcuts", (body, close) => {
    body.querySelector("h2").tabIndex = -1; // the dialog focuses its heading, so a long sheet opens at the top, not at Close
    SHEET.forEach(([title, rows]) => {
      const list = rows();
      if (!list.length) return;
      body.append(el("h3", "sec", title));
      const dl = el("dl", "keys-list");
      list.forEach(([keys, what]) => {
        const dt = el("dt");
        keys.split(" ").forEach((k, i) => {
          if (/^(to|or|then)$/.test(k)) dt.append(document.createTextNode(` ${k} `));
          else dt.append(...(i ? [document.createTextNode(" ")] : []), el("kbd", "", k));
        });
        dl.append(dt, el("dd", "", what));
      });
      body.append(dl);
    });
    const row = el("div", "dlg-tools");
    const done = el("button", "btn", "Close", { type: "button" });
    done.onclick = close;
    row.append(el("span", "grow"), done);
    body.append(row);
  });
}

let goUntil = 0;
document.addEventListener("keydown", (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === "Escape") {
    const toggle = $(".bulk-toggle[aria-pressed='true']");
    if (toggle && !dialogOpen() && !typing()) toggle.click();
    return;
  }
  if (typing() || dialogOpen()) return;

  if (goUntil > Date.now()) {
    goUntil = 0;
    e.preventDefault();
    goTo(e.key);
    return;
  }
  switch (e.key) {
    case "?":
      e.preventDefault();
      cheatSheet();
      break;
    case "g":
      goUntil = Date.now() + GO_WINDOW_MS;
      break;
    case "j":
      if (moveRow(1)) e.preventDefault();
      break;
    case "k":
      if (moveRow(-1)) e.preventDefault();
      break;
    case "x": {
      const row = currentRow();
      if (row && $(".bulk-toggle")) {
        e.preventDefault();
        toggleSelectOn(row);
      }
      break;
    }
    case "f": {
      const box = $(
        ".split-list input[type=search], .tools input[type=search], input[type=search]",
      );
      if (box) {
        e.preventDefault();
        box.focus();
        box.select();
      }
      break;
    }
    case "y":
    case "Y": {
      const buttons = $$(".split-pane .host-head .copy-btn");
      const pick = e.key === "Y" ? buttons[buttons.length - 1] : buttons[0];
      if (pick) {
        e.preventDefault();
        pick.click();
      }
      break;
    }
    case ".": {
      const menuButton = currentRow() && $(".row-menu-btn", currentRow());
      if (menuButton) {
        e.preventDefault();
        menuButton.click();
      }
      break;
    }
    case "e": {
      const status = $('.split-pane select[aria-label="Remediation status"]');
      if (status) {
        e.preventDefault();
        status.focus();
      }
      break;
    }
    default:
      if (/^[1-6]$/.test(e.key)) {
        const tab = $$(".host-tabs [role=tab]")[Number(e.key) - 1];
        if (tab) {
          e.preventDefault();
          tab.click();
        }
      }
  }
});

// The palette (shell.js) lists these too; the help entries in the account menu open the sheet.
window.cveCommands = (window.cveCommands || []).filter(
  (c) => c.owner !== "keys",
);
window.cveCommands.push({
  owner: "keys",
  label: "Keyboard shortcuts",
  hint: "Help",
  run: cheatSheet,
});
window.cveCommands.push({
  owner: "keys",
  label: "Select several rows",
  hint: "Action",
  when: () => Boolean($(".bulk-toggle")),
  run: () => $(".bulk-toggle").click(),
});
$$("[data-keys-help]").forEach((b) => b.addEventListener("click", cheatSheet));
