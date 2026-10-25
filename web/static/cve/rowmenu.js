// A small actions menu on each list row: copy, open in a new tab, pin, set a status. One popover is shared by every row.
// Keyboard: the menu button is a tab stop inside the row, "." on a focused row opens it, arrows move, Escape closes.
import { el } from "/staticfiles/cve/ui.js";

let current = null; // { button, menu, onKey, onAway }

export function closeRowMenu() {
  if (!current) return;
  const { button, menu, onAway, onKey } = current;
  document.removeEventListener("pointerdown", onAway, true);
  document.removeEventListener("keydown", onKey, true);
  window.removeEventListener("scroll", closeRowMenu, true);
  window.removeEventListener("resize", closeRowMenu);
  menu.remove();
  button.setAttribute("aria-expanded", "false");
  current = null;
}

const DOTS =
  '<circle cx="5" cy="12" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="19" cy="12" r="1.7"/>';

/**
 * @param {HTMLElement} row
 * @param {string} label            what the menu is for ("outbound.example.com"), for the button's accessible name
 * @param {() => Array<{label:string, run:() => void|Promise<void>, danger?:boolean, disabled?:boolean, section?:string}>} itemsFn
 */
export function attachRowMenu(row, label, itemsFn, into = null) {
  const button = el("button", "row-menu-btn", null, {
    type: "button",
    "aria-haspopup": "menu",
    "aria-expanded": "false",
    "aria-label": `Actions for ${label}`,
    title: "Actions",
  });
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = DOTS;
  button.append(svg);
  button.addEventListener("click", (e) => {
    e.stopPropagation();
    e.preventDefault();
    if (current && current.button === button) return closeRowMenu();
    openMenu(button, itemsFn());
  });
  (into || row).append(button);
  return button;
}

function openMenu(button, items) {
  closeRowMenu();
  const menu = el("div", "row-menu", null, {
    role: "menu",
    "aria-label": button.getAttribute("aria-label"),
  });
  let lastSection = null;
  items.forEach((item) => {
    if (item.section && item.section !== lastSection && lastSection !== null)
      menu.append(el("div", "row-menu-sep", null, { role: "separator" }));
    lastSection = item.section || lastSection;
    const b = el(
      "button",
      `row-menu-item${item.danger ? " danger" : ""}`,
      item.label,
      { type: "button", role: "menuitem" },
    );
    if (item.disabled) b.disabled = true;
    b.addEventListener("click", async (e) => {
      e.stopPropagation();
      closeRowMenu();
      button.focus();
      await item.run();
    });
    menu.append(b);
  });
  document.body.append(menu);
  // place under the button, flipping above or to the left when it would leave the screen
  const r = button.getBoundingClientRect();
  const w = menu.offsetWidth;
  const h = menu.offsetHeight;
  menu.style.left = `${Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8))}px`;
  menu.style.top = `${r.bottom + h + 8 > window.innerHeight ? Math.max(8, r.top - h - 4) : r.bottom + 4}px`;
  button.setAttribute("aria-expanded", "true");
  const enabled = () => [...menu.querySelectorAll("button:not([disabled])")];
  const onKey = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      closeRowMenu();
      button.focus();
    } else if (
      e.key === "ArrowDown" ||
      e.key === "ArrowUp" ||
      e.key === "Home" ||
      e.key === "End"
    ) {
      e.preventDefault();
      const list = enabled();
      const at = list.indexOf(document.activeElement);
      const next =
        e.key === "Home"
          ? 0
          : e.key === "End"
            ? list.length - 1
            : (at + (e.key === "ArrowDown" ? 1 : -1) + list.length) %
              list.length;
      list[next].focus();
    } else if (e.key === "Tab") {
      closeRowMenu();
    }
  };
  const onAway = (e) => {
    if (
      !menu.contains(e.target) &&
      e.target !== button &&
      !button.contains(e.target)
    )
      closeRowMenu();
  };
  document.addEventListener("keydown", onKey, true);
  document.addEventListener("pointerdown", onAway, true);
  window.addEventListener("scroll", closeRowMenu, true);
  window.addEventListener("resize", closeRowMenu);
  current = { button, menu, onKey, onAway };
  const first = enabled()[0];
  if (first) first.focus();
}
