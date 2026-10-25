// "New since you last looked": a per-browser memory of when a page was last visited, used to mark what has appeared since.
// The baseline is read once per page load and kept for the whole visit, so marks stay on screen while you work; the stored time
// moves forward only when you leave or hide the page. Nothing is sent to the server, and a first visit marks nothing.
import { el } from "/staticfiles/cve/ui.js";

const keyFor = (page, slug) => `cve.seen.v1.${slug}.${page}`;

export function sinceLastVisit(page, slug) {
  let baseline = null;
  const stamp = () => {
    try {
      localStorage.setItem(keyFor(page, slug), new Date().toISOString());
    } catch (_) {
      /* private window or blocked storage: marks simply do not persist */
    }
  };
  try {
    baseline = localStorage.getItem(keyFor(page, slug));
  } catch (_) {
    baseline = null;
  }
  if (!baseline) stamp(); // first visit: nothing is new yet, and the next visit has a baseline
  window.addEventListener("pagehide", stamp);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") stamp();
  });
  return baseline;
}

export const isNewSince = (iso, since) => {
  const t = Date.parse(iso || "");
  const s = Date.parse(since || "");
  return Number.isFinite(t) && Number.isFinite(s) && t > s;
};

export const newTag = () =>
  el("span", "new-tag", "New", {
    title: "Appeared since you last looked at this page",
  });

// A "New 3" toggle that narrows a row container to the rows marked data-fresh. update() recounts after rows change.
export function newToggle(rows) {
  const node = el("button", "new-toggle", "", {
    type: "button",
    "aria-pressed": "false",
    title: "Show only what appeared since you last looked",
  });
  node.hidden = true;
  node.onclick = () => {
    const on = !rows.classList.contains("only-new");
    rows.classList.toggle("only-new", on);
    node.setAttribute("aria-pressed", String(on));
  };
  const update = () => {
    const n = rows.querySelectorAll("[data-fresh]").length;
    node.textContent = `New ${n}`;
    node.hidden = n === 0;
    if (n === 0) {
      rows.classList.remove("only-new");
      node.setAttribute("aria-pressed", "false");
    }
  };
  return { node, update };
}
