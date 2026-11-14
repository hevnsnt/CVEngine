// One status strip for every page: scannerbar.js (what the scanners are doing) and alertbar.js (an App Admin's open alerts) both report here, and
// this draws a single 40px line above the page: the first notice, how many there are, and a Details button that opens every notice in full.
// Every word is set with textContent (a notice can quote a Sentinel's error or what a scanned host said, and none of it is ever HTML).
import { renderKeepingState } from "/staticfiles/cve/keep-state.js";

const el = (tag, cls, text, attrs) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  if (attrs) for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
};
const KEY = "cve.statusstrip.dismissed"; // sessionStorage: notes the viewer dismissed in this browser session, by their exact text
const sources = new Map(); // source -> [{kind, text, node?, rank, dismissible}]
let strip = null;
let open = false;

function dismissed() {
  try {
    return JSON.parse(window.sessionStorage.getItem(KEY) || "[]");
  } catch (_) {
    return [];
  }
}
function dismiss(text) {
  try {
    window.sessionStorage.setItem(KEY, JSON.stringify([...new Set([...dismissed(), text])]));
  } catch (_) {
    /* storage blocked: the note stays until the page is reloaded */
  }
  paint(true);
}

// force: a person pressed a button (dismiss, Details), which is not a poll and is drawn at once; a notice that arrived by polling waits while they use the strip
function paint(force = false) {
  const gone = dismissed();
  const items = [...sources.values()]
    .flat()
    .filter((i) => !(i.dismissible && gone.includes(i.text)))
    .sort((a, b) => a.rank - b.rank);
  if (!items.length) {
    if (strip) strip.remove();
    strip = null;
    return;
  }
  if (!strip) {
    const layout = document.querySelector(".layout") || document.getElementById("main");
    if (!layout || !layout.parentNode) return;
    strip = el("div", "scannerbar", null, { role: "status" });
    layout.parentNode.insertBefore(strip, layout);
  }
  const lead = el("span", "sb-lead", items[0].text, { title: items[0].text });
  const bar = el("div", "sb-strip", null, { "data-keep-key": "bar" });
  bar.append(lead);
  if (items.length > 1) bar.append(el("span", "sb-count", `${items.length} notices`));
  const details = el("div", "sb-details", null, { id: "sb-details", "data-keep-key": "details", "data-keep-fresh": "" });
  details.hidden = !open;
  for (const i of items) {
    if (i.node) {
      details.append(i.node);
      continue;
    }
    const row = el("div", `sb-row sb-row-${i.kind}`);
    row.append(el("p", `sb-${i.kind}`, i.text));
    if (i.dismissible) {
      const b = el("button", "btn sm ghost sb-dismiss", "Dismiss for this session", { type: "button" });
      b.addEventListener("click", () => dismiss(i.text));
      row.append(b);
    }
    details.append(row);
  }
  const toggle = el("button", "sb-toggle", open ? "Hide details" : "Details", { type: "button", "aria-expanded": String(open), "aria-controls": "sb-details" });
  toggle.addEventListener("click", () => {
    open = !open;
    paint(true);
    const again = strip && strip.querySelector(".sb-toggle");
    if (again) again.focus();
  });
  bar.append(toggle);
  // on a phone the whole line is the button: a tap anywhere on it opens the notices
  bar.addEventListener("click", (e) => {
    if (!e.target.closest("button")) toggle.click();
  });
  renderKeepingState(strip, () => [bar, details], { force });
}

// source: "scanner" or "alerts"; items: [{kind, text, rank, dismissible?, node?}]. An empty list takes the source's notices away.
export function setNotices(source, items) {
  if (items && items.length) sources.set(source, items);
  else sources.delete(source);
  paint();
}
