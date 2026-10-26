// Small dependency-free SVG charts for the Thermal UI. DOM is built with textContent only.
// areaChart: a daily series with range tabs, a scrubbing tooltip and arrow-key access.
const NS = "http://www.w3.org/2000/svg";
const DAY = 86400000;
const W = 640;
const H = 200;
const PAD = { t: 14, b: 6 };

const h = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const s = (tag, attrs = {}) => {
  const n = document.createElementNS(NS, tag);
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};

const dayKey = (d) =>
  new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
const fmtDay = (ms) =>
  new Date(ms).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });

// Bucket ISO timestamps into one count per local day, ending today.
export function dailyCounts(isoDates, days) {
  const end = dayKey(new Date());
  const counts = new Map();
  isoDates.forEach((iso) => {
    const d = new Date(iso);
    if (!Number.isNaN(d.getTime()))
      counts.set(dayKey(d), (counts.get(dayKey(d)) || 0) + 1);
  });
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const t = end - i * DAY;
    out.push({ t, v: counts.get(t) || 0 });
  }
  return out;
}

// Catmull-Rom through the points, as a cubic Bezier path (clamped so it never dips below zero).
function smooth(pts, floor) {
  if (pts.length < 2) return "";
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] || p2;
    const c1y = Math.min(floor, p1[1] + (p2[1] - p0[1]) / 6);
    const c2y = Math.min(floor, p2[1] - (p3[1] - p1[1]) / 6);
    d += `C${p1[0] + (p2[0] - p0[0]) / 6},${c1y} ${p2[0] - (p3[0] - p1[0]) / 6},${c2y} ${p2[0]},${p2[1]}`;
  }
  return d;
}

/**
 * @param {{title:string, unit?:string, ranges:[string, number][], dates:string[], defaultRange?:string}} opts
 *   dates: ISO timestamps, one per event. ranges: label and days, e.g. [["7D",7],["30D",30],["90D",90]].
 */
export function areaChart({
  title,
  unit = "events",
  ranges,
  dates,
  defaultRange,
  compare = true,
}) {
  const root = h("section", "card chart");
  const head = h("div", "chart-head");
  const lead = h("div");
  const tabs = h("div", "chart-ranges");
  tabs.setAttribute("role", "group");
  tabs.setAttribute("aria-label", `${title} range`);
  head.append(lead, tabs);

  const total = h("b", "chart-total");
  const delta = h("span", "chart-delta");
  lead.append(h("span", "eyebrow", title), h("div", "chart-big"));
  lead.lastChild.append(total, delta);

  const stage = h("div", "chart-stage");
  stage.tabIndex = 0;
  stage.setAttribute("role", "img");
  const svg = s("svg", {
    viewBox: `0 0 ${W} ${H}`,
    preserveAspectRatio: "none",
    "aria-hidden": "true",
  });
  const grid = s("g", { class: "chart-grid" });
  const area = s("path", { class: "chart-area" });
  const line = s("path", { class: "chart-line" });
  const cursor = s("line", { class: "chart-cursor", y1: PAD.t, y2: H - PAD.b });
  svg.append(grid, area, line, cursor);
  const dot = h("i", "chart-dot");
  const tip = h("div", "chart-tip");
  tip.setAttribute("aria-live", "polite");
  const axis = h("div", "chart-axis");
  stage.append(svg, dot, tip);
  root.append(head, stage, axis);

  let series = [];
  let active = defaultRange || ranges[Math.min(1, ranges.length - 1)][0];
  let index = -1;
  let max = 1;
  const x = (i) => (series.length < 2 ? W / 2 : (i / (series.length - 1)) * W);
  const y = (v) => H - PAD.b - (v / max) * (H - PAD.t - PAD.b);

  function showAt(i) {
    index = Math.max(0, Math.min(series.length - 1, i));
    const p = series[index];
    const fx = x(index) / W;
    const fy = y(p.v) / H;
    cursor.setAttribute("x1", x(index));
    cursor.setAttribute("x2", x(index));
    cursor.style.opacity = 1;
    dot.style.cssText = `left:${fx * 100}%;top:${fy * 100}%;opacity:1`;
    tip.textContent = `${fmtDay(p.t)}: ${p.v} ${unit}`;
    tip.style.cssText = `left:${Math.min(86, Math.max(14, fx * 100))}%;opacity:1`;
  }
  function hide() {
    index = -1;
    cursor.style.opacity = 0;
    dot.style.opacity = 0;
    tip.style.opacity = 0;
  }

  function draw() {
    const days = ranges.find((r) => r[0] === active)[1];
    series = dailyCounts(dates, days * 2).slice(days); // second half is the range, first half is the comparison
    const prev = dailyCounts(dates, days * 2)
      .slice(0, days)
      .reduce((n, p) => n + p.v, 0);
    const sum = series.reduce((n, p) => n + p.v, 0);
    max = Math.max(1, ...series.map((p) => p.v));
    const floor = H - PAD.b;
    const pts = series.map((p, i) => [x(i), y(p.v)]);
    const d = smooth(pts, floor);
    line.setAttribute("d", d);
    area.setAttribute("d", d ? `${d}L${W},${floor}L0,${floor}Z` : "");
    grid.textContent = "";
    [0.25, 0.5, 0.75].forEach((f) => {
      const gy = PAD.t + (H - PAD.t - PAD.b) * f;
      grid.append(s("line", { x1: 0, x2: W, y1: gy, y2: gy }));
    });
    total.textContent = sum;
    const change =
      prev === 0 ? (sum ? null : 0) : Math.round(((sum - prev) / prev) * 100);
    delta.hidden = !compare;
    delta.textContent =
      change == null
        ? "new"
        : change === 0
          ? "no change"
          : `${change > 0 ? "+" : ""}${change}%`;
    delta.dataset.dir =
      change == null || change > 0 ? "up" : change < 0 ? "down" : "flat";
    axis.textContent = "";
    [0, Math.floor((series.length - 1) / 2), series.length - 1].forEach((i) =>
      axis.append(h("span", "", fmtDay(series[i].t))),
    );
    stage.setAttribute(
      "aria-label",
      `${title}, ${active}: ${sum} ${unit}, peak ${max} in one day. Use the arrow keys to read each day.`,
    );
    tabs
      .querySelectorAll("button")
      .forEach((b) =>
        b.setAttribute("aria-pressed", String(b.dataset.range === active)),
      );
    hide();
    root.classList.remove("redraw");
    void root.offsetWidth; // restart the draw-in animation
    root.classList.add("redraw");
  }

  ranges.forEach(([label]) => {
    const b = h("button", "", label);
    b.type = "button";
    b.dataset.range = label;
    b.onclick = () => {
      active = label;
      draw();
    };
    tabs.append(b);
  });

  const fromPointer = (e) => {
    const r = stage.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
    showAt(Math.round(f * (series.length - 1)));
  };
  stage.addEventListener("pointermove", fromPointer);
  stage.addEventListener("pointerdown", fromPointer);
  stage.addEventListener("pointerleave", hide);
  stage.addEventListener("blur", hide);
  stage.addEventListener("keydown", (e) => {
    const step = {
      ArrowLeft: -1,
      ArrowRight: 1,
      Home: -Infinity,
      End: Infinity,
    }[e.key];
    if (step == null) return;
    e.preventDefault();
    showAt(index < 0 ? (step < 0 ? series.length - 1 : 0) : index + step);
  });

  draw();
  return root;
}

/**
 * Contribution calendar: one cell per day for the last `weeks` weeks, weeks as columns, Monday on top.
 * @param {{title:string, unit?:string, dates:string[], weeks?:number}} opts
 */
export function heatmap({ title, unit = "events", dates, weeks = 18 }) {
  const root = h("section", "card chart heat");
  const head = h("div", "chart-head");
  const total = h("b", "chart-total");
  const lead = h("div");
  const big = h("div", "chart-big");
  big.append(total, h("span", "chart-delta", `last ${weeks} weeks`));
  lead.append(h("span", "eyebrow", title), big);
  const readout = h("span", "heat-read note", "Hover a day");
  readout.setAttribute("aria-live", "polite");
  head.append(lead, readout);

  const counts = new Map();
  dates.forEach((iso) => {
    const d = new Date(iso);
    if (!Number.isNaN(d.getTime())) counts.set(dayKey(d), (counts.get(dayKey(d)) || 0) + 1);
  });
  const today = dayKey(new Date());
  const dow = (new Date(today).getDay() + 6) % 7; // Monday = 0
  const start = today - (dow + (weeks - 1) * 7) * DAY;
  const days = [];
  for (let t = start; t <= today; t += DAY) days.push({ t, v: counts.get(t) || 0 });
  const peak = Math.max(1, ...days.map((d) => d.v));
  const sum = days.reduce((n, d) => n + d.v, 0);
  total.textContent = sum;

  const grid = h("div", "heat-grid");
  grid.setAttribute("role", "img");
  grid.setAttribute("aria-label", `${title}: ${sum} ${unit} over the last ${weeks} weeks, busiest day ${peak}.`);
  grid.style.setProperty("--weeks", weeks);
  days.forEach((d) => {
    const c = h("i", "heat-cell");
    c.dataset.level = d.v === 0 ? 0 : Math.min(4, Math.ceil((d.v / peak) * 4));
    c.title = `${fmtDay(d.t)}: ${d.v} ${unit}`;
    c.addEventListener("pointerenter", () => {
      readout.textContent = `${new Date(d.t).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })}: ${d.v} ${unit}`;
    });
    grid.append(c);
  });
  grid.addEventListener("pointerleave", () => (readout.textContent = "Hover a day"));

  const legend = h("div", "heat-legend");
  legend.append(h("span", "", "Less"));
  [0, 1, 2, 3, 4].forEach((l) => {
    const c = h("i", "heat-cell");
    c.dataset.level = l;
    legend.append(c);
  });
  legend.append(h("span", "", "More"));
  root.append(head, grid, legend);
  return root;
}

/**
 * A small trend line for a counter: the last days as a line with the latest point marked. Decorative (aria-hidden); the number
 * beside it is the real information.
 * @param {number[]} values one number per day, oldest first
 */
export function sparkline(values) {
  const W = 120;
  const H = 24;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "spark");
  svg.setAttribute("aria-hidden", "true");
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => [values.length < 2 ? W / 2 : (i / (values.length - 1)) * W, H - 3 - (v / max) * (H - 8)]);
  const line = document.createElementNS(NS, "polyline");
  line.setAttribute("points", pts.map((p) => p.join(",")).join(" "));
  line.setAttribute("class", "spark-line");
  svg.append(line);
  const last = pts[pts.length - 1];
  if (last) {
    const dot = document.createElementNS(NS, "circle");
    dot.setAttribute("cx", last[0]);
    dot.setAttribute("cy", last[1]);
    dot.setAttribute("r", "2.4");
    dot.setAttribute("class", "spark-dot");
    svg.append(dot);
  }
  return svg;
}

/**
 * A two-row activity matrix: one cell per day, a week per column, as wide as the card allows. A "tiered" row colors each day by its
 * worst temperature (fire, smoke, ice) and shades it by how many arrived; a plain row shades by count. Beside each grid sit the
 * totals, split by temperature, and the busiest day.
 * @param {{title:string, rows:Array<{key:string,label:string,unit:string,tiered?:boolean,items:Array<{date:string,tier?:string}>}>}} spec
 */
const TIER_NAMES = ["fire", "smoke", "ice"];
const MATRIX_CELL = 16;
const MATRIX_GAP = 4;
const MATRIX_MAX_WEEKS = 30;
const plural = (n, unit) => `${n} ${unit}`;

export function activityMatrix({ title, rows }) {
  const root = h("section", "card chart matrix");
  const head = h("div", "mx-head");
  head.append(h("span", "eyebrow", title));
  const readout = h("span", "mx-read note", "Hover a day");
  readout.setAttribute("aria-live", "polite");
  const legend = h("div", "mx-legend");
  legend.setAttribute("aria-hidden", "true");
  TIER_NAMES.forEach((t) => {
    const k = h("span", "");
    k.append(h("i", `mx-key ${t}`), document.createTextNode(t[0].toUpperCase() + t.slice(1)));
    legend.append(k);
  });
  legend.append(h("span", "mx-scale", "Less"));
  [1, 2, 3, 4].forEach((l) => {
    const i = h("i", "mx-key level");
    i.dataset.level = l;
    legend.append(i);
  });
  legend.append(h("span", "mx-scale", "More"));
  head.append(readout, legend);
  root.append(head);

  const views = rows.map((row) => {
    const box = h("div", "mx-row");
    const lead = h("div", "mx-lead");
    const total = h("b", "mx-total");
    lead.append(h("span", "eyebrow", row.label), total);
    const gridWrap = h("div", "mx-grid-wrap");
    const side = h("div", "mx-side");
    box.append(lead, gridWrap, side);
    root.append(box);
    // bucket the items per local day, with the count per temperature
    const days = new Map();
    row.items.forEach((it) => {
      const d = new Date(it.date);
      if (Number.isNaN(d.getTime())) return;
      const k = dayKey(d);
      const e = days.get(k) || { n: 0, fire: 0, smoke: 0, ice: 0 };
      e.n += 1;
      if (row.tiered && TIER_NAMES.includes(it.tier)) e[it.tier] += 1;
      days.set(k, e);
    });
    return { row, gridWrap, total, side, days };
  });

  const paint = () => {
    const today = dayKey(new Date());
    const dow = (new Date(today).getDay() + 6) % 7; // Monday = 0
    views.forEach(({ row, gridWrap, total, side, days }) => {
      const avail = Math.max(gridWrap.clientWidth, 200);
      const weeks = Math.max(8, Math.min(MATRIX_MAX_WEEKS, Math.floor((avail + MATRIX_GAP) / (MATRIX_CELL + MATRIX_GAP))));
      const start = today - (dow + (weeks - 1) * 7) * DAY;
      const list = [];
      for (let t = start; t <= today; t += DAY) list.push({ t, e: days.get(t) || { n: 0, fire: 0, smoke: 0, ice: 0 } });
      const peak = Math.max(1, ...list.map((d) => d.e.n));
      const sum = list.reduce((n, d) => n + d.e.n, 0);
      const byTier = TIER_NAMES.map((t) => list.reduce((n, d) => n + d.e[t], 0));
      const busiest = list.reduce((b, d) => (d.e.n > b.e.n ? d : b), list[0]);
      total.textContent = sum.toLocaleString();

      const grid = h("div", "mx-grid");
      grid.style.setProperty("--weeks", weeks);
      grid.setAttribute("role", "img");
      grid.setAttribute("aria-label", `${row.label}: ${sum} ${row.unit} over the last ${weeks} weeks${sum ? `, busiest day ${peak}` : ""}.`);
      list.forEach((d) => {
        const c = h("i", "mx-cell");
        const level = d.e.n === 0 ? 0 : Math.min(4, Math.ceil((d.e.n / peak) * 4));
        c.dataset.level = level;
        if (row.tiered && d.e.n) c.dataset.tier = d.e.fire ? "fire" : d.e.smoke ? "smoke" : "ice";
        const day = new Date(d.t).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
        const split = row.tiered && d.e.n ? ` (${TIER_NAMES.filter((t) => d.e[t]).map((t) => `${d.e[t]} ${t}`).join(", ")})` : "";
        c.title = `${day}: ${plural(d.e.n, row.unit)}${split}`;
        c.addEventListener("pointerenter", () => (readout.textContent = `${row.label}, ${day}: ${plural(d.e.n, row.unit)}${split}`));
        grid.append(c);
      });
      grid.addEventListener("pointerleave", () => (readout.textContent = "Hover a day"));
      gridWrap.replaceChildren(grid);

      side.replaceChildren();
      if (row.tiered) {
        TIER_NAMES.forEach((t, i) => {
          const line = h("span", "mx-stat");
          line.append(h("i", `mx-key ${t}`), h("b", "", String(byTier[i])), document.createTextNode(` ${t}`));
          side.append(line);
        });
      }
      const busy = h("span", "mx-busy note", busiest.e.n ? `Busiest: ${fmtDay(busiest.t)}, ${busiest.e.n}` : "Nothing in this window");
      side.append(busy);
    });
  };
  new ResizeObserver(() => requestAnimationFrame(paint)).observe(root);
  requestAnimationFrame(paint);
  return root;
}
