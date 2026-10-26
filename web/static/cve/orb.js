// A small particle orb that says what the engine is doing: a sphere of points that spins, breathes or stirs. Monochrome (it takes the
// page's ink color), drawn on a canvas, still when the visitor prefers reduced motion, and paused while off screen or in a hidden tab.
// mountOrb(host, {size, state}) returns {setState(name), destroy()}. Meant as a status light with character, not a chart.
const GOLDEN = Math.PI * (3 - Math.sqrt(5));
const STATES = {
  working: { spin: 1.1, wobble: 0.1, pulse: 0.05, rate: 2.4 },
  searching: { spin: 0.7, wobble: 0.28, pulse: 0.04, rate: 3.1 },
  breathing: { spin: 0.18, wobble: 0.02, pulse: 0.11, rate: 0.9 },
  idle: { spin: 0.08, wobble: 0.0, pulse: 0.04, rate: 0.6 },
};

export function mountOrb(host, { size = 34, state = "breathing" } = {}) {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(size * dpr);
  canvas.height = Math.round(size * dpr);
  canvas.style.width = `${size}px`;
  canvas.style.height = `${size}px`;
  canvas.setAttribute("aria-hidden", "true");
  host.append(canvas);
  const ctx = canvas.getContext("2d");
  const count = Math.round(size * 3.4);
  const pts = Array.from({ length: count }, (_, i) => {
    const y = 1 - (2 * (i + 0.5)) / count;
    const r = Math.sqrt(1 - y * y);
    return { x: Math.cos(i * GOLDEN) * r, y, z: Math.sin(i * GOLDEN) * r, p: (i * 0.618) % 1 };
  });
  let current = STATES[state] || STATES.breathing;
  let blend = 1;
  let from = current;
  let rot = 0;
  let last = 0;
  let raf = 0;
  let visible = true;
  let ink = "20,20,22";
  const readInk = () => {
    const m = /(\d+)[ ,]+(\d+)[ ,]+(\d+)/.exec(getComputedStyle(host).color || "");
    if (m) ink = `${m[1]},${m[2]},${m[3]}`;
  };
  readInk();
  const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function draw(t) {
    const dt = last ? Math.min((t - last) / 1000, 0.05) : 0;
    last = t;
    blend = Math.min(1, blend + dt * 2.5);
    const mix = (k) => from[k] + (current[k] - from[k]) * blend;
    rot += dt * mix("spin");
    const wobble = mix("wobble");
    const pulse = mix("pulse");
    const rate = mix("rate");
    const time = t / 1000;
    const R = (size * dpr) / 2 - 2 * dpr;
    const c = (size * dpr) / 2;
    const tilt = 0.42;
    const cr = Math.cos(rot);
    const sr = Math.sin(rot);
    const ct = Math.cos(tilt);
    const st = Math.sin(tilt);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of pts) {
      // deform the sphere: a slow swell travelling over its surface plus a breathing pulse
      const swell = 1 + wobble * Math.sin(p.y * 4 + time * 1.6 + p.p * 6) + pulse * Math.sin(time * rate + p.p * 6.28);
      const x0 = p.x * swell;
      const y0 = p.y * swell;
      const z0 = p.z * swell;
      const x1 = x0 * cr + z0 * sr;
      const z1 = -x0 * sr + z0 * cr;
      const y2 = y0 * ct - z1 * st;
      const z2 = y0 * st + z1 * ct;
      const depth = (z2 + 1.4) / 2.8; // 0 at the back, 1 at the front
      ctx.fillStyle = `rgba(${ink},${(0.12 + depth * 0.88).toFixed(3)})`;
      ctx.beginPath();
      ctx.arc(c + x1 * R, c + y2 * R, (0.45 + depth * 0.95) * dpr * Math.max(size / 34, 0.8), 0, 6.2832);
      ctx.fill();
    }
  }
  function loop(t) {
    raf = 0;
    if (!visible || document.hidden) return;
    draw(t);
    raf = requestAnimationFrame(loop);
  }
  const start = () => {
    if (!raf && !reduced) {
      last = 0;
      raf = requestAnimationFrame(loop);
    }
  };
  if (reduced) draw(0);
  const io = new IntersectionObserver((entries) => {
    visible = entries.some((e) => e.isIntersecting);
    if (visible) start();
  });
  io.observe(host);
  const onVis = () => {
    if (!document.hidden) start();
  };
  document.addEventListener("visibilitychange", onVis);
  const themeWatch = new MutationObserver(() => {
    readInk();
    if (reduced) draw(0);
  });
  themeWatch.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  start();
  return {
    setState(name) {
      const next = STATES[name] || STATES.breathing;
      if (next === current) return;
      from = { ...current };
      current = next;
      blend = 0;
      if (reduced) draw(0);
    },
    destroy() {
      cancelAnimationFrame(raf);
      io.disconnect();
      themeWatch.disconnect();
      document.removeEventListener("visibilitychange", onVis);
      canvas.remove();
    },
  };
}
