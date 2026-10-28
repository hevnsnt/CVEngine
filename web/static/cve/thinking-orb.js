// The Thinking Orb (easyui.site/components/thinking-orb), ported from its React component to a plain module: a sphere of particles on a
// golden spiral, drawn on a canvas, whose motion follows a "cognitive state" preset. Monochrome like the original: luminous white on a dark
// theme, graphite on a light one, following the page's data-theme. thinkingOrb() returns {node, setState, setPaused, destroy}; changing the
// state keeps the same particles, so a live page can update it every few seconds without the orb restarting.

const STATE_CONFIG = {
  working: {
    energy: 0.8,
    turbulence: 0.2,
    rotation: 0.35,
    pulse: 0.7,
    compression: 1.0,
    wave: 0.2,
    drift: 0.12,
    coreGlow: 0.9,
  },
  searching: {
    energy: 1.15,
    turbulence: 0.5,
    rotation: 0.8,
    pulse: 0.55,
    compression: 1.02,
    wave: 0.45,
    drift: 0.28,
    coreGlow: 0.75,
  },
  solving: {
    energy: 1.35,
    turbulence: 0.7,
    rotation: 0.95,
    pulse: 0.85,
    compression: 0.92,
    wave: 0.65,
    drift: 0.38,
    coreGlow: 1.0,
  },
  listening: {
    energy: 0.4,
    turbulence: 0.08,
    rotation: 0.12,
    pulse: 1.2,
    compression: 1.04,
    wave: 0.06,
    drift: 0.03,
    coreGlow: 0.65,
  },
  connecting: {
    energy: 0.95,
    turbulence: 0.28,
    rotation: 1.3,
    pulse: 0.5,
    compression: 1.0,
    wave: 0.3,
    drift: 0.4,
    coreGlow: 0.85,
  },
  weaving: {
    energy: 1.1,
    turbulence: 0.6,
    rotation: 0.45,
    pulse: 0.65,
    compression: 0.88,
    wave: 0.9,
    drift: 0.25,
    coreGlow: 0.8,
  },
  composing: {
    energy: 0.75,
    turbulence: 0.18,
    rotation: 0.2,
    pulse: 0.9,
    compression: 0.75,
    wave: 0.35,
    drift: 0.1,
    coreGlow: 0.7,
  },
  breathing: {
    energy: 0.25,
    turbulence: 0.04,
    rotation: 0.06,
    pulse: 1.5,
    compression: 1.1,
    wave: 0.03,
    drift: 0.02,
    coreGlow: 0.5,
  },
  shaping: {
    energy: 0.95,
    turbulence: 0.42,
    rotation: 0.5,
    pulse: 0.7,
    compression: 0.92,
    wave: 0.75,
    drift: 0.25,
    coreGlow: 0.85,
  },
};
export const ORB_STATES = Object.keys(STATE_CONFIG);

function particles(count) {
  return Array.from({ length: count }, (_, i) => ({
    // golden spiral distribution across a spherical shell
    phi: Math.acos(1 - (2 * (i + 0.5)) / count),
    theta: Math.PI * (1 + Math.sqrt(5)) * i,
    radius: 0.75 + Math.random() * 0.25,
    speed: 0.15 + Math.random() * 0.85,
    size: 0.4 + Math.random() * 1.1,
    phase: Math.random() * Math.PI * 2,
    depth: Math.random(),
  }));
}

const themeIsDark = () =>
  document.documentElement.getAttribute("data-theme") === "dark";

export function thinkingOrb({
  state = "working",
  size = 64,
  speed = 1,
  dark,
  paused = false,
  label,
} = {}) {
  const node = document.createElement("span");
  node.className = "thinking-orb";
  node.style.cssText = `display:inline-flex;position:relative;width:${size}px;height:${size}px;flex-shrink:0;overflow:visible`;
  node.setAttribute("role", "img");
  const canvas = document.createElement("canvas");
  canvas.setAttribute("aria-hidden", "true");
  canvas.style.cssText = `display:block;width:${size}px;height:${size}px`;
  node.append(canvas);
  const ctx = canvas.getContext("2d");

  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = size * ratio;
  canvas.height = size * ratio;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

  const count = size <= 24 ? 45 : size <= 48 ? 90 : size <= 80 ? 160 : 220;
  const dots = particles(count);
  const center = size / 2;
  const baseRadius = size * 0.36;
  const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let isDark = dark !== undefined ? dark : themeIsDark();
  let time = 0;
  let last = 0;
  let frame = null;
  let visible = true;

  const render = (timestamp) => {
    const delta = last === 0 ? 16 : Math.min(timestamp - last, 40);
    last = timestamp;
    if (!paused && !motion.matches) time += (delta / 1000) * speed;
    const config = STATE_CONFIG[state] || STATE_CONFIG.working;
    ctx.clearRect(0, 0, size, size);

    // 1. atmospheric halo
    const halo = ctx.createRadialGradient(
      center,
      center,
      0,
      center,
      center,
      baseRadius * 1.55,
    );
    if (isDark) {
      halo.addColorStop(0, "rgba(255, 255, 255, 0.06)");
      halo.addColorStop(0.35, "rgba(255, 255, 255, 0.02)");
      halo.addColorStop(0.7, "rgba(255, 255, 255, 0.005)");
      halo.addColorStop(1, "rgba(0, 0, 0, 0)");
    } else {
      halo.addColorStop(0, "rgba(0, 0, 0, 0.05)");
      halo.addColorStop(0.4, "rgba(0, 0, 0, 0.015)");
      halo.addColorStop(0.8, "rgba(0, 0, 0, 0.003)");
      halo.addColorStop(1, "rgba(255, 255, 255, 0)");
    }
    ctx.fillStyle = halo;
    ctx.fillRect(0, 0, size, size);

    // 2. breathing and global precession
    const breathing =
      1 + Math.sin(time * config.pulse * 1.35) * 0.045 * config.energy;
    const rotation = time * config.rotation * 0.65;

    // 3. the particles
    for (const p of dots) {
      let theta = p.theta + rotation * (0.65 + p.depth * 0.45);
      let phi = p.phi;
      const wave =
        Math.sin(theta * 3 + time * (1.05 + config.energy * 0.8)) *
        Math.cos(phi * 3 - time * 0.5);
      let r =
        p.radius *
        breathing *
        config.compression *
        (1 + wave * config.turbulence * 0.06);

      if (state === "searching") {
        r += Math.sin(time * 1.6 + p.phase) * 0.03;
        theta += Math.sin(time * 1.2 + p.phase) * 0.02;
      } else if (state === "solving") {
        const converge = Math.sin(time * 2.8 + p.phase);
        r += converge * 0.045;
        phi += converge * 0.02;
      } else if (state === "listening") {
        r += Math.sin(time * 0.75 + p.phase) * 0.012;
      } else if (state === "connecting") {
        theta += p.radius * time * 0.5;
        phi += Math.sin(time * 1.1 + p.phase) * 0.03;
      } else if (state === "weaving") {
        theta += Math.sin(phi * 6 + time * 1.4) * 0.05;
        phi += Math.cos(theta * 4 + time * 1.1) * 0.045;
      } else if (state === "composing") {
        r *= 0.96;
        phi += Math.sin(time * 1.4 + p.phase) * 0.015;
      } else if (state === "shaping") {
        r *= 1 + Math.sin(theta * 2 + time * 0.9) * 0.08;
      }

      let x = Math.sin(phi) * Math.cos(theta) * r;
      let y = Math.cos(phi) * r;
      const z = Math.sin(phi) * Math.sin(theta);
      const flow = Math.sin(theta * 3 + time) * Math.sin(phi * 2 - time * 0.4);
      x += flow * config.wave * 0.025;
      y += Math.cos(theta * 2 - time * 0.8) * config.wave * 0.02;

      const perspective = 1 / (1.22 - z * 0.22);
      const sx = center + x * baseRadius * perspective;
      const sy = center + y * baseRadius * perspective;
      const depth = (z + 1) / 2;
      const pSize = p.size * (0.5 + depth * 0.85) * (size / 64);
      let alpha = (0.2 + depth * 0.8) * (0.25 + p.depth * 0.55) * config.energy;
      if (depth < 0.25) alpha *= 0.5;
      alpha = Math.min(Math.max(alpha, 0.05), 0.95);

      if (config.energy > 0.8 && pSize > 0.85 && size >= 48) {
        const trailLen = p.speed * config.rotation * 2.2;
        const tx = sx - Math.cos(theta) * trailLen;
        const ty = sy - Math.sin(theta) * trailLen;
        const trail = ctx.createLinearGradient(tx, ty, sx, sy);
        trail.addColorStop(
          0,
          isDark ? "rgba(255, 255, 255, 0)" : "rgba(20, 20, 26, 0)",
        );
        trail.addColorStop(
          1,
          isDark
            ? `rgba(255, 255, 255, ${alpha * 0.18})`
            : `rgba(20, 20, 26, ${alpha * 0.22})`,
        );
        ctx.strokeStyle = trail;
        ctx.lineWidth = Math.max(pSize * 0.5, 0.35);
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(sx, sy);
        ctx.stroke();
      }

      if (size >= 40 && depth > 0.4) {
        ctx.shadowBlur = pSize * 4.5;
        ctx.shadowColor = isDark
          ? `rgba(255, 255, 255, ${alpha * 0.35})`
          : `rgba(0, 0, 0, ${alpha * 0.2})`;
      } else {
        ctx.shadowBlur = 0;
      }
      ctx.beginPath();
      ctx.arc(sx, sy, Math.max(pSize, 0.35), 0, Math.PI * 2);
      ctx.fillStyle = isDark
        ? `rgba(255, 255, 255, ${alpha})`
        : `rgba(20, 20, 28, ${alpha})`;
      ctx.fill();
      ctx.shadowBlur = 0;

      const sparkle = Math.sin(time * (1.5 + p.speed) + p.phase * 5);
      if (sparkle > 0.99 && depth > 0.7 && size >= 48) {
        const s = pSize * 2;
        ctx.strokeStyle = isDark
          ? `rgba(255, 255, 255, ${alpha * 0.7})`
          : `rgba(20, 20, 28, ${alpha * 0.75})`;
        ctx.lineWidth = 0.4;
        ctx.beginPath();
        ctx.moveTo(sx - s, sy);
        ctx.lineTo(sx + s, sy);
        ctx.moveTo(sx, sy - s);
        ctx.lineTo(sx, sy + s);
        ctx.stroke();
      }
    }

    // 4. the breathing core
    const corePulse =
      1 + Math.sin(time * config.pulse * 1.7) * 0.1 * config.coreGlow;
    const coreRadius = size * 0.046 * corePulse;
    const bloom = ctx.createRadialGradient(
      center,
      center,
      0,
      center,
      center,
      coreRadius * 4.2,
    );
    if (isDark) {
      bloom.addColorStop(0, "rgba(255, 255, 255, 0.92)");
      bloom.addColorStop(0.18, "rgba(255, 255, 255, 0.55)");
      bloom.addColorStop(0.4, "rgba(240, 240, 248, 0.18)");
      bloom.addColorStop(0.7, "rgba(220, 220, 235, 0.04)");
      bloom.addColorStop(1, "rgba(0, 0, 0, 0)");
    } else {
      bloom.addColorStop(0, "rgba(18, 18, 24, 0.92)");
      bloom.addColorStop(0.2, "rgba(35, 35, 45, 0.5)");
      bloom.addColorStop(0.45, "rgba(70, 70, 85, 0.16)");
      bloom.addColorStop(0.75, "rgba(100, 100, 120, 0.03)");
      bloom.addColorStop(1, "rgba(255, 255, 255, 0)");
    }
    ctx.shadowBlur = size * 0.14;
    ctx.shadowColor = isDark
      ? "rgba(255, 255, 255, 0.25)"
      : "rgba(0, 0, 0, 0.15)";
    ctx.beginPath();
    ctx.arc(center, center, coreRadius * 4.2, 0, Math.PI * 2);
    ctx.fillStyle = bloom;
    ctx.fill();
    ctx.shadowBlur = 0;

    // 5. the pinpoint hot center
    const hot = ctx.createRadialGradient(
      center,
      center,
      0,
      center,
      center,
      coreRadius * 0.95,
    );
    if (isDark) {
      hot.addColorStop(0, "rgba(255, 255, 255, 0.98)");
      hot.addColorStop(0.45, "rgba(255, 255, 255, 0.45)");
      hot.addColorStop(1, "rgba(255, 255, 255, 0)");
    } else {
      hot.addColorStop(0, "rgba(10, 10, 15, 0.98)");
      hot.addColorStop(0.45, "rgba(30, 30, 40, 0.45)");
      hot.addColorStop(1, "rgba(0, 0, 0, 0)");
    }
    ctx.beginPath();
    ctx.arc(center, center, coreRadius * 0.95, 0, Math.PI * 2);
    ctx.fillStyle = hot;
    ctx.fill();

    if (!visible || paused || motion.matches) {
      frame = null;
      return;
    }
    frame = requestAnimationFrame(render);
  };
  const start = () => {
    if (frame === null && visible && !paused && !motion.matches)
      frame = requestAnimationFrame(render);
  };
  const stop = () => {
    if (frame !== null) cancelAnimationFrame(frame);
    frame = null;
  };

  // only animate while on screen, as the original does
  const seen =
    typeof IntersectionObserver === "function"
      ? new IntersectionObserver(
          ([entry]) => {
            visible = entry
              ? entry.isIntersecting || entry.intersectionRatio > 0
              : true;
            if (visible) start();
            else stop();
          },
          { rootMargin: "100px 0px" },
        )
      : null;
  if (seen) seen.observe(canvas);
  // follow the page's theme when no theme was forced
  const themed =
    dark === undefined
      ? new MutationObserver(() => {
          isDark = themeIsDark();
          if (frame === null) render(performance.now());
        })
      : null;
  if (themed)
    themed.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
  const onMotion = () => (motion.matches ? stop() : start());
  motion.addEventListener("change", onMotion);

  const describe = () =>
    node.setAttribute("aria-label", label || `${state} orb`);
  describe();
  render(performance.now());

  return {
    node,
    setState(next, nextLabel) {
      if (nextLabel !== undefined) label = nextLabel;
      if (next && next !== state && STATE_CONFIG[next]) state = next;
      describe();
      if (frame === null) render(performance.now());
    },
    setPaused(on) {
      paused = Boolean(on);
      if (paused) {
        stop();
        render(performance.now());
      } else {
        last = 0;
        start();
      }
    },
    destroy() {
      stop();
      if (seen) seen.disconnect();
      if (themed) themed.disconnect();
      motion.removeEventListener("change", onMotion);
      node.remove();
    },
  };
}
