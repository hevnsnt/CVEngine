// Every page, every user: when the site stops answering (an update going in, a restart), the page covers itself with the "we are
// rebuilding" scene and comes back by itself once the site answers again. The scene is fetched while the site is still up and shown from
// memory (srcdoc), because during the outage nothing can serve it: on some hosts not even the proxy that normally hands it out.
// An administrator's page watching an update (static/cve/updatebar.js) drives the same veil itself and tells this module to stand back.
import { buildAction } from "/staticfiles/cve/build-logic.js";
const SCENE_URL = new URL("maintenance.html", import.meta.url).pathname;
const ALIVE = "/cve/api/alive";
const EVERY_MS = 15000; // while the site is up
const DOWN_MS = 3000; // once a check failed, look again soon
const BACK_MS = 4000; // while veiled
const DOWN_AFTER = 2; // misses in a row before the page is covered: one dropped request is not an outage
const UP_AFTER = 2; // answers in a row before the page reloads
const FRESHEN_MS = 6000; // the longest a hard reload waits for files before reloading anyway

let scene = null;
let veil = null;
let veilText = "";
let managed = false;
let serverBuild = "";
let dirty = false; // the person typed in a field of this page: a build change then offers a reload instead of doing it
const GUARD = "cvengine-build-reloaded"; // sessionStorage: the build this tab last reloaded for, so a build mismatch never loops
const pageBuild = () => {
  const m = document.querySelector('meta[name="cvengine-build"]');
  return m ? m.getAttribute("content") || "" : "";
};
const typed = (e) => {
  if (e.isTrusted) dirty = true;
};
document.addEventListener("input", typed, true);
document.addEventListener("change", typed, true);

export async function loadScene() {
  if (scene) return scene;
  try {
    const r = await fetch(SCENE_URL, { cache: "no-store", credentials: "same-origin" });
    if (r.ok) scene = await r.text();
  } catch (_) {
    /* the iframe falls back to loading it by address */
  }
  return scene;
}

const tell = () => {
  try {
    veil.contentWindow.postMessage({ state: veilText }, location.origin);
  } catch (_) {}
};

export function showVeil(status) {
  const body = [...document.querySelectorAll(".layout, #main")];
  if (!veil) {
    veil = document.createElement("iframe");
    veil.className = "update-veil";
    veil.title = "cvENGINE is being rebuilt";
    if (scene) veil.srcdoc = scene;
    else veil.src = SCENE_URL;
    veil.addEventListener("load", tell);
    document.body.append(veil);
    document.documentElement.classList.add("updating");
    body.forEach((n) => n.setAttribute("inert", ""));
  }
  if (status) {
    veilText = status;
    tell();
  }
}

export function hideVeil() {
  if (!veil) return;
  veil.remove();
  veil = null;
  document.documentElement.classList.remove("updating");
  document.querySelectorAll(".layout, #main").forEach((n) => n.removeAttribute("inert"));
}

// A hard reload, as Ctrl+Shift+R would do it: a script cannot ask for one, so the page refetches itself and every file it or the new
// page use past the browser cache (cache: "reload" overwrites the cached copy), empties Cache Storage, then navigates. After an update
// that means no stale font, image, scene or module a hashed URL does not cover. Bounded, so a slow file never keeps the veil up.
export async function hardReload(to = location.href) {
  const files = new Set();
  const keep = (u) => {
    try {
      const url = new URL(u, location.href);
      if (url.origin === location.origin && url.pathname.startsWith("/staticfiles/")) files.add(url.href);
    } catch (_) {}
  };
  performance.getEntriesByType("resource").forEach((e) => keep(e.name));
  const freshen = async () => {
    try {
      if (window.caches) await Promise.all((await caches.keys()).map((k) => caches.delete(k)));
    } catch (_) {}
    try {
      const html = await (await fetch(to, { cache: "reload", credentials: "same-origin" })).text();
      for (const m of html.matchAll(/(?:src|href)="([^"]+)"|"(\/staticfiles\/[^"]+)"/g)) keep(m[1] || m[2]);
    } catch (_) {}
    await Promise.all([...files].map((u) => fetch(u, { cache: "reload", credentials: "same-origin" }).catch(() => null)));
  };
  await Promise.race([freshen(), new Promise((done) => setTimeout(done, FRESHEN_MS))]);
  if (to === location.href) location.reload();
  else location.replace(to);
}

// the update watcher owns the veil from here on: it knows the phases and where to go when the update is done
export function manageVeil() {
  managed = true;
}

// A page rendered by another build than the one the server runs now (an update went in while it was open, in a background tab, or behind
// back/forward) hard-reloads itself, or offers to when that would lose what was typed. Fed by the poll below and by the Settings Updates
// section, which both read the server's build anyway: no request of its own.
export function noteBuild(server) {
  if (managed || !server) return;
  serverBuild = server;
  let seen = server; // a tab that cannot remember is treated as having reloaded already: it gets the bar, never a loop
  try {
    seen = sessionStorage.getItem(GUARD);
  } catch (_) {}
  const action = buildAction({ page: pageBuild(), server, hidden: document.hidden, dirty, dialog: !!document.querySelector("dialog[open], [aria-modal='true']"), reloadedFor: seen });
  if (action === "reload") {
    try {
      sessionStorage.setItem(GUARD, server);
      return hardReload();
    } catch (_) {}
  }
  if (action === "reload" || action === "bar") showReloadBar();
}

let reloadBar = null;
function showReloadBar() {
  if (reloadBar) return;
  reloadBar = document.createElement("div");
  reloadBar.className = "toast notice";
  reloadBar.setAttribute("role", "status");
  const text = document.createElement("span");
  text.textContent = "A new version is installed.";
  const go = document.createElement("button");
  go.type = "button";
  go.className = "notice-link";
  go.textContent = "Reload";
  go.onclick = () => hardReload();
  const close = document.createElement("button");
  close.type = "button";
  close.className = "notice-close";
  close.textContent = "\u00d7";
  close.setAttribute("aria-label", "Dismiss");
  close.onclick = () => (reloadBar.hidden = true);
  reloadBar.append(text, go, close);
  document.body.append(reloadBar);
}

async function answers() {
  try {
    const r = await fetch(`${ALIVE}?t=${Date.now()}`, { cache: "no-store", credentials: "same-origin", redirect: "manual" });
    if (r.ok) {
      const body = await r.json().catch(() => null);
      serverBuild = (body && body.build) || "";
    }
    return r.type === "opaqueredirect" || r.status < 500; // a 502, 503 (the maintenance page) or 504 is the site being down
  } catch (_) {
    return false;
  }
}

let misses = 0;
let hits = 0;
let timer = 0;
let busy = false;
let last = 0;
const later = (fn, ms) => {
  clearTimeout(timer);
  timer = setTimeout(fn, ms);
};
async function check() {
  if (managed || busy) return;
  if (document.hidden && !veil) return later(check, EVERY_MS);
  busy = true;
  last = Date.now();
  let up;
  try {
    serverBuild = "";
    up = await answers();
  } finally {
    busy = false;
  }
  if (managed) return;
  if (up) {
    misses = 0;
    if (!veil) noteBuild(serverBuild); // while veiled, the reload below brings the new build
    if (veil) {
      hits += 1;
      if (hits >= UP_AFTER) {
        showVeil("Back. Reloading.");
        return hardReload();
      }
      return later(check, BACK_MS);
    }
    if (!scene) loadScene();
    return later(check, EVERY_MS);
  }
  hits = 0;
  misses += 1;
  if (misses >= DOWN_AFTER) {
    showVeil("The site is not answering. This page comes back by itself.");
    return later(check, BACK_MS);
  }
  later(check, DOWN_MS);
}

const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 1500));
idle(() => loadScene());
later(check, EVERY_MS);
window.addEventListener("online", () => later(check, 500));
// A page that was in the background (or asleep, or behind back/forward) skipped its polls: when it is shown again it asks at once, so a page
// from before an update does not stay on screen. At most one extra request, only when the person comes back.
const WAKE_GAP_MS = 3000;
const wake = () => {
  if (!document.hidden && Date.now() - last > WAKE_GAP_MS) later(check, 0);
};
document.addEventListener("visibilitychange", wake);
window.addEventListener("pageshow", (e) => {
  const nav = performance.getEntriesByType("navigation")[0];
  if (e.persisted || (nav && nav.type === "back_forward")) later(check, 0);
});
