// Every page, every user: a quiet strip when work is waiting for a scanner. It is not the scanning pause (nothing is held and nothing has failed) and not the
// update bar: it is read from /cve/api/scanner, which derives it from the Sentinels' own heartbeats, so it disappears by itself when a scanner reconnects.
// The second sentence (a kind no scanner ever registered for) is sent to an App Admin only and is the louder of the two.
import { fmtTime, zoneLabel } from "/staticfiles/cve/prefs.js";

const EVERY_MS = 60000;
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

let bar = null;

// The server words the retry time in UTC; the page shows it in the zone every other time on the page uses (prefs.js).
function coolingText(s) {
  const times = Object.values(s.cooling || {}).map((r) => Date.parse(r.retry_at)).filter((t) => !Number.isNaN(t));
  if (!times.length) return s.cooling_message;
  const local = `${fmtTime(new Date(Math.min(...times)).toISOString(), false)} (${zoneLabel()})`;
  return s.cooling_message.replace(/ at \d\d:\d\d UTC/, ` at ${local}`);
}

function paint(s) {
  const lines = [];
  if (s && s.message) lines.push(["waiting", s.message]);
  if (s && s.cooling_message) lines.push(["cooling", coolingText(s)]); // the scanner is online; a kind failed repeatedly and is withheld until its retry time
  if (s && s.disabled_message) lines.push(["disabled", s.disabled_message]); // turned off by a setting, not a scanner that is gone
  if (s && s.never_seen_message) lines.push(["never", s.never_seen_message]);
  if (!lines.length) {
    if (bar) bar.remove();
    bar = null;
    return;
  }
  if (!bar) {
    const layout = document.querySelector(".layout") || document.getElementById("main");
    if (!layout) return;
    bar = el("div", "scannerbar");
    bar.setAttribute("role", "status");
    layout.parentNode.insertBefore(bar, layout);
  }
  bar.replaceChildren(...lines.map(([kind, text]) => el("p", `sb-${kind}`, text)));
}

async function tick() {
  if (!document.hidden) {
    try {
      const r = await fetch("/cve/api/scanner", { credentials: "same-origin", cache: "no-store" });
      if (r.ok) paint(await r.json());
    } catch (_) {
      /* down: sitewatch covers the page */
    }
  }
  setTimeout(tick, EVERY_MS);
}
tick();
