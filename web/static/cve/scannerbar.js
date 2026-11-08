// Every page, every user: a quiet strip when work is waiting for a scanner. It is not the scanning pause (nothing is held and nothing has failed) and not the
// update bar: it is read from /cve/api/scanner, which derives it from the Sentinels' own heartbeats, so it disappears by itself when a scanner reconnects.
// The second sentence (a kind no scanner ever registered for) is sent to an App Admin only and is the louder of the two. It is drawn in the one status strip
// (statusstrip.js) with the admin alerts, and can be dismissed for the browser session.
import { fmtTime, zoneLabel } from "/staticfiles/cve/prefs.js";
import { setNotices } from "/staticfiles/cve/statusstrip.js";

const EVERY_MS = 60000;

// The server words the retry time in UTC; the page shows it in the zone every other time on the page uses (prefs.js).
function coolingText(s) {
  const times = Object.values(s.cooling || {}).map((r) => Date.parse(r.retry_at)).filter((t) => !Number.isNaN(t));
  if (!times.length) return s.cooling_message;
  const local = `${fmtTime(new Date(Math.min(...times)).toISOString(), false)} (${zoneLabel()})`;
  return s.cooling_message.replace(/ at \d\d:\d\d UTC/, ` at ${local}`);
}

function paint(s) {
  const lines = [];
  if (s && s.message) lines.push({ kind: "waiting", text: s.message, rank: 1 });
  if (s && s.cooling_message) lines.push({ kind: "cooling", text: coolingText(s), rank: 1 }); // the scanner is online; a kind failed repeatedly and is withheld until its retry time
  if (s && s.disabled_message) lines.push({ kind: "disabled", text: s.disabled_message, rank: 1 }); // turned off by a setting, not a scanner that is gone
  if (s && s.never_seen_message) lines.push({ kind: "never", text: s.never_seen_message, rank: 1, dismissible: true }); // an optional scanner: dismiss it for the session
  setNotices("scanner", lines);
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
