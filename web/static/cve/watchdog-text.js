// The watchdog writes a time into a sentence as {{time:2026-11-08T18:12:00Z}}; the page shows it in the viewer's own time (the zone chosen in
// preferences, else the browser's): "6:12 PM" style is the 24-hour "18:12" every list here uses, with the day when it is not today.
import { fmtDay, fmtTime } from "/staticfiles/cve/prefs.js";

const TOKEN = /\{\{time:([0-9T:+\-Z.]{10,40})\}\}/g;

export function localTimes(text) {
  return String(text == null ? "" : text).replace(TOKEN, (_all, iso) => {
    const time = fmtTime(iso, false);
    if (!time) return "a moment ago";
    const day = fmtDay(iso);
    return day && day !== "Today" ? `${time} ${day}` : time;
  });
}
