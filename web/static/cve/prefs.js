// Per-browser display preferences. Today: whether times are shown in this browser's time zone (the default) or in UTC.
// Pages import the formatters, so every timestamp follows the choice; the account-menu button flips it and reloads the page.
const KEY = "cve.tz";
const pad = (n) => String(n).padStart(2, "0");
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

export const tzMode = () => {
  try {
    return localStorage.getItem(KEY) === "utc" ? "utc" : "local";
  } catch (_) {
    return "local";
  }
};

function setTzMode(mode) {
  try {
    localStorage.setItem(KEY, mode);
  } catch (_) {
    /* blocked storage: the choice just does not stick */
  }
}

// The calendar fields of a moment in the chosen zone.
function fields(date) {
  const utc = tzMode() === "utc";
  return utc
    ? {
        y: date.getUTCFullYear(),
        mo: date.getUTCMonth(),
        d: date.getUTCDate(),
        h: date.getUTCHours(),
        mi: date.getUTCMinutes(),
        s: date.getUTCSeconds(),
      }
    : {
        y: date.getFullYear(),
        mo: date.getMonth(),
        d: date.getDate(),
        h: date.getHours(),
        mi: date.getMinutes(),
        s: date.getSeconds(),
      };
}

const parse = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
};

// "2026-10-25 17:33", the format the lists have always used, now in the chosen zone.
export function fmtDateTime(iso) {
  const d = iso && parse(iso);
  if (!d) return "";
  const f = fields(d);
  return `${f.y}-${pad(f.mo + 1)}-${pad(f.d)} ${pad(f.h)}:${pad(f.mi)}`;
}

export function fmtTime(iso, withSeconds = true) {
  const d = iso && parse(iso);
  if (!d) return "";
  const f = fields(d);
  return `${pad(f.h)}:${pad(f.mi)}${withSeconds ? `:${pad(f.s)}` : ""}`;
}

// "Today", "Yesterday" or "Oct 24" (with the year when it is far back), counted in the chosen zone's calendar.
export function fmtDay(iso) {
  const d = iso && parse(iso);
  if (!d) return "";
  const f = fields(d);
  const midnight = (x) =>
    tzMode() === "utc"
      ? Date.UTC(x.y, x.mo, x.d)
      : new Date(x.y, x.mo, x.d).getTime();
  const gap = Math.round(
    (midnight(fields(new Date())) - midnight(f)) / 86400000,
  );
  if (gap === 0) return "Today";
  if (gap === 1) return "Yesterday";
  return `${MONTHS[f.mo]} ${f.d}${gap > 300 ? `, ${f.y}` : ""}`;
}

export const zoneLabel = () =>
  tzMode() === "utc"
    ? "UTC"
    : Intl.DateTimeFormat().resolvedOptions().timeZone || "local time";

// The account-menu button (present on every page that extends the shell).
const button = document.querySelector("[data-tz-toggle]");
if (button) {
  const label = button.querySelector("span");
  if (label)
    label.textContent =
      tzMode() === "utc" ? "Times: UTC" : "Times: your time zone";
  button.setAttribute("aria-pressed", String(tzMode() === "utc"));
  button.title = `Showing times in ${zoneLabel()}. Click to switch.`;
  button.addEventListener("click", () => {
    setTzMode(tzMode() === "utc" ? "local" : "utc");
    window.location.reload();
  });
}

// Theme chooser in the account menu: Light (the default), Dark, or Auto (follow the system). theme.js applies it.
const choices = [...document.querySelectorAll("[data-theme-choice]")];
if (choices.length) {
  const paint = () => {
    const now = (window.cveTheme && window.cveTheme.get()) || "light";
    choices.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themeChoice === now)));
  };
  choices.forEach((b) =>
    b.addEventListener("click", () => {
      if (window.cveTheme) window.cveTheme.set(b.dataset.themeChoice);
      paint();
      // the asset graph paints its nodes once, from the theme in force; redraw it by reloading
      if (document.getElementById("graph") || document.getElementById("d-graph")) window.location.reload();
    }),
  );
  paint();
}
