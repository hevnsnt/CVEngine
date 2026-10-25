// Scan notifications in the browser: when a scan that was running or queued finishes, fails or is stopped, say so with a
// notice (a link to the scan), count it in the tab title while the tab is hidden, and, if you opted in from the account menu,
// raise a desktop notification. The server's own channels (Slack, webhooks, mail) are separate and unchanged.
// It watches the project in view by asking for its running and queued scans every POLL_MS; the first answer is only a baseline.
import { el } from "/staticfiles/cve/ui.js";

const POLL_MS = 20000;
const NOTICE_MS = 12000;
const PREF_KEY = "cve.notify.desktop";
const STATUS_WORD = { 0: "failed", 2: "finished", 3: "was stopped" };

const select = document.getElementById("project");
const slug =
  select && select.value && select.value !== "_all" ? select.value : "";
if (slug) start();

function start() {
  const base = `/api/v1/projects/${encodeURIComponent(slug)}`;
  const baseTitle = document.title;
  let previous = null; // ids of scans seen running or queued on the last poll
  let unread = 0;

  const get = async (path) => {
    const res = await fetch(`${base}/${path}`, { credentials: "same-origin" });
    if (!res.ok) throw new Error(String(res.status));
    return res.json();
  };
  const desktopOn = () => {
    try {
      return (
        localStorage.getItem(PREF_KEY) === "1" &&
        "Notification" in window &&
        Notification.permission === "granted"
      );
    } catch (_) {
      return false;
    }
  };

  function paintTitle() {
    document.title = unread ? `(${unread}) ${baseTitle}` : baseTitle;
  }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      unread = 0;
      paintTitle();
    }
  });

  function notice(scan, word) {
    const href = `/cve/${encodeURIComponent(slug)}/scans/${scan.id}/`;
    const failed = scan.status === 0;
    const box = el("div", `toast notice${failed ? " err" : ""}`, null, {
      role: "status",
    });
    const findings = scan.findings || scan.vulnerabilities;
    const detail =
      scan.status === 2 && findings
        ? `, ${findings} finding${findings === 1 ? "" : "s"}`
        : "";
    box.append(
      el("span", "", `Scan #${scan.id} of ${scan.target} ${word}${detail}`),
    );
    const open = el("a", "notice-link", "Open", { href });
    const close = el("button", "notice-close", "×", {
      type: "button",
      "aria-label": "Dismiss",
    });
    close.onclick = () => box.remove();
    box.append(open, close);
    document.body.append(box);
    setTimeout(() => box.remove(), NOTICE_MS);
    if (document.visibilityState === "hidden") {
      unread += 1;
      paintTitle();
    }
    if (desktopOn() && document.visibilityState === "hidden") {
      const n = new Notification(`CVEngine: scan ${word}`, {
        body: `Scan #${scan.id} of ${scan.target}${detail}`,
        tag: `scan-${scan.id}`,
      });
      n.onclick = () => {
        window.focus();
        window.location.href = href;
        n.close();
      };
    }
  }

  async function poll() {
    try {
      const [running, queued] = await Promise.all([
        get("scans?status=running&page_size=50"),
        get("scans?status=queued&page_size=50"),
      ]);
      const now = new Set(
        [...(running.results || []), ...(queued.results || [])].map(
          (s) => s.id,
        ),
      );
      if (previous) {
        for (const id of previous) {
          if (now.has(id)) continue;
          try {
            const scan = await get(`scans/${id}`);
            if (STATUS_WORD[scan.status])
              notice(scan, STATUS_WORD[scan.status]);
          } catch (_) {
            /* a scan we cannot read (removed, or no access) is not worth a notice */
          }
        }
      }
      previous = now;
    } catch (_) {
      /* keep the last baseline; the next poll tries again */
    }
  }
  poll();
  setInterval(poll, POLL_MS);
}

// The account menu entry: turns desktop notifications on or off. Permission is asked only on this click, as browsers require.
const toggle = document.querySelector("[data-notify-toggle]");
if (toggle) {
  if (!("Notification" in window)) toggle.hidden = true;
  const label = () => {
    let on = false;
    try {
      on =
        localStorage.getItem(PREF_KEY) === "1" &&
        Notification.permission === "granted";
    } catch (_) {
      on = false;
    }
    toggle.querySelector("span").textContent = on
      ? "Desktop notifications: on"
      : "Desktop notifications: off";
    toggle.setAttribute("aria-pressed", String(on));
  };
  label();
  toggle.addEventListener("click", async () => {
    let on = false;
    try {
      on = localStorage.getItem(PREF_KEY) === "1";
    } catch (_) {
      on = false;
    }
    if (on) {
      try {
        localStorage.setItem(PREF_KEY, "0");
      } catch (_) {
        /* ignore */
      }
    } else {
      const allowed =
        Notification.permission === "granted" ||
        (await Notification.requestPermission()) === "granted";
      try {
        localStorage.setItem(PREF_KEY, allowed ? "1" : "0");
      } catch (_) {
        /* ignore */
      }
    }
    label();
  });
}
