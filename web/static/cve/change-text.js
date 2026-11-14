// The one sentence the Changes page (and a host's change history) says for each kind of change (cveFeed/changes.py, route_auth.py: AssetChange.KINDS).
// Pure text, no DOM, so `node --test` feeds every kind the server can emit through it (tests/test_change_text.mjs). A value the server did not send is
// said in words ("version unknown"), never as "?", "undefined", "null" or "[object Object]".
const AUTH_LABEL = { open: "open", login: "login page", session_required: "session required", sso: "SSO", redirect: "redirect", not_found: "not found", catch_all: "same as a missing page" };
export const authLabel = (s) => AUTH_LABEL[s] || (typeof s === "string" && s) || "unknown";
export const pathOf = (url) => {
  if (typeof url !== "string" || !url) return "a page";
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch (_) {
    return url;
  }
};
const text = (v) => (typeof v === "string" || typeof v === "number" ? String(v).trim() : "");
const dateOnly = (iso) => (text(iso) ? text(iso).slice(0, 10) : "");
// "nginx:1.18.0" (a technology the scan read) -> "nginx 1.18.0"; a bare "nginx" stays as it is
const techText = (t) => {
  const s = text(t);
  if (!s) return "a technology";
  const i = s.indexOf(":");
  return i > 0 && i < s.length - 1 ? `${s.slice(0, i)} ${s.slice(i + 1)}` : s;
};
const svcText = (s) => [text(s && (s.product || s.service)), text(s && s.version)].filter(Boolean).join(" ");
const onPort = (port) => (text(port) ? ` on port ${text(port)}` : "");
const asObject = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
const list = (v) => (Array.isArray(v) ? v.map(text).filter(Boolean) : []);

export function changeDetail(c) {
  const b = asObject(c.before);
  const a = asObject(c.after);
  const port = (side) => text(side.port) || text(c.port);
  switch (c.kind) {
    case "host_new": {
      const ips = Object.keys(asObject(a.ips));
      return ips.length ? `New host, answers on ${ips.join(", ")}` : "New host";
    }
    case "host_returned":
      return "Resolves again after being retired or archived";
    case "host_retired": {
      const open = list(a.tcp_alive);
      return open.length ? `No longer resolves; ${open.join(", ")} still accepts connections` : "No longer resolves";
    }
    case "port_opened": {
      const what = svcText(a);
      return `${text(c.ip) ? `${text(c.ip)} ` : ""}port ${port(a) || "unknown"} opened${what ? `: ${what}` : ""}`;
    }
    case "port_closed": {
      const what = svcText(b);
      return `${text(c.ip) ? `${text(c.ip)} ` : ""}port ${port(b) || "unknown"} closed${what ? ` (was ${what})` : ""}`;
    }
    case "service_changed": {
      const was = svcText(b), now = svcText(a);
      const where = onPort(port(a) || port(b));
      const same = text(b.product) && text(b.product) === text(a.product) && text(b.version) && text(a.version);
      if (same) return `${text(a.product)} ${text(b.version)} → ${text(a.version)}${where}`;
      if (was && now) return `${was} → ${now}${where}`;
      if (now) return `${now} now reported${where}; it named no product before`;
      if (was) return `${was} no longer named${where}`;
      return `Service description changed${where}`;
    }
    case "tech_added":
      return `${techText(c.after)} added`;
    case "tech_removed":
      return `${techText(c.before)} removed`;
    case "tech_version_changed":
      return `${techText(c.before)} → ${techText(c.after)}`;
    case "cert_changed": {
      const parts = [];
      if (b.issuer !== a.issuer) parts.push(`issuer ${text(b.issuer) || "unknown"} → ${text(a.issuer) || "unknown"}`);
      if (b.subject !== a.subject) parts.push(`subject ${text(b.subject) || "unknown"} → ${text(a.subject) || "unknown"}`);
      if (b.not_after !== a.not_after) parts.push(`expires ${dateOnly(b.not_after) || "unknown"} → ${dateOnly(a.not_after) || "unknown"}`);
      return `Certificate changed: ${parts.length ? parts.join(", ") : "its names or key"}`;
    }
    case "auth_changed":
      return `${pathOf(a.url || b.url)}: ${authLabel(b.auth_state)} → ${authLabel(a.auth_state)}`;
    case "sensitive_found": {
      const types = list(a.types);
      return `${pathOf(a.url)} now serves ${types.length ? types.join(", ") : "sensitive data"}`;
    }
    case "zombie_host": {
      const alive = list(a.alive);
      return `DNS is gone but it still answers${alive.length ? ` on ${alive.join(", ")}` : ""}`;
    }
    case "zombie_cleared":
      return "Resolves again";
    case "route_retired": {
      const status = text(a.http_status);
      return `${pathOf(b.url || a.url)}: ${authLabel(b.auth_state)} → gone${status ? ` (HTTP ${status})` : ""}`;
    }
    case "zombie_route": {
      const status = text(a.http_status);
      return `${pathOf(a.url || b.url)} answers again${status ? ` (HTTP ${status})` : ""}`;
    }
    case "screenshot_changed": {
      const d = typeof a.distance === "number" ? ` (${a.distance} of 64 apart)` : "";
      return `Front page looks different${d}${["login", "sso"].includes(a.root_auth) ? ", now shows a login page" : ""}`;
    }
    default:
      return text(c.kind).replaceAll("_", " ") || "Changed";
  }
}
