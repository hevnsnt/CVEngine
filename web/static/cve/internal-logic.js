// The words of the Internal network page (static/cve/internal.js), kept apart from the DOM so tests/test_internal_page.mjs can check them.
// Every edge state says what it means for the network: a range with no Sentinel checking in is not being scanned, so a quiet row there is
// never shown as clean.

export const SENTINEL_WORDS = {
  online: "Checking in",
  offline: "Offline: not checking in",
  none: "No internal Sentinel",
};

const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

// "3 hours", "2 days": how long ago or ahead, from two times in milliseconds
export function span(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 90) return plural(s, "second", "seconds");
  const m = Math.round(s / 60);
  if (m < 90) return plural(m, "minute", "minutes");
  const h = Math.round(m / 60);
  if (h < 36) return plural(h, "hour", "hours");
  return plural(Math.round(h / 24), "day", "days");
}

export const ago = (iso, now = Date.now()) => (iso ? `${span(now - Date.parse(iso))} ago` : "never");

// Which Sentinels are inside the network: their names when the server sent them, else how many instance-wide ones cover it.
export function sentinelNames(sentinel) {
  const s = sentinel || { state: "none" };
  const names = (s.sentinels || []).map((x) => `${x.name} (${x.state === "online" ? "online" : "offline"})`);
  if (names.length) return names.join(", ");
  if (s.state !== "none" && s.total) return plural(s.total, "instance-wide Sentinel", "instance-wide Sentinels");
  return "";
}

// The Sentinel cell as one line: its state, then the names.
export function sentinelText(sentinel) {
  const s = sentinel || { state: "none" };
  const word = SENTINEL_WORDS[s.state] || s.state;
  const names = sentinelNames(s);
  return names ? `${word}. ${names}` : word;
}

// The last discovery cell.
export function lastDiscoveryText(n, now = Date.now()) {
  if (!n.last_discovery_at) return "Never swept";
  return ago(n.last_discovery_at, now);
}

// The next discovery cell (cveFeed.internal_page._next_discovery).
export function nextDiscoveryText(n, now = Date.now()) {
  const next = n.next_discovery || { state: "waiting" };
  if (next.state === "waiting") return "Waits for a Sentinel inside the network";
  if (next.state === "due") return n.last_discovery_at ? "Due now" : "Due now: first sweep";
  return `In ${span(Date.parse(next.at) - now)}`;
}

// The live hosts cell: what the last sweep found, else how many internal hosts are known.
export function liveHostsText(n) {
  if (n.last_discovery_hosts != null) return `${n.last_discovery_hosts.toLocaleString()} at last sweep`;
  return n.hosts ? `${plural(n.hosts, "known host", "known hosts")}, not swept yet` : "Not swept yet";
}

// The last error cell: the discovery error first (it stops the sweep), then the last internal scan's.
export function lastErrorText(n) {
  if (n.last_discovery_error) return `Discovery: ${n.last_discovery_error}`;
  if (n.last_error) return `Scan: ${n.last_error}`;
  return "";
}

// One line under the table per range in an edge state, so the reason is said in words and not only by a dot.
export function rangeWarning(n) {
  const state = (n.sentinel && n.sentinel.state) || "none";
  if (state === "offline") return `${n.cidr}: the Sentinel inside is offline, so this network is not being scanned. Its last results stay below.`;
  if (state === "none") return `${n.cidr}: no Sentinel inside this network covers it, so nothing scans it. Provision one with network set to internal.`;
  if (n.last_discovery_error) return `${n.cidr}: the last discovery failed (${n.last_discovery_error}). The next sweep tries again.`;
  if (!n.last_discovery_at) return `${n.cidr}: never swept yet. The first sweep runs on the next round.`;
  return "";
}

export const TASK_WORDS = { discover: "Discovery", nmap: "nmap", nmap_udp: "nmap UDP", testssl: "testssl", openvas: "OpenVAS" };
export const taskName = (kind) => TASK_WORDS[kind] || String(kind || "").replace(/_/g, " ");
export const STATUS_BADGE = { queued: "queued", claimed: "running", running: "running", done: "success", failed: "high", expired: "low" };
