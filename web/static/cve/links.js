// Where a hostname, an IP address, a CVE id and a "Needs validation" label point, in one place. Every page that prints one of
// them builds its link here, so they cannot disagree about where the record is.
//
//   host        /cve/<project>/hosts/?host=<name>        the host record, selected
//   IP address  /cve/<project>/hosts/?q=ip:<address>      the host that holds it
//   CVE         /cve/<project>/matches/#<match id>        the match on that host (or, with no match id, ?cve= the matches for it)
//   validation  /cve/<project>/matches/#<match id>&validate   the match, with Validate now pressed
//   finding     /cve/<project>/vulns/#<kind>-<id>              any other finding, on the unified Findings page
//
// DOM is built with textContent only; nothing here parses HTML.
const enc = encodeURIComponent;

export const hostHref = (project, name) => `/cve/${enc(project)}/hosts/?host=${enc(name)}`;
export const ipHref = (project, address) => `/cve/${enc(project)}/hosts/?q=${enc(`ip:${address}`)}`;
export const cveHref = (project, cveId, matchId, host) =>
  matchId
    ? `/cve/${enc(project)}/matches/#${matchId}`
    : `/cve/${enc(project)}/matches/?cve=${enc(cveId)}${host ? `&host=${enc(host)}` : ""}`;
export const matchHref = (project, matchId) => `/cve/${enc(project)}/matches/#${matchId}`;
// a match opens on the matches page; any other kind on the unified Findings page, keyed "<kind>-<id>"
export const findingHref = (project, kind, id) =>
  kind === "match" ? `/cve/${enc(project)}/matches/#${id}` : `/cve/${enc(project)}/vulns/#${enc(kind)}-${id}`;
export const validateHref = (project, matchId) => `/cve/${enc(project)}/matches/#${matchId}&validate`;

const a = (cls, text, href, title) => {
  const n = document.createElement("a");
  n.className = cls;
  n.textContent = text;
  n.setAttribute("href", href);
  if (title) n.title = title;
  return n;
};
export const hostAnchor = (project, name) => a("host-link", name, hostHref(project, name));
export const ipAnchor = (project, address) => a("host-link", address, ipHref(project, address), `The host with address ${address}`);
export const cveAnchor = (project, cveId, matchId, host) =>
  a("host-link cve-link", cveId, cveHref(project, cveId, matchId, host), matchId || host ? "The match on this host" : "Every match of this CVE");

// Free text (an activity line, a scan note) names hosts, addresses and CVEs without saying which are which. This finds them.
const TOKEN = /\b(CVE-\d{4}-\d{4,})\b|\b((?:\d{1,3}\.){3}\d{1,3})\b|\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/gi;
// not hosts: names of files and of the products CVEngine reads
const NOT_A_HOST = /\.(?:ya?ml|json|txt|log|html?|php|css|png|jpe?g|svg|js|py|conf|cfg|xml|csv|pem|crt|key|zip|gz)$/i;
const PRODUCTS = new Set(["cve.now", "github.com", "nvd.nist.gov", "cisa.gov", "exploit-db.com"]);
const validIp = (s) => s.split(".").every((o) => Number(o) <= 255);

/**
 * Append ``text`` to ``parent`` with every hostname, IP address and CVE id in it turned into a link to its record. With no
 * ``project`` (a system-wide line) there is no page to link to, so the text is left as it is. ``kinds`` narrows what is linked (a
 * change line names IPs but also products like ASP.NET); ``host`` is the host a CVE belongs to, when the line is about one.
 */
export function linkify(parent, text, project, { kinds = ["cve", "ip", "host"], host = "" } = {}) {
  const s = String(text == null ? "" : text);
  if (!project) {
    parent.append(document.createTextNode(s));
    return parent;
  }
  // a line about one host ("CVE-2026-1 matches www.example.com") sends its CVE to that host's match
  const named = [...s.matchAll(TOKEN)].map((m) => m[3]).filter((n) => n && !NOT_A_HOST.test(n) && !PRODUCTS.has(n.toLowerCase()));
  if (!host && new Set(named.map((n) => n.toLowerCase())).size === 1) host = named[0];
  let last = 0;
  for (const m of s.matchAll(TOKEN)) {
    const [, cve, ip, name] = m;
    let node = null;
    if (cve && kinds.includes("cve")) node = cveAnchor(project, cve.toUpperCase(), null, host);
    else if (ip && kinds.includes("ip") && validIp(ip)) node = ipAnchor(project, ip);
    else if (name && kinds.includes("host") && !NOT_A_HOST.test(name) && !PRODUCTS.has(name.toLowerCase())) node = hostAnchor(project, name);
    if (!node) continue;
    if (m.index > last) parent.append(document.createTextNode(s.slice(last, m.index)));
    parent.append(node);
    last = m.index + m[0].length;
  }
  if (last < s.length) parent.append(document.createTextNode(s.slice(last)));
  return parent;
}

/** A "Needs validation" label that does something: it opens the match and presses Validate now (a finding that is not a CVE match opens its own page). */
export function needsValidation(project, kind, id, label = "Needs validation") {
  const href = kind === "match" ? validateHref(project, id) : findingHref(project, kind, id);
  const n = a("badge ice needs-validation", label, href, kind === "match" ? "Open this match and run Validate now" : "Open this finding");
  n.dataset.kind = kind;
  n.dataset.id = String(id);
  n.dataset.project = project;
  return n;
}
