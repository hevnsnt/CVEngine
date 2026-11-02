// Add targets dialog: how a paste is read and counted, and the scope choice. Kept free of the DOM and of imports so that `node --test` can
// run it (tests/test_addtargets_logic.mjs); addtargets.js only draws. The server parses the paste again (agentapi.services.parse_target_list,
// normalize_target, add_entries) and checks every value; these mirror it so the count under the box matches what will be added.
//
// Two marks may start an entry: "-example.com" excludes that domain and everything under it for the whole organization, and "=example.com"
// adds exactly that host (scope "host": no subdomain is discovered, kept or scanned under it, and its parent domain is never promoted).
// An address, CIDR or range has no subdomains, so "=" changes nothing for one.

export const HOST_ONLY_MARK = "=";

// The batch scope: what every new domain target of the paste is created with. A line written "=example.com" is "host" whatever is chosen here.
export const SCOPE_CHOICES = [
  ["auto", "Scope: auto (subdomains are discovered, as always)"],
  ["host", "Scope: this host only (no subdomains, never its parent)"],
  ["parent", "Scope: include the parent domain (use with care)"],
];
export const DEFAULT_SCOPE = "auto";
export const SCOPE_HINT =
  "Start a line with = to add exactly that host: =example.com is scanned on its own, with no subdomain discovery. It overrides the scope chosen here.";

// What the request carries: nothing for auto, so a server or proxy that predates the field sees exactly the request it always did.
export const scopeBody = (choice) => (choice && choice !== DEFAULT_SCOPE && SCOPE_CHOICES.some(([v]) => v === choice) ? { scope_mode: choice } : {});

// Mirrors agentapi.services.normalize_target: URLs become hosts, a wildcard and the trailing dot go, a leading - or = is kept in front.
export const normalizeTarget = (token) => {
  let t = (token || "").trim().replace(/^["'<>`,;]+|["'<>`,;]+$/g, "");
  if (!t) return "";
  if (t.length > 1 && t.startsWith("-")) {
    const rest = normalizeTarget(t.slice(1));
    return rest && !rest.startsWith("-") ? `-${rest}` : "";
  }
  if (t.length > 1 && t.startsWith(HOST_ONLY_MARK)) {
    const rest = normalizeTarget(t.slice(1));
    return rest ? `${HOST_ONLY_MARK}${rest}` : "";
  }
  t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(t)) {
    t = t.split(/[/?#]/)[0];
    t = t.slice(t.lastIndexOf("@") + 1);
    if (t.startsWith("[")) t = t.slice(1).split("]")[0];
    else if ((t.match(/:/g) || []).length === 1) t = t.replace(/:\d{1,5}$/, "");
  }
  t = t.toLowerCase().replace(/\.+$/, "").replace(/^\*\./, "");
  return t.replace(/^(\d{1,3}(\.\d{1,3}){3})\/32$/, "$1");
};

// Grouped format: an optional "##Organization" line, then "#Project" above each list ("# a comment" with a space is a comment).
export const isOrgFormat = (text) => text.split("\n").some((l) => /^\s*#\S/.test(l));
const stripLinks = (line) => line.replace(/\[[^\]]*\]\(([^)\s]*)\)/g, "$1");
export const tokensOf = (lines) =>
  new Set(lines.map((l) => stripLinks(l.split("#")[0])).join(" ").split(/[,\s;]+/).map(normalizeTarget).filter(Boolean));
// "=example.com" and "example.com" in one paste are one target (created as exactly that host), as on the server
const targetsOf = (lines) => new Set([...tokensOf(lines)].filter((t) => !t.startsWith("-")).map((t) => (t.startsWith(HOST_ONLY_MARK) ? t.slice(1) : t)));
const bodyLines = (text) => (isOrgFormat(text) ? text.split("\n").filter((l) => !l.trim().startsWith("#")) : text.split("\n"));

export const countEntries = (text) => targetsOf(bodyLines(text)).size;
// "-example.com" lines exclude a domain (and everything under it) instead of adding a target
export const countExclusions = (text) => [...tokensOf(bodyLines(text))].filter((t) => t.startsWith("-")).length;
// "=example.com": how many targets are added as exactly one host
export const countHostOnly = (text) => new Set([...tokensOf(bodyLines(text))].filter((t) => t.startsWith(HOST_ONLY_MARK)).map((t) => t.slice(1))).size;
export const projectCount = (text) =>
  new Set(text.split("\n").map((l) => l.trim()).filter((l) => /^#[^#\s]/.test(l)).map((l) => l.slice(1).trim().toLowerCase())).size;

export const countLabel = (text) => {
  const n = countEntries(text), x = countExclusions(text), h = countHostOnly(text), p = projectCount(text);
  return `${n} target${n === 1 ? "" : "s"}${h ? ` (${h} this host only)` : ""}${x ? `, ${x} exclusion${x === 1 ? "" : "s"}` : ""}${isOrgFormat(text) ? ` across ${p} project${p === 1 ? "" : "s"}` : ""}`;
};
