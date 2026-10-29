// Shodan-style search inside the Ctrl+K palette. The query language is the one the Hosts page already speaks (the server parses
// it): filter:value, "quoted phrases", -negation, and a space means AND. This module adds filter suggestions as you type, a live
// preview of the matching hosts, and a help sheet. Nothing here parses the query itself; the server is the single authority.
import { dialog, el } from "/staticfiles/cve/ui.js";

export const FILTERS = [
  { name: "port", hint: "an open port", example: "port:443" },
  {
    name: "product",
    hint: "software seen on a port",
    example: "product:nginx",
  },
  { name: "service", hint: "service name", example: "service:ssh" },
  {
    name: "tech",
    hint: "anything a host runs",
    example: 'tech:"apache tomcat"',
  },
  {
    name: "banner",
    hint: "service banner or script output",
    example: 'banner:"Authentication disabled"',
  },
  { name: "os", hint: "operating system", example: "os:ubuntu" },
  { name: "proto", hint: "an open port over tcp or udp", example: "proto:udp", values: ["tcp", "udp"] },
  { name: "ip", hint: "an address or a CIDR range", example: "ip:10.0.0.0/24" },
  { name: "host", hint: "part of a host name", example: "host:staging" },
  { name: "cve", hint: "hosts matched by a CVE", example: "cve:CVE-2026-1101" },
  { name: "vuln", hint: "an open finding by name", example: "vuln:jenkins" },
  {
    name: "sev",
    hint: "severity of an open finding",
    example: "sev:critical",
    values: ["critical", "high", "medium", "low", "info"],
  },
  {
    name: "auth",
    hint: "web route sign-in state",
    example: "auth:open",
    values: ["open", "login", "session_required", "sso"],
  },
  {
    name: "sensitive",
    hint: "sensitive data seen",
    example: "sensitive:credentials",
    values: ["any", "credentials", "pii", "internal"],
  },
  {
    name: "zombie",
    hint: "DNS gone but still answering",
    example: "zombie:yes",
    values: ["yes", "no"],
  },
];

// The word being typed at the end of the box: its text without a leading "-", the filter before a colon if there is one, and where it starts.
export function lastToken(text) {
  const m = /(?:^|\s)(-?)([A-Za-z]*)(:?)("?[^\s"]*)$/.exec(text);
  if (!m)
    return { start: text.length, neg: "", name: "", colon: "", value: "" };
  return {
    start: m.index + (m[0].startsWith(" ") ? 1 : 0),
    neg: m[1],
    name: m[2],
    colon: m[3],
    value: m[4],
  };
}

// Rows that complete the filter being typed: names while there is no colon yet, known values after one.
export function suggestions(text) {
  const t = lastToken(text);
  const out = [];
  if (!t.colon && t.name) {
    FILTERS.filter(
      (f) =>
        f.name.startsWith(t.name.toLowerCase()) &&
        f.name !== t.name.toLowerCase(),
    ).forEach((f) =>
      out.push({
        label: `${t.neg}${f.name}:`,
        hint: f.hint,
        sub: f.example,
        insert: `${t.neg}${f.name}:`,
        start: t.start,
        section: "Filters",
      }),
    );
  } else if (t.colon) {
    const f = FILTERS.find((x) => x.name === t.name.toLowerCase());
    if (f && f.values) {
      const typed = t.value.replace(/^"/, "").toLowerCase();
      f.values
        .filter((v) => v.startsWith(typed) && v !== typed)
        .forEach((v) =>
          out.push({
            label: `${t.neg}${f.name}:${v}`,
            hint: f.hint,
            insert: `${t.neg}${f.name}:${v} `,
            start: t.start,
            section: "Filters",
          }),
        );
    }
  }
  return out.slice(0, 6);
}

export async function previewHosts(slug, q, signal) {
  const res = await fetch(
    `/api/v1/projects/${encodeURIComponent(slug)}/search?q=${encodeURIComponent(q)}&page_size=6&facets=none`,
    { credentials: "same-origin", signal },
  );
  if (!res.ok) {
    let why = `Search failed (${res.status})`;
    try {
      why = (await res.json()).error || why;
    } catch (_) {
      /* keep the generic message */
    }
    throw new Error(why);
  }
  return res.json();
}

export const hostRow = (slug, h) => {
  const ports = [
    ...new Set((h.ips || []).flatMap((ip) => ip.ports.map((p) => p.number))),
  ]
    .slice(0, 5)
    .join(" ");
  const why = (h.matched || [])[0];
  const parts = [
    (h.ips && h.ips[0] && h.ips[0].address) || "no address",
    ports,
    why,
  ].filter(Boolean);
  return {
    label: h.host,
    sub: parts.join(" · "),
    hint: h.heat && h.heat !== "unscanned" ? h.heat : "host",
    heat: h.heat,
    section: "Hosts",
    href: `/cve/${encodeURIComponent(h.project || slug)}/hosts/?host=${encodeURIComponent(h.host)}`,
  };
};

export function syntaxHelp() {
  dialog("Search syntax", (body, close) => {
    body.append(
      el(
        "p",
        "note",
        "The same filter:value language Shodan uses. Type it here, or in the search box on the Hosts page, which also keeps the query in the address.",
      ),
    );
    const rules = el("dl", "keys-list");
    [
      [
        "port:443",
        "A filter is a name, a colon and a value, with no space between them.",
      ],
      [
        'tech:"apache tomcat"',
        "Wrap a value that contains spaces in double quotes.",
      ],
      ["port:22 sev:high", "Several terms are all required (AND)."],
      ["-host:www", "A leading minus excludes what matches."],
      [
        "nginx",
        "A bare word searches names, addresses, technologies, banners, page titles and CVE ids.",
      ],
    ].forEach(([q, what]) =>
      rules.append(el("dt", "mono", q), el("dd", "", what)),
    );
    body.append(rules, el("h3", "sec", "Filters"));
    const table = el("dl", "keys-list");
    FILTERS.forEach((f) => {
      table.append(
        el("dt", "mono", `${f.name}:`),
        el("dd", "", `${f.hint}. Example: ${f.example}`),
      );
    });
    body.append(table);
    const row = el("div", "dlg-tools");
    const done = el("button", "btn", "Close", { type: "button" });
    done.onclick = close;
    row.append(el("span", "grow"), done);
    body.append(row);
    body.querySelector("h2").tabIndex = -1;
  });
}
