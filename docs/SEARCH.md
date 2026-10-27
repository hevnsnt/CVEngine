# Search

Search your whole attack surface the way you search the Internet on [Shodan](https://www.shodan.io): type `filter:value` terms and get back every host that matches, with the reason it matched. The difference is the haystack. Shodan searches the Internet. cvENGINE searches **your** inventory: every host, IP, port, service, banner, technology, finding, and CVE match your scans have found.

```text
port:3389 -host:vpn                 Remote Desktop exposed, not on the VPN
tech:"apache tomcat" sev:high       Tomcat hosts with a high finding
ip:203.0.113.0/24 product:nginx     nginx anywhere in a network range
```

## Where to search

| Where | How |
| --- | --- |
| **Hosts page** | The search box. The query lives in the address (`?q=`), so you can bookmark or send a search. |
| **Anywhere in the app** | Press `Ctrl+K` (`Cmd+K` on a Mac) or `/`. Filter names and values complete as you type, up to six matching hosts preview live, and the help sheet lists every filter. |
| **REST API** | `GET /api/v1/projects/<slug>/search?q=...` ([AGENT-API.md](AGENT-API.md)) |
| **MCP** | The `search_hosts` tool, so an agent can ask the same questions |

Use the slug `_all` to search every project you can see.

## The syntax

- A **bare word** matches almost anything: host name, IP, technology, web server, port product, service, version, CPE, banner, page title, OS, finding name, and CVE id. `nginx`, `jenkins`, `CVE-2026-111497`.
- A **filter** is `name:value` with no space around the colon.
- A space means **AND**. Every term must match the host, but each term is tested on its own: `port:22 product:nginx` finds hosts with SSH open somewhere and nginx somewhere, not necessarily on the same port.
- A leading `-` **excludes**: `-host:www`.
- Wrap a value with spaces in **quotes**: `tech:"apache tomcat"`.
- Matching is case-insensitive and by substring, so `nginx` finds `nginx/1.24.0`. There is no OR between terms, no parentheses, and no wildcard. Inside one filter, a comma list is OR: `port:80,443` is port 80 or 443, `sev:high,critical` is either severity, and it is still ANDed with the other terms. Quote the value (`tech:"foo,bar"`) to keep a literal comma.
- A search may have at most 15 terms of 200 characters each and 1,000 characters in all. More is a 400.
- Unknown filter names are treated as plain text, so a pasted URL searches for the URL.

| Filter | Matches | Example |
| --- | --- | --- |
| `port:` | An **open** port number | `port:3306` |
| `product:` | Software nmap saw on a port | `product:openssh` |
| `service:` | Service name on a port | `service:ssh` |
| `tech:` | Everything a host runs: technologies, `Server` and `X-Powered-By` headers, product and version, banners, script output, page titles, cookie names, route fingerprints | `tech:php` |
| `banner:` | Service banners and NSE script output on an open port | `banner:"Anonymous FTP login allowed"` |
| `os:` | Operating system guess | `os:windows` |
| `ip:` | An address, a prefix, or a CIDR range | `ip:198.51.100.0/24` |
| `host:` | Part of a host name | `host:staging` |
| `cve:` | Hosts matched by a CVE (a full id or a prefix) | `cve:CVE-2026-111497` |
| `vuln:` | A finding by name, open or closed | `vuln:jenkins` |
| `sev:` | A finding of this severity, open or closed: `critical`, `high`, `medium`, `low`, `info` | `sev:critical` |
| `auth:` | A web route's sign-in state: `open`, `login`, `session_required`, `sso`, `redirect`, `not_found`, `error` | `auth:open` |
| `sensitive:` | A route that served sensitive data: `any`, `credentials`, `pii`, `internal` | `sensitive:credentials` |
| `zombie:` | Hosts whose DNS is gone but still answer: `yes` or `no` | `zombie:yes` |
| `country:` | The country of a host's IP address, by ISO code or name | `country:US`, `country:Germany` |

`port:` takes a number only. Use `product:` or `service:` for names. A bad value, such as `sev:scary`, returns an error that lists the allowed ones.

`tech:` also reads what the Internet Archive saw on the host in the past (a `.php` page, `/wp-content/`). Those hits are labelled **seen in web archive**, because they are history, not what runs today.

## Examples

**What is exposed**

```text
port:3389                              every host with Remote Desktop open
port:22 port:2222                      SSH on both the usual and the alternate port
product:redis                          Redis anywhere, including on odd ports
os:windows port:445                    Windows hosts with SMB reachable
banner:"Anonymous FTP login allowed"   FTP servers that let anyone in
```

**What is vulnerable**

```text
cve:CVE-2026-111497                    hosts matched by one CVE
cve:CVE-2026- sev:critical             hosts matched by a 2026 CVE that also have a critical finding
tech:"apache tomcat" sev:high          Tomcat hosts with a high finding
vuln:wordpress sev:high                hosts with a WordPress finding and a high finding
```

**What is risky on the web**

```text
auth:open sensitive:credentials        hosts with an open route and a route that showed credentials
auth:open tech:jenkins                 Jenkins hosts that also have a route open to anyone
tech:php -tech:nginx                   PHP hosts that are not behind nginx
zombie:yes                             retired names that still answer, with the old name
```

**Scope it down**

```text
ip:203.0.113.0/24 product:nginx        nginx inside one network range
host:staging -host:internal            staging names, minus internal
tech:wordpress -ip:192.0.2.            WordPress outside one address prefix
```

## Shodan filters and their cvENGINE equivalents

If you know Shodan's [filters](https://www.shodan.io/search/filters), these are the closest matches. See also Shodan's [search query fundamentals](https://help.shodan.io/the-basics/search-query-fundamentals).

| Shodan | cvENGINE | Note |
| --- | --- | --- |
| `port:` | `port:` | Open ports only |
| `product:` | `product:` | |
| `os:` | `os:` | |
| `net:` | `ip:` | CIDR ranges and prefixes |
| `hostname:` | `host:` | |
| `country:` | `country:` | |
| `http.component:` | `tech:` | Reads more than the web page |
| `http.title:` | a bare word | Page titles are searched with everything else |
| `vuln:CVE-...` | `cve:` | Here `vuln:` searches finding names |

cvENGINE has no `org:`, `asn:`, `hosting:`, or `city:` filters, because every host in the inventory is yours.

## Reading the results

Hosts come back highest [score](PIPELINE.md#host-score) first. Add `sort=name` to the API call, or use the Sort control on the Hosts page, to order by name. Each result carries `matched`, a short list of what the query hit (`port 8443 nginx 1.24.0`, `technology WordPress`, `CVE CVE-2026-111497`), so you can see why a host is in the list without opening it.

```bash
curl -s -H "Authorization: Bearer $CVENGINE_TOKEN" \
  "https://scanner.example.com/api/v1/projects/acme/search?q=port:3389+-host:vpn&page_size=20" \
  | jq '.results[] | {host, score, matched}'
```

`page_size` goes up to 200. With no `q`, the search lists every host. `heat=fire|smoke|ice|clean|unscanned` narrows the page, and `facets=port,product,tech,os,country` (with `facet_size`, 10 by default and 50 at most) returns counts per value, plus `facets.heat` over the whole match; counts stop after 5,000 hosts. The heat chips on the Hosts page filter only the rows already loaded.

See also: [PIPELINE.md](PIPELINE.md) for what fills the inventory, [FRONTEND.md](FRONTEND.md), [documentation index](README.md).
