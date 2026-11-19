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
| **Saved searches** | Keep a search and be told when it finds something new ([below](#saved-searches-and-alerts)) |

Use the slug `_all` to search every project you can see.

### Your inventory or the CVE catalog

Host search (everything above) answers "which of my hosts...". To look up a CVE itself, or every CVE for a technology, use the **CVE catalog** at `/cve/cves/`: type an id (`CVE-2024-6387`, `2024-6387`) or a product (`ssh`, `php`, `tomcat`). Each row says how many of your hosts that CVE matches, and the detail drawer lists them. In `Ctrl+K`, a bare word or id also offers **Search CVEs for "..."**. The API is `GET /cve/api/cves?q=...` ([FRONTEND.md](FRONTEND.md#cve-catalog)).

| You want | Use |
| --- | --- |
| Hosts running OpenSSH | Hosts page: `product:openssh` |
| Hosts matched by one CVE | Hosts page: `cve:CVE-2024-6387` |
| Every OpenSSH CVE, and how many of your hosts each one hits | CVE catalog: `ssh` |
| One CVE's summary, ranges and references | CVE catalog: `CVE-2024-6387` |

## The syntax

- A **bare word** matches almost anything: host name, the alias and note a person gave the host (or, for an address added as a target, the target), IP, technology, web server, port product, service, version, CPE, banner, page title, OS, finding name, and CVE id. `nginx`, `jenkins`, `CVE-2026-111497`.
- A **filter** is `name:value` with no space around the colon.
- A space means **AND**. Every term must match the host, but each term is tested on its own: `port:22 product:nginx` finds hosts with SSH open somewhere and nginx somewhere, not necessarily on the same port.
- A leading `-` **excludes**: `-host:www`.
- Wrap a value with spaces in **quotes**: `tech:"apache tomcat"`.
- Matching is case-insensitive and by substring, so `nginx` finds `nginx/1.24.0`. There is no OR between terms, no parentheses, and no wildcard. Inside one filter, a comma list is OR: `port:80,443` is port 80 or 443, `sev:high,critical` is either severity, and it is still ANDed with the other terms. Quote the value (`tech:"foo,bar"`) to keep a literal comma.
- A search may have at most 15 terms of 200 characters each and 1,000 characters in all. A search may name at most 40 values in all (every term, and every item of a comma list), and negate at most 3 terms. More is a 400.
- Unknown filter names are treated as plain text, so a pasted URL searches for the URL.

| Filter | Matches | Example |
| --- | --- | --- |
| `port:` | An **open** port number | `port:3306` |
| `proto:` | Hosts with an open port over `tcp` or `udp`. A UDP port counts only when it answered, never when it stayed silent (`open\|filtered`). | `proto:udp` |
| `product:` | Software nmap saw on a port | `product:openssh` |
| `service:` | Service name on a port | `service:ssh` |
| `tech:` | Which hosts run a product ([below](#what-a-host-runs)). Every source counts: technologies, open ports (product, version, CPE, banner, script output, HTTP header and title), the stored `Server` header, live routes' `Server` and `X-Powered-By` headers, fingerprints and cookie names, version source readings (first- and third-party, products and runtimes), Java runtime readings, and what runs on a platform (`tech:php` finds WordPress). A name matches as text and as the same product under any of its names (`apache httpd`, `apache http server` and `apachegeneric` are one). After `@`: `unknown` (or `none`) for no version known, `known`, or a release prefix (`@7.1` finds 7.1.4, never 7.10) | `tech:php`, `tech:"apache http server"`, `tech:java@unknown`, `tech:wordpress@7.1` |
| `banner:` | Service banners and NSE script output on an open port | `banner:"Anonymous FTP login allowed"` |
| `os:` | Operating system: the port scan's guess and its runners-up, an operating system CPE a port carries, the Windows release an NTLM challenge states, runZero's operating system (never a service or the hardware runZero names), a network operating system's or Shodan's OS CPE reading, and VMware ESXi as `vmware-version` states it | `os:windows`, `os:fortios`, `os:ubuntu` |
| `ip:` | An address, a prefix, or a CIDR range | `ip:198.51.100.0/24` |
| `host:` | Part of a host name or of its alias | `host:staging` |
| `alias:` | The short display name given to a host (or, for an address added as a target, to the target) | `alias:printer` |
| `note:` | The note written on a host (or its target) | `note:"rack 3"` |
| `cve:` | Hosts matched by a CVE (a full id or a prefix) | `cve:CVE-2026-111497` |
| `vuln:` | A finding by name, open or closed | `vuln:jenkins` |
| `sev:` | A finding of this severity, open or closed: `critical`, `high`, `medium`, `low`, `info` | `sev:critical` |
| `auth:` | A web route's sign-in state: `open`, `login`, `session_required`, `sso`, `redirect`, `not_found`, `catch_all`, `error` | `auth:open` |
| `sensitive:` | A route that served sensitive data: `any`, `credentials`, `pii`, `internal` | `sensitive:credentials` |
| `secret:` | Hosts that serve an exposed secret the inventory counts (docs/SECRETS-PLAN.md): `any`, a class (`s` server secret, `p` browser key, `i` identifier), `live` (validated active) or a provider name | `secret:s`, `secret:google` |
| `zombie:` | Hosts whose DNS is gone but still answer: `yes` or `no` | `zombie:yes` |
| `java:` | The Java runtime a host was read to run ([PIPELINE.md](PIPELINE.md#java-runtime)): a line, a release (a dotted prefix finds the releases under it), a vendor or a source; inferred readings count. `java:any` is `tech:java` and `java:unknown` is `tech:java@unknown` ([below](#what-a-host-runs)) | `java:17`, `java:17.0.9`, `java:8u392`, `java:temurin`, `java:jdwp`, `java:any`, `java:unknown` |
| `component:` | A product a version source read on the host ([PIPELINE.md](PIPELINE.md#version-sources)), an SNMP agent's release, or a component a vendor bundles with a product release (inferred): its name, read as `tech:` reads one (every alias of the product, a vendor in front, an edition or a detector's word behind, a quoted name with spaces: `component:"apache httpd"` finds `Apache HTTP Server`), optionally a release prefix after `@` (`@10.2` finds 10.2.3 and Junos `@21.4` finds 21.4R3-S2, never 10.20), or `any` | `component:grafana`, `component:docker@24`, `component:tomcat@9.0`, `component:junos@21.4`, `component:any`; an edge appliance's build: `component:netscaler`, `component:pan-os`, `component:fortios`, `component:connect-secure` ([PIPELINE.md](PIPELINE.md#edge-appliance-builds)) |
| `runtime:` | A language runtime the host states (Python, Go, Node.js, PHP, Ruby, .NET Framework, Erlang/OTP; `dotnet`, `golang`, `node` and `otp` are aliases), optionally a release prefix after `@`, or `any`; present-without-a-version readings count | `runtime:python`, `runtime:go@1.21`, `runtime:dotnet` |
| `vsource:` | Where a version was read: a catalogue entry, `header` for the stored headers, `snmp` for an SNMP agent's sysDescr, `bundled` for a component inferred from a vendor's bundle, `nmap`, `webserver`, `testssl`, `wpscan` or `db-probe` for [data already received](PIPELINE.md#versions-already-received), `nuclei` for a versioned product a [network detection template](PIPELINE.md#stages) read on a port nmap named another product on, `shodan-idb` or `runzero` for a third-party reading (`reported` for every one; runZero's are its operating system, the services it read a version on, per port, and its hardware firmware as a hint), `ntlm` for the [Windows release an NTLM challenge states](PIPELINE.md#windows-release-from-ntlm), `ssh` for the banner the SSH inspection read, `panel` for what a nuclei panel template read (a version, or the product alone when it showed none), or `any`. An identity reading (a product named with no version: a FortiGate's OS guess or certificate, a Recog identity, a panel page that shows no version) is found by its source too | `vsource:prometheus-metrics`, `vsource:docker-api`, `vsource:header`, `vsource:snmp`, `vsource:bundled` |
| `country:` | The country of a host's IP address, by ISO code or name | `country:US`, `country:Germany` |
| `distro:` | The distribution a service banner names ([PIPELINE.md](PIPELINE.md#cve-intelligence)): a distribution (`ubuntu`, `debian`, `rhel` for the Red Hat family, `centos`, `alpine`, `amzn`, `suse`, `freebsd`), a codename (`jammy`, `bookworm`), a release prefix after `@`, or `any`. A release is known when the banner, the OS CPE or the package build states it, or when only one release ever shipped that build | `distro:jammy`, `distro:ubuntu@22.04`, `distro:debian@12`, `distro:rhel@9` |
| `pkg:` | A distribution source package a service banner names, optionally its exact build after `@` (the dpkg epoch, which banners never show, may be left out), or the start of one | `pkg:openssh`, `pkg:openssh@1:8.9p1-3ubuntu0.6`, `pkg:openssh@8.9p1-3ubuntu0`, `pkg:php8.1` |

`port:` takes a number only and matches the port over either protocol; add `proto:` to pick one (`proto:udp port:123`). Use `product:` or `service:` for names. A bad value, such as `sev:scary`, returns an error that lists the allowed ones.

`tech:` also reads what the Internet Archive saw on the host in the past (a `.php` page, `/wp-content/`). Those hits are labelled **seen in web archive**, because they are history, not what runs today.

A bare word followed by a dotted version is that product at that release: `wordpress 7.1` is `tech:wordpress@7.1`. A version on its own (`7.1`) keeps matching any text that contains it.

### What a host runs

`tech:<name>` answers "which of my hosts run X, at which version, and which ones have no version known", for any product.

- **Every source counts.** A technology row (by its name, or by the CPE the nuclei template that named it states: `tech:http_server` finds an "Apache2 Default Page" its template named `apache:http_server`), an open port's product or CPE, the `Server` header the web check stored, a live route's headers and fingerprints, a [version source](PIPELINE.md#version-sources) reading (a product or a language runtime, first-party or [third-party](PIPELINE.md#versions-already-received)), and for Java a [Java runtime](PIPELINE.md#java-runtime) reading. A closed port and a retired route do not count.
- **Every name of the product counts.** The name is read the way correlation reads a technology (a `Name:version`, a `product/version` header token, a CPE), then compared with the names the stored rows use through the product aliases (`web/cveFeed/data/product_aliases.json`): `tech:"apache httpd"`, `tech:"apache http server"` and `tech:apachegeneric` find the same hosts, a vendor in front or an edition behind is the same product (`tech:tomcat` finds "Apache Tomcat", `tech:grafana` "Grafana OSS"), and a longer name is another product (`tech:php` is not phpMyAdmin by name). Matching as text is kept too, so no search finds fewer hosts than before.
- **What runs on a platform counts as the platform** (`web/cveFeed/data/runs_on.json`, each entry citing the product's own requirements):

| Platform | `tech:` | Products that run on it |
| --- | --- | --- |
| Java | `java`, `jdk`, `jre`, `openjdk`, `jvm` | Tomcat, Jetty, Jenkins, Jira, Confluence, Spring, WebLogic, WildFly, Elasticsearch, Kafka ... (the [Java runtime](PIPELINE.md#java-runtime) list) |
| PHP | `php` | WordPress, Drupal, Joomla, Magento, Laravel, phpMyAdmin, MediaWiki, Nextcloud |
| .NET | `dotnet`, `.net`, `asp.net` | SharePoint, Exchange (OWA), Umbraco, DotNetNuke; IIS counts only with ASP.NET's own signal (`X-Powered-By: ASP.NET`, `X-AspNet-Version`), since IIS alone also serves PHP and static files |
| Node.js | `nodejs`, `node.js`, `node` | Express, Next.js, Nuxt, Ghost, Strapi |
| Python | `python` | Django, Flask (Werkzeug), Plone, Odoo, Gunicorn |
| Ruby | `ruby` | Rails, GitLab, Discourse, Redmine |

- **The version state goes after `@`**, as with `component:` and `runtime:`. `@unknown` (or `@none`) is a host that runs it where no source states a version of that product; for a platform found through what runs on it, that means no reading of the platform itself (WordPress 6.4.2 states WordPress's version, not PHP's). `@known` is the opposite. `@<release>` is that release, by prefix: `@7.1` finds 7.1 and 7.1.4, never 7.10. A version a protocol states is never the product's ("Apache Tomcat/Coyote JSP engine 1.1" is Tomcat's HTTP/1.1 connector). A Windows release an NTLM challenge states ([PIPELINE.md](PIPELINE.md#windows-release-from-ntlm)) is the release without its patch level: `tech:windows@unknown` finds it, `tech:windows@known` does not, and `tech:"windows server 2022"@10.0.20348` does (the release is stated; `@10.0.20348.2762`, a revision, is not).
- **Each result says why**: what showed the product and its version (`technology WordPress:7.1.4`, `port 80 Apache httpd 2.4.58`, `runtime PHP 8.2.12 (passive)`, `Java runtime 17.0.9 (jdwp)`), the product that showed the platform (`runs PHP (WordPress 6.4.2)`, `runs Java (Tomcat 10.1.48)`), or `PHP version not known`.

```text
tech:java                              every host that runs Java (java:any)
tech:java@unknown                      Java hosts whose runtime nobody has read (java:unknown)
tech:php -tech:php@known               the same question for PHP, written the long way
tech:"apache http server@2.4"          Apache httpd 2.4.x, under any of its names (the qualifier goes inside the quotes)
tech:wordpress@unknown                 WordPress hosts with no version known
tech:php,java -tech:nginx              PHP or Java hosts not behind nginx
```

## Examples

**What is exposed**

```text
port:3389                              every host with Remote Desktop open
port:22 port:2222                      SSH on both the usual and the alternate port
product:redis                          Redis anywhere, including on odd ports
os:windows port:445                    Windows hosts with SMB reachable
proto:udp port:161                     SNMP that answered over UDP (UDP 161 is not TCP 161)
proto:udp product:memcached            memcached that answers datagrams
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

**By the names you gave your hosts** (an alias and a note, set on the Targets and Hosts pages or over the API; see [Frontend](FRONTEND.md))

```text
printer                                a bare word also reads aliases and notes
alias:printer                          hosts you named "printer"
note:"rack 3" -alias:spare             hosts with that note, minus the spares
```

**Scope it down**

```text
ip:203.0.113.0/24 product:nginx        nginx inside one network range
distro:jammy pkg:openssh@8.9p1-3ubuntu0.6   Ubuntu 22.04 hosts still on one OpenSSH build
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

`page_size` goes up to 200. With no `q`, the search lists every host. `heat=fire|smoke|ice|clean|unscanned` narrows the whole result to hosts of that [temperature](FIRE-SMOKE-ICE.md), and `facets=port,product,tech,os,country` (with `facet_size`, 10 by default and 50 at most) returns counts per value, plus `facets.heat` over the whole match of `q` (it ignores `heat` itself, so every chip keeps its real total); counts stop after 5,000 hosts and the response says so (`facets.truncated`). `facets.unscannable` splits the *Not scanned* hosts that have no address a scanner can use (`private`: it points inside a private network, `no_dns`: no DNS answer, `unknown`: not looked at yet) from those still waiting their turn. `internal=1` keeps only hosts inside a network their project declared internal (scanned by a [Sentinel](ARCHITECTURE.md#sentinels) there), and `internal=0` only the others. Temperature and scope are API parameters and chips, not `filter:value` terms, so they are not part of a saved search's query.

On the Hosts page, the **Temperature** chips (All, Fire, Smoke, Ice, Clean, Not scanned, each with its count) set `heat=` and ask the server, so they narrow the whole inventory and not only the rows on screen. The **Scope** chips (All hosts, External, Internal) set `internal=` and appear once a project you can see declares an internal network. Both live in the address (`?heat=`, `?internal=`), next to `?q=` and `?sort=`.

## Saved searches and alerts

A search you run again and again can be kept. On the Hosts page, type a search and choose **Save search**; **Saved searches** lists yours. A saved search is a query in the syntax above, kept on the server, private to you and to one project. Within ten minutes of saving it (or at once, with **Run now**) cvENGINE runs it for the first time and records which hosts match. That first check is silent: it sets the baseline, so saving a search never floods a channel with every host that already matches. From the next check on you are told what changed.

```text
port:5432 -ip:10.0.0.0/8        Postgres reachable on a public address
tech:grafana                    every Grafana, and a message when a new one appears
auth:open sensitive:credentials a route that serves credentials without a login
zombie:yes tech:wordpress       retired names that still answer and run WordPress
```

| Setting | What it does |
| --- | --- |
| **How often** | Every hour, day or week (default: every day). Checks run when due, at most 25 searches every ten minutes, oldest first. |
| **Alert when a host starts to match** | On by default. One message, naming up to five new hosts and counting the rest, with a link that opens the search. |
| **Alert when a host stops matching** | Off by default. Same message, for hosts that left the result. |
| **Alert when the match count reaches** | Optional. Once each time the count rises to that number; it re-arms when the count falls below it. |
| **Send alerts to** | Slack, Discord, Telegram, or Lark, among those switched on in Settings, Notifications. Nothing ticked means every channel that is on. |

How it behaves:

- **Same results as the search box.** A saved search runs through the same code as the live search, so it finds exactly what the Hosts page finds. The query is checked when you save it: an empty query, an unusable value (`port:abc`, `sev:scary`), more than 15 terms or 1,000 characters is refused with the same message the search gives.
- **One host is one match.** Names that point at the same addresses are one host (see the Hosts page), so `example.com` gaining a `www.example.com` on the same servers is not a new match. A host whose set of addresses changes does count as a new one.
- **At most one message per search per check**, plus a line in the Activity feed (kind **Saved search**), even when Settings has no channel switched on. Alerts use the "Interesting findings" switch under Settings, Notifications.
- **Your access, at every check.** The search runs with your rights as they are then. If you leave the project or your account is deactivated, the search is switched off with the reason shown on the list; it is never run with the access it was saved under. Switching it on again (which needs access) restarts its baseline.
- **Too broad.** A search that matches more than 1,000 hosts is flagged **too broad** and is not alerted on until you narrow it: a set that large shifts all the time and cannot be compared cheaply.
- **Limits.** 25 saved searches per person and 100 per project. Editing the query restarts the baseline. Each check has a 20 second database limit; a failure is recorded in the Activity feed and retried at the next time.
- **Browser views stay.** The saved views kept in your browser (Hosts, Findings) keep working. **Import browser views** on the Saved searches list copies the ones that hold a search into saved searches, with alerts off, and leaves the local copies alone.

Over the API ([AGENT-API.md](AGENT-API.md#saved-searches)) the same operations are `GET/POST projects/{slug}/saved-searches`, `GET/PATCH/DELETE .../saved-searches/{id}`, `POST .../{id}/run` and `GET .../{id}/matches`, and the MCP tools `list_saved_searches`, `create_saved_search`, `update_saved_search`, `delete_saved_search`, `run_saved_search` and `get_saved_search_matches`.

See also: [PIPELINE.md](PIPELINE.md) for what fills the inventory, [FRONTEND.md](FRONTEND.md), [documentation index](README.md).
