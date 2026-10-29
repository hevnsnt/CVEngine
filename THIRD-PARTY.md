# Third-party software

cvENGINE is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x, released under the GPL-3.0 (see [LICENSE](LICENSE), [CONTRIBUTORS.md](CONTRIBUTORS.md)). It stands on the projects below. Each keeps its own license, and the license on its page applies.

## Scanners and tools

| Project | License | Used for |
| --- | --- | --- |
| [bbot](https://github.com/blacklanternsecurity/bbot) | AGPL-3.0 | Subdomain and asset discovery, run as a separate process |
| [nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Vulnerability scanning and CVE tests |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | The community template library |
| [nmap](https://github.com/nmap/nmap) | [Nmap Public Source License](https://nmap.org/npsl/) | Service and OS fingerprinting and the UDP exposure sweep. Pinned to one release with its checksum: on amd64 the official release package from nmap.org is unpacked, on arm64 (where nmap.org publishes no binary) the release tarball is compiled |
| [naabu](https://github.com/projectdiscovery/naabu) | MIT | Full-port discovery ahead of nmap |
| [gowitness](https://github.com/sensepost/gowitness) | GPL-3.0 | Front-page screenshots, installed by bbot (with a Chromium that bbot downloads alongside it, under its own licenses) and used in the default and deep discovery modes |
| [MailFail](https://github.com/ACK-J/MailFail) | AGPL-3.0 | Source of the email-security checks, re-implemented server side with credit |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | BSD-3-Clause | Names the web application firewall in front of a web host |
| [WPScan](https://github.com/wpscanteam/wpscan) | [WPScan Public Source License](https://github.com/wpscanteam/wpscan/blob/master/LICENSE) (free for testing your own systems and for pentesters; a commercial license is needed for managed or hosted use) | WordPress vulnerability scanning |
| [testssl.sh](https://github.com/testssl/testssl.sh) | GPL-2.0 (run as a separate program, never linked) | Tests the TLS configuration of every TLS port: protocols, ciphers, forward secrecy and the named TLS vulnerabilities |
| [Tailscale](https://github.com/tailscale/tailscale) (the `tailscale/tailscale` container image) | BSD-3-Clause | The optional `tailscale` compose service that joins a tailnet so scans can reach it; read through its local status API |
| [Greenbone Community Edition](https://greenbone.github.io/docs/latest/): [gvmd](https://github.com/greenbone/gvmd) (with its library [gvm-libs](https://github.com/greenbone/gvm-libs), GPL-2.0-or-later) | AGPL-3.0-or-later | The vulnerability manager of the optional `openvas` compose profile; cvENGINE drives it over GMP. Every Greenbone component runs as a separate container (image from `registry.community.greenbone.net`), never linked into the cvENGINE image |
| [ospd-openvas](https://github.com/greenbone/ospd-openvas) | AGPL-3.0-or-later | The scanner wrapper of the `openvas` profile; the only container there with `NET_RAW` and `NET_ADMIN` |
| [openvas-scanner](https://github.com/greenbone/openvas-scanner) | GPL-2.0 (its Rust parts GPL-2.0-or-later) | The scan engine and the notus service of the `openvas` profile |
| [pg-gvm](https://github.com/greenbone/pg-gvm) | GPL-3.0 | The PostgreSQL database image of the `openvas` profile (PostgreSQL itself is under the PostgreSQL License) |
| Redis, in Greenbone's `redis-server` image | The license of the Redis version Greenbone ships (check it in the image before redistributing) | The scanner's cache in the `openvas` profile; a separate container |
| Greenbone feed data (`vulnerability-tests`, `notus-data`, `scap-data`, `cert-bund-data`, `dfn-cert-data`, `data-objects`, `report-formats` images, and `gpg-data`, the signing keys) | Its own terms, printed by the data containers when they start | Vulnerability tests and advisory data for the `openvas` profile. The data images follow a moving tag on purpose (the definitions must keep updating), so what they contain changes without a cvENGINE release; `gpg-data` is pinned by digest |
| [python-gvm](https://github.com/greenbone/python-gvm) (pinned in `web/requirements.txt`) | GPL-3.0-or-later (its dependencies: `httpx` and `httpcore` BSD-3-Clause, `lxml` BSD-3-Clause, `paramiko` LGPL-2.1, `PyNaCl` and `bcrypt` Apache-2.0, `invoke` BSD-2-Clause, `h2`, `hpack` and `hyperframe` MIT) | The GMP client library behind the OpenVAS add-on; installed in the cvENGINE image (it is linked, which is why its license must fit the GPL-3.0) |
| [aardwolf](https://github.com/skelsec/aardwolf) | MIT | The headless RDP client behind the login-screen screenshot |
| [node2shell-scanner](https://github.com/assetnote/node2shell-scanner) by Assetnote | MIT | Read-only detection of CVE-2026-111497; vendored (trimmed to its detection core) as `web/cveFeed/vendor/node2shell.py`, with the exact source commit in that file's header |

## Data sources

| Source | Used for |
| --- | --- |
| [cve.now](https://cve.now) | The CVE feed |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CC0) | Known exploited vulnerabilities |
| [ENISA EUVD](https://euvd.enisa.europa.eu) | European exploited vulnerabilities |
| [VulnCheck KEV](https://vulncheck.com) | Exploitation data, with a free community key |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit prediction scores |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) (GPL-2.0 or later) | Public exploit references |
| [Metasploit Framework](https://github.com/rapid7/metasploit-framework) (BSD-3-Clause) | Exploit module references |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | CVE records |
| [OSV](https://osv.dev) (Apache-2.0 code) and [Debian security tracker](https://security-tracker.debian.org) | Distribution fix data for backport detection |
| [crt.sh](https://crt.sh) | Certificate transparency lookups |
| [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) | Registry lookups for email hygiene checks |
| [cvENGINE CVE seed](https://github.com/hevnsnt/CVEngine/releases/tag/cve-seed) | The pre-built CVE catalog a new install downloads and verifies on first start |
| [GitHub API](https://docs.github.com/rest) | The in-app update check |
| [Internet Archive CDX index](https://web.archive.org) | Saved URLs, as passive evidence of what a host once ran |
| [Tailscale API](https://tailscale.com/api) and [security bulletins](https://tailscale.com/security-bulletins) | Read-only access to your own tailnet with your own credentials, and the fixed versions the Tailscale checks use |
| [Tailworm](https://tailworm.com/) (an October 2026 security assessment of Tailscale and headscale, unconfirmed by the vendor) | Guidance behind the SSH, tag-owner and Funnel policy checks; referenced, nothing copied |
| [wpscan.com API](https://wpscan.com/) | WordPress vulnerability data for WPScan, with your own token |
| [runZero Export API](https://help.runzero.com/docs/exporting-asset-data/) | Asset inventory (OS, hardware, tags, CVE reports) read with your own Export API token from `console.runzero.com`; no runZero code is bundled |
| [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) (MIT) | Public scope of bug bounty programs, read at run time |
| [Bugcrowd Vulnerability Rating Taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy) (Apache-2.0) | Bundled as `web/cveFeed/data/vrt.json` for report categories and priority |

## AI back ends

cvENGINE talks to [Anthropic](https://www.anthropic.com), [OpenAI](https://openai.com), and [OpenRouter](https://openrouter.ai) over their APIs, and to self-hosted [Ollama](https://github.com/ollama/ollama) (MIT) [vLLM](https://github.com/vllm-project/vllm) (Apache-2.0) and [LM Studio](https://lmstudio.ai) servers (cvENGINE only calls their HTTP APIs; no LM Studio code is included). Agents connect through the [Model Context Protocol](https://modelcontextprotocol.io).

## Front end

| Project | License | Files |
| --- | --- | --- |
| [Geist and Geist Mono](https://github.com/vercel/geist-font) | SIL Open Font License 1.1 | `web/static/cve/geist.woff2`, `geist-mono.woff2`; license text in `web/static/cve/OFL.txt` |
| [VivaGraphJS](https://github.com/anvaka/VivaGraphJS) | BSD-3-Clause | `web/static/cve/vivagraph.min.js`; notice in `web/static/cve/VIVAGRAPH-LICENSE.txt` |
| [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) | MIT | `web/static/mfa/qrcode.js`, license header kept in the file |
| [DejaVu Sans](https://dejavu-fonts.github.io) (Debian `fonts-dejavu-core`) | Bitstream Vera license with public-domain DejaVu changes | Installed in the image; the PDF reports are set in it |
| [pypdf](https://github.com/py-pdf/pypdf) | BSD-3-Clause | A pinned Python requirement (`web/requirements.txt`); the tests use it to read the generated report PDFs back, the application does not import it |
| [Inter](https://github.com/rsms/inter) | SIL Open Font License 1.1 | Loaded from Google Fonts by HTML reports, not shipped |

## Platform

[Django](https://github.com/django/django), [Celery](https://github.com/celery/celery), [Redis](https://github.com/redis/redis), [PostgreSQL](https://www.postgresql.org), [nginx](https://github.com/nginx/nginx), [Gunicorn](https://github.com/benoitc/gunicorn), and [WeasyPrint](https://github.com/Kozea/WeasyPrint) run the application. The libraries in `web/requirements.txt` are installed from PyPI under their own licenses.
