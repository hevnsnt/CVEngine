# Third-party software

cvENGINE is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x, released under the GPL-3.0 (see [LICENSE](LICENSE), [CONTRIBUTORS.md](CONTRIBUTORS.md)). It stands on the projects below. Each keeps its own license, and the license on its page applies.

## Scanners and tools

| Project | License | Used for |
| --- | --- | --- |
| [bbot](https://github.com/blacklanternsecurity/bbot) | AGPL-3.0 | Subdomain and asset discovery, run as a separate process on the Sentinel (its own virtual environment, pinned in the Sentinel image); the server image has none |
| [nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Vulnerability scanning and CVE tests |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | The community template library |
| [nmap](https://github.com/nmap/nmap) | [Nmap Public Source License](https://nmap.org/npsl/) | Service and OS fingerprinting and the UDP exposure sweep. Pinned to one release with its checksum: on amd64 the official release package from nmap.org is unpacked, on arm64 (where nmap.org publishes no binary) the release tarball is compiled |
| [naabu](https://github.com/projectdiscovery/naabu) | MIT | Full-port discovery ahead of nmap |
| [Playwright](https://github.com/microsoft/playwright-python) and its [Chromium](https://www.chromium.org/) (the `--only-shell` headless build Playwright downloads) | Apache-2.0 (Playwright); Chromium is under its own licenses (BSD-3-Clause and the licenses of what it bundles) | The browser behind the screenshots of every host's web pages. It is installed in the **Sentinel image** (the cvENGINE-sentinel repository pins it and checks it), not in this one: the server runs no browser (`web/cveFeed/web_shot.py` only queues pages and stores what a Sentinel returns) |
| Playwright's [seccomp profile](https://github.com/microsoft/playwright/blob/v1.64.1/utils/docker/seccomp_profile.json) (`config/seccomp/playwright-chromium.json`, vendored unchanged from v1.64.1, SHA-256 `cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849`) | Apache-2.0 (Playwright; it is Docker's default seccomp profile, also Apache-2.0, plus the user namespace system calls) | Applied to the built-in `scanner` container (the Sentinel image runs the browser there) so Chromium's sandbox can start (docs/PIPELINE.md, "Web screenshots") |
| [gowitness](https://github.com/sensepost/gowitness) | GPL-3.0 | Front-page screenshots taken during a bbot discovery, installed by bbot (with a Chromium that bbot downloads alongside it, under its own licenses) and used in the default and deep discovery modes; the host page falls back to them where the browser has taken none |
| [MailFail](https://github.com/ACK-J/MailFail) | AGPL-3.0 | Source of the email-security checks, re-implemented server side with credit |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | BSD-3-Clause | Names the web application firewall in front of a web host |
| [Kingfisher](https://github.com/mongodb/kingfisher) by MongoDB, with its rule bundle (rules imported from Betterleaks, Gitleaks and Veles; their notices ship in the archive) and the [Vectorscan](https://github.com/VectorCamp/vectorscan) engine it links | Apache-2.0 (Vectorscan BSD-3-Clause) | Secret detection in the scanner image only (the Sentinel kind `secrets_scan`, docs/SECRETS-PLAN.md): the release tarball pinned by sha256 per architecture, with its build attestation verified in CI, and its `NOTICE` files kept under `/usr/share/doc/kingfisher/` (Apache-2.0 section 4(d): "Copyright 2025-2026 MongoDB, Inc", with the attributions for Nosey Parker, Praetorian Security and the rules it imports). The server image has none |
| [sshamble](https://github.com/runZeroInc/sshamble) by runZero | BSD-2-Clause (Copyright (c) 2024, runZero, Inc; it also carries a modified copy of [golang/crypto](https://github.com/golang/crypto) under the Go BSD 3-clause license) | SSH inspection in the Sentinel image only (the Sentinel kind `ssh_probe`): the release tarball per architecture, pinned by sha256, with its `LICENSE.md` kept at `/usr/share/doc/sshamble/LICENSE.md`. Only `sshamble scan` with the one fixed check `badkeys-blocklist` is ever run (the client refuses any other command line): it reads the server's own handshake (banner, host keys, algorithms, offered authentication methods) and compares the host keys with the badkeys blocklist. Nothing submits a credential or tries to log in. The server image has none |
| [badkeys.info](https://badkeys.info) blocklist data (from the [badkeys](https://github.com/badkeys/badkeys) project) | The badkeys software is MIT (Copyright Hanno Böck); the license of the blocklist data itself is not stated where it is downloaded and is recorded here as **unknown** | The known-weak SSH host keys sshamble checks against. Not baked into the image: the Sentinel downloads it daily with `sshamble badkeys-update` into its own state volume (off with `CVENGINE_BADKEYS_REFRESH=0` for an air-gapped Sentinel, which then reports "not checked") |
| [cvengine-scanner](https://github.com/hevnsnt/cvENGINE-sentinel) (the scanner library) | GPL-3.0-only (the Sentinel repository's declared license) | The scan policy, parsers and the result contract the server shares with every Sentinel; `web/requirements.txt` pins it to a full commit sha |
| The Sentinel image's Python libraries (`requests`, `python-gvm`, `xmltodict`, `h11`, `aardwolf`, `Pillow`, `redis`, `playwright`, `PyMySQL`, `pymongo`, `dnspython`, `cryptography`, `tldextract`) | MIT, Apache-2.0, BSD-3-Clause, ISC, GPL-3.0-or-later (python-gvm) and MIT-CMU (Pillow), each under its own license (read from the package metadata) | The Sentinel client's dependencies, pinned in the Sentinel repository's `requirements.txt` (PyMySQL and pymongo speak the one credential-less database greeting of `db_probe`; Pillow and aardwolf the RDP screenshot) |
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
| [aardwolf](https://github.com/skelsec/aardwolf) | MIT | The headless RDP client behind the login-screen screenshot, in the Sentinel image (pinned in the Sentinel `requirements.txt`; the server image no longer installs it) |
| [node2shell-scanner](https://github.com/assetnote/node2shell-scanner) by Assetnote | MIT | Read-only detection of CVE-2026-111497; vendored (trimmed to its detection core) as `client/vendor/node2shell.py` in the Sentinel repository ([cvENGINE-sentinel](https://github.com/hevnsnt/cvENGINE-sentinel)), with the exact source commit in that file's header; the server's `web/cveFeed/node2shell_scan.py` only queues the work |

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
| [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) and the registries it names | Registry lookups for the hygiene and dangling-domain checks |
| [cvENGINE CVE seed](https://github.com/hevnsnt/CVEngine/releases/tag/cve-seed) | The pre-built CVE catalog a new install downloads and verifies on first start |
| [GitHub API](https://docs.github.com/rest) | The in-app update check |
| [badkeys.info](https://badkeys.info) | Known-weak SSH host keys, downloaded by the Sentinel (see sshamble above) |
| [nuclei-templates releases](https://github.com/projectdiscovery/nuclei-templates/releases) | The server's template refresh and the reviewer's check for a newer release |
| [Greenbone Community feed](https://greenbone.github.io/docs/latest/) | The OpenVAS add-on's vulnerability tests, from `registry.community.greenbone.net` |
| [HackerOne API](https://api.hackerone.com) | Submitting a report you wrote, with your own API token |
| Slack, Discord, Telegram and Lark webhooks | Notifications to the webhook or bot you configure |
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
| [CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) | GPL-3.0 | Not run and not copied: its per-CMS version routines (the generator tag, version headers, and the files Drupal, Joomla and Magento state a release in) were the reference for the version sources in `cvengine_scanner/cms.py` (the scanner library, hevnsnt/cvENGINE-sentinel) and the version probes in `web/cveFeed/probes.py` |
| [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) | MIT | `web/static/mfa/qrcode.js`, license header kept in the file |
| [DejaVu Sans](https://dejavu-fonts.github.io) (Debian `fonts-dejavu-core`) | Bitstream Vera license with public-domain DejaVu changes | Installed in the image; the PDF reports are set in it |
| [pypdf](https://github.com/py-pdf/pypdf) | BSD-3-Clause | A pinned Python requirement (`web/requirements.txt`); the tests use it to read the generated report PDFs back, the application does not import it |
| [Inter](https://github.com/rsms/inter) | SIL Open Font License 1.1 | Loaded from Google Fonts by HTML reports, not shipped |

## Platform

| Project | License | Where |
| --- | --- | --- |
| [Ubuntu](https://ubuntu.com) 26.04 | Free software, each package under its own license (the per-package copyright files were not read for this list) | The base of the server and Sentinel images (`web/Dockerfile`, the Sentinel `Dockerfile`) |
| [Django](https://github.com/django/django) 5.2, [Celery](https://github.com/celery/celery) 5.6, [Gunicorn](https://github.com/benoitc/gunicorn) 26 and gevent, [WeasyPrint](https://github.com/Kozea/WeasyPrint) 70 | BSD-3-Clause, BSD-3-Clause, MIT, BSD-3-Clause (WeasyPrint's PyPI classifier) | The server application, pinned in `web/requirements.txt` |
| [PostgreSQL](https://www.postgresql.org) 18 | PostgreSQL License | The `postgres:18-alpine` compose image |
| [Redis](https://github.com/redis/redis) | The compose image `redis:alpine` is a moving tag. Redis 8 and later is RSALv2, SSPLv1 or AGPLv3 at your option; Redis 7.2 and earlier is BSD-3-Clause. Check the version you pulled | The Celery broker, cache and locks. cvENGINE links no Redis code: it talks to a separate container |
| [nginx](https://github.com/nginx/nginx) | BSD-2-Clause | The `nginx:alpine` compose image, the TLS reverse proxy |
| [Anthropic SDK](https://github.com/anthropics/anthropic-sdk-python) 2.3.0 and its pinned dependencies | Apache-2.0 (SDK) and MIT, BSD-3-Clause, Apache-2.0, PSF-2.0 for the rest, per their package metadata | The AI reviewer image only (`reviewer/requirements.txt`) |

The libraries in `web/requirements.txt` are installed from PyPI under their own licenses. Which tools run in which image, with their versions and licenses, is also on the About page of every install (`web/cveFeed/software.py`).
