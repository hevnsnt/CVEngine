# Third-party software

cvENGINE is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x, released under the GPL-3.0 (see [LICENSE](LICENSE), [CONTRIBUTORS.md](CONTRIBUTORS.md)). It stands on the projects below. Each keeps its own license, and the license on its page applies.

## Scanners and tools

| Project | License | Used for |
| --- | --- | --- |
| [bbot](https://github.com/blacklanternsecurity/bbot) | AGPL-3.0 | Subdomain and asset discovery, run as a separate process |
| [nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Vulnerability scanning and CVE tests |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | The community template library |
| [nmap](https://github.com/nmap/nmap) | [Nmap Public Source License](https://nmap.org/npsl/) | Service and OS fingerprinting |
| [naabu](https://github.com/projectdiscovery/naabu) | MIT | Optional full-port discovery |
| [gowitness](https://github.com/sensepost/gowitness) | GPL-3.0 | Screenshots in deep discovery |
| [MailFail](https://github.com/ACK-J/MailFail) | AGPL-3.0 | Source of the email-security checks, re-implemented server side with credit |

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
| [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) (MIT) | Public scope of bug bounty programs, read at run time |
| [Bugcrowd Vulnerability Rating Taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy) (Apache-2.0) | Bundled as `web/cveFeed/data/vrt.json` for report categories and priority |

## AI back ends

cvENGINE talks to [Anthropic](https://www.anthropic.com), [OpenAI](https://openai.com), and [OpenRouter](https://openrouter.ai) over their APIs, and to self-hosted [Ollama](https://github.com/ollama/ollama) (MIT) and [vLLM](https://github.com/vllm-project/vllm) (Apache-2.0) servers. Agents connect through the [Model Context Protocol](https://modelcontextprotocol.io).

## Front end

| Project | License | Files |
| --- | --- | --- |
| [Geist and Geist Mono](https://github.com/vercel/geist-font) | SIL Open Font License 1.1 | `web/static/cve/geist.woff2`, `geist-mono.woff2`; license text in `web/static/cve/OFL.txt` |
| [VivaGraphJS](https://github.com/anvaka/VivaGraphJS) | BSD-3-Clause | `web/static/cve/vivagraph.min.js`; notice in `web/static/cve/VIVAGRAPH-LICENSE.txt` |
| [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) | MIT | `web/static/mfa/qrcode.js`, license header kept in the file |
| [Inter](https://github.com/rsms/inter) | SIL Open Font License 1.1 | Loaded from Google Fonts by HTML reports, not shipped |

## Platform

[Django](https://github.com/django/django), [Celery](https://github.com/celery/celery), [Redis](https://github.com/redis/redis), [PostgreSQL](https://www.postgresql.org), [nginx](https://github.com/nginx/nginx), [Gunicorn](https://github.com/benoitc/gunicorn), and [WeasyPrint](https://github.com/Kozea/WeasyPrint) run the application. The libraries in `web/requirements.txt` are installed from PyPI under their own licenses.
