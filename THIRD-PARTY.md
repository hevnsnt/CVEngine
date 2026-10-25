# Third-party software

CVEngine is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x, released under the GPL-3.0 (see [LICENSE](LICENSE)). It also uses and ships the software below. Each project keeps its own license, and the license on its page applies.

## Scanners and data sources

| Project | Used for |
| --- | --- |
| [bbot](https://github.com/blacklanternsecurity/bbot) | Discovery, including screenshots through its gowitness module |
| [nuclei](https://github.com/projectdiscovery/nuclei) and its templates | Vulnerability scanning and CVE tests |
| [naabu](https://github.com/projectdiscovery/naabu) | Optional full-port discovery |
| [nmap](https://nmap.org) | Service and OS fingerprinting, under the [Nmap Public Source License](https://nmap.org/npsl/) |
| [gowitness](https://github.com/sensepost/gowitness) | Screenshots |
| [cve.now](https://cve.now) | The CVE feed, which aggregates the CVE List, GHSA, OSV, NVD, EUVD, CISA KEV, EPSS, and Exploit-DB |
| [Debian security tracker](https://security-tracker.debian.org) and [OSV](https://osv.dev) | Distribution fix data for backport detection |
| [crt.sh](https://crt.sh) | Certificate transparency lookups |
| [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) (MIT) | Public scope data of bug bounty programs, read at run time by the Bug bounty page |
| [Bugcrowd Vulnerability Rating Taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy) (Apache-2.0) | Bundled as `web/cveFeed/data/vrt.json` for the report category and its priority |

## Front end

| Project | License | Files |
| --- | --- | --- |
| [Geist and Geist Mono](https://github.com/vercel/geist-font) | SIL Open Font License 1.1 | `web/static/cve/geist.woff2`, `geist-mono.woff2`. License text in `web/static/cve/OFL.txt`. |
| [VivaGraphJS](https://github.com/anvaka/VivaGraphJS) | BSD-3-Clause | `web/static/cve/vivagraph.min.js`; upstream notice in `web/static/cve/VIVAGRAPH-LICENSE.txt`. |
| [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) | MIT | `web/static/mfa/qrcode.js` (license header kept in the file) |

## Python libraries

The libraries in `web/requirements.txt` (Django, Celery, and others) are installed from PyPI under their own licenses.
