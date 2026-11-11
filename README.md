<p align="center">
  <img src="docs/images/cvengine-logo.png" alt="cvENGINE" width="560">
</p>

<h3 align="center">The most advanced external attack surface assessment you can get for free.</h3>

<p align="center">
  Type in your domain. cvENGINE finds everything you expose, then tells you which of today's exploited CVEs can actually hit you, with proof.<br>
  No license fee. No per-asset pricing. No black box. 100% open source and self-hosted.
</p>

<p align="center">
  <img alt="License GPL-3.0" src="https://img.shields.io/badge/license-GPL--3.0-black">
  <img alt="Python 3.14" src="https://img.shields.io/badge/python-3.14-black">
  <img alt="Django 6.0" src="https://img.shields.io/badge/django-6.0-black">
  <img alt="PostgreSQL 18" src="https://img.shields.io/badge/postgresql-18-black">
  <img alt="Runs in Docker" src="https://img.shields.io/badge/runs%20in-docker-black">
</p>

---

<p align="center">
  <img src="docs/images/cvengine-tour-1.3.gif" alt="What is new in 1.3: the Live page with hosts inside private networks counted apart, the Hosts page filtered to internal hosts, the Sentinels that scan them from inside the network, provisioning a Sentinel from a list of your organizations, the regrouped Settings tabs and the new Email tab" width="900">
</p>

## Know what you expose. Fix what's exploitable first.

Attack surface tools find assets. Vulnerability scanners find flaws. Threat feeds find CVEs. **cvENGINE runs all three as one continuous loop** and hands you a verdict instead of a pile of alerts. It answers the question that matters: *of everything exploited today, what do I have exposed?*

- **Total visibility.** Domains, subdomains, IPs, ports, products, versions, TLS, and technologies, discovered for you and kept current in one Shodan-style inventory.
- **Exploitation-ranked.** Every CVE is rated [fire, smoke, or ice](docs/FIRE-SMOKE-ICE.md) from the real exploitation sources, then matched to what you actually run.
- **Proof, not noise.** AI triage plus read-only checks that reproduce the finding, with the exact command recorded.
- **Nothing changes unseen.** New hosts, opened ports, version bumps, and changed front pages land on a timeline.
- **Yours completely.** One Docker Compose stack on your own server. Bring your own AI keys, or run a local model.

## Everything in the box

| | |
| --- | --- |
| **Discover** | Subdomains, certificates, IPs, and ports with [bbot](https://github.com/blacklanternsecurity/bbot) and [naabu](https://github.com/projectdiscovery/naabu), a certificate transparency watch, weekly deep sweeps, and [Sentinels](docs/SENTINELS.md) that find hosts inside private networks |
| **Understand** | [nmap](https://nmap.org) service and OS fingerprints, UDP exposure, a TLS audit, web routes and their sign-in state, exposed databases and cloud storage, firewalls, WordPress, email and DNS hygiene, and an optional [OpenVAS](docs/OPENVAS.md) add-on |
| **Prioritize** | Fire, smoke, and ice ratings, a 0 to 100 score per host, and AI triage into confirmed, likely, or needs validation |
| **Verify** | Read-only validation with [Nuclei](https://github.com/projectdiscovery/nuclei), nmap, and banner probes. **Validate now** on any match |
| **Search** | [Shodan-style search](docs/SEARCH.md) over your own inventory: `port:3389 -host:vpn`, `tech:"apache tomcat" sev:high` |
| **Operate** | A live dashboard, a change timeline with screenshot diffs, PDF reports, organizations and roles, two-step sign-in, a REST API, an MCP server, and Slack, Discord, Telegram, and Lark alerts |
| **Hunt** | A [bug bounty workbench](docs/BUG-BOUNTY.md): program scope from HackerOne, Bugcrowd, Intigriti, and YesWeHack, and report drafts |
| **Bring your own AI** | Anthropic, OpenAI, OpenRouter, Ollama, LM Studio, or vLLM. Without a model it still discovers, scans, matches, and validates |

## New in 1.4 (in development)

### Every scan runs on a Sentinel

The server runs no scan tool. Every install starts a **built-in scanner** next to it (the cvENGINE Sentinel image, enrolled with nobody typing a secret), and every kind of scan work (36 kinds: nmap, naabu, nuclei, testssl.sh, WPScan, wafw00f, bbot, secret detection, SSH inspection, screenshots and the web, DNS and mail probes) runs there or on external [Sentinels](docs/SENTINELS.md) you add. External Sentinels take work first; the [built-in scanner](docs/BUILTIN-SCANNER.md) is the path of last resort. With no scanner able to take work, scans wait and nothing is marked failed. The server image is smaller for it (one tool, nuclei, stays, for templates).

### Set up in the browser

`sudo ./install.sh` is a thin bootstrap; the [setup wizard](docs/DEPLOYMENT.md#setup-wizard) takes your organization, project and first domain (a discovery starts at once), then how you scan and whether to switch OpenVAS on.

### More checks, an AI reviewer, a simpler shell

- **Exposed secrets.** A project [secrets inventory](docs/SECRETS-PLAN.md) fed by [Kingfisher](https://github.com/mongodb/kingfisher) in the scanner, with browser keys told apart from server secrets.
- **SSH inspection.** [sshamble](https://github.com/runZeroInc/sshamble) reads each SSH service's own handshake and checks its host keys against the badkeys blocklist. Nothing logs in or submits a credential.
- **AI reviewer.** A [boxed-in container](docs/AI-REVIEWER.md) reviews every open finding once and checks operations.
- **OpenVAS** is a Greenbone stack on a Sentinel, off until you turn it on ([OpenVAS](docs/OPENVAS.md)).
- **Screenshots** are taken by a Sentinel's headless Chromium.
- **The left rail has 6 links** (Overview, Findings, Assets, Scans, Scanners, Bug bounty); Settings, Administration and Help are in the footer.

Upgrading from 1.3: [upgrading to 1.4](docs/UPGRADE.md#upgrading-to-14). Everything the product is built from, with versions and licenses, is on the About page and in [THIRD-PARTY.md](THIRD-PARTY.md).

## New in 1.3

### Sentinels: scale out, and scan inside your network

Run a **Sentinel** on any machine and cvENGINE hands it scan work. Deploy one or a hundred to spread scanning across machines. Put one outside your network to see what the internet sees. Put one inside to reach what no outside scanner can: declare a private range, and the Sentinel finds the live hosts in it and runs the same nmap, naabu, Nuclei, TLS, UDP, WordPress, and OpenVAS checks on them, with the same CVE matching and the same dashboard. Provisioning is one copy-paste: press **Provision** on the Sentinels page, then `docker compose up -d` with the blob it gives you. Update and configure every Sentinel from cvENGINE. The client lives in [hevnsnt/cvengine-sentinel](https://github.com/hevnsnt/cvengine-sentinel). [Sentinels guide](docs/SENTINELS.md)

### OpenVAS, built in and off by default

Switch on Greenbone's [OpenVAS](docs/OPENVAS.md) from Settings and its network vulnerability tests run beside Nuclei and nmap, against the hosts you choose, on a slow, throttled, safe-checks-only schedule. Every result that names a CVE becomes a finding in the same list, the same fire, smoke, and ice ratings, and the same AI triage. Switched off, it costs nothing.

### And a ton more

- **Hard evidence only.** A CVE match now needs the same product and a version inside a bounded affected range. A product name alone no longer makes noise, and OS and kernel flaws stay host-only.
- **Asks the host what it is.** Safe version and identity probes fill in the version a fingerprint missed, so more of your inventory can be matched.
- **TLS audit.** [testssl.sh](https://github.com/testssl/testssl.sh) on every TLS port: protocols, ciphers, and the named TLS vulnerabilities, with hard CVE evidence.
- **UDP exposure scan.** DNS, NTP, SNMP, IKE, IPMI, SSDP, memcached and more, checked slowly in the background.
- **Cloud storage.** Public and dangling S3, Google Cloud Storage, and Azure Blob buckets.
- **More of every host.** Other sites on the same address, applications under subdirectories, and authenticated checks with stored headers or cookies.
- **Suppliers.** The vendors you depend on get a Shodan-style host card and a technology search.
- **One-click PDF reports** for a project or a host.
- **Tailscale.** Attach a tailnet, import its devices, scan them, and check its configuration.
- **Host inventory and runZero.** Hosts report their own OS, packages, and patches, and a runZero sync adds what it knows.
- **Saved searches with alerts,** per-host check coverage, internal-host flags, and a CVE match that opens on three clear cards.
- **Every Nuclei template by default,** LM Studio as an AI provider, one API keys page, and a friendly page while an update rebuilds.
- **Supply chain you can audit.** Pinned scanner versions checked before every release, and a CycloneDX bill of materials with every release.

Upgrading an existing install: [upgrading to 1.3](docs/UPGRADE.md#upgrading-to-13). Earlier releases are in the [changelog](CHANGELOG.md).

## How it works

```mermaid
flowchart LR
    T(["Add a target<br/>domain, IP, CIDR, URL"])

    subgraph FIND["1 &nbsp; FIND"]
        direction TB
        D["Discovery<br/>bbot"] --> I["Inventory<br/>nmap, naabu"]
    end

    subgraph PROBE["2 &nbsp; PROBE"]
        direction TB
        X["Exposure checks<br/>databases, RDP screenshot"] --> N1["nuclei<br/>technology pass"] --> R["Firewall, web route<br/>and version probes"] --> W["WordPress, WPScan,<br/>node2shell opt-in"]
    end

    subgraph MATCH["3 &nbsp; MATCH"]
        direction TB
        C["CVE correlation"] --> N2["nuclei<br/>AI-targeted pass"]
    end

    subgraph DECIDE["4 &nbsp; DECIDE"]
        direction TB
        A["AI triage<br/>and validation"] --> O["Changes, host score,<br/>dashboard, API, alerts"]
    end

    H["Hygiene<br/>TLS, SPF, DKIM, DMARC, CAA, cleartext services"]

    T --> FIND --> PROBE --> MATCH --> DECIDE
    DECIDE -.-> H

    style FIND fill:#e8f1ff,stroke:#3b82f6,color:#0b3b8c
    style PROBE fill:#f1eaff,stroke:#8b5cf6,color:#3b1d8c
    style MATCH fill:#fff4e0,stroke:#f59e0b,color:#7a4a00
    style DECIDE fill:#e6f7ec,stroke:#22c55e,color:#0b5a2a
    linkStyle default stroke:#555,stroke-width:2px

    classDef start fill:#111,stroke:#111,color:#fff
    classDef step fill:#fff,stroke:#444,color:#111
    classDef out fill:#fff,stroke:#16a34a,stroke-width:2px,color:#111
    class T start
    class D,I,X,N1,R,W,C,N2,A step
    class O out
    class H step
```

Each scanner runs once per host inside a time window, so repeat scans stay fast. Every scanning stage runs on a [Sentinel](docs/SENTINELS.md) (the built-in scanner or one you add), never on the server. See the [pipeline](docs/PIPELINE.md) for every stage.

## Built on the best

cvENGINE stands on excellent open source work. Full credits and licenses are in [THIRD-PARTY.md](THIRD-PARTY.md).

| | |
| --- | --- |
| **Scanners** | [bbot](https://github.com/blacklanternsecurity/bbot), [Nuclei](https://github.com/projectdiscovery/nuclei) and its [templates](https://github.com/projectdiscovery/nuclei-templates), [naabu](https://github.com/projectdiscovery/naabu), [nmap](https://nmap.org), [testssl.sh](https://github.com/testssl/testssl.sh), [gowitness](https://github.com/sensepost/gowitness), [wafw00f](https://github.com/EnableSecurity/wafw00f), [WPScan](https://wpscan.com/), [Kingfisher](https://github.com/mongodb/kingfisher), [sshamble](https://github.com/runZeroInc/sshamble), [Playwright](https://playwright.dev)'s Chromium, [aardwolf](https://github.com/skelsec/aardwolf), [node2shell](https://github.com/assetnote/node2shell-scanner), and optionally [OpenVAS](docs/OPENVAS.md) from [Greenbone](https://greenbone.github.io/docs/) |
| **Exploitation intelligence** | [cve.now](https://cve.now), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [ENISA EUVD](https://euvd.enisa.europa.eu/), [FIRST EPSS](https://www.first.org/epss/), [Exploit-DB](https://gitlab.com/exploit-database/exploitdb), [Metasploit](https://github.com/rapid7/metasploit-framework), [VulnCheck KEV](https://vulncheck.com), [CVE List V5](https://github.com/CVEProject/cvelistV5) |
| **Also** | [OSV](https://osv.dev), [Debian security tracker](https://security-tracker.debian.org), [crt.sh](https://crt.sh), [MailFail](https://github.com/ACK-J/MailFail), [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data), [Bugcrowd VRT](https://github.com/bugcrowd/vulnerability-rating-taxonomy), [Tailscale](https://github.com/tailscale/tailscale), [runZero](https://www.runzero.com), [Ollama](https://github.com/ollama/ollama), [LM Studio](https://lmstudio.ai), [vLLM](https://github.com/vllm-project/vllm), [Model Context Protocol](https://modelcontextprotocol.io) |

## Install in minutes

On a Linux server (Debian or Ubuntu is easiest, with 4 GB of RAM or more):

```bash
git clone https://github.com/hevnsnt/CVEngine.git
cd CVEngine
sudo ./install.sh
```

It is a thin bootstrap: it installs what is missing, generates every secret, creates the HTTPS certificate, starts cvENGINE, waits until it answers, and prints the address and where your generated admin password is. Open the address and sign in: the setup wizard in the browser does the rest (your first target, scanners, Sentinels). Automation can pass `--sentinels=internal|both|external` and `-n`; on a terminal one optional question offers the same choice. OpenVAS is never installed by it. Your browser will warn about the private certificate until you trust `secrets/certs/ca.crt`.

Step-by-step install, a public name with a trusted certificate, and Mac and Windows are in [Deployment](docs/DEPLOYMENT.md) and [Hosting online](docs/HOSTING-ONLINE.md).

## Safe by design

Read-only checks, no password lists, and no scanning of loopback, link-local, or cloud metadata addresses. Each organization's data is isolated, stored secrets are encrypted, and access is protected by two-step sign-in, an IP allowlist, and an audit log. Only scan systems you own or are authorized to test.

## Documentation

| Doc | What it covers |
| --- | --- |
| [Deployment](docs/DEPLOYMENT.md) and [Hosting online](docs/HOSTING-ONLINE.md) | Install, HTTPS, proxies, backups, dev stack |
| [Updates](docs/UPDATES.md) and [Upgrade](docs/UPGRADE.md) | Staying current |
| [Configuration](docs/CONFIGURATION.md) | Every setting |
| [Search](docs/SEARCH.md) | Shodan-style search, with examples |
| [Fire, smoke, and ice](docs/FIRE-SMOKE-ICE.md) | How CVEs are rated and why |
| [Pipeline](docs/PIPELINE.md) and [Architecture](docs/ARCHITECTURE.md) | How it works |
| [Compare](docs/COMPARISON.md) | cvENGINE and ProjectDiscovery, feature by feature |
| [Tenancy](docs/TENANCY.md), [Agent API](docs/AGENT-API.md), [AI usage](docs/AI-USAGE.md) | Teams, the REST API and MCP, and AI cost |
| [Bug bounty](docs/BUG-BOUNTY.md) and [Front end](docs/FRONTEND.md) | The bounty workbench and the interface |
| [Host inventory](docs/HOST-INVENTORY.md) | Hosts reporting their own OS, packages and patches with a script |
| [Sentinels](docs/SENTINELS.md), [Built-in scanner](docs/BUILTIN-SCANNER.md) and [Scanner architecture](docs/SCANNER-ARCHITECTURE.md) | Where every scan runs, scaling across machines, and scanning private networks |
| [AI reviewer](docs/AI-REVIEWER.md) and [Secrets](docs/SECRETS-PLAN.md) | The boxed-in reviewer, and the exposed-secrets inventory |
| [Tailscale](docs/TAILSCALE.md) | Scanning a tailnet and its Tailscale checks |
| [OpenVAS](docs/OPENVAS.md) | The optional Greenbone scanner: enabling it, its resource floor and what it imports |

## Credits and license

cvENGINE is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x by Yogesh Ojha and its contributors, and builds on the projects above. Thanks to our beta testers, above all [camstork](https://github.com/camstork), whose careful reports shaped 1.3. See the [changelog](CHANGELOG.md), [contributors](CONTRIBUTORS.md), and [third-party software](THIRD-PARTY.md).

Released under the GPL-3.0. See [LICENSE](LICENSE).

[![M8ven Score](https://m8ven.ai/badge/mcp/hevnsnt-cvengine-s24yvi?v=8392a4bdbfdb1665e05d1484542cfff0)](https://m8ven.ai/mcp/hevnsnt-cvengine-s24yvi?s=readme)
