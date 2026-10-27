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
  <img alt="Django 5.2 LTS" src="https://img.shields.io/badge/django-5.2%20LTS-black">
  <img alt="PostgreSQL 18" src="https://img.shields.io/badge/postgresql-18-black">
  <img alt="Runs in Docker" src="https://img.shields.io/badge/runs%20in-docker-black">
</p>

---

<p align="center">
  <img src="docs/images/cvengine-tour.gif" alt="A 30-second tour of cvENGINE: add a domain name, watch it discover every host, port and service, see today's exploited CVEs matched and AI-validated against what you run, hosts ranked with their evidence, and a timeline of every change" width="900">
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
| **Discover** | Subdomains, certificates, IPs, and ports with [bbot](https://github.com/blacklanternsecurity/bbot) and [naabu](https://github.com/projectdiscovery/naabu), plus a certificate transparency watch and weekly deep sweeps |
| **Understand** | [nmap](https://nmap.org) service and OS fingerprints, web routes and their sign-in state, exposed databases, firewalls, WordPress, and email and DNS hygiene, plus an optional, off-by-default [OpenVAS](docs/OPENVAS.md) scanner add-on |
| **Prioritize** | Fire, smoke, and ice ratings, a 0 to 100 score per host, and AI triage into confirmed, likely, or needs validation |
| **Verify** | Read-only validation with [Nuclei](https://github.com/projectdiscovery/nuclei), nmap, and banner probes. **Validate now** on any match |
| **Search** | [Shodan-style search](docs/SEARCH.md) over your own inventory: `port:3389 -host:vpn`, `tech:"apache tomcat" sev:high` |
| **Operate** | A live dashboard, a change timeline with screenshot diffs, organizations and roles, two-step sign-in, a REST API, an MCP server, and Slack, Discord, Telegram, and Lark alerts |
| **Hunt** | A [bug bounty workbench](docs/BUG-BOUNTY.md): program scope from HackerOne, Bugcrowd, Intigriti, and YesWeHack, and report drafts |
| **Bring your own AI** | Anthropic, OpenAI, OpenRouter, Ollama, or vLLM. Without a model it still discovers, scans, matches, and validates |

## New in 1.2

- **Every CVE says how to prove it.** A shared detection strategy and validation profile for the whole catalog, readable through the API and MCP.
- **A full CVE catalog on day one.** New installs download a verified catalog on first start instead of rebuilding it one request at a time.
- **It names the firewall in front of every host,** with [wafw00f](https://github.com/EnableSecurity/wafw00f).
- **It never sits idle.** A work conductor keeps discovery running across a thousand hosts.
- **One host, many names.** `example.com` and `www.example.com` on the same servers are one host.
- **Every Nuclei template, if you choose.** A switch in Settings runs the whole library (off by default).
- **Updates in seconds,** with a CI upgrade rehearsal before every release ([updates](docs/UPDATES.md)).
- **Hardened.** A Redis password, a rotatable key for stored secrets, hashed sessions, a sign-in throttle, and an encrypted CA key. Older installs: see [upgrading to 1.2](docs/UPGRADE.md#upgrading-to-12).

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
        X["Exposure checks<br/>databases, RDP screenshot"] --> N1["nuclei<br/>technology pass"] --> R["Firewall and web<br/>route checks"] --> V["Version and<br/>identity probes"] --> W["WordPress detection,<br/>WPScan, node2shell opt-in"]
    end

    subgraph MATCH["3 &nbsp; MATCH"]
        direction TB
        C["CVE correlation"] --> N2["nuclei<br/>AI-targeted pass"]
    end

    subgraph DECIDE["4 &nbsp; DECIDE"]
        direction TB
        A["AI triage<br/>and validation"] --> O["Changes, host score,<br/>dashboard, API, alerts"]
    end

    H["Hygiene<br/>TLS, SPF, DKIM, DMARC, CAA"]

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

Each scanner runs once per host inside a time window, so repeat scans stay fast. See the [pipeline](docs/PIPELINE.md) for every stage.

## Built on the best

cvENGINE stands on excellent open source work. Full credits and licenses are in [THIRD-PARTY.md](THIRD-PARTY.md).

| | |
| --- | --- |
| **Scanners** | [bbot](https://github.com/blacklanternsecurity/bbot), [Nuclei](https://github.com/projectdiscovery/nuclei) and its [templates](https://github.com/projectdiscovery/nuclei-templates), [naabu](https://github.com/projectdiscovery/naabu), [nmap](https://nmap.org), [gowitness](https://github.com/sensepost/gowitness), [wafw00f](https://github.com/EnableSecurity/wafw00f), [WPScan](https://wpscan.com/), [aardwolf](https://github.com/skelsec/aardwolf), [node2shell](https://github.com/assetnote/node2shell-scanner), and optionally [OpenVAS](docs/OPENVAS.md) from [Greenbone](https://greenbone.github.io/docs/) |
| **Exploitation intelligence** | [cve.now](https://cve.now), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [ENISA EUVD](https://euvd.enisa.europa.eu/), [FIRST EPSS](https://www.first.org/epss/), [Exploit-DB](https://gitlab.com/exploit-database/exploitdb), [Metasploit](https://github.com/rapid7/metasploit-framework), [VulnCheck KEV](https://vulncheck.com), [CVE List V5](https://github.com/CVEProject/cvelistV5) |
| **Also** | [OSV](https://osv.dev), [Debian security tracker](https://security-tracker.debian.org), [crt.sh](https://crt.sh), [MailFail](https://github.com/ACK-J/MailFail), [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data), [Bugcrowd VRT](https://github.com/bugcrowd/vulnerability-rating-taxonomy), [Ollama](https://github.com/ollama/ollama), [vLLM](https://github.com/vllm-project/vllm), [Model Context Protocol](https://modelcontextprotocol.io) |

## Install in minutes

On a Linux server (Debian or Ubuntu is easiest, with 4 GB of RAM or more):

```bash
git clone https://github.com/hevnsnt/CVEngine.git
cd CVEngine
sudo ./install.sh
```

It asks nothing: it installs what is missing, generates every secret, creates the HTTPS certificate, starts cvENGINE, and prints the address and your admin password. Open the address, sign in, and add a domain. The setup wizard does the rest. Your browser will warn about the private certificate until you trust `secrets/certs/ca.crt`.

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
| [Tailscale](docs/TAILSCALE.md) | Scanning a tailnet and its Tailscale checks |
| [OpenVAS](docs/OPENVAS.md) | The optional Greenbone scanner: enabling it, its resource floor and what it imports |

## Credits and license

cvENGINE is a fork of [reNgine](https://github.com/yogeshojha/rengine) 2.x by Yogesh Ojha and its contributors, and builds on the projects above. See the [changelog](CHANGELOG.md), [contributors](CONTRIBUTORS.md), and [third-party software](THIRD-PARTY.md).

Released under the GPL-3.0. See [LICENSE](LICENSE).
