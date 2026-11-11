"""The software cvENGINE is built from and the services it contacts: the one list the About page shows.

Every entry names where its version is pinned. ``pins`` is a list of ``(file, regex)``; a file is read from the repository root ("web/Dockerfile"),
or, with the prefix ``sentinel:``, from the Sentinel repository's own file (hevnsnt/cvENGINE-sentinel, read at the known-good floor commit of ``scanner.lock.json``). The page
shows the version read from the pin when the file is in the running image (the server image holds web/Dockerfile and requirements.txt as
``Dockerfile`` and ``requirements.txt`` in the application directory); otherwise it shows the ``version`` written here. tests/test_about_page.py holds
the two equal, and fails when a tool pinned in either Dockerfile has no entry, so the list cannot drift from the images.

``where``: ``sentinel`` (runs in the Sentinel image, on the scanner), ``server`` (the cvENGINE server image or its compose services), ``both``.
``optional``: ``''`` when it always runs, otherwise what switches it on or off.
"""
import re
from functools import lru_cache
from importlib import metadata
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent

GROUPS = (
    ('scanners', 'Scanners and tools', 'These run on Sentinels, in the Sentinel image, at the versions of the Sentinel commit this release was tested with; the built-in scanner follows the newest published Sentinel build, so what runs can be newer. The server image keeps only nuclei, to read and check templates'),
    ('greenbone', 'OpenVAS add-on', 'Greenbone Community Edition, in separate containers a Sentinel runs. Off until you turn it on'),
    ('platform', 'Platform', 'What the server and its containers run on'),
)


def tool(key, name, url, group, version, license, purpose, where='sentinel', optional='', pins=(), notes=''):
    return {'key': key, 'name': name, 'url': url, 'group': group, 'version': version, 'license': license, 'purpose': purpose,
            'where': where, 'optional': optional, 'pins': tuple(pins), 'notes': notes}


# The Sentinel commit the Sentinel versions below were read from (its Dockerfile and requirements.txt). tests/test_about_page.py holds it equal to
# the floor commit of scanner.lock.json and to the sha web/requirements.txt pins: raising the floor means reading the Sentinel's pins again, then changing this line.
# (The built-in scanner image follows the newest published build; the page says what it was read at, not that it runs exactly this.)
SENTINEL_PINS_COMMIT = 'cf29610a513cc3135c1a81f004cd02e0b0c0e604'

GH = 'https://github.com/'
SENTINEL_DOCKERFILE = 'sentinel:Dockerfile'
SENTINEL_REQUIREMENTS = 'sentinel:requirements.txt'

TOOLS = [
    # -- Scanners and tools -------------------------------------------------------------------------------------------------------------------------
    tool('nmap', 'nmap', 'https://nmap.org', 'scanners', '7.993', 'Nmap Public Source License 0.95',
         'Service and OS fingerprinting, and the UDP exposure sweep', pins=[(SENTINEL_DOCKERFILE, r'ARG NMAPVERSION=([0-9.]+)')]),
    tool('naabu', 'naabu', GH + 'projectdiscovery/naabu', 'scanners', '2.7.0', 'MIT', 'Full-port discovery ahead of nmap',
         pins=[(SENTINEL_DOCKERFILE, r'ARG NAABU_VERSION=([0-9.]+)')]),
    tool('nuclei', 'nuclei', GH + 'projectdiscovery/nuclei', 'scanners', '3.11.1', 'MIT',
         'Vulnerability scanning and CVE tests. The Sentinel runs it; the server keeps the binary only to read and check templates', where='both',
         pins=[('web/Dockerfile', r'ARG NUCLEI_VERSION=([0-9.]+)'), (SENTINEL_DOCKERFILE, r'ARG NUCLEI_VERSION=([0-9.]+)')]),
    tool('nuclei-templates', 'nuclei-templates', GH + 'projectdiscovery/nuclei-templates', 'scanners', 'v10.5.1', 'MIT',
         'The community template library. The Sentinel image carries this pinned release as a fallback; the server refreshes its own set daily from the '
         'project and hands Sentinels the approved bundle', where='both', pins=[(SENTINEL_DOCKERFILE, r'ARG NUCLEI_TEMPLATES_VERSION=(v[0-9.]+)')]),
    tool('testssl', 'testssl.sh', GH + 'testssl/testssl.sh', 'scanners', '3.2.4', 'GPL-2.0 (a separate program, never linked)',
         'TLS audit: protocols, ciphers and the named TLS vulnerabilities', pins=[(SENTINEL_DOCKERFILE, r'ARG TESTSSL_VERSION=([0-9.]+)')]),
    tool('wpscan', 'WPScan', GH + 'wpscanteam/wpscan', 'scanners', '4.2.0', 'WPScan Public Source License',
         'WordPress core, plugin and theme checks (free for testing your own systems; a commercial license is needed for managed or hosted use)',
         pins=[(SENTINEL_DOCKERFILE, r'ARG WPSCAN_VERSION=([0-9.]+)')]),
    tool('wafw00f', 'wafw00f', GH + 'EnableSecurity/wafw00f', 'scanners', '2.4.2', 'BSD-3-Clause', 'Names the firewall in front of a web host',
         pins=[(SENTINEL_DOCKERFILE, r'ARG WAFW00F_VERSION=([0-9.]+)')]),
    tool('bbot', 'bbot', GH + 'blacklanternsecurity/bbot', 'scanners', '3.0.2', 'AGPL-3.0 (a separate program, never imported)',
         'Discovery of domains, subdomains and addresses', pins=[(SENTINEL_DOCKERFILE, r'ARG BBOT_VERSION=([0-9.]+)')]),
    tool('gowitness', 'gowitness', GH + 'sensepost/gowitness', 'scanners', '', 'GPL-3.0',
         'Older discovery-time screenshots, installed and run by bbot (the host page falls back to them)'),
    tool('kingfisher', 'Kingfisher', GH + 'mongodb/kingfisher', 'scanners', '2.16.0', 'Apache-2.0',
         'Finds exposed secrets in pages and scripts, on the Sentinel only (the `secrets_scan` kind)', pins=[(SENTINEL_DOCKERFILE, r'ARG KINGFISHER_VERSION=([0-9.]+)')]),
    tool('sshamble', 'sshamble', GH + 'runZeroInc/sshamble', 'scanners', '0.5.1', 'BSD-2-Clause',
         'Reads an SSH service\'s own handshake (banner, host keys, algorithms) and checks the host keys against the badkeys blocklist. Only that one host key '
         'check runs: it never submits a credential', pins=[(SENTINEL_DOCKERFILE, r'ARG SSHAMBLE_VERSION=([0-9.]+)')]),
    tool('badkeys-data', 'badkeys blocklist data', 'https://badkeys.info', 'scanners', '', 'Unknown (the badkeys software is MIT; no license for the data is stated)',
         'Known-weak SSH host keys. The Sentinel refreshes it daily with `sshamble badkeys-update`; turn that off with CVENGINE_BADKEYS_REFRESH=0 on an air-gapped Sentinel'),
    tool('playwright', 'Playwright', GH + 'microsoft/playwright-python', 'scanners', '1.64.1', 'Apache-2.0',
         'Drives the headless Chromium that takes the screenshot of every web page of every host, in the Sentinel image',
         pins=[(SENTINEL_REQUIREMENTS, r'(?m)^playwright==([0-9.]+)')]),
    tool('chromium', 'Chromium (Playwright headless shell)', 'https://www.chromium.org/', 'scanners', '156.0.8078.4',
         'BSD-3-Clause, plus the licenses of what it bundles', 'The browser behind the screenshots, pinned to the build Playwright 1.64.1 drives',
         pins=[(SENTINEL_DOCKERFILE, r'ARG PLAYWRIGHT_CHROMIUM_VERSION=([0-9.]+)')]),
    tool('aardwolf', 'aardwolf', GH + 'skelsec/aardwolf', 'scanners', '0.2.16', 'MIT', 'The headless RDP client behind the login-screen screenshot',
         pins=[(SENTINEL_REQUIREMENTS, r'(?m)^aardwolf==([0-9.]+)')]),
    tool('node2shell', 'node2shell-scanner', GH + 'assetnote/node2shell-scanner', 'scanners', 'commit bf2dc38', 'MIT',
         'Read-only detection of CVE-2026-111497, from Assetnote (vendored into the Sentinel client, off by default on the server)', optional='CVENGINE_NODE2SHELL=1'),
    tool('mailfail', 'MailFail', GH + 'ACK-J/MailFail', 'scanners', '', 'AGPL-3.0',
         'The email-security checks of the hygiene scan, re-implemented with credit (from MailFail by Black Hills Information Security)', where='both'),
    tool('python-gvm-sentinel', 'python-gvm', GH + 'greenbone/python-gvm', 'scanners', '27.10.1', 'GPL-3.0-or-later',
         'The GMP client library behind the OpenVAS add-on, in the Sentinel image and in the server image', where='both',
         pins=[('web/requirements.txt', r'(?m)^python-gvm==([0-9.]+)'), (SENTINEL_REQUIREMENTS, r'(?m)^python-gvm==([0-9.]+)')]),
    tool('go', 'Go toolchain', 'https://go.dev', 'scanners', '1.27.4', 'BSD-3-Clause',
         'Builds nuclei and naabu; removed again in the same image layer, so no Go runs in either image', where='both',
         pins=[('web/Dockerfile', r'ARG GOVERSION=([0-9.]+)'), (SENTINEL_DOCKERFILE, r'ARG GOVERSION=([0-9.]+)')]),
    tool('tailscale', 'Tailscale', GH + 'tailscale/tailscale', 'scanners', '1.104.6', 'BSD-3-Clause',
         'The optional sidecar that joins a tailnet so scans can reach it', where='server', optional='COMPOSE_PROFILES=tailscale',
         pins=[('docker-compose.yml', r'tailscale/tailscale:v([0-9.]+)')]),
    # -- OpenVAS add-on -----------------------------------------------------------------------------------------------------------------------------
    tool('gvmd', 'gvmd', GH + 'greenbone/gvmd', 'greenbone', 'stable (image pinned by digest)', 'AGPL-3.0-or-later (with gvm-libs, GPL-2.0-or-later)',
         'The vulnerability manager; cvENGINE drives it over GMP', optional='COMPOSE_PROFILES=openvas on a Sentinel'),
    tool('ospd-openvas', 'ospd-openvas', GH + 'greenbone/ospd-openvas', 'greenbone', 'stable (image pinned by digest)', 'AGPL-3.0-or-later',
         'The scanner wrapper; the only container there with NET_RAW and NET_ADMIN', optional='COMPOSE_PROFILES=openvas on a Sentinel'),
    tool('openvas-scanner', 'openvas-scanner (with openvasd and the notus service)', GH + 'greenbone/openvas-scanner', 'greenbone',
         'stable (image pinned by digest)', 'GPL-2.0 (its Rust parts GPL-2.0-or-later)', 'The scan engine', optional='COMPOSE_PROFILES=openvas on a Sentinel'),
    tool('pg-gvm', 'pg-gvm', GH + 'greenbone/pg-gvm', 'greenbone', 'stable (image pinned by digest)', 'GPL-3.0 (PostgreSQL itself: PostgreSQL License)',
         'The PostgreSQL database of the OpenVAS add-on, with pg-gvm-migrator for upgrades', optional='COMPOSE_PROFILES=openvas on a Sentinel'),
    tool('greenbone-redis', 'Redis (Greenbone redis-server image)', 'https://greenbone.github.io/docs/latest/', 'greenbone', 'stable (image pinned by digest)',
         'Unknown (the license of the Redis version Greenbone ships; not read from the image)', 'The scanner\'s cache', optional='COMPOSE_PROFILES=openvas on a Sentinel'),
    tool('greenbone-feed', 'Greenbone feed data',
         'https://greenbone.github.io/docs/latest/', 'greenbone', 'community (moving tag); gpg-data pinned by digest', 'Its own terms, printed by the data containers when they start',
         'Vulnerability tests and advisory data, refreshed by the data containers', optional='COMPOSE_PROFILES=openvas on a Sentinel',
         notes='Data sets: vulnerability-tests, notus-data, scap-data, cert-bund-data, dfn-cert-data, data-objects, report-formats, gpg-data'),
    # -- Platform -----------------------------------------------------------------------------------------------------------------------------------
    tool('ubuntu', 'Ubuntu', 'https://ubuntu.com', 'platform', '26.04', 'Free software, each package under its own license', 'The base of the server and Sentinel images',
         where='both', pins=[('web/Dockerfile', r'(?m)^FROM ubuntu:([0-9.]+)$'), (SENTINEL_DOCKERFILE, r'(?m)^FROM ubuntu:([0-9.]+)@')]),
    tool('python', 'Python', 'https://www.python.org', 'platform', 'distribution package', 'PSF License', 'The runtime of the server, the Sentinel client and the AI reviewer '
         '(the reviewer image is python:3.13-slim-bookworm)', where='both'),
    tool('django', 'Django', 'https://www.djangoproject.com', 'platform', '6.0.10', 'BSD-3-Clause', 'The web framework and its REST framework',
         where='server', pins=[('web/requirements.txt', r'(?m)^Django==([0-9.]+)')]),
    tool('celery', 'Celery', GH + 'celery/celery', 'platform', '5.7.0', 'BSD-3-Clause', 'The task queue (with kombu, amqp, billiard and vine) and its beat scheduler',
         where='server', pins=[('web/requirements.txt', r'(?m)^celery==([0-9.]+)')]),
    tool('gunicorn', 'Gunicorn and gevent', GH + 'benoitc/gunicorn', 'platform', '27.0.0', 'MIT', 'The application server, with gevent for the workers',
         where='server', pins=[('web/requirements.txt', r'(?m)^gunicorn==([0-9.]+)')]),
    tool('weasyprint', 'WeasyPrint', GH + 'Kozea/WeasyPrint', 'platform', '70.0', 'BSD-3-Clause', 'Renders the PDF reports (with DejaVu Sans)',
         where='server', pins=[('web/requirements.txt', r'(?m)^weasyprint==([0-9.]+)')]),
    tool('postgresql', 'PostgreSQL', 'https://www.postgresql.org', 'platform', '18', 'PostgreSQL License', 'The database (the postgres:18-alpine image)',
         where='server', pins=[('docker-compose.yml', r'image: "postgres:([0-9]+)-alpine"')]),
    tool('redis', 'Redis', GH + 'redis/redis', 'platform', 'moving tag (redis:alpine)',
         'Redis 8 and later: RSALv2, SSPLv1 or AGPLv3 at your option; Redis 7.2 and earlier: BSD-3-Clause. The tag moves, so check the image you pulled',
         'The Celery broker, the cache and the locks', where='server'),
    tool('nginx', 'nginx', GH + 'nginx/nginx', 'platform', 'moving tag (nginx:alpine)', 'BSD-2-Clause', 'The reverse proxy that terminates TLS', where='server'),
    tool('anthropic-sdk', 'Anthropic SDK', GH + 'anthropics/anthropic-sdk-python', 'platform', '2.8.0', 'Apache-2.0',
         'The AI reviewer container\'s only dependency of note (with its pinned dependencies); OpenAI-compatible servers and Ollama are called with the standard library',
         where='server', optional='idles until an AI provider is set up', pins=[('reviewer/requirements.txt', r'(?m)^anthropic==([0-9.]+)')]),
]

LIBRARY_NOTE = ('Python libraries are pinned in web/requirements.txt (server) and the Sentinel repository\'s requirements.txt; each is under its own license.')

# Python packages only the Sentinel image installs (the server ones come from web/requirements.txt, read below).
SENTINEL_LIBRARIES = (
    ('aardwolf', '0.2.16', 'MIT'), ('h11', '0.16.0', 'MIT'), ('Pillow', '>=13.0.0,<14', 'MIT-CMU'), ('PyMySQL', '1.2.3', 'MIT'),
    ('pymongo', '4.19.0', 'Apache-2.0'), ('playwright', '1.64.1', 'Apache-2.0'),
)


def library_license(name):
    try:
        meta = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return ''
    text = meta.get('License-Expression') or meta.get('License') or ''
    if not text or text == 'UNKNOWN' or len(text) > 60:
        classifiers = [c.split('::')[-1].strip() for c in meta.get_all('Classifier') or [] if c.startswith('License')]
        text = classifiers[0] if classifiers else ''
    return text.replace(' License', '').strip()


@lru_cache(maxsize=1)
def server_libraries():
    """``[(name, pinned version, license)]`` of every package in web/requirements.txt (the license from the installed package, empty when unknown)."""
    path = APP_DIR / 'requirements.txt'
    rows = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.split('#')[0].strip()
        match = re.match(r'([A-Za-z0-9_.-]+)\s*==\s*([^\s;]+)', line)
        if match and match.group(1).lower() != 'cvengine-scanner':
            rows.append((match.group(1), match.group(2), library_license(match.group(1))))
    return rows


def read_pin(pin, root=None):
    """The version a ``(file, regex)`` pin holds, or None when the file is not here (the Sentinel's files; the compose file inside the server image)."""
    path, pattern = pin
    if path.startswith('sentinel:'):
        return None
    names = {'web/Dockerfile': 'Dockerfile', 'web/requirements.txt': 'requirements.txt'}
    candidates = [Path(root) / path] if root else [APP_DIR.parent / path, APP_DIR / names.get(path, '\0')]
    for file in candidates:
        if file.is_file():
            found = re.search(pattern, file.read_text(encoding='utf-8'))
            return found.group(1) if found else None
    return None


def version_of(item):
    """The version to show: read from the first pin this image holds, else the one written in ``TOOLS``."""
    for pin in item['pins']:
        found = read_pin(pin)
        if found:
            return found
    return item['version']


def tools_by_group():
    return [{'id': key, 'title': title, 'intro': intro, 'items': [dict(t, shown=version_of(t)) for t in TOOLS if t['group'] == key]}
            for key, title, intro in GROUPS]


_SENTENCE_BREAK = re.compile(r'(?<=[a-z0-9\)`])\. (?=[A-Z])')


def tidy(text):
    """A short string without a trailing period."""
    return (text or '').replace('`', '').strip().rstrip('.').strip()


def split_purpose(text):
    """``(first sentence, the rest)``: the table shows the first as the purpose and the rest, smaller, beneath it."""
    parts = _SENTENCE_BREAK.split(tidy(text), maxsplit=1)
    return parts[0], (tidy(parts[1]) if len(parts) > 1 else '')


def source(name, url, purpose, optional='', terms='', used_by=''):
    first, rest = split_purpose(purpose)
    return {'name': name, 'url': url, 'purpose': first, 'detail': rest, 'optional': tidy(optional), 'terms': terms, 'used_by': used_by,
            'status': 'Optional' if optional else 'Used by default'}


# What the product contacts, with the code that does it (the paths are under web/ unless the Sentinel repository is named). ``optional`` is what you
# switch on or supply for it ('' means cvENGINE uses it in a normal install).
DATA_SOURCES = [
    source('cve.now', 'https://cve.now', 'The CVE feed (CVE List, GHSA, OSV, NVD, EUVD, CISA KEV, EPSS, Exploit-DB). There is no direct NVD API call', used_by='cveFeed/cve_now.py'),
    source('cvENGINE CVE seed', 'https://github.com/hevnsnt/CVEngine/releases/tag/cve-seed', 'The pre-built CVE catalog a new install downloads and verifies on first start', used_by='cveFeed/seed.py'),
    source('CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'Known exploited vulnerabilities (CC0)', used_by='cveFeed/intel.py'),
    source('ENISA EUVD', 'https://euvd.enisa.europa.eu/', 'European exploited vulnerabilities', used_by='cveFeed/intel.py'),
    source('VulnCheck KEV', 'https://vulncheck.com', 'Exploitation data, back to 2002', 'a free community key', used_by='cveFeed/intel.py'),
    source('FIRST EPSS', 'https://www.first.org/epss/', 'Exploit prediction scores for every CVE', used_by='cveFeed/intel.py'),
    source('Exploit-DB', 'https://www.exploit-db.com/', 'Public exploit references (GPL-2.0 or later)', used_by='cveFeed/intel.py'),
    source('Metasploit Framework', 'https://github.com/rapid7/metasploit-framework', 'Exploit module references (BSD-3-Clause)', used_by='cveFeed/intel.py'),
    source('CVE List V5', 'https://github.com/CVEProject/cvelistV5', 'CVE records imported for exploited CVEs the feed does not carry', used_by='cveFeed/intel.py'),
    source('OSV', 'https://osv.dev', 'Distribution fix data for Ubuntu and Debian packages (backport detection)', used_by='cveFeed/distro_sync.py'),
    source('Debian security tracker', 'https://security-tracker.debian.org', 'Debian fix data', used_by='cveFeed/distro_sync.py'),
    source('crt.sh', 'https://crt.sh', 'Certificate transparency lookups', used_by='cveFeed/ctmonitor.py'),
    source('IANA RDAP bootstrap and the registries it names', 'https://data.iana.org/rdap/dns.json', 'Registry lookups for the dangling-domain and email hygiene checks', used_by='cveFeed/mailfail.py'),
    source('Internet Archive', 'https://web.archive.org', 'Saved URLs, as passive evidence of what a host once ran', used_by='cveFeed/archive_urls.py'),
    source('nuclei-templates releases', 'https://github.com/projectdiscovery/nuclei-templates/releases', 'The server\'s daily template refresh and the reviewer\'s check for a newer release', used_by='cveFeed/reviewer.py, the update_nuclei_templates task'),
    source('badkeys blocklist', 'https://badkeys.info', 'Known-weak SSH host keys, downloaded by `sshamble badkeys-update` on the Sentinel, daily. Turn that off with CVENGINE_BADKEYS_REFRESH=0 on an air-gapped Sentinel', used_by='cvENGINE-sentinel client/badkeys.py'),
    source('Greenbone Community feed', 'https://greenbone.github.io/docs/latest/', 'Vulnerability tests and advisory data for the OpenVAS add-on, from registry.community.greenbone.net', 'the OpenVAS add-on', used_by='docker-compose.yml, the openvas-* data services'),
    source('GitHub', 'https://docs.github.com/rest', 'The in-app update check (the releases API)', used_by='cveFeed/updater.py'),
    source('bounty-targets-data', 'https://github.com/arkadiyt/bounty-targets-data', 'Public scope of bug bounty programs, read at run time (MIT)', used_by='cveFeed/bounty_data.py'),
    source('Bugcrowd Vulnerability Rating Taxonomy', 'https://github.com/bugcrowd/vulnerability-rating-taxonomy', 'Bundled as cveFeed/data/vrt.json for report categories and priority (Apache-2.0)', used_by='cveFeed/bounty_playbook.py'),
    source('HackerOne', 'https://api.hackerone.com', 'Submitting a report you wrote, with your own API token', 'your own HackerOne token', used_by='cveFeed/bounty_submit.py'),
    source('WPScan vulnerability data', 'https://wpscan.com/', 'WordPress vulnerabilities for WPScan', 'your own wpscan.com token', used_by='the Sentinel\'s WPScan'),
    source('runZero Export API', 'https://www.runzero.com', 'Asset inventory (OS, hardware, tags, CVE reports); no runZero code is bundled', 'your own Export API token', used_by='cveFeed/runzero.py'),
    source('Tailscale API', 'https://tailscale.com/api', 'Read-only access to your own tailnet, and the fixed versions from Tailscale\'s security bulletins', 'the Tailscale add-on and your own credentials', used_by='cveFeed/tailscale_api.py'),
    source('Slack, Discord, Telegram and Lark', 'https://slack.com', 'Notifications, to the webhook or bot you configure', 'a webhook you configure', used_by='reNgine/common_func.py'),
    source('Google Fonts', 'https://fonts.google.com', 'Inter, loaded by the HTML report only when you open one (the app itself serves its own fonts)', used_by='templates/report/'),
]

AI_PROVIDERS = [
    source('Anthropic', 'https://www.anthropic.com', 'AI triage, template drafting, validation and the reviewer, through its API', 'an API key you add', used_by='reNgine/ai_profiles.py'),
    source('OpenAI', 'https://openai.com', 'The same, through its API', 'an API key you add', used_by='reNgine/ai_profiles.py'),
    source('OpenRouter', 'https://openrouter.ai', 'The same, through its API', 'an API key you add', used_by='reNgine/ai_profiles.py'),
    source('Ollama, vLLM and LM Studio', 'https://github.com/ollama/ollama', 'Self-hosted servers cvENGINE calls over HTTP (Ollama MIT, vLLM Apache-2.0; no code of any of them is included)', 'a server you run', used_by='reNgine/ai_providers.py'),
    source('Model Context Protocol', 'https://modelcontextprotocol.io', 'How agents connect to cvENGINE', used_by='agentapi/mcp.py'),
]


# ---- the inventory the About page shows: one flat row shape for every group --------------------------------------------------------------------------
# Every row carries a name, url, version, license and purpose. Nothing is left blank: an unknown license reads "Not stated", a version nobody pins reads
# "Not pinned" (tests/test_about_page.py fails on a row without them).

WHERE_LABEL = {'sentinel': 'Sentinel', 'server': 'Server', 'both': 'Both'}
NOT_STATED = 'Not stated'
NOT_PINNED = 'Not pinned'

# Front-end and report assets the server ships (no version is pinned for them).
FRONTEND = [
    ('Geist', GH + 'vercel/geist-font', 'Typeface of the web interface', 'SIL Open Font License 1.1'),
    ('VivaGraphJS', GH + 'anvaka/VivaGraphJS', 'Draws the asset graph', 'BSD-3-Clause'),
    ('qrcode-generator', GH + 'kazuhikoarase/qrcode-generator', 'QR codes for two-step sign-in', 'MIT'),
    ('DejaVu Sans', 'https://dejavu-fonts.github.io', 'Typeface of the PDF reports', 'Bitstream Vera license with public-domain DejaVu changes'),
]

def split_license(text):
    """``(license, note)``: "GPL-2.0 (a separate program, never linked)" shows GPL-2.0 with the parenthesis beneath it."""
    text = tidy(text)
    found = re.fullmatch(r'(.+?) \((.+)\)', text)
    return (found.group(1), found.group(2)) if found else (text, '')


def row(name, url, version, license, purpose, where, optional='', detail=''):
    first, rest = split_purpose(purpose)
    lic, lic_note = split_license(license)
    return {'name': name, 'url': url, 'version': version or NOT_PINNED, 'pinned': bool(version), 'license': lic or NOT_STATED, 'license_note': lic_note,
            'purpose': first or 'Not stated', 'detail': ' '.join(x for x in (rest, detail) if x), 'where': WHERE_LABEL.get(where, where), 'optional': tidy(optional)}


def inventory():
    """The software inventory in page order: ``[{'id', 'title', 'intro', 'rows': [row...]}]``. Every row has name, url, version, license and purpose."""
    groups = []
    for group in tools_by_group():
        groups.append({'id': group['id'], 'title': group['title'], 'intro': group['intro'],
                       'rows': [row(t['name'], t['url'], t['shown'], t['license'], t['purpose'], t['where'], t['optional'], t['notes']) for t in group['items']]})
    groups.append({'id': 'frontend', 'title': 'Front end and reports', 'intro': 'Fonts and scripts the server ships',
                   'rows': [row(n, u, '', lic, purpose, 'server') for n, u, purpose, lic in FRONTEND]})
    pypi = 'https://pypi.org/project/'
    groups.append({'id': 'libraries-server', 'title': 'Python libraries, server image', 'intro': 'Pinned in web/requirements.txt, each under its own license',
                   'rows': [row(n, pypi + n + '/', v, lic, 'Python dependency of the server', 'server') for n, v, lic in server_libraries()]})
    groups.append({'id': 'libraries-sentinel', 'title': 'Python libraries, Sentinel image', 'intro': 'Pinned in the Sentinel repository (as of the commit this release was tested with), each under its own license',
                   'rows': [row(n, pypi + n + '/', v, lic, 'Python dependency of the Sentinel', 'sentinel') for n, v, lic in SENTINEL_LIBRARIES]})
    for group in groups:
        group['count'] = len(group['rows'])
        if group['id'] == 'greenbone':  # the group heading already says the whole add-on is optional
            for r in group['rows']:
                r['optional'] = 'Optional'
    return groups


def source_groups():
    """The data and service tables of the page: ``[(title, intro, [source...])]``."""
    return [('Data and services', '', DATA_SOURCES),
            ('AI and agents', 'Nothing calls a model until you set a provider up', AI_PROVIDERS)]
