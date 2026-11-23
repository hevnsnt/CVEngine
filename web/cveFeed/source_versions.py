"""Every version a source already sent: the exact product versions and CPEs that data cvENGINE already receives carries, stored as version
readings (``ProbeObservation``, probe ``vsrc:<source>``) so they become technologies or matchable readings instead of display text.
No request is made here: everything below reads what a scan, a Sentinel's result or a third-party sync already handed over.

First-party readings (our own scans: fresh, ``exact``; a product reading becomes a technology of the host, a language runtime goes to the
runtime rules of ``cveFeed.version_sources``):

  vsrc:nmap      what the port scan stored on each port beyond the product and version it already matches: the other application CPEs nmap
                 printed (``extra.cpes``; the first one is ``Port.cpe`` and is matched with the port), the CPE of a port nmap named no
                 product for, the modules nmap's ``extrainfo`` lists (``(CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16``), the Server and generator
                 lines of ``http-server-header``, ``http-headers`` and ``http-generator``, and the versions the database scripts read (``mysql-info``,
                 ``redis-info``, ``memcached-info``, ``mongodb-info``, ``ms-sql-info``) and ``ntp-info``, and what the scripts of nmap's version
                 category print on their own (``extra.version_scripts``, ``version_script_readings``): ``vmware-version``'s ESXi or vCenter
                 release with its build (an ESXi version carries the build, ``7.0.3-21930508``: VMware's advisories are build based,
                 ``correlation.esxi_ranges``), ``amqp-info``'s product and version, ``docker-version``'s Docker release and ``wdb-version``'s
                 VxWorks release. A reading the port row already states (same product, same version) is not stored twice; a build the port
                 row does not state is never dropped as a twin. Derived from the stored ports: refreshed with the other stored-data
                 readings (``version_sources.refresh_host``), and dropped when the port no longer says it.
  vsrc:webserver the Server header the web check stored for the host (``Subdomain.webserver``: bbot's HTTP pass, the web route check), its
                 web server and modules, less what a port of the host states at the same version; derived like ``vsrc:nmap``.
  vsrc:testssl   testssl.sh's ``banner_server`` and ``banner_application`` items (the Server and X-Powered-By headers it read), per tested port.
  vsrc:wpscan    the ``headers`` interesting finding of a WordPress scan (``Server: Apache/2.4.29 (Ubuntu)``, ``X-Powered-By: PHP/7.2.24``).
  vsrc:db-probe  the version a credential-less database probe's reply states (``PONG (redis 7.2.4)``, ``PostgreSQL 15.4``, ``(MySQL 8.0.35)``,
                 ``VERSION 1.6.21``, ``cluster x, version 8.11.1``), per port.
  vsrc:panel     the version an info-level panel template result (tag ``panel``) extracted, under the product the template names, with its
                 CPE (``cveFeed.panel_versions``), per port. Never stored over a version another source states for the product.
  vsrc:ssh       the banner the Sentinel's SSH inspection read (``cveFeed.ssh_scan``), through Recog's SSH database or the OpenSSH reader
                 (``ssh_readings``), per port, less what the port row states at the same version.
  identities     a product a source names with no version (``cveFeed.identity_readings``: shown, searched, a lead, never a technology): what
                 Recog names without a version (its ``hw.*`` fields a hint) under ``vsrc:recog``, and the network operating system an OS guess,
                 a certificate or an OS CPE names (``cveFeed.identities``) under ``vsrc:nmap``. An unidentified service's nmap fingerprint
                 (``cveFeed.servicefp``) is read decoded by both.
  vsrc:recog     what Rapid7 Recog's fingerprint databases (``cveFeed.recog``) read in the banners the host's rows already store: SSH, SMTP, FTP,
                 POP3, IMAP and telnet banners (``Port.banner``), the Server and Set-Cookie lines of the NSE output, ``mysql-info``'s server
                 version, ``ntp-info``'s readvar variables, an SNMP agent's sysDescr, the host's Server header (``Subdomain.webserver``) and its
                 live routes' Server headers and cookies. Each service (and its component) Recog names with a version, with Recog's CPE, which
                 correlation matches first. An operating system Recog names is a hint (shown and searched, never matched: an operating system
                 is not matched by name) unless it is a network operating system whose CVE records name it (``recog.NETWORK_OS``: Cisco IOS,
                 IOS XE, IOS XR, NX-OS, FortiOS, Junos OS, PAN-OS, SonicOS, RouterOS). A product a port row, another first-party reading or a
                 technology already states with a version is left out (``recog_readings``): Recog only adds what nmap and the other readers
                 did not read, and never replaces their version. Derived like ``vsrc:nmap``.
  vsrc:nuclei    what a ``network/detection/`` template read on a port (``cveFeed.network_detection``): a versioned product when the port's own row names
                 another product (nmap's product and version are never overwritten, so a second product the service names is a reading of its own),
                 an unversioned one as an identity reading, and the version the pass filled into the port row (``on_port``: the port is matched, so
                 no second technology; ``port_inventory`` keeps the port's version while this reading is fresh), per port.

The Windows release (``cveFeed.windows_builds``: kind ``hint``, ``release_only``, never a technology, matched by its own rules as "release known,
patch level unknown"):

  vsrc:ntlm      the build an NTLM challenge states (``rdp-ntlm-info``, ``ms-sql-ntlm-info`` and the other ``*-ntlm-info`` scripts) or
                 ``smb-os-discovery`` names, read as the Windows release it is (``data/windows_builds.json``). Never nmap's OS guess.

Third-party readings (kind and outcome ``reported``): passive data another service collected at some earlier time, never a technology:

  vsrc:shodan-idb  every CPE bbot's ``shodan_idb`` module (Shodan's InternetDB) gives a discovered host, labelled "vendor product"
                   (``shodan_reading``): versioned or not (``cpe:/a:openbsd:openssh:8.9p1``, ``cpe:/a:apache:http_server``), an application or an
                   operating system (``cpe:/o:canonical:ubuntu_linux``). InternetDB is keyed by IP address, not by host: behind a CDN or any
                   shared edge address it describes whatever other site Shodan once saw there. **A Shodan reading is a lead, never a finding**:
                   it never makes a CVE match (``collect_reported`` skips it, ``in_use`` never returns it), is never a technology and is
                   found only by the explicit ``vsource:shodan-idb`` search. It guides our own checks instead (``leads_of``, ``lead_state``):
                   a Shodan-named product with no first-party reading of it queues the matching first-party check (the WordPress probe, or
                   the version source reads of ``version_sources.host_products``), unless the host sits on a shared edge address (CDN) or our
                   own check already ruled the product out (the WordPress probe found none, the port is closed or answers with another
                   product). The host page lists the readings apart as "Reported by Shodan (unverified lead)". InternetDB states no scan date:
                   the reading is dated when cvENGINE received it, and marked ``undated``. Do not turn matching back on: ``cleanup_shodan_matches``
                   closes any open match whose only basis is one.
  vsrc:runzero     the operating system and its version runZero's inventory states for an address (``os``, ``os_version``), dated by the
                   asset's ``last_seen``; each service runZero read a product version on (its services export: Recog's ``service.*`` and
                   ``service.component.*`` attributes, with the CPE), per port, dated by the service's ``updated_at``; and the firmware a
                   hardware description ends with (``hw``: "Ubiquiti UniFi AP 6.5.28"), a hint: shown and searched, never matched.

The freshness rule (``in_use``). A reported reading of a source that may match (runZero: the customer's own active scanner, not a passive
internet dataset; never Shodan InternetDB, see above) is matched (``collect_reported``: correlation source ``tech``, the CPE first,
confidence at most ``REPORTED_CONFIDENCE``, never proof of a version) only while all of these hold, and is otherwise shown and searched but
matched to nothing, so the next correlation closes a match it made:

  1. it is at most ``REPORTED_MAX_AGE_DAYS`` old (its source's date, else when it was received);
  2. nothing first-party names the same product on the host: a technology, a port's product or CPE (a closed port counts: our scan saw the
     product and saw it go), or a first-party reading. A first-party reading always wins, whatever its version and however old the
     third-party one is, and a product our scan saw with no version is not given the third-party version either;
  3. when it names a port, our own scan of that port does not show it closed or answering with another product;
  4. it is no hint (a device's firmware, ``evidence.hint``): those are shown and searched only.

A match made from a reported reading is never hotter than ice (``threat.match_heat``) until a first-party read or a check confirms it.

Tenancy: a reading belongs to the project of the host it was stored for (the discovery's target, the project whose runZero sync wrote the
address's block); correlation reads only the rows of the host's own project.
"""
import logging
import re
from datetime import datetime, timedelta

from django.db.models import Q
from django.utils import timezone

from cveFeed import tech_links
from cveFeed import version_catalogue as catalogue

logger = logging.getLogger(__name__)

PREFIX = 'vsrc:'
NMAP_PROBE = 'vsrc:nmap'
TESTSSL_PROBE = 'vsrc:testssl'
WPSCAN_PROBE = 'vsrc:wpscan'
DB_PROBE = 'vsrc:db-probe'
WEBSERVER_PROBE = 'vsrc:webserver'
SHODAN_PROBE = 'vsrc:shodan-idb'
RUNZERO_PROBE = 'vsrc:runzero'
PANEL_PROBE = 'vsrc:panel'
PANEL_SOURCE = 'panel'
RECOG_PROBE = 'vsrc:recog'
NTLM_PROBE = 'vsrc:ntlm'  # cveFeed.windows_builds.PROBE: the Windows release an NTLM challenge states
NUCLEI_PROBE = 'vsrc:nuclei'  # cveFeed.network_detection: a versioned product a network detection template read on a port whose own row names another product
SSH_PROBE = 'vsrc:ssh'  # cveFeed.ssh_scan: the SSH banner the Sentinel's SSH inspection read, through Recog and the OpenSSH reader
FIRST_PARTY_PROBES = (NMAP_PROBE, WEBSERVER_PROBE, TESTSSL_PROBE, WPSCAN_PROBE, DB_PROBE, PANEL_PROBE, RECOG_PROBE, NUCLEI_PROBE, SSH_PROBE)
REPORTED_PROBES = (SHODAN_PROBE, RUNZERO_PROBE)
# the Windows release is first-party, but a release with no patch level never makes a third-party reading of the same system give way (a runZero
# operating system version names the update revision the NTLM challenge does not): it is kept out of FIRST_PARTY_PROBES
PROBES = FIRST_PARTY_PROBES + REPORTED_PROBES + (NTLM_PROBE,)
SEARCH = {p[len(PREFIX):]: p for p in PROBES}  # vsource:<name>
REPORTED = 'reported'               # ProbeObservation kind and outcome of a third-party reading: never a technology, never a first-party read
REPORTED_MAX_AGE_DAYS = 90          # older than this, a third-party reading is not matched (version_sources.STALE_DAYS, the Java runtime's rule)
REPORTED_CONFIDENCE = 0.5           # the most a match made from a third-party reading can carry: a candidate to validate
SHODAN_PROVIDER = 'shodan_idb'
RUNZERO_PROVIDER = 'runzero'
# the providers whose readings may become CVE matches (``in_use``). Shodan's InternetDB is keyed by IP address and says nothing about which host
# answers there (a CDN's shared edge address describes other sites): its readings are leads for our own checks, never findings.
NEVER_MATCHED = (SHODAN_PROVIDER,)
PROVIDER_LABELS = {SHODAN_PROVIDER: 'Shodan InternetDB', RUNZERO_PROVIDER: 'runZero'}
SHODAN_CLOSURE = ('Closed automatically: based only on Shodan InternetDB data for the host\'s address, which cvENGINE uses as a lead, not as a '
                  'finding; our own checks did not confirm {what} on this host.')
MAX_READINGS_PER_PORT = 12
_STATED = re.compile(r'^v?\d{1,5}\.\d{1,9}[0-9A-Za-z.()+~_-]{0,50}$')  # a version as a source states it: 8.9p1, 1.0.2k-fips, 15.2(4)M7; never a bare major
_MIN_CONTAIN = 4                    # a product token this short is compared whole, never by containment

_CPE_RE = re.compile(r'^cpe:(?:/|2\.3:)a:([^:\s]*):([^:\s]+)(?::([^:\s]*))?', re.IGNORECASE)
_MODULE_RE = re.compile(r'(?<![\w.])([A-Za-z][A-Za-z0-9_.+-]{1,30})/v?(\d[^\s(),;]{0,30})')
_MYSQL = re.compile(r'(?mi)^\s*Version:\s*(\d[\w.+~-]{0,60})')
_SAME_VERSION = re.compile(r'(?mi)^\s*Version:\s*(\d[\w.+~-]{0,40})')
_MONGO = re.compile(r'(?mi)^\s*version\s*=\s*(\d[\w.+-]{0,40})')
_MSSQL = re.compile(r'(?mi)^\s*number:\s*(\d{1,2}\.\d{1,2}\.\d{1,5}(?:\.\d{1,5})?)')
_NTP = re.compile(r'(?mi)^\s*version:\s*ntpd\s+(\d[\w.]{0,30})')
_MARIADB = re.compile(r'^(?:5\.5\.5-)?(\d+\.\d+\.\d+)-MariaDB', re.IGNORECASE)
SCRIPT_PRODUCTS = (  # (script id, pattern, product)
    ('redis-info', _SAME_VERSION, 'Redis'),
    ('memcached-info', _SAME_VERSION, 'Memcached'),
    ('mongodb-info', _MONGO, 'MongoDB'),
    ('ms-sql-info', _MSSQL, 'Microsoft SQL Server'),
    ('ntp-info', _NTP, 'NTP'),
)
# the exact evidence lines a Sentinel's db_probe returns (client/dbprobe.py of the Sentinel): one pattern per database, anchored
DB_REPLIES = (
    ('Redis', re.compile(r'^PONG \(redis (\d[\w.]{0,30})\)$')),
    ('Memcached', re.compile(r'^VERSION (\d[\w.]{0,30})$')),
    ('PostgreSQL', re.compile(r'^PostgreSQL (\d[\w.]{0,30})(?: \(.{0,120}\))?$')),
    ('Elasticsearch', re.compile(r'^cluster .{0,200}, version (\d[\w.-]{0,30})$')),
    ('MySQL', re.compile(r'^connected as root with no password \(MySQL (\d[\w.+~-]{0,60})\)$')),
)


# ----------------------------------------------------------------------------- reading what sources said (pure)

def _component(label):
    return re.sub(r'[^a-z0-9]+', '-', (label or '').lower()).strip('-')[:60]


def product_reading(label, version, source, evidence='', url='', cpe=''):
    """One exact product reading in ``version_catalogue.reading``'s shape, or None when ``version`` states no version. A language runtime
    (PHP, Python, Ruby ...) is returned as the runtime reading it is (``version_catalogue.from_technology``)."""
    label = catalogue.clip(label, 80)
    version = catalogue.clip(version, 60).lstrip('vV') if _STATED.match(catalogue.clip(version, 60)) else ''
    if not label or not version:
        return None
    runtime = catalogue.from_technology(label, version)
    if runtime:
        out = {**runtime, 'source': source, 'evidence': catalogue.clip(evidence) or runtime['evidence'], 'url': catalogue.clip(url, 300)}
    else:
        out = catalogue.reading(_component(label), label, version, evidence=evidence, url=url, source=source)
    if cpe:
        out['cpe'] = catalogue.clip(cpe, 200)
    return out


def cpe_reading(cpe, source, evidence=''):
    """The product reading an application CPE states (``cpe:/a:openbsd:openssh:8.9p1``): named as the CPE's product, the CPE kept for
    correlation's CPE-first matching. None for an operating system or hardware CPE, or one without a version."""
    found = _CPE_RE.match(str(cpe or '').strip())
    if not found:
        return None
    version = found.group(3) or ''
    if version in ('*', '-'):
        return None
    label = found.group(2).replace('_', ' ').strip()
    return product_reading(label, version, source, evidence=evidence or str(cpe), cpe=str(cpe).strip())


def identity_reading(label, source, evidence='', url='', cpe=''):
    """An identity reading: the product a source names with no version (``cveFeed.identity_readings.reading``)."""
    from cveFeed import identity_readings
    return identity_readings.reading(label, source, evidence=evidence, url=url, cpe=cpe)


_ANY_CPE_RE = re.compile(r'^cpe:(?:/|2\.3:)([aoh]):([^:\s]*):([^:\s]+)(?::([^:\s]*))?', re.IGNORECASE)


def is_cpe(text):
    """Whether ``text`` is a CPE (an application, operating system or hardware one, 2.2 or 2.3 form)."""
    return bool(_ANY_CPE_RE.match(str(text or '').strip()))


def cpe_label(vendor, product):
    """The name a CPE's vendor and product make: "vendor product" (``apache:http_server`` is "apache http server", never the bare "http server"),
    the product alone when it already starts with its vendor (``nginx:nginx``, ``linux:linux_kernel``)."""
    vendor, product = (vendor or '').replace('_', ' ').strip(), (product or '').replace('_', ' ').strip()
    if not vendor or vendor in ('*', '-') or _component(product).startswith(_component(vendor)):
        return product
    return f'{vendor} {product}'


def shodan_reading(cpe):
    """The third-party reading one CPE Shodan's InternetDB handed bbot is, or None for text that is no CPE: an application, operating system or
    hardware CPE, versioned or not, labelled "vendor product" (``cpe_label``), the CPE kept for correlation's CPE-first matching. Never a
    technology: what InternetDB says is passive and of unknown age (``store_bbot_reported``)."""
    text = catalogue.clip(cpe, 200)
    found = _ANY_CPE_RE.match(text)
    if not found:
        return None
    label = cpe_label(found.group(2), found.group(3))
    version = found.group(4) or ''
    version = '' if version in ('*', '-') else version
    evidence = f'Shodan InternetDB CPE {text}'
    from cveFeed import js_libraries
    if version and js_libraries.is_library(found.group(3)):
        # a JavaScript library's version comes only from its own file (cveFeed.js_libraries), never from another tool's reading
        return identity_reading(label, SHODAN_PROVIDER, evidence=f'{evidence} (a library\'s version is read from its own file)', cpe=text)
    if version and _STATED.match(version):
        # read as the product InternetDB names, a runtime too (cpe:/a:php:php:8.1.2): the CPE is what correlation matches
        return {**catalogue.reading(_component(label), label, version.lstrip('vV'), evidence=evidence, source=SHODAN_PROVIDER), 'cpe': text}
    return identity_reading(label, SHODAN_PROVIDER, evidence=evidence, cpe=text)


def header_readings(headers, source, url='/'):
    """The readings response headers state (``{lowercase name: value}``): every versioned product the shared header parser reads
    (``cvengine_scanner.versions.parse_headers``: the Server header and its modules, X-Powered-By, the version headers, X-Generator, Via) and the
    runtime readers of ``version_catalogue.from_headers``."""
    from cvengine_scanner import versions
    headers = {str(k).lower(): catalogue.clip(v, 300) for k, v in (headers or {}).items() if v}
    out = []
    for item in versions.parse_headers(headers):
        name, _sep, version = item['name'].partition(':')
        if not version or name == versions.ASP_NET_RUNTIME:  # the CLR line is the runtime readers' (an inferred .NET Framework line)
            continue
        header = item['source'].partition(':')[2] or 'server'
        got = product_reading(name, version, source, evidence=f'{header}: {headers.get(header, "")}', url=url)
        if got:
            out.append(got)
    out += [{**r, 'source': source} for r in catalogue.from_headers(headers, url=url)]
    return _unique(out)


def _modules(extrainfo, source):
    """The modules and runtimes a Server-header style ``extrainfo`` lists (nmap prints what follows the web server's own version there)."""
    from cvengine_scanner import versions
    out = []
    for name, version in _MODULE_RE.findall(str(extrainfo or '')[:300]):
        key = name.lower()
        product = versions.MODULE_PRODUCTS.get(key) or (name if re.match(r'^mod_[a-z0-9_]{1,26}$', key) else None)
        if product:
            got = product_reading(product, version, source, evidence=f'extrainfo: {extrainfo}')
            if got:
                out.append(got)
    return out


def script_readings(scripts):
    """The readings the reviewed NSE scripts of one port state (``Port.extra['scripts']``)."""
    from cvengine_scanner import versions
    scripts = scripts if isinstance(scripts, dict) else {}
    out = []
    text = str(scripts.get('mysql-info') or '')[:4000]
    found = _MYSQL.search(text)
    if found:
        version = found.group(1)
        maria = _MARIADB.match(version)
        got = (product_reading('MariaDB', maria.group(1), 'nse:mysql-info', evidence=f'mysql-info Version: {version}') if maria
               else product_reading('MySQL', version, 'nse:mysql-info', evidence=f'mysql-info Version: {version}'))
        out.append(got)
    for script, pattern, product in SCRIPT_PRODUCTS:
        found = pattern.search(str(scripts.get(script) or '')[:4000])
        if found:
            out.append(product_reading(product, found.group(1), f'nse:{script}', evidence=f'{script}: {found.group(0).strip()}'))
    for line in str(scripts.get('http-server-header') or '').splitlines()[:4]:
        out += header_readings({'server': line.strip()}, 'nse:http-server-header')
    headers = catalogue.header_lines(scripts.get('http-headers') or '')
    if headers:  # the Server, X-Powered-By and version headers of the http-headers dump
        out += [r for r in header_readings(headers, 'nse:http-headers') if r['kind'] != 'runtime']  # its runtimes: version_sources' vsrc:passive
    for line in str(scripts.get('http-generator') or '').splitlines()[:4]:
        got = versions.parse_generator(line)
        if got and got[1]:
            out.append(product_reading(got[0], got[1], 'nse:http-generator', evidence=f'generator: {line.strip()}'))
    return [r for r in out if r]


_GUTTER = re.compile(r'^\s*\|[ _]?')  # normal output's two-character gutter: "| " on a line, "|_" on the last
_FIELD_KEY = re.compile(r'[A-Za-z][A-Za-z0-9 _.-]{0,40}')
_VMWARE_SERVER = re.compile(r'^(VMware (?:ESXi?|vCenter Server|Server|GSX Server))\s+(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)$', re.IGNORECASE)
_VMWARE_BUILD = re.compile(r'^\d{4,9}$')
_VXWORKS = re.compile(r'^(?:VxWorks\s*)?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)$', re.IGNORECASE)
_PRODUCT_NAME = re.compile(r'^[A-Za-z][A-Za-z0-9 ._+-]{1,40}$')


def script_fields(text, script=''):
    """``{lower-case key: value}`` of the top-level ``Key: value`` lines one NSE script printed: its ``-oX`` ``output`` text (what a Sentinel sends)
    or the normal output's ``|`` gutter, the ``script:`` header line left out, the first value of a key kept. An indented line under a key with no
    value (``capabilities:``, a table) is that table's, never a top-level field. At most 60 lines are read."""
    out, indent = {}, None
    for raw in str(text or '')[:4000].replace('\r', '').split('\n')[:60]:
        line = _GUTTER.sub('', raw, count=1) if raw.lstrip().startswith('|') else raw
        body = line.strip()
        if not body or (script and body.lower() == f'{script}:'):
            continue
        depth = len(line) - len(line.lstrip(' '))
        indent = depth if indent is None else min(indent, depth)
        if depth > indent:
            continue  # a nested table's line
        key, sep, value = body.partition(':')
        if sep and _FIELD_KEY.fullmatch(key.strip()):
            out.setdefault(key.strip().lower(), value.strip())
    return out


def vmware_readings(text):
    """The reading ``vmware-version`` states (the SOAP API's ``Server version`` and ``Build``): VMware ESXi (or ESX) with the build in its version
    (``7.0.3-21930508``, as VMware's advisories name the fix by its build), any other VMware server (vCenter) with the release and the build kept
    as evidence. ``[]`` for anything else."""
    fields = script_fields(text, 'vmware-version')
    found = _VMWARE_SERVER.match(fields.get('server version', ''))
    if not found:
        return []
    name, release = found.group(1), found.group(2)
    build = fields.get('build', '') if _VMWARE_BUILD.match(fields.get('build', '')) else ''
    esx = bool(re.fullmatch(r'VMware ESXi?', name, re.IGNORECASE))
    said = f'vmware-version: Server version: {name} {release}' + (f'; Build: {build}' if build else '')
    line = catalogue.clip(fields.get('product line id', ''), 30)
    if line:
        said += f'; Product Line ID: {line}'
    slug = re.sub(r'[^a-z0-9]+', '_', name.split(' ', 1)[1].lower()).strip('_')
    cpe = f'cpe:/o:vmware:{slug}:{release}' if esx else f'cpe:/a:vmware:{slug}:{release}'
    got = product_reading(name, f'{release}-{build}' if esx and build else release, 'nse:vmware-version', evidence=said, cpe=cpe)
    if got and esx and build:
        got['build'] = build  # what the port row (nmap's "VMware ESXi SOAP API 7.0.3") does not state: never dropped as its twin
    return [got] if got else []


def _amqp_readings(text):
    fields = script_fields(text, 'amqp-info')
    product, version = fields.get('product', ''), fields.get('version', '')
    if not _PRODUCT_NAME.match(product):
        return []
    return [product_reading(product, version, 'nse:amqp-info', evidence=f'amqp-info product: {product}; version: {version}')]


def _docker_readings(text):
    version = script_fields(text, 'docker-version').get('version', '')
    return [product_reading('Docker', version, 'nse:docker-version', evidence=f'docker-version Version: {version}')]


def _wdb_readings(text):
    stated = script_fields(text, 'wdb-version').get('vxworks version', '')
    found = _VXWORKS.match(stated)
    if not found:
        return []
    return [product_reading('VxWorks', found.group(1), 'nse:wdb-version', evidence=f'wdb-version VxWorks version: {stated}',
                            cpe=f'cpe:/o:windriver:vxworks:{found.group(1)}')]


# the scripts of nmap's version category whose output states a product and its version in a fixed form (-sV runs them unasked; nmap's scripts
# directory has the output each prints). The others (rpcinfo's program table, hnap-info's device page, xmpp-info's capabilities ...) state
# no product version of their own, or only what nmap already put in the port row.
VERSION_SCRIPT_READERS = (
    ('vmware-version', vmware_readings),
    ('amqp-info', _amqp_readings),
    ('docker-version', _docker_readings),
    ('wdb-version', _wdb_readings),
)


VERSION_SCRIPT_SOURCES = frozenset(f'nse:{script}' for script, _reader in VERSION_SCRIPT_READERS)


def version_script_readings(scripts):
    """The readings the version category scripts of one port state (``Port.extra['version_scripts']``, ``VERSION_SCRIPT_READERS``)."""
    scripts = scripts if isinstance(scripts, dict) else {}
    out = []
    for script, reader in VERSION_SCRIPT_READERS:
        text = scripts.get(script)
        if isinstance(text, str) and text.strip():
            out += [r for r in reader(text[:4000]) if r]
    return out


def port_readings(port):
    """What one stored port states beyond the product and version the port row itself is matched by: the other application CPEs, the CPE of
    a port with no product, the modules of ``extrainfo`` and the NSE script versions. The port's own reading is left out."""
    from cveFeed.correlation import _norm, parse_cpe
    extra = port.extra if isinstance(port.extra, dict) else {}
    out = []
    own = parse_cpe(port.cpe or '')
    cpes = [c for c in (extra.get('cpes') or []) if isinstance(c, str)][:8]
    if (port.product or '').strip():
        cpes = [c for c in cpes if c.strip() != (port.cpe or '').strip() and (parse_cpe(c) or (None, None))[1] != (own or (None, None))[1]]
    elif port.cpe and port.cpe not in cpes:
        cpes.insert(0, port.cpe)  # nmap named no product, only the CPE: correlation skips the port, so the CPE is the reading
    out += _modules(port.service_extra, 'nmap-extrainfo')
    out += script_readings(extra.get('scripts'))
    out += version_script_readings(extra.get('version_scripts'))
    from cveFeed import servicefp
    replies = servicefp.decode(port.banner or '')
    if replies:  # an unidentified service's fingerprint: the Server, X-Powered-By and version headers of the HTTP reply it got
        out += [r for r in header_readings(servicefp.http_headers(replies), 'nmap-servicefp', url=f'port {port.number}') if r['kind'] != 'runtime']
    for got in (cpe_reading(c, 'nmap-cpe', evidence=f'nmap CPE {c}') for c in cpes):
        if not got:
            continue
        twin = next((r for r in out if r['component'] == got['component'] and r['kind'] == got['kind']), None)
        if twin is None:
            out.append(got)
        elif _same_version(got['version'], twin['version']):
            twin['cpe'] = got['cpe']  # the banner's spelling (1.0.2k-fips) with the CPE's product: one reading
    token, version = _norm(port.product or ''), (port.version or '').strip()
    # a build the port row does not state (vmware-version's ESXi build) is what the reading adds: never dropped as the port's twin
    return [r for r in _unique(out) if not (version and _same_version(r['version'], version) and _names_port(r['label'], token)
                                            and not (r.get('build') and r['build'] not in version))][:MAX_READINGS_PER_PORT]


def _names_port(label, port_token):
    """Whether a reading names the port's own product (nmap's "Apache httpd" is the Server header's "Apache HTTP Server"): the same product
    token, or the same first word."""
    from cveFeed.correlation import _norm
    if _same_product(_norm(label), {port_token}):
        return True
    first = re.match(r'[a-z0-9]+', (label or '').lower())
    return bool(first and len(first.group(0)) >= 3 and port_token.startswith(first.group(0)))


def nmap_readings(sub, ports):
    """``[(port number, reading)]`` of every stored open port of a host (``ports``: ``[(address, port)]``, ``version_sources._ports``), and the
    network operating system or appliance its OS guess, a certificate or an operating system CPE names (``cveFeed.identities``)."""
    from cveFeed import identities
    out, seen = [], set()
    for _address, port in ports:
        if port.state not in ('', 'open'):
            continue
        for r in port_readings(port):
            key = (port.number, r['component'], r['kind'], r['version'])
            if key not in seen:
                seen.add(key)
                out.append((port.number, r))
    for number, r in identities.host_readings(sub, ports):
        if not any(n == number and o['component'] == r['component'] for n, o in out):
            out.append((number, r))
    return out


def webserver_readings(sub, ports):
    """``[(0, reading)]`` of the Server header the web check stored for the host (``Subdomain.webserver``, from bbot's HTTP pass or the web route
    check): the web server and the modules it lists, less what a port of the host already states at the same version."""
    from cveFeed.correlation import _norm
    text = catalogue.clip(getattr(sub, 'webserver', '') or '', 300)
    if not text:
        return []
    stated = [(_norm(p.product or ''), (p.version or '').strip()) for _a, p in ports if (p.product or '').strip()]
    out = []
    for r in header_readings({'server': text}, 'webserver'):
        if r['kind'] == 'runtime':
            continue  # the runtime a Server header names is version_sources' (vsrc:passive) reading already
        if not any(version and _same_version(r['version'], version) and _names_port(r['label'], token) for token, version in stated):
            out.append((0, r))
    return out


def testssl_readings(items, port=0):
    """The readings of testssl.sh's banner items (``banner_server``: the Server header; ``banner_application``: X-Powered-By and the like)."""
    headers = {}
    for item in items or ():
        if not isinstance(item, dict):
            continue
        finding = catalogue.clip(item.get('finding'), 300)
        if not finding or finding.lower().startswith(('no ', 'not ', '--', '(no')):
            continue
        if item.get('id') == 'banner_server':
            headers.setdefault('server', finding)
        elif item.get('id') == 'banner_application':
            name, sep, value = finding.partition(':')
            if sep and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,40}', name.strip()):
                headers.setdefault(name.strip().lower(), value.strip())
    return header_readings(headers, 'testssl', url=f'port {port}' if port else '/')


def wpscan_readings(report):
    """The readings of a WordPress scan's ``headers`` interesting finding (its ``interesting_entries`` are ``Name: value`` header lines)."""
    headers = {}
    for item in (report or {}).get('interesting_findings') or []:
        if not isinstance(item, dict) or item.get('type') != 'headers':
            continue
        for entry in (item.get('interesting_entries') or [])[:20]:
            name, sep, value = str(entry).partition(':')
            if sep and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,40}', name.strip()):
                headers.setdefault(name.strip().lower(), value.strip())
    return header_readings(headers, 'wpscan', url='/')


def db_readings(reply):
    """The reading a db_probe reply states, or ``[]``. Only the exact lines the Sentinel writes are read (anchored), so text a database
    sends cannot make another product's reading."""
    text = catalogue.clip(reply, 300)
    for product, pattern in DB_REPLIES:
        found = pattern.match(text)
        if found:
            maria = _MARIADB.match(found.group(1)) if product == 'MySQL' else None
            got = product_reading('MariaDB' if maria else product, maria.group(1) if maria else found.group(1), 'db_probe', evidence=text)
            return [got] if got else []
    return []


_SSH_BANNER = re.compile(r'^SSH-\d{1,2}(?:\.\d{1,2})?-(\S{1,120})')
_OPENSSH = re.compile(r'^OpenSSH_(\d+\.\d+(?:p\d+)?)', re.IGNORECASE)


def ssh_readings(banner, port=0):
    """The readings an SSH banner (``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6``) states: what Rapid7 Recog's SSH database names (the server and
    its version, a network operating system), else the OpenSSH release its software version token carries. ``[]`` for anything else."""
    from cveFeed import recog
    text = catalogue.clip(banner, 300)
    found = _SSH_BANNER.match(text)
    if not found:
        return []
    out = []
    params = recog.match('ssh.banner', text[found.start(1):])
    for result in recog.results(params or {}):
        got = _recog_reading(result, 'ssh.banner', f'SSH banner: {text}', (params or {}).get('fingerprint.description') or '')
        if got:
            out.append(got)
    if not any(r['version'] for r in out):
        openssh = _OPENSSH.match(found.group(1))
        if openssh:
            out.append(product_reading('OpenSSH', openssh.group(1), 'ssh-banner', evidence=f'SSH banner: {text}', cpe=f'cpe:/a:openbsd:openssh:{openssh.group(1)}'))
    return _unique([{**r, 'source': 'ssh'} if r.get('source') == 'recog' else r for r in out if r])


def store_ssh(sub, port, banner):
    """After an SSH inspection of ``sub``'s ``port``: store what its banner states (``ssh_readings``) under ``vsrc:ssh``, less what the port row
    already states at the same version, and drop what it no longer states. Returns whether anything moved."""
    from cveFeed.correlation import _norm
    from cveFeed import version_sources
    stated = [(_norm(p.product or ''), (p.version or '').strip()) for _a, p in version_sources._ports(sub) if p.number == port and (p.product or '').strip()]
    readings = [r for r in ssh_readings(banner, port)
                if not any(v and _same_version(r['version'], v) and _names_port(r['label'], t) for t, v in stated)]
    return store_port(sub, SSH_PROBE, port, readings)


def _recog_reading(result, database, said, description):
    """The reading one Recog result (``recog.results``) is, or None: a product reading named as Recog names it, with Recog's CPE; an operating
    system that is not a network operating system is a ``weak`` hint (``version_sources.kind_of``: never a technology, never matched)."""
    from cveFeed import recog
    from cveFeed.correlation import stated_version
    version = re.split(r'[\s@]', result['version'].strip(), maxsplit=1)[0] if result['version'].strip() else ''  # ntpd's "4.2.8p15@1.3728-o" is 4.2.8p15
    label = result['label']
    hint = result['part'] == 'hw' or (result['part'] == 'os' and not result['network_os'])  # a device model or an operating system: shown, never matched
    if not version:
        # an identity: Recog names the product and no version. A service, its component or a network operating system is an identity reading
        # (shown, searched, a lead); an operating system or a device named with no version adds nothing a guess does not
        if hint:
            return None
        from cveFeed import identity_readings
        return identity_readings.reading(label, 'recog', evidence=f'{said} (Recog {recog.DATABASES.get(database, database)}: {description})',
                                         cpe=result['cpe'])
    if hint and result['vendor'] and not label.lower().startswith(result['vendor'].lower()):
        label = f"{result['vendor']} {label}"  # "Ubuntu Linux", not "Linux"
    if any(not stated_version(name, version) for name in (label, f"{result['vendor']} {result['product']}")):
        return None  # a protocol's version, never the product's: Apache-Coyote/1.1, Microsoft-HTTPAPI/2.0 (correlation.stated_version)
    evidence = f'{said} (Recog {recog.DATABASES.get(database, database)}: {description})'
    cpe = result['cpe'] if result['cpe'] and not hint else ''
    got = product_reading(label, version, 'recog', evidence=evidence, cpe=cpe)
    if got and hint:
        got = {**got, 'confidence': 'weak'}
    return got


def recog_texts(sub, ports):
    """``[(port number, database, text, said)]``: the stored banners of ``sub`` Recog reads (``ports``: ``[(address, port)]``, open ones)."""
    from cveFeed import recog
    from cveFeed.models import RouteAuth
    out = []
    for _address, port in ports:
        if port.state not in ('', 'open'):
            continue
        out += [(port.number, db, text, said) for db, text, said in recog.banner_texts(port) + recog.script_texts(port)]
    webserver = catalogue.clip(getattr(sub, 'webserver', '') or '', 300)
    if webserver:
        out.append((0, 'http_header.server', webserver, f'Server: {webserver}'))
    if sub.target_domain_id is not None:
        routes = (RouteAuth.objects.filter(project_id=sub.target_domain.project_id, host=_host(sub), retired_at__isnull=True)
                  .order_by('-checked_at').values_list('evidence', flat=True)[:50])
        out += [(0, db, text, said) for db, text, said in recog.route_texts(routes)]
    seen, unique = set(), []
    for item in out:
        if item[:3] not in seen:
            seen.add(item[:3])
            unique.append(item)
    return unique


def _stated_products(sub, ports):
    """``[(product token, CPE product, version)]`` of what the host's ports, its other version readings and its technologies already state:
    what a Recog reading must not override. Recog's own technologies are left out."""
    from cveFeed.correlation import _norm, parse_cpe, split_name_version
    from cveFeed.models import ProbeObservation
    out = []
    for _address, port in ports:
        extra = port.extra if isinstance(port.extra, dict) else {}
        version = (port.version or '').strip()
        for cpe in [port.cpe, *(extra.get('cpes') or [])]:
            parsed = parse_cpe(cpe) if isinstance(cpe, str) else None
            if parsed:
                out.append((_norm(port.product or ''), parsed[1], version or parsed[2]))
        if (port.product or '').strip():
            out.append((_norm(port.product), '', version))
    own = set()
    if sub.target_domain_id is not None:
        for row in ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=_host(sub), probe__startswith=PREFIX).exclude(kind=REPORTED):
            if row.probe == RECOG_PROBE:
                own.add(f'{row.product}:{row.version}')
                continue
            ev = row.evidence if isinstance(row.evidence, dict) else {}
            parsed = parse_cpe(ev.get('cpe') or '')
            out.append((_norm(row.product), parsed[1] if parsed else '', row.version or ''))
    for tech in sub.technologies.all():
        if tech.name in own:
            continue
        name, version = split_name_version(tech.name or '')
        out.append((_norm(name), '', version or ''))
    return [item for item in out if item[0] or item[1]]


def _recog_names(reading, stated, named_only=False):
    """Whether ``stated`` (``_stated_products``) names the product of a Recog reading with a version (``named_only``: at all, for an identity
    reading, which adds nothing where a port or another reading already names the product)."""
    from cveFeed.correlation import _norm, parse_cpe
    token = _norm(reading['label'])
    parsed = parse_cpe(reading.get('cpe') or '')
    cpe_product = parsed[1] if parsed else ''
    for other, other_cpe, version in stated:
        if not version and not named_only:
            continue
        if (_same_product(token, {other}) or (cpe_product and other_cpe and cpe_product == other_cpe)
                or (cpe_product and _same_product(cpe_product, {other})) or (other_cpe and _same_product(token, {other_cpe}))):
            return True
    return False


def recog_readings(sub, ports):
    """``[(port number, reading)]`` Recog reads in the host's stored banners (``recog_texts``), less every product something first-party on the
    host already states with a version (``_stated_products``): a Recog version never overrides nmap's or another reader's."""
    from cveFeed import recog
    found, seen = [], set()
    for number, database, text, said in recog_texts(sub, ports):
        params = recog.match(database, text)
        if not params:
            continue
        for result in recog.results(params):
            got = _recog_reading(result, database, said, params.get('fingerprint.description') or '')
            key = (number, got['component'], got['kind'], got['version']) if got else None
            if got and key not in seen:
                seen.add(key)
                found.append((number, got))
    if not found:
        return []
    stated = _stated_products(sub, ports)
    return [(number, r) for number, r in found if not _recog_names(r, stated, named_only=not r['version'])]


def reported_cpe(tech):
    """The third-party reading a technology string bbot reported is, when it is a CPE (only Shodan's InternetDB hands bbot CPEs: versioned or
    not, an application or an operating system, ``shodan_reading``), else None: anything else is a technology like any other."""
    return shodan_reading(tech)


_HW_FIRMWARE = re.compile(r'^(.{2,80}?)\s+v?(\d{1,4}\.\d{1,6}(?:[._-][0-9A-Za-z]{1,12}){0,4})$')


def runzero_readings(block):
    """The address-wide readings of a runZero block: its operating system (``os``, ``os_version``) and the firmware its hardware description
    ends with (``hw``: "Ubiquiti UniFi AP 6.5.28"; a hint, never matched: a model number is no version, so only a dotted last word reads),
    both dated by the asset's ``last_seen``. ``[]`` when it states neither."""
    if not isinstance(block, dict):
        return []
    out = []
    os_name, os_version = catalogue.clip(block.get('os'), 100), catalogue.clip(block.get('os_version'), 100)
    if os_name and _STATED.match(os_version):
        label = re.sub(rf'\s*{re.escape(os_version)}\s*$', '', os_name).strip() or os_name
        got = product_reading(label, os_version, RUNZERO_PROVIDER, evidence=f'runZero os: {os_name}; os_version: {os_version}')
        if got:
            out.append({**got, 'part': 'os'})
    hw = catalogue.clip(block.get('hw'), 100)
    found = _HW_FIRMWARE.match(hw)
    if found and _STATED.match(found.group(2)):
        got = product_reading(found.group(1).strip(), found.group(2), RUNZERO_PROVIDER, evidence=f'runZero hw: {hw}')
        if got and got['kind'] == 'product':
            out.append({**got, 'confidence': 'weak', 'part': 'hw', 'hint': True})
    return out


MAX_RUNZERO_SERVICES = 64


def runzero_service_readings(block):
    """``[(port, reading, dated)]`` of the services a runZero block keeps (``runzero_sync._services_of``): each product runZero's fingerprint names
    with a version on a port (Recog's ``service.*`` and ``service.component.*`` attributes, read by ``recog.results`` as Recog's own readings are,
    with the CPE runZero gives), dated by the service's ``updated``. A protocol's version (``stated_version``) is no reading."""
    from cveFeed import recog
    from cveFeed.correlation import stated_version
    out = []
    services = block.get('services') if isinstance(block, dict) and isinstance(block.get('services'), list) else []
    for service in services[:MAX_RUNZERO_SERVICES]:
        port = service.get('port') if isinstance(service, dict) else None
        attributes = service.get('attributes') if isinstance(service, dict) else None
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536 or not isinstance(attributes, dict):
            continue
        params = {str(k): catalogue.clip(v, 200) for k, v in list(attributes.items())[:20] if isinstance(v, str)}
        transport = catalogue.clip(service.get('transport'), 10)
        for result in recog.results(params):
            if result['part'] not in ('service', 'service.component'):
                continue  # the operating system is the asset's (``runzero_readings``)
            version = re.split(r'[\s@]', result['version'].strip(), maxsplit=1)[0] if result['version'].strip() else ''
            if not version or any(not stated_version(name, version) for name in (result['label'], f"{result['vendor']} {result['product']}")):
                continue
            said = f"runZero service {port}/{transport}: {result['vendor']} {result['product']} {result['version']}".replace('  ', ' ')
            cpe = result['cpe'] if is_cpe(result['cpe']) and '{' not in result['cpe'] else ''
            got = product_reading(result['label'], version, RUNZERO_PROVIDER, evidence=said, cpe=cpe)
            if got:
                out.append((port, {**got, 'part': result['part']}, catalogue.clip(service.get('updated'), 40)))
    seen, unique = set(), []
    for port, r, when in out:
        key = (port, r['component'], r['kind'], r['version'])
        if key not in seen:
            seen.add(key)
            unique.append((port, r, when))
    return unique


def _unique(readings):
    seen, out = set(), []
    for r in readings:
        if not r:
            continue
        key = (r['component'], r['kind'], r['version'])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _same_version(a, b):
    a, b = (a or '').strip().lower(), (b or '').strip().lower()
    return bool(a and b) and (a == b or b.startswith(a + ' ') or b.startswith(a + '-') or a.startswith(b + '-'))


def _same_product(token, tokens):
    """Whether a product token names the same product as one of ``tokens`` (whole, or one inside the other for tokens of four or more
    characters). Deliberately loose: it only ever decides that a third-party reading gives way, or that a reading is not stored twice."""
    if not token:
        return False
    for other in tokens:
        if not other:
            continue
        if token == other or (len(token) >= _MIN_CONTAIN and len(other) >= _MIN_CONTAIN and (token in other or other in token)):
            return True
    return False


# ----------------------------------------------------------------------------- storing

def _host(sub):
    return sub.name.lower().rstrip('.')


def store_port(sub, probe, port, readings, now=None):
    """Store one port's first-party ``readings`` of ``sub`` under ``probe`` (products become technologies, runtimes go to the runtime rules:
    ``version_sources.store_readings``) and drop that probe's rows of the port the source no longer states. Returns whether anything moved."""
    from cveFeed import version_sources
    from cveFeed.models import ProbeObservation
    if sub.target_domain_id is None:
        return False
    readings = [r for r in readings if r][:MAX_READINGS_PER_PORT]
    changed = version_sources.store_readings(sub, probe, readings, port=port, now=now)[1] if readings else False
    kept = {(version_sources.kind_of(r), r['label']) for r in version_sources.expand(readings) if r['kind'] != 'java'}
    for row in ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=_host(sub), probe=probe, port=port):
        if (row.kind, row.product) not in kept:
            row.delete()
            changed = True
    return changed


def _reported_observation(r, provider, reported_at, port=0, undated=False):
    from cveFeed import probes
    if '_reported_at' in r:  # a reading dated on its own (a runZero service: its own updated_at)
        reported_at, undated = r['_reported_at'], not r['_reported_at']
    when = reported_at.isoformat() if isinstance(reported_at, datetime) else str(reported_at or '')
    evidence = {'confidence': r['confidence'], 'line_only': r['line_only'], 'component': r['component'], 'source': provider, 'said': r['evidence'],
                'version_source': True, 'reported': True, 'provider': provider, 'reported_at': when[:40],
                **({'undated': True} if undated else {}), **({'cpe': r['cpe']} if r.get('cpe') else {}),
                **({'part': r['part']} if r.get('part') else {}), **({'hint': True} if r.get('hint') else {})}
    return probes._observation(REPORTED, r['label'], r['version'], '', REPORTED, REPORTED_CONFIDENCE, f'{provider}'[:48], port=r.get('_port', port),
                               url=r.get('url') or '', evidence=evidence)


def store_reported(project_id, domain_id, host, probe, readings, provider, reported_at, port=0, undated=False, replace=False, now=None):
    """Store third-party ``readings`` of a host of ``project_id`` (kind and outcome ``reported``: never a technology, never read as a first-party
    fact). ``replace`` drops the probe's rows of the host the readings no longer name. A reading may carry its own ``_port`` and ``_reported_at``
    (a runZero service). Returns whether anything moved."""
    from cveFeed import probes
    from cveFeed.models import ProbeObservation
    host = (host or '').lower().rstrip('.')
    if not project_id or not domain_id or not host:
        return False
    observations = [_reported_observation(r, provider, reported_at, port=port, undated=undated) for r in readings if r]
    rows = list(ProbeObservation.objects.filter(project_id=project_id, host=host, probe=probe))
    before = {(o.kind, o.product, o.port): (o.version, (o.evidence or {}).get('reported_at')) for o in rows}
    changed = False
    if observations:
        probes.record(project_id, domain_id, host, probe, observations, now=now, existing=rows)
        changed = any(before.get((o['kind'], o['product'], o['port'])) != (o['version'], o['evidence']['reported_at']) for o in observations)
    if replace:
        keep = {(o['kind'], o['product'], o['port']) for o in observations}
        gone = [row.pk for row in rows if (row.kind, row.product, row.port) not in keep]
        if gone:
            ProbeObservation.objects.filter(pk__in=gone).delete()
            changed = True
    return changed


def store_bbot_reported(subdomain, readings, now=None):
    """Store what Shodan's InternetDB told bbot about a discovered host (``reported_cpe``), dated when it was received (InternetDB states no date)."""
    if not readings or subdomain is None or subdomain.target_domain_id is None:
        return False
    now = now or timezone.now()
    return store_reported(subdomain.target_domain.project_id, subdomain.target_domain_id, subdomain.name, SHODAN_PROBE, readings, SHODAN_PROVIDER,
                          now, undated=True, now=now)


def _runzero_block(ip, project_id, configured=None):
    """The runZero block of ``ip`` when it belongs to ``project_id``: written by that project's sync, or (a block written before the project was
    recorded) the project has a runZero token of its own or its organization's."""
    block = ((ip.fingerprint or {}).get('runzero') or {}) if isinstance(ip.fingerprint, dict) else {}
    if not isinstance(block, dict) or not block:
        return None
    owner = block.get('project_id')
    if owner is not None:
        return block if owner == project_id else None
    if configured is None:
        from cveFeed import runzero_sync
        configured = runzero_sync.configured_project_ids()
    return block if project_id in configured else None


def runzero_host_readings(sub, configured=None):
    """Every runZero reading of ``sub``'s addresses (its own project's blocks only): the address-wide ones (``runzero_readings``, port 0) and the
    services (``runzero_service_readings``, on their port), each carrying its ``_port`` and ``_reported_at``."""
    project_id = sub.target_domain.project_id
    out, seen = [], set()
    for ip in sub.ip_addresses.all():
        block = _runzero_block(ip, project_id, configured)
        if not block:
            continue
        dated = block.get('last_seen') or block.get('updated') or ''
        found = [(0, r, dated) for r in runzero_readings(block)] + [(p, r, when or dated) for p, r, when in runzero_service_readings(block)]
        for port, r, when in found:
            key = (port, r['component'], r['kind'], r['version'])
            if key not in seen:
                seen.add(key)
                out.append({**r, '_port': port, '_reported_at': when})
    return out


def refresh_runzero(sub, configured=None, now=None):
    """Store the readings runZero's blocks state for the addresses of ``sub`` (``runzero_host_readings``) and drop the ones no block states any
    more. Returns whether anything moved."""
    if sub.target_domain_id is None:
        return False
    readings = runzero_host_readings(sub, configured)
    known = getattr(sub, '_derived_probes', None)  # the probes the host has rows of, read for the whole scan (version_sources.prefetch_derived)
    if known is not None:
        if not readings and RUNZERO_PROBE not in known:
            return False  # nothing to store and no row to drop: the answer store_reported would give
        known.add(RUNZERO_PROBE)
    return store_reported(sub.target_domain.project_id, sub.target_domain_id, sub.name, RUNZERO_PROBE, readings, RUNZERO_PROVIDER, '',
                          replace=True, now=now)


def refresh_host(sub, ports, now=None):
    """The stored-data part (``version_sources.refresh_host`` calls it): the nmap readings of the host's stored ports and its runZero readings.
    Returns ``(nmap readings, whether anything moved)``."""
    from cveFeed import version_sources
    now = now or timezone.now()
    found = nmap_readings(sub, ports)
    changed = version_sources._store_derived(sub, NMAP_PROBE, found, now)
    served = webserver_readings(sub, ports)
    changed = version_sources._store_derived(sub, WEBSERVER_PROBE, served, now) or changed
    from cveFeed import windows_builds
    windows = windows_builds.host_readings(sub, ports)  # the Windows release the NTLM scripts and smb-os-discovery state
    changed = version_sources._store_derived(sub, NTLM_PROBE, windows, now) or changed
    found = found + served + windows
    try:
        changed = refresh_runzero(sub, now=now) or changed
    except Exception:  # noqa: BLE001 - a malformed block never stops the host's other readings
        logger.exception('runZero readings of host %s failed', sub.pk)
    try:
        read, moved = refresh_recog(sub, ports, now=now)
        found, changed = found + read, moved or changed
    except Exception:  # noqa: BLE001 - a banner Recog cannot read never stops the host's other readings
        logger.exception('Recog readings of host %s failed', sub.pk)
    return found, changed


def refresh_recog(sub, ports=None, now=None):
    """Store what Recog reads in the host's stored banners (``recog_readings``) under ``vsrc:recog`` and drop what it no longer reads. Runs after
    the host's other stored-data readings are stored, so those are what it gives way to. Returns ``(readings, whether anything moved)``."""
    from cveFeed import version_sources
    if sub.target_domain_id is None:
        return [], False
    ports = version_sources._ports(sub) if ports is None else ports
    found = recog_readings(sub, ports)
    return found, version_sources._store_derived(sub, RECOG_PROBE, found, now or timezone.now())


def store_testssl(sub, port, items):
    """After a TLS audit of ``sub``'s ``port``: store what testssl.sh's banner items state. Returns whether anything moved."""
    return store_port(sub, TESTSSL_PROBE, port, testssl_readings(items, port))


def store_wpscan(sub, url, report):
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url or '')
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        port = 0
    return store_port(sub, WPSCAN_PROBE, port, wpscan_readings(report))


def store_db(sub, port, reply):
    return store_port(sub, DB_PROBE, port, db_readings(reply))


# ----------------------------------------------------------------------------- the freshness rule and correlation

def _rows(sub):
    rows = getattr(sub, '_source_rows', None)
    if rows is None:
        from cveFeed.models import ProbeObservation
        if sub.target_domain_id is None:
            return []
        rows = list(ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=_host(sub), probe__in=PROBES))
        sub._source_rows = rows  # read once per correlation of the host (the CPE map and the reported readings both read them)
    return rows


def prefetch(subs):
    """Give each of ``subs`` its source reading rows (``_source_rows``) in one query (``correlation.correlate_subdomains``)."""
    from cveFeed.models import ProbeObservation
    from targetApp.models import Domain
    subs = [s for s in subs if getattr(s, 'target_domain_id', None)]
    if not subs:
        return
    project_of = dict(Domain.objects.filter(id__in={s.target_domain_id for s in subs}).values_list('id', 'project_id'))
    by_key = {}
    for row in ProbeObservation.objects.filter(project_id__in=set(project_of.values()), host__in={_host(s) for s in subs}, probe__in=PROBES):
        by_key.setdefault((row.project_id, row.host), []).append(row)
    for sub in subs:
        sub._source_rows = by_key.get((project_of.get(sub.target_domain_id), _host(sub)), [])
    from startScan.models import SubdomainTechnology
    cpes, derived = {}, {}
    for sub_id, name, cpe, source in SubdomainTechnology.objects.filter(subdomain_id__in=[s.pk for s in subs]).exclude(cpe='') \
            .values_list('subdomain_id', 'technology__name', 'cpe', 'source'):
        cpes.setdefault(sub_id, {})[name or ''] = cpe
        if tech_links.is_derived(source):
            derived.setdefault(sub_id, set()).add(name or '')
    for sub in subs:
        sub._link_cpes, sub._link_derived = cpes.get(sub.pk, {}), derived.get(sub.pk, set())


def link_cpes(sub):
    """``{technology name: CPE}`` the host's technology links carry (``SubdomainTechnology.cpe``: the CPE the nuclei template that named the
    technology states in its metadata, ``nuclei_scan.tech_cpe_from``, or the one the server derived from a name matcher's name,
    ``tech_links.derived_cpe``); read once per correlation of the host (``prefetch``)."""
    got = getattr(sub, '_link_cpes', None)
    if got is None:
        from startScan.models import SubdomainTechnology
        rows = list(SubdomainTechnology.objects.filter(subdomain_id=sub.pk).exclude(cpe='').values_list('technology__name', 'cpe', 'source')) \
            if sub.pk else []
        got = {name or '': cpe for name, cpe, _source in rows}
        sub._link_cpes, sub._link_derived = got, {name or '' for name, _cpe, source in rows if tech_links.is_derived(source)}
    return got


def derived_link_cpes(sub):
    """The names of ``link_cpes`` whose CPE the server derived from the name (``tech_links.DERIVED``), not one a template stated."""
    link_cpes(sub)
    return getattr(sub, '_link_derived', set())


def technology_cpes(sub):
    """``{technology name: CPE}`` for the technologies a first-party CPE reading made (``vsrc:nmap`` from nmap's other CPEs, ``vsrc:panel``) and the
    ones a nuclei template named with a CPE in its metadata (``link_cpes``), so correlation matches them CPE first like the port row's own CPE. A
    reading's CPE (it carries the version) is taken over the template's."""
    out = dict(link_cpes(sub))
    for row in _rows(sub):
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        if row.probe in FIRST_PARTY_PROBES and row.kind == 'version' and row.outcome == 'found' and row.version and ev.get('cpe'):
            out[f'{row.product}:{row.version}'] = ev['cpe']
    return out


def _reported_at(row):
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    text = ev.get('reported_at')
    if isinstance(text, str) and text:
        try:
            when = datetime.fromisoformat(text.replace('Z', '+00:00'))
            return when if timezone.is_aware(when) else timezone.make_aware(when)
        except ValueError:
            pass
    return row.observed_at


def first_party(sub):
    """``(product tokens, CPE products, {port number: [(state, product token)]})`` of what our own scans saw on ``sub``: its technologies, every
    port row of its addresses (closed ones too) with its CPEs, and its first-party readings."""
    from cveFeed.correlation import _norm, parse_cpe, split_name_version
    tokens, cpes, ports = set(), set(), {}
    for tech in sub.technologies.all():
        tokens.add(_norm(split_name_version(tech.name or '')[0]))
    for cpe in link_cpes(sub).values():  # the CPE a technology template named for one of them
        parsed = parse_cpe(cpe)
        if parsed:
            cpes.add(parsed[1])
    for ip in sub.ip_addresses.all():
        for port in ip.ports.all():
            if (port.source or '') == 'bbot' and not port.product:
                continue  # an open port bbot reported (Shodan's InternetDB among its sources) is not a scan of the service
            token = _norm(port.product or '')
            tokens.add(token)
            extra = port.extra if isinstance(port.extra, dict) else {}
            for cpe in [port.cpe, *(extra.get('cpes') or [])]:
                parsed = parse_cpe(cpe) if isinstance(cpe, str) else None
                if parsed:
                    cpes.add(parsed[1])
            ports.setdefault(port.number, []).append((port.state or 'open', token))
    for row in _rows(sub):
        if row.probe in FIRST_PARTY_PROBES:
            tokens.add(_norm(row.product))
            parsed = parse_cpe((row.evidence or {}).get('cpe') or '') if isinstance(row.evidence, dict) else None
            if parsed:
                cpes.add(parsed[1])
    tokens.discard('')
    return tokens, cpes, ports


def verdict(row, seen, now=None):
    """Why a reported reading is not matched (``aged``, ``superseded``, ``port_closed``, ``port_other_product``), or '' when it is (``in_use``).
    ``seen`` is ``first_party(sub)``."""
    from cveFeed.correlation import _norm, parse_cpe
    now = now or timezone.now()
    when = _reported_at(row)
    if when is None or when < now - timedelta(days=REPORTED_MAX_AGE_DAYS):
        return 'aged'
    tokens, cpes, ports = seen
    token = _norm(row.product)
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    parsed = parse_cpe(ev.get('cpe') or '')
    if _same_product(token, tokens) or (parsed and (parsed[1] in cpes or _same_product(parsed[1], tokens))):
        return 'superseded'
    if row.port and row.port in ports:
        states = ports[row.port]
        if all(state not in ('', 'open') for state, _t in states):
            return 'port_closed'
        if any(t and not _same_product(token, {t}) for state, t in states if state in ('', 'open')):
            return 'port_other_product'
    return ''


def is_lead(row):
    """Whether a reading is a lead, never a finding (Shodan's InternetDB: ``NEVER_MATCHED``)."""
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    return row.probe == SHODAN_PROBE or (ev.get('provider') or row.source) in NEVER_MATCHED


def in_use(sub, now=None):
    """The reported readings of ``sub`` the freshness rule lets correlation match (``verdict``), never a Shodan InternetDB one (``is_lead``)."""
    rows = [r for r in _rows(sub) if r.kind == REPORTED and r.outcome == REPORTED and r.version and not is_lead(r)
            and not (isinstance(r.evidence, dict) and r.evidence.get('hint'))]  # a hint (a device's firmware) is shown and searched only
    if not rows:
        return []
    seen = first_party(sub)
    return [r for r in rows if not verdict(r, seen, now)]


def collect_reported(subdomain, product_index, cve_by_id, rows, scan_history=None, min_confidence=0.0, fix_lookup=None):
    """Append the matches of the reported readings ``in_use`` lets through: named like a technology (correlation source ``tech``), the CPE
    first, the confidence capped at ``REPORTED_CONFIDENCE``, the provider and its date in the evidence. Returns how many. Shodan InternetDB
    readings are skipped entirely (``is_lead``): they are leads for our own checks, never matches."""
    from cveFeed.correlation import _MIN_TOKEN, _norm, _record_matches, parse_cpe
    if not product_index:
        return 0
    found = 0
    for row in in_use(subdomain):
        if is_lead(row):
            continue
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        cpe = ev.get('cpe') or ''
        token = _norm(row.product)
        if len(token) < _MIN_TOKEN and parse_cpe(cpe):
            token = parse_cpe(cpe)[1]
        if len(token) < _MIN_TOKEN:
            continue
        evidence = {'source': 'tech', 'reported': True, 'reported_by': ev.get('provider') or row.source, 'reported_at': ev.get('reported_at') or '',
                    'reading_id': row.pk, **({'undated': True} if ev.get('undated') else {}), **({'cpe': cpe[:255]} if cpe else {})}
        found += _record_matches(subdomain, row.product, row.version, token, 'tech', product_index, cve_by_id, min_confidence, scan_history, rows,
                                 cpe=cpe, fix_lookup=fix_lookup, evidence=evidence, confidence_cap=REPORTED_CONFIDENCE)
    return found


def os_rows(value):
    """The version source rows that name an operating system containing ``value`` (``os:``): the Windows release an NTLM challenge states
    (``vsrc:ntlm``), runZero's operating system (``vsrc:runzero``, the address-wide reading that is no hardware hint: its services are
    applications) and any reading carrying an operating system CPE (a network operating system's identity, VMware ESXi as vmware-version
    states it). Shodan InternetDB's ``cpe:/o:`` CPEs are leads, not the host's operating system: ``readings_qs`` leaves them out."""
    from cveFeed import version_sources
    runzero_os = Q(probe=RUNZERO_PROBE, port=0) & (Q(evidence__part='os') | ~Q(evidence__has_key='part'))
    return version_sources.readings_qs().filter(Q(probe=NTLM_PROBE) | runzero_os | Q(evidence__cpe__istartswith='cpe:/o:')
                                                | Q(evidence__cpe__istartswith='cpe:2.3:o:')) \
        .filter(Q(product__icontains=value) | Q(evidence__cpe__icontains=value))


def reported_host_ids(base_qs):
    """The ids of the Subdomain rows of ``base_qs`` with a reported reading that may match (``correlation.candidate_subdomains``): never one
    that only has Shodan InternetDB readings."""
    from django.db.models import Exists, OuterRef
    from cveFeed.models import ProbeObservation
    readings = ProbeObservation.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'), kind=REPORTED) \
        .exclude(probe=SHODAN_PROBE)
    return base_qs.filter(Exists(readings)).values('id')


# ----------------------------------------------------------------------------- Shodan readings are leads for our own checks

LEAD_LABELS = {
    'open': 'Reported by Shodan (unverified lead)',
    'ruled_out': 'Reported by Shodan, ruled out by our probe',
    'confirmed': 'Reported by Shodan, also found by our own scan',
    'aged': 'Reported by Shodan, not refreshed for 90 days',
}
_WORDPRESS = re.compile(r'wordpress', re.IGNORECASE)


def edge_label(provider):
    return f'Shodan data for a shared edge address ({provider}), probably another site'


def shared_edge_for(addresses, name='', cname='', webserver='', cdn_name='', flagged=False):
    """The provider of the shared edge (a CDN, a platform other tenants share) the host's addresses sit on, else ''. Reads only what is stored: a
    provider's published address ranges (``hosting.provider_range``), the CDN flag of the host or an address, its recorded CNAME, name and Server header
    (``hosting.classify``). A name is never resolved here: the server resolves and probes nothing, only Sentinels do."""
    from cveFeed import hosting
    for address in addresses:
        known = hosting.provider_range(address)
        if known:
            return known[0]
    info = hosting.classify(name=name, cname=cname or '', webserver=webserver or '', cdn_name=cdn_name or '', is_cdn=bool(flagged))
    if info['shared_ip'] and info['provider']:
        return info['provider']
    return (cdn_name or 'a CDN').strip()[:60] if flagged else ''


def shared_edge(sub):
    """``shared_edge_for`` the stored row of a host: Cloudflare's published range or CDN flag on one of its addresses, its CNAME, name or Server header."""
    ips = list(sub.ip_addresses.all())
    return shared_edge_for([ip.address for ip in ips if ip.address], name=sub.name, cname=sub.cname, webserver=sub.webserver, cdn_name=sub.cdn_name,
                           flagged=bool(sub.is_cdn or any(ip.is_cdn for ip in ips)))


def is_wordpress_lead(row):
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    return bool(_WORDPRESS.search(row.product or '') or _WORDPRESS.search(ev.get('cpe') or ''))


def lead_state(row, seen, edge='', wordpress_absent=False, now=None):
    """Where a Shodan reading stands as a lead: ``edge`` (the host's addresses are a shared edge: Shodan's IP-keyed data is about another site, no
    check is queued from it), ``ruled_out`` (our own probe says the product is absent: the WordPress probe found no WordPress, the port is closed
    or answers with another product), ``confirmed`` (a first-party reading names the product: nothing left to check), ``aged`` (older than
    ``REPORTED_MAX_AGE_DAYS``) or ``open`` (a check is wanted). ``seen`` is ``first_party(sub)``."""
    if edge:
        return 'edge'
    if wordpress_absent and is_wordpress_lead(row):
        return 'ruled_out'
    why = verdict(row, seen, now)
    return {'': 'open', 'aged': 'aged', 'superseded': 'confirmed'}.get(why, 'ruled_out')


def lead_item(row, state, edge=''):
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    return {'product': row.product, 'version': row.version, 'cpe': ev.get('cpe') or '', 'state': state, 'ruled_out': state == 'ruled_out',
            'edge': edge or None, 'label': edge_label(edge) if state == 'edge' else LEAD_LABELS.get(state, LEAD_LABELS['open']),
            'port': row.port or None, 'reported': {'by': ev.get('provider') or SHODAN_PROVIDER, 'at': ev.get('reported_at') or '',
                                                   'undated': bool(ev.get('undated'))}}


def leads_of(sub, rows=None, now=None):
    """The Shodan readings of ``sub`` as leads, each with where it stands (``lead_state``) and its wording for the host page. ``rows``: the host's
    probe rows when the caller has them (the WordPress state is read from them), else the stored readings and a query for the WordPress probe."""
    from cveFeed import wpscan_scan
    from cveFeed.models import ProbeObservation
    if sub.target_domain_id is None:
        return []
    if rows is None:
        rows = list(ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=_host(sub)))
    shodan = [r for r in rows if r.probe == SHODAN_PROBE and r.kind == REPORTED]
    if not shodan:
        return []
    if getattr(sub, '_source_rows', None) is None:
        sub._source_rows = [r for r in rows if r.probe in PROBES]
    wp = wpscan_scan.state_of([r for r in rows if r.kind == 'wordpress'])
    absent = bool(wp and wp['state'] == 'not_wordpress')
    seen, edge = first_party(sub), shared_edge(sub)
    return [lead_item(r, lead_state(r, seen, edge, absent, now), edge) for r in sorted(shodan, key=lambda r: (r.product, r.port))][:30]


def lead_products(sub, now=None):
    """``[(product, '')]`` of the Shodan leads of ``sub`` still open: a product Shodan named that nothing first-party names and our checks did not rule
    out, on a host that is not on a shared edge address. They go to ``version_sources.host_products``, so the existing version source reads
    (``wanted``: a catalogue entry whose ``leads`` the product matches, asked on the port or the web base) check it ourselves. WordPress is the
    WordPress probe's lead (``wordpress_leads``), not an entry of the catalogue."""
    shodan = [r for r in _rows(sub) if r.probe == SHODAN_PROBE and r.kind == REPORTED]
    if not shodan:
        return []
    edge = shared_edge(sub)
    if edge:
        return []
    seen = first_party(sub)
    return [(r.product, '') for r in shodan if not is_wordpress_lead(r) and lead_state(r, seen, '', False, now) == 'open']


def planner_leads(rows, facts, now=None):
    """``[(product, '')]`` of the open Shodan leads of the host ``facts`` (``check_coverage.HostFacts``) for the work planner, from ``rows``: the
    host's Shodan readings and first-party readings (``check_coverage.load``). The same rule as ``lead_products``, read from the planner's facts:
    nothing on a shared edge address (the host's addresses, its CDN flags), nothing a first-party technology, port product or reading names,
    nothing our own scan ruled out. WordPress is the probe's lead."""
    from cveFeed.correlation import _norm, split_name_version
    shodan = [r for r in rows if r.probe == SHODAN_PROBE and r.kind == REPORTED]
    if not shodan:
        return []
    addresses = list(facts.addresses.values())
    if facts.shared_platform or shared_edge_for([a.address for a in addresses], name=facts.name, flagged=any(a.is_cdn for a in addresses)):
        return []
    tokens = {_norm(split_name_version(t)[0]) for t in facts.techs}
    ports = {}
    for a in addresses:
        for port in a.ports:
            token = _norm(getattr(port, 'product', '') or '')
            tokens.add(token)
            ports.setdefault(port.number, []).append((getattr(port, 'state', '') or 'open', token))
    cpes = set()
    for r in rows:
        if r.probe in FIRST_PARTY_PROBES:
            tokens.add(_norm(r.product))
    tokens.discard('')
    seen = (tokens, cpes, ports)
    return [(r.product, '') for r in shodan if not is_wordpress_lead(r) and lead_state(r, seen, '', False, now) == 'open']


def wordpress_leads(subs, now=None):
    """The lower-cased names of ``subs`` (current rows of one scan) where Shodan named WordPress, nothing first-party names it, no probe ruled it
    out and the addresses are no shared edge: the WordPress probe asks these first (``wpscan_scan.detect``). Reads only stored rows."""
    from cveFeed.models import ProbeObservation
    from cveFeed import wpscan_scan
    subs = [s for s in subs if getattr(s, 'target_domain_id', None)]
    if not subs:
        return set()
    projects = {s.target_domain_id: s.target_domain.project_id for s in subs}
    names = {_host(s) for s in subs}
    rows = {}
    for row in ProbeObservation.objects.filter(project_id__in=set(projects.values()), host__in=names).filter(Q(probe=SHODAN_PROBE) | Q(kind='wordpress')):
        rows.setdefault((row.project_id, row.host), []).append(row)
    out = set()
    for sub in subs:
        mine = rows.get((projects[sub.target_domain_id], _host(sub)), [])
        leads = [r for r in mine if r.probe == SHODAN_PROBE and is_wordpress_lead(r)]
        if not leads:
            continue
        wp = wpscan_scan.state_of([r for r in mine if r.kind == 'wordpress'])
        if (wp and wp['state'] == 'not_wordpress') or shared_edge(sub):
            continue
        seen = first_party(sub)
        if any(lead_state(r, seen, '', False, now) == 'open' for r in leads):
            out.add(_host(sub))
    return out


# ----------------------------------------------------------------------------- Shodan-only matches are closed

def _shodan_made(match, reading_ids):
    ev = match.evidence if isinstance(match.evidence, dict) else {}
    return bool(ev.get('reported')) and (ev.get('reported_by') in NEVER_MATCHED or ev.get('reading_id') in reading_ids)


def close_shodan_matches(matches):
    """Close, automatically and as a false positive, the open matches among ``matches`` whose only basis is a Shodan InternetDB reading (evidence
    ``reported`` with ``reported_by`` shodan_idb, or a ``reading_id`` that is a ``vsrc:shodan-idb`` row): one nobody worked (still open, no one set
    it), with no hard evidence (a template hit, the distribution's tracker, a validation hit). The note says why; the audit trail and the activity
    feed say it too. Idempotent: a closed match is not touched again. Returns the ids closed."""
    from django.db import transaction
    from cveFeed import activity, match_policy, scoring
    from cveFeed.models import CVEMatch, FindingAuditEvent, Triage, ProbeObservation
    from reNgine.state_machines import REMEDIATION
    matches = [m for m in matches if m.remediation_status == 'open' and getattr(m, 'remediation_by_id', None) is None]
    if not matches:
        return []
    reading_ids = None
    shodan = []
    for m in matches:
        ev = m.evidence if isinstance(m.evidence, dict) else {}
        if not ev.get('reported'):
            continue
        if ev.get('reported_by') not in NEVER_MATCHED and reading_ids is None:
            reading_ids = set(ProbeObservation.objects.filter(probe=SHODAN_PROBE).values_list('pk', flat=True))
        if _shodan_made(m, reading_ids or set()):
            shodan.append(m)
    if not shodan:
        return []
    hits = set(Triage.objects.filter(match_id__in=[m.pk for m in shodan], validation_status='hit').values_list('match_id', flat=True))
    now = timezone.now()
    closed, audit, by_project = [], [], {}
    for m in shodan:
        if m.pk in hits or match_policy.has_hard_evidence(m.source, m.evidence, m.template_result or '', m.distro_status or ''):
            continue
        what = ' '.join(x for x in (m.matched_product, m.matched_version) if x) or 'this product'
        note = SHODAN_CLOSURE.format(what=what)
        with transaction.atomic():
            moved = REMEDIATION.move(CVEMatch._base_manager.filter(pk=m.pk, remediation_by__isnull=True), 'false_positive', only_from=('open',),
                                     remediation_note=note, remediation_updated_at=now, ai_verdict='not_affected', ai_reason=note,
                                     ai_model='deterministic-correlation', confidence=0.0, updated_at=now)
            if not moved:
                continue
            Triage.objects.filter(match_id=m.pk).update(verdict=None, status='triaged', classification='not_applicable', reason=note, updated_at=now)
        m.remediation_status, m.remediation_note, m.ai_verdict, m.ai_reason, m.confidence = 'false_positive', note, 'not_affected', note, 0.0
        closed.append(m)
        project = m.subdomain.target_domain.project_id if m.subdomain_id and m.subdomain.target_domain_id else None
        if project:
            audit.append(FindingAuditEvent(project_id=project, finding_kind='match', finding_id=m.pk, event='status', actor=None,
                                           before={'status': 'open'}, after={'status': 'false_positive', 'note': note, 'by': 'shodan_lead_rule'}))
            by_project.setdefault(project, []).append(m.pk)
    if audit:
        FindingAuditEvent.objects.bulk_create(audit)
    for project, pks in by_project.items():
        activity.log('confirm', (f'{len(pks)} CVE match(es) closed: based only on Shodan InternetDB data for the host\'s address, which is a lead for our '
                                 'own checks, not a finding'), project=project, match_id=pks[0], match_ids=pks[:20], count=len(pks),
                     decision='closed_not_applicable')
    if closed:
        try:
            scoring.rescore_for_matches(closed)
        except Exception:  # noqa: BLE001 - the closure stands; the next rescore counts it
            logger.exception('could not rescore the hosts of %d Shodan-only matches', len(closed))
    return [m.pk for m in closed]


def cleanup_shodan_matches(apply=False, batch=500):
    """The one-time cleanup an update runs (``manage.py cleanup_shodan_matches --apply``) and what every correlation of a host repeats
    (``correlation.close_stale``): close the open CVE matches whose only basis is a Shodan InternetDB reading (``close_shodan_matches``). Bounded
    (``batch`` matches a read, one query for the readings) and idempotent: a closed match no longer reads as open. Returns
    ``{'matches': found, 'closed': closed}``."""
    from cveFeed.models import CVEMatch
    out = {'matches': 0, 'closed': 0}
    base = (CVEMatch._base_manager.filter(remediation_status='open', remediation_by__isnull=True, evidence__reported=True)
            .exclude(template_result='vulnerable').exclude(distro_status='vulnerable').select_related('subdomain__target_domain').order_by('pk'))
    last = 0
    while True:
        rows = list(base.filter(pk__gt=last)[:batch])
        if not rows:
            break
        last = rows[-1].pk
        reading_ids = None
        mine = []
        for m in rows:
            ev = m.evidence if isinstance(m.evidence, dict) else {}
            if ev.get('reported_by') not in NEVER_MATCHED and reading_ids is None:
                from cveFeed.models import ProbeObservation
                reading_ids = set(ProbeObservation.objects.filter(probe=SHODAN_PROBE).values_list('pk', flat=True))
            if _shodan_made(m, reading_ids or set()):
                mine.append(m)
        out['matches'] += len(mine)
        if apply and mine:
            out['closed'] += len(close_shodan_matches(mine))
    return out


# ----------------------------------------------------------------------------- the one-time backfill

def _current_row(domain_id, host):
    from cveFeed import correlation
    from startScan.models import Subdomain
    return (Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain_id=domain_id, name=host)
            .select_related('target_domain').order_by('-id').first())


def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_source_versions --apply``): re-read what is still stored into readings, then
    correlate the hosts that gained or lost one. Read: every current host's stored ports and runZero blocks (``refresh_host``), the Shodan
    InternetDB CPEs the discovery feed kept (``DiscoveryEvent``, dated when received; the CPE technology an earlier discovery stored on the host
    under its normalized name is taken off the current row, the reading replaces it), and the replies of the database exposure findings. testssl.sh
    banners and WordPress scan headers were never stored: they are read from the next audit and scan. Idempotent. Returns
    ``{'hosts', 'readings', 'matches'}``."""
    from cveFeed import correlation, version_sources
    from startScan.models import Subdomain, Vulnerability
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    ids = list(base.order_by('id').values_list('id', flat=True))
    out = {'hosts': len(ids), 'readings': 0, 'matches': 0}
    if not apply:
        return out
    moved = set()
    configured = None
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        if configured is None:
            from cveFeed import runzero_sync
            configured = runzero_sync.configured_project_ids()
        for sub in subs:
            try:
                ports = version_sources._ports(sub)
                found = nmap_readings(sub, ports)
                changed = version_sources._store_derived(sub, NMAP_PROBE, found, timezone.now())
                served = webserver_readings(sub, ports)
                changed = version_sources._store_derived(sub, WEBSERVER_PROBE, served, timezone.now()) or changed
                found = found + served
                changed = refresh_runzero(sub, configured=configured) or changed
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('source version catch-up of host %s failed', sub.pk)
                continue
            out['readings'] += len(found)
            # correlated whether or not this pass wrote anything: the version source backfill before it (or the stage since the update) may
            # already have stored the same readings through version_sources.refresh_host, without correlating the hosts for them
            on_runzero = any(isinstance(ip.fingerprint, dict) and ip.fingerprint.get('runzero') for ip in sub.ip_addresses.all())
            if changed or found or on_runzero:
                moved.add(sub.pk)
    out['readings'] += _shodan_events(moved)
    # the replies the database exposure findings kept
    for vuln in Vulnerability.objects.filter(source='db_exposure').exclude(subdomain__isnull=True).select_related('subdomain').iterator(chunk_size=500):
        replies = [r for r in (vuln.extracted_results or []) if isinstance(r, str)] if isinstance(vuln.extracted_results, list) else []
        readings = [r for reply in replies[:1] for r in db_readings(reply)]
        port = re.search(r':(\d{1,5})$', vuln.http_url or '')
        sub = _current_row(vuln.subdomain.target_domain_id, vuln.subdomain.name) if readings and port else None
        if sub is None:
            continue
        if store_db(sub, int(port.group(1)), replies[0]):
            moved.add(sub.pk)
        out['readings'] += len(readings)
    if moved:
        # every host that gained or lost a reading (or a technology): one that lost its only one is correlated too, so its matches close
        cve_by_id, index = correlation.cve_pool()
        ordered = sorted(moved)
        for start in range(0, len(ordered), batch):
            subs = list(Subdomain.objects.filter(pk__in=ordered[start:start + batch]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    return out


def _shodan_events(moved):
    """Store the CPEs Shodan's InternetDB handed bbot, as the discovery feed kept them ("<technology> on <host>"), newest first, as reported
    readings of the host's current row (dated when they were received), and take off that row the technology an earlier discovery stored
    for the CPE under its normalized name ("http server", "http_server:2.4.41"): the reading replaces it. Adds each host that moved to
    ``moved``; returns how many readings were read."""
    from cveFeed.models import DiscoveryEvent
    from cvengine_scanner import versions
    from startScan.models import Subdomain, Technology
    seen, count = set(), 0
    for event in DiscoveryEvent.objects.filter(type='TECHNOLOGY', label__istartswith='cpe:').order_by('-id').iterator(chunk_size=500):
        tech, sep, host = event.label.rpartition(' on ')
        host = (host or event.host or '').strip().lower().rstrip('.')
        reading = reported_cpe(tech.strip()) if sep else None
        if not reading or (event.domain_id, host, reading['label']) in seen:
            continue
        seen.add((event.domain_id, host, reading['label']))
        sub = _current_row(event.domain_id, host)
        if sub is None:
            continue
        if store_reported(sub.target_domain.project_id, sub.target_domain_id, sub.name, SHODAN_PROBE, [reading], SHODAN_PROVIDER, event.created_at,
                          undated=True):
            moved.add(sub.pk)
        count += 1
        names = {versions.normalize_technology(tech.strip()), tech.strip()}
        stored = Technology.objects.filter(name__in=names).values_list('id', flat=True)
        links = Subdomain.technologies.through.objects.filter(subdomain_id=sub.pk, technology_id__in=list(stored))
        if links.exists():
            links.delete()  # an earlier discovery stored the CPE as a first-party technology: the reported reading replaces it
            moved.add(sub.pk)
    return count


def catch_up_shodan(apply=False, batch=200):
    """The one-time catch-up of the Shodan InternetDB CPEs an update runs (``manage.py backfill_shodan_cpes --apply``): every CPE is a reported
    reading labelled "vendor product" (``shodan_reading``: unversioned and operating system CPEs too, which were stored as technologies named
    "http server" or "cpe:/o:..."). Relabels the stored readings ("openssh" is "openbsd openssh"), re-reads the CPEs the discovery feed kept
    (``_shodan_events``), turns every technology named as a raw CPE into the reading it is and drops it, then correlates the hosts that moved.
    Idempotent. Returns ``{'relabelled', 'readings', 'technologies', 'hosts', 'matches'}``."""
    from cveFeed import correlation
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain, Technology
    rows = list(ProbeObservation.objects.filter(probe=SHODAN_PROBE))
    stale = [(row, shodan_reading((row.evidence or {}).get('cpe') if isinstance(row.evidence, dict) else '')) for row in rows]
    stale = [(row, r) for row, r in stale if r and r['label'] != row.product]
    raw = list(Technology.objects.filter(name__istartswith='cpe:'))
    links = list(Subdomain.technologies.through.objects.filter(technology_id__in=[t.pk for t in raw]).values_list('subdomain_id', 'technology_id'))
    out = {'relabelled': len(stale), 'readings': 0, 'technologies': len(raw), 'hosts': 0, 'matches': 0}
    if not apply:
        return out
    moved = set()
    for row, reading in stale:
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        sub = _current_row(row.domain_id, row.host)
        store_reported(row.project_id, row.domain_id, row.host, SHODAN_PROBE, [reading], SHODAN_PROVIDER, ev.get('reported_at') or row.observed_at,
                       port=row.port, undated=bool(ev.get('undated')))
        row.delete()
        if sub is not None:
            moved.add(sub.pk)
    out['readings'] += _shodan_events(moved)
    names = {t.pk: t.name for t in raw}
    current = set(Subdomain.objects.filter(correlation.latest_scan_q()).filter(pk__in={s for s, _t in links}).values_list('pk', flat=True))
    for sub in Subdomain.objects.filter(pk__in=current).select_related('target_domain'):
        readings = [reported_cpe(names[t]) for s, t in links if s == sub.pk]
        if sub.target_domain_id and store_bbot_reported(sub, [r for r in readings if r]):
            out['readings'] += len([r for r in readings if r])
        moved.add(sub.pk)
    Subdomain.technologies.through.objects.filter(technology_id__in=list(names)).delete()
    Technology.objects.filter(pk__in=list(names)).delete()
    out['hosts'] = len(moved)
    if moved:
        cve_by_id, index = correlation.cve_pool()
        ordered = sorted(moved)
        for start in range(0, len(ordered), batch):
            subs = list(Subdomain.objects.filter(pk__in=ordered[start:start + batch]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    return out


def catch_up_recog(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_recog_readings --apply``): read every current host's stored banners with
    Recog (``refresh_recog``), then correlate the hosts that gained or lost a reading. Idempotent. Returns ``{'hosts', 'readings', 'matches'}``."""
    from cveFeed import correlation
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    ids = list(base.order_by('id').values_list('id', flat=True))
    out = {'hosts': len(ids), 'readings': 0, 'matches': 0}
    if not apply:
        return out
    moved = set()
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        for sub in subs:
            try:
                found, changed = refresh_recog(sub)
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('Recog catch-up of host %s failed', sub.pk)
                continue
            out['readings'] += len(found)
            if changed:
                moved.add(sub.pk)
    if moved:
        cve_by_id, index = correlation.cve_pool()
        ordered = sorted(moved)
        for start in range(0, len(ordered), batch):
            subs = list(Subdomain.objects.filter(pk__in=ordered[start:start + batch]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    return out


def catch_up_version_scripts(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_version_scripts --apply``): read the version category script output every current
    host's ports already store (``extra.version_scripts``: vmware-version's ESXi build, amqp-info, docker-version, wdb-version) into ``vsrc:nmap``
    readings, and the firmware hint a stored runZero block's ``hw`` states (its services come with the next sync), then correlate the hosts that
    moved and every host whose port or technology names VMware ESXi (its CVE ranges are read by build now: ``correlation.esxi_ranges``).
    Idempotent. Returns ``{'hosts', 'readings', 'matches'}``."""
    from cveFeed import correlation, version_sources
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    stored = base.filter(Q(ip_addresses__ports__extra__has_key='version_scripts') | Q(ip_addresses__fingerprint__has_key='runzero'))
    esxi = base.filter(Q(ip_addresses__ports__product__icontains='esx') | Q(technologies__name__icontains='esxi'))
    ids = sorted(set(stored.values_list('id', flat=True)))
    moved = set(esxi.values_list('id', flat=True))
    out = {'hosts': len(set(ids) | moved), 'readings': 0, 'matches': 0}
    if not apply:
        return out
    configured = None
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        if configured is None:
            from cveFeed import runzero_sync
            configured = runzero_sync.configured_project_ids()
        for sub in subs:
            try:
                ports = version_sources._ports(sub)
                found = nmap_readings(sub, ports)
                changed = version_sources._store_derived(sub, NMAP_PROBE, found, timezone.now())
                changed = refresh_runzero(sub, configured=configured) or changed
                changed = refresh_recog(sub, ports)[1] or changed  # Recog gives way to the nmap readings just stored
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('version script catch-up of host %s failed', sub.pk)
                continue
            out['readings'] += sum(1 for _n, r in found if str(r.get('source') or '') in VERSION_SCRIPT_SOURCES)
            if changed:
                moved.add(sub.pk)
    if moved:
        cve_by_id, index = correlation.cve_pool()
        ordered = sorted(moved)
        for start in range(0, len(ordered), batch):
            subs = list(Subdomain.objects.filter(pk__in=ordered[start:start + batch]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    return out


def payload_fields(row):
    """The host payload's fields of a reported reading (``version_sources.as_dict``): who reported it and as of when; ``stale`` and ``matched``
    follow its age (``REPORTED_MAX_AGE_DAYS``). A reading a first-party one supersedes is not told apart here: ``in_use`` decides at correlation."""
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    when = _reported_at(row)
    aged = when is None or when < timezone.now() - timedelta(days=REPORTED_MAX_AGE_DAYS)
    return {'reported': {'by': ev.get('provider') or '', 'at': ev.get('reported_at') or '', 'undated': bool(ev.get('undated'))},
            'stale': aged, 'matched': not aged and not ev.get('hint'), **({'hint': True} if ev.get('hint') else {})}


def refresh_runzero_project(project):
    """After a runZero sync of ``project``: refresh the runZero readings of its current hosts that sit on an address with a block or already carry
    a runZero reading, and correlate the ones that moved. Returns how many moved."""
    from cveFeed import correlation, probes
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    hosts = set(ProbeObservation.objects.filter(project_id=project.pk, probe=RUNZERO_PROBE).values_list('host', flat=True))
    on_blocks = Subdomain.objects.filter(target_domain__project=project, ip_addresses__fingerprint__has_key='runzero').values('id')
    subs = (Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__project=project)
            .filter(Q(id__in=on_blocks) | Q(name__in=hosts)).select_related('target_domain').prefetch_related('ip_addresses').distinct())
    moved = 0
    for sub in subs:
        if refresh_runzero(sub):
            moved += 1
            probes.recorrelate(sub)
    return moved
