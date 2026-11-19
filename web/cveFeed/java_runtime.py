"""The Java runtime of a host, read from outside, and the runtime CVEs it makes visible.

Why. A CVE in the JDK itself (CVE-2026-114938: OpenJDK 17.0.6 and every later 17.x) names the runtime, not the application on top of it, and
cvENGINE almost never knew which runtime a Tomcat, a Jenkins or a Confluence runs: such a CVE matched nothing and stayed silent. Almost no customer
runs the host inventory reporter, so this module assumes outside detection is the only source and never reads an inventory.

What is read (``cvengine_scanner.java`` holds every parser; the server and the Sentinel share it). Each reading is one ``JavaRuntime`` row with a
source and a confidence:

  exact     jdwp          the JDWP handshake and VirtualMachine.Version on a debug port (nmap's own jdwp-version during the fingerprint pass, or
                          the ``java_runtime`` kind on a debug port nmap left unidentified). An open JDWP port is also a critical exposure: anyone
                          who reaches it can run code in that JVM (``jdwp_exposed``, a scanner finding).
            actuator      Spring Boot actuator: ``env/java.version``, ``info``, ``metrics/jvm.info``, Boot 1's ``env/java.version``
            jolokia       the Runtime MXBean's VmVersion and VmVendor, only when ``/jolokia/version`` is Jolokia's own answer
            status_page   Solr, GeoServer, Druid, Elasticsearch and OpenSearch status pages
            header        X-Powered-By and Server (GlassFish and Payara print the JVM vendor and line)
            error_page    a JVM banner or ``java.version`` in a page the version probes already fetched (never a page made to fail)
  inferred  bundled_inference  the JDK a vendor bundles with the product version the host shows (``data/bundled_jdk.json``: Atlassian installers,
                          Elasticsearch, OpenSearch, the official Jenkins, Keycloak and SonarQube images); "unless the owner replaced it"
  weak      bundled_inference  a vendor's supported Java line when it bundles none (Bamboo, Crowd)
            jenkins_minimum    the oldest Java a Jenkins release starts on: a hard minimum, never the Java it runs

Where it runs. Nothing here sends a request. The reads that need none (an nmap JDWP port, a stored header, a product version) are made by
``refresh_host`` from what the scans already stored. The active reads are the Sentinel kind ``java_runtime`` (contract version 6): a stage of the
host pipeline after the version probes (``run_for_scan``), and the work planner for the hosts already in the inventory (``run_for_hosts``), once a
week per host and again a day later when it could not complete. A web check is asked only of a host already identified as that product (a
technology or a port product: Spring for the actuator and Jolokia, Solr, GeoServer, Druid, Elasticsearch or OpenSearch); the JDWP handshake only of a
port nmap names jdwp or an open debug port (5005 to 5010, 8000, 8787, 9009) nmap left unidentified. Every host and address passes the same gates as
every probe: the organization's exclusions (fail closed), archived hosts, a bug bounty program's scope and its automated-testing confirmation, the
address rules, and the do-not-scan list the dispatcher applies.

Correlation (``collect_matches``, called from ``correlation.collect_subdomain_matches``): a CVE whose affected products name the Java runtime
(``is_runtime_item``) is tested against the host's readings. One match per host and CVE, source ``java``:

  * an exact reading inside the range is a normal version match (version only: ``match_policy`` decides proof and heat as for any banner; a
    distribution's build is judged by the distribution's tracker, ``distro``); an exact reading outside every range is no match;
  * with no exact reading, a host where Java is clear (an exact line, an inference, or a Java product) is a "Java runtime of unknown version"
    candidate when the CVE affects a Java line the host can run: ``evidence.java_unknown``, which ``match_policy.is_version_unknown`` reads as
    version unknown (needs validation, ice, the lowest priority, never fire, never validated or AI-triaged automatically). An inferred or weak
    reading inside the range raises its confidence and says so; one outside the range lowers it; a line the host is known to run, or a Jenkins
    minimum, that excludes every affected line removes it. The explanation leads with what an outside check could not see, then the commands a
    host owner runs (``confirm_guide``).
"""
import functools
import json
import logging
import os
import re
from datetime import timedelta
from pathlib import Path

from django.utils import timezone

from cvengine_scanner import java

logger = logging.getLogger(__name__)

KIND = 'java_runtime'  # the Sentinel task kind
SERVICE = 'java-runtime'  # the ledger service: one row per host name, a week
FAILED_SERVICE = 'java-runtime-failed'  # a host that could not be read completely: asked again after a day
MATCH_SOURCE = 'java'  # CVEMatch.source
MATCHED_PRODUCT = 'Java runtime'
FINDING_SOURCE = 'java-runtime'  # Vulnerability.source
JDWP_TEMPLATE = 'jdwp-exposed'
JDWP_FINDING = 'Java debug port (JDWP) open to the network'
SEVERITY_CRITICAL = 4
MAX_WEB_PER_TASK = 50
MAX_JDWP_PER_TASK = 25
MAX_PER_SCAN = 60  # hosts one scan sends; the rest are due on the next pass or the work planner's
ANY_VALUES = ('any', 'yes', 'all')  # java:any is tech:java: every host that runs Java, its version read or not (cveFeed.tech_search)
UNKNOWN_VALUES = ('unknown', 'unread', 'none')  # java:unknown is tech:java@unknown: a host that runs Java at a version nothing has read
STALE_DAYS = 90  # a reading not seen again for this long is not used to match
UNKNOWN_CONFIDENCE = 0.4  # a Java runtime of unknown version (the correlation floor: correlate_cves keeps matches at 0.4 and above)
INFERRED_IN_RANGE_CONFIDENCE = 0.5
INFERRED_OUT_CONFIDENCE = 0.4
DATA = Path(__file__).with_name('data') / 'bundled_jdk.json'
JDWP_PORTS = (5005, 5006, 5007, 5008, 5009, 5010, 8000, 8787, 9009)
# a debug port nmap identified as something else is not sent the handshake; one it left unnamed (or tcpwrapped: a JDWP debuggee hangs up on nmap's
# NULL probe) is
_UNIDENTIFIED = re.compile(r'^(?:|unknown|tcpwrapped|jdwp)$')

# ----------------------------------------------------------------------------- which hosts run Java

# products that run on a JVM: a host showing one of these runs Java, whatever version (the "Java is clear" hosts)
JAVA_PRODUCT_RE = re.compile(
    r'\b(?:java|jdk|jre|openjdk|jvm|tomcat|coyote|jetty|jenkins|hudson|confluence|jira|bitbucket|bamboo|crowd|atlassian|spring|'
    r'weblogic|wildfly|jboss|undertow|glassfish|payara|websphere|liberty|resin|polarion|keycloak|sonarqube|nexus|artifactory|'
    r'solr|elasticsearch|opensearch|logstash|geoserver|druid|kafka|zookeeper|activemq|artemis|hadoop|hbase|cassandra|neo4j|'
    r'jolokia|hawtio|karaf|liferay|alfresco|openfire|teamcity|youtrack|gerrit|struts|grails|play framework|vert\.x|netty|'
    r'jdwp|java debug wire protocol|graylog|metabase|apache ofbiz|apache nifi|apache flink|apache spark|camunda|mulesoft|tibco)\b', re.I)
# check -> what a host must show before the check's paths are asked of it (its technology fingerprint or a port product)
CHECK_PRODUCTS = {
    'actuator': re.compile(r'spring|actuator', re.I),
    'jolokia': re.compile(r'spring|jolokia|hawtio|activemq|karaf', re.I),
    'solr': re.compile(r'\bsolr\b', re.I),
    'geoserver': re.compile(r'geoserver', re.I),
    'druid': re.compile(r'\bdruid\b', re.I),
    'elasticsearch': re.compile(r'elasticsearch|opensearch', re.I),
}


def enabled():
    return os.environ.get('CVENGINE_JAVA_RUNTIME', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def is_java_name(name):
    return bool(JAVA_PRODUCT_RE.search(str(name or '')[:200]))


def _split(name):
    from cveFeed.correlation import split_name_version
    return split_name_version(name or '')


def host_products(sub, ports=None):
    """``[(name, version)]``: what ``sub`` shows of itself, its technologies and the products of its open ports (``ports`` when given)."""
    out = [_split(t.name) for t in sub.technologies.all() if t.name]
    if ports is None:
        from startScan.models import open_services
        ports = [p for ip in sub.ip_addresses.all() for p in open_services(ip)]
    out += [((p.product or '').strip(), (p.version or '').strip()) for p in ports if (p.product or '').strip()]
    return out


def web_checks(products):
    """The web checks a host's products warrant, in a fixed order: a check is asked only of a host already identified as its product."""
    return [check for check, pattern in CHECK_PRODUCTS.items() if any(pattern.search(name or '') for name, _v in products)]


def jdwp_kind(port):
    """'nmap' for an open TCP port nmap named jdwp (its jdwp-version read it), 'debug' for an open common debug port it left unidentified, else ''."""
    if (getattr(port, 'protocol', 'tcp') or 'tcp') not in ('tcp', '') or (getattr(port, 'state', 'open') or 'open') != 'open':
        return ''
    service = (getattr(port, 'service_name', '') or '').strip().lower()
    product = getattr(port, 'product', '') or ''
    if service == 'jdwp' or java.NMAP_JDWP_PRODUCT.match(product):
        return 'nmap'
    if getattr(port, 'number', 0) in JDWP_PORTS and _UNIDENTIFIED.match(service) and not product.strip():
        return 'debug'
    return ''


# ----------------------------------------------------------------------------- the bundled-JDK table (inference)

@functools.lru_cache(maxsize=1)
def table():
    """The bundled-JDK table (``data/bundled_jdk.json``), read once."""
    return json.loads(DATA.read_text(encoding='utf-8'))


def _vkey(text):
    return tuple(int(x) for x in re.findall(r'\d+', str(text or ''))[:4])


def _vcmp(a, b):
    a, b = _vkey(a), _vkey(b)
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _jenkins_line(version):
    """``(base, lts)`` of a Jenkins version: ``2.479.1`` is LTS 479, ``2.480`` weekly 480, else None."""
    found = re.match(r'^2\.(\d{2,4})(?:\.(\d{1,3}))?$', (version or '').strip())
    if not found:
        return None
    return int(found.group(1)), found.group(2) is not None


def _jenkins_range(ranges, version):
    """The last of ``ranges`` (``weekly_from``, ``lts_from``) a Jenkins ``version`` is at or past, or None."""
    line = _jenkins_line(version)
    if line is None:
        return None
    hit = None
    for rng in ranges:
        start = rng['lts_from'] if line[1] else rng['weekly_from']
        if _vcmp(version, start) >= 0:
            hit = rng
    return hit


def _product(name):
    token = re.sub(r'[^a-z0-9 ]', ' ', (name or '').lower()).strip()
    for entry in table()['products']:
        if any(re.search(rf'(?:^|\s){re.escape(m)}(?:\s|$)', token) for m in entry['match']):
            yield entry


def infer(name, version):
    """The readings the bundled-JDK table gives for a product ``name`` at ``version`` (a product and version the host showed): an inferred bundled
    JDK (the exact build the vendor shipped with that release, or the line of the official image), a weak supported line, and for Jenkins its hard
    minimum. Each reading carries its basis and citation in ``detail``. Nothing for a product or version the table does not list."""
    out = []
    version = (version or '').strip()
    if not version or not re.match(r'^\d', version):
        return out
    for entry in _product(name):
        reading, detail = None, {'product': entry['label'], 'product_version': version[:40], 'basis': entry['basis'], 'note': entry['note']}
        releases = entry.get('releases')
        if releases:
            key = '.'.join(str(p) for p in (_vkey(version) + (0, 0, 0))[:3])
            got = releases.get(key)
            source = entry['source'].replace('{version}', key)
            if got:
                reading = java.reading(got['jdk'], 'bundled_inference', (got.get('vendor') or '',), confidence=entry['confidence'])
                detail.update(release=key, source=source)
            else:  # a release the vendor's table does not list: the line every listed release of the same feature line bundles, if they agree
                line = '.'.join(key.split('.')[:2]) + '.'
                majors = {java.major_of(v['jdk']) for k, v in releases.items() if k.startswith(line)}
                if len(majors) == 1 and 0 not in majors:
                    reading = java.reading(str(majors.pop()), 'bundled_inference', (), confidence=entry['confidence'])
                    detail.update(release_line=line.rstrip('.'), source=entry['source'].replace('{version}', key),
                                  note=entry['note'] + '; this release is not in the vendor\'s table, the line every listed release of it bundles')
        else:
            rng = _jenkins_range(entry['ranges'], version) if entry.get('scheme') == 'jenkins' else next(
                (r for r in entry['ranges'] if _vcmp(version, r['from']) >= 0 and _vcmp(version, r['to']) <= 0), None)
            if rng is not None:
                majors = rng.get('majors') or [rng['major']]
                detail.update(source=rng['source'], possible_majors=majors)
                if len(majors) == 1:
                    reading = java.reading(str(majors[0]), 'bundled_inference', (rng.get('vendor') or '',), confidence=entry['confidence'])
                elif majors:
                    reading = java.reading(str(min(majors)), 'bundled_inference', (), confidence='weak')
                    if reading:
                        reading['line_only'] = True
        if reading:
            reading['evidence'] = java.clip(f"{entry['label']} {version}: {entry['note']}")
            reading['detail'] = detail
            out.append((f"bundled:{entry['id']}", reading))
    minimum = jenkins_minimum(name, version)
    if minimum:
        out.append(minimum)
    return out


def jenkins_minimum(name, version):
    """``(key, reading)`` of the oldest Java a Jenkins ``version`` starts on (``jenkins_minimum``: weak, the line only, ``detail.minimum``), or None."""
    if not re.search(r'\bjenkins\b', name or '', re.I):
        return None
    spec = table()['jenkins_minimum']
    rng = _jenkins_range(spec['ranges'], version)
    if rng is None:
        return None
    reading = java.reading(str(rng['major']), 'jenkins_minimum', (), confidence='weak')
    reading['line_only'] = True
    reading['evidence'] = java.clip(f'Jenkins {version} starts only on Java {rng["major"]} or later')
    reading['detail'] = {'product': 'Jenkins', 'product_version': version[:40], 'minimum': rng['major'], 'basis': 'minimum', 'source': spec['source']}
    return 'jenkins:minimum', reading


# ----------------------------------------------------------------------------- the readings that need no request

_HEADER_LINE = re.compile(r'(?im)^\s*(x-powered-by|server)\s*:\s*(.{1,300})$')


def passive_readings(sub, ports=None, probe_rows=None):
    """``[(key, reading)]`` a host gives away in what the scans already stored: a port nmap's jdwp-version identified, the X-Powered-By and Server
    headers (the host's web server header, nmap's http-headers output, a version probe's page), a JVM banner a version probe read, and the
    inferences of the products and versions it shows. Pure but for the rows passed in (or the host's prefetched ones)."""
    from startScan.models import open_services
    if ports is None:
        ports = [(ip.address, p) for ip in sub.ip_addresses.all() for p in open_services(ip)]
    out = []
    for _address, port in ports:
        if jdwp_kind(port) == 'nmap':
            got = java.from_nmap_port(port.service_name, port.product, port.version, port=port.number)
            if got:
                out.append((f'jdwp:{port.number}', got))
        scripts = ((port.extra or {}).get('scripts') or {}) if isinstance(port.extra, dict) else {}
        text = str(scripts.get('http-headers') or '')[:8000] if isinstance(scripts, dict) else ''
        headers = {name.lower(): value for name, value in _HEADER_LINE.findall(text)}
        for got in java.from_headers(headers, url=f'port {port.number}'):
            got['port'] = port.number
            out.append((f'header:{port.number}', got))
    if getattr(sub, 'webserver', ''):
        for got in java.from_headers({'server': sub.webserver}, url='/'):
            out.append(('header:server', got))
    for row in probe_rows or ():
        if row.product != 'Java runtime' or row.outcome != 'found':
            continue
        stated = (row.evidence or {}).get('java') if isinstance(row.evidence, dict) else None
        got = java.reading(row.version, 'header' if (row.source or '').startswith('header') else 'error_page',
                           (row.variant, (stated or {}).get('vendor') if isinstance(stated, dict) else ''), url=row.url,
                           evidence=(stated or {}).get('evidence', '') if isinstance(stated, dict) else '')
        if got:
            if isinstance(stated, dict) and stated.get('line_only') is True:
                got['line_only'] = True
            out.append((f'probe:{row.probe}:{got["version"]}', got))
    for name, version in host_products(sub, [p for _a, p in ports]):
        if re.search(r'\b(?:java|jdk|jre|openjdk)\b', name or '', re.I) and version:  # a scanner's own "Java:1.8.0_292" technology
            got = java.reading(version, 'header', (name,), confidence='weak', evidence=f'technology {name} {version}')
            if got:
                out.append((f'tech:{got["version"]}', got))
        out += infer(name, version)
    seen, unique = set(), []
    for key, reading in out:
        if key not in seen:
            seen.add(key)
            unique.append((key[:200], reading))
    return unique


def store(project_id, domain_id, host, key, reading, now=None):
    """Write one reading (a repeat of the key updates it). Returns the row."""
    from cveFeed.models import JavaRuntime
    now = now or timezone.now()
    row, created = JavaRuntime.objects.update_or_create(
        project_id=project_id, host=host.lower().rstrip('.'), key=key[:200],
        defaults={'domain_id': domain_id, 'version': reading['version'][:40], 'major': int(reading['major']), 'vendor': (reading['vendor'] or 'unknown')[:40],
                  'runtime': (reading.get('runtime') or '')[:200], 'build': (reading.get('build') or '')[:60],
                  'line_only': bool(reading.get('line_only')), 'source': reading['source'][:24], 'confidence': reading['confidence'][:12],
                  'port': int(reading.get('port') or 0), 'url': (reading.get('url') or '')[:300], 'evidence': (reading.get('evidence') or '')[:300],
                  'detail': reading.get('detail') or {}, 'last_seen': now})
    return row


PASSIVE_KEYS = ('jdwp:', 'header:', 'probe:', 'tech:', 'bundled:', 'jenkins:')


def refresh_host(sub, now=None, rescan_findings=True):
    """Make and store the readings ``sub`` gives away without a request (``passive_readings``), drop the derived ones it no longer gives (a product
    upgraded, a header gone), and file the JDWP exposure of a port nmap identified. Returns the readings stored."""
    from cveFeed.models import JavaRuntime, ProbeObservation
    from startScan.models import open_services
    now = now or timezone.now()
    project_id = sub.target_domain.project_id
    host = sub.name.lower().rstrip('.')
    ports = [(ip.address, p) for ip in sub.ip_addresses.all() for p in open_services(ip)]
    probe_rows = ProbeObservation.objects.filter(project_id=project_id, host=host, product='Java runtime', kind='version')
    found = passive_readings(sub, ports, probe_rows)
    for key, reading in found:
        store(project_id, sub.target_domain_id, host, key, reading, now=now)
    stale = JavaRuntime.objects.filter(project_id=project_id, host=host).exclude(key__in=[k for k, _r in found])
    stale.filter(key__regex=r'^(bundled|jenkins|tech|header):').delete()  # derived from what the host shows now: gone when that is gone
    if rescan_findings and sub.scan_history_id:
        for address, port in ports:
            if jdwp_kind(port) == 'nmap':
                file_jdwp_exposure(sub.scan_history, sub, address, port.number, f'nmap jdwp-version: {port.product} {port.version}'.strip())
    return found


def is_java_host(sub, runtimes=None):
    """Whether Java is clear on ``sub``: a reading of any kind, or a product that runs on a JVM."""
    if runtimes:
        return True
    return any(is_java_name(name) for name, _v in host_products(sub))


# ----------------------------------------------------------------------------- the JDWP exposure finding

def file_jdwp_exposure(scan, sub, address, port, evidence=''):
    """The critical finding of an open JDWP port: one row per host name and endpoint (a rescan updates it). Returns 1 when it is new."""
    from reNgine.tasks import save_vulnerability
    if scan is None:
        return 0
    evidence = java.clip(evidence, 300)
    _vuln, created = save_vulnerability(
        target_domain=scan.domain, scan_history=scan, subdomain=sub, source=FINDING_SOURCE, template_id=JDWP_TEMPLATE, name=JDWP_FINDING,
        severity=SEVERITY_CRITICAL, http_url=f'jdwp://{address}:{port}', type='java',
        description=(f'{address}:{port} answers the Java Debug Wire Protocol handshake: a JVM runs with its debug agent '
                     '(-agentlib:jdwp) listening on the network. JDWP has no authentication.') + (f' It said: {evidence}' if evidence else ''),
        impact='Anyone who can reach this port can load classes and run any code in that JVM, as the account it runs under: remote code execution.',
        remediation=('Remove -agentlib:jdwp (or -Xrunjdwp, or JAVA_TOOL_OPTIONS/JPDA settings such as catalina.sh jpda) from the production start '
                     'options and restart, or bind it to 127.0.0.1 (address=127.0.0.1:PORT) and reach it through an SSH tunnel. Block the port at the '
                     'firewall meanwhile.'),
        extracted_results=[evidence] if evidence else [], tags=['java', 'jdwp', 'exposure'])
    return 1 if created else 0


def close_jdwp_exposure(scan, sub, address, port):
    """A complete check that found no JDWP debuggee on the endpoint (something else answered): the finding of an earlier check is gone. Only the
    liveness field changes; a status a person set is kept."""
    from startScan.models import Vulnerability
    Vulnerability.objects.filter(target_domain__project_id=scan.domain.project_id, subdomain__name=sub.name, source=FINDING_SOURCE,
                                 template_id=JDWP_TEMPLATE, http_url=f'jdwp://{address}:{port}', open_status=True).update(open_status=False)


# ----------------------------------------------------------------------------- the active reads: plan

def _gate():
    from cveFeed.bounty_gate import Gate
    return Gate(blocked=())


def plan(project_id, subdomains, unattended=False):
    """``{host: {'subs': [Subdomain], 'web': {'base', 'checks'} or None, 'jdwp': [(address, port, kind)]}}`` for the hosts of ``subdomains`` that have
    something to ask: a web check their products warrant, or a JDWP endpoint. Leaves out what the organization excluded (fail closed), archived hosts,
    what a bug bounty program's scope does not name (and, ``unattended``, a project whose engagement has not confirmed automated testing) and the
    addresses a scanner may not reach."""
    from cveFeed import route_auth
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.exclusions import excluded_names, normalize
    from startScan.models import open_services
    from targetApp.target_types import is_scannable_ip
    banned = excluded_names(project_id, strict=True)
    archived = set(archived_names(project_id))
    gate = _gate()
    if unattended and gate.project_blocked(project_id):
        return {}
    out = {}
    for sub in subdomains:
        name = sub.name.lower().rstrip('.')
        if normalize(sub.name) in banned or name in archived or gate.refusal(project_id, sub.name, unattended=unattended):
            continue
        ports = [(ip.address, p) for ip in sub.ip_addresses.all() for p in open_services(ip)]
        checks = web_checks(host_products(sub, [p for _a, p in ports]))
        bases = route_auth.web_bases(sub) if checks else []
        endpoints = []
        for ip in sub.ip_addresses.all():
            if not is_scannable_ip(ip.address, project=project_id) or gate.refusal(project_id, ip.address, unattended=unattended, derived=True):
                continue
            for p in open_services(ip):
                kind = jdwp_kind(p)
                if kind:
                    endpoints.append((ip.address, p.number, kind))
        if not (bases or endpoints):
            continue
        entry = out.setdefault(name, {'subs': [], 'web': None, 'jdwp': []})
        entry['subs'].append(sub)
        if bases and entry['web'] is None:
            entry['web'] = {'base': bases[0], 'checks': checks}
        for e in endpoints:
            if e not in entry['jdwp']:
                entry['jdwp'].append(e)
    return out


def candidates(scan, unattended=False):
    from startScan.models import Subdomain
    rows = (Subdomain.objects.filter(scan_history=scan).select_related('target_domain', 'scan_history')
            .prefetch_related('technologies', 'ip_addresses__ports'))
    return plan(scan.domain.project_id, rows, unattended=unattended)


def candidates_for_hosts(project_id, names, unattended=True):
    """``plan`` for the current inventory rows of the named hosts of a project (the work planner's entry)."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    rows = (Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id, name__in=sorted({n.lower().rstrip('.') for n in names}))
            .select_related('scan_history', 'target_domain').prefetch_related('technologies', 'ip_addresses__ports'))
    return plan(project_id, rows, unattended=unattended)


def applies(sub, ports=None):
    """Whether the active reads apply to ``sub`` (``check_coverage``): a web check its products warrant on a web host, or a JDWP endpoint."""
    from cveFeed import route_auth
    from startScan.models import open_services
    if ports is None:
        ports = [p for ip in sub.ip_addresses.all() for p in open_services(ip)]
    if any(jdwp_kind(p) for p in ports):
        return True
    return bool(web_checks(host_products(sub, ports))) and bool(route_auth.web_bases(sub))


def due(project_id, found, force=False, limit=MAX_PER_SCAN):
    """The hosts of ``found`` to ask now, in a stable order, at most ``limit``: no complete read inside the week and no failed one inside the day.
    ``force`` (a retest) asks every one."""
    from cveFeed import ledger
    names = sorted(found)
    if force or not names:
        return names[:limit]
    done = ledger.fresh(SERVICE, names, project_id)
    retry_later = ledger.fresh(FAILED_SERVICE, names, project_id)
    return [n for n in names if ledger._norm(n) not in done and ledger._norm(n) not in retry_later][:limit]


def jdwp_id(address, port):
    """The id of one JDWP entry of a task (``jdwp|<address>|<port>``: never read as an address by the do-not-scan guard)."""
    return f'jdwp|{address}|{port}'


def _entries(found, names):
    """The task entries of ``names``: ``([(sub, web entry)], [jdwp entry])`` and which entry ids belong to which host."""
    from cveFeed import probes
    web, jdwp, owner = [], [], {}
    for name in names:
        item = found[name]
        sub = item['subs'][0]
        if item['web']:
            ident = f'{name}|java|{item["web"]["base"]}'[:200]
            web.append((sub, {'id': ident, 'host': name, 'base': item['web']['base'].rstrip('/'), 'checks': item['web']['checks'],
                              'allowed': sorted(probes.allowed_names(sub))[:20]}))
            owner[('web', ident)] = name
        for address, port, _kind in item['jdwp']:
            ident = jdwp_id(address, port)
            if ('jdwp', ident) not in owner:
                jdwp.append({'id': ident, 'address': address, 'port': port})
                owner[('jdwp', ident)] = name
    return web, jdwp, owner


# ----------------------------------------------------------------------------- the active reads: run and store

def run_for_scan(scan_id, force=False, dispatch=None):
    """The host pipeline stage: refresh the passive readings of every host of the scan, then send the active reads that are due to a Sentinel and
    store what comes back. Returns ``{'hosts', 'asked', 'readings', 'exposed', 'waiting'}``. Raises ``ScannerUnavailable`` when no scanner can take the
    kind (the active reads stay due; the passive readings are stored first)."""
    from agentapi import probe_dispatch, sentinel_dispatch
    from cveFeed import activity
    from reNgine.resources import ScannerUnavailable
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain__project').get(pk=scan_id)
    project = scan.domain.project
    summary = {'hosts': 0, 'asked': 0, 'readings': 0, 'exposed': 0, 'waiting': 0}
    if not enabled():
        return {**summary, 'skipped': 'disabled'}
    for sub in Subdomain.objects.filter(scan_history=scan).select_related('target_domain', 'scan_history').prefetch_related('technologies', 'ip_addresses__ports'):
        try:
            summary['readings'] += len(refresh_host(sub))
        except Exception:  # noqa: BLE001 - one host's stored data never stops the stage
            logger.exception('passive Java runtime readings of host %s failed', sub.pk)
    found = candidates(scan)
    names = due(project.pk, found, force=force)
    summary['hosts'] = len(found)
    if not names:
        return summary
    if dispatch is None:
        sentinel_dispatch.scanner_or_local(project, KIND)  # raises ScannerUnavailable when none can take it: the kind has no local path
        dispatch = lambda project_, web, jdwp: probe_dispatch.try_java_runtime(project_, web, jdwp, scan=scan, unattended=False)  # noqa: E731
    _ask(project, names, found, lambda name: scan, dispatch, summary)
    activity.log('run_check', f'Java runtime reads of {summary["asked"]} of {len(names)} host(s) of {scan.domain.name}: {summary["readings"]} reading(s)'
                 + (f', {summary["exposed"]} open JDWP port(s)' if summary['exposed'] else '')
                 + (f'; {summary["waiting"]} wait for a scanner' if summary['waiting'] else ''), project=project.pk, scan_id=scan.id)
    if summary['waiting']:
        raise ScannerUnavailable(KIND, f'a Sentinel returned no result for {summary["waiting"]} host(s): they stay due')
    return summary


def run_for_hosts(project, host_names, dispatch=None, priority=1):
    """The work planner's entry: the same plan, gates (unattended: the bug bounty engagement must have confirmed automated testing), ledger and
    storage as ``run_for_scan`` for the named hosts' current inventory rows, with no scan of its own."""
    from agentapi import probe_dispatch, sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    summary = {'hosts': 0, 'asked': 0, 'readings': 0, 'exposed': 0, 'waiting': 0}
    if not enabled():
        return {**summary, 'skipped': 'disabled'}
    found = candidates_for_hosts(project.pk, host_names, unattended=True)
    for item in found.values():
        for sub in item['subs']:
            refresh_host(sub)
    names = due(project.pk, found, limit=MAX_WEB_PER_TASK)
    summary['hosts'] = len(found)
    if not names:
        return summary
    if dispatch is None:
        sentinel_dispatch.scanner_or_local(project, KIND)
        dispatch = lambda project_, web, jdwp: probe_dispatch.try_java_runtime(project_, web, jdwp, priority=priority, unattended=True)  # noqa: E731
    _ask(project, names, found, lambda name: found[name]['subs'][0].scan_history, dispatch, summary)
    if summary['waiting']:
        raise ScannerUnavailable(KIND, f'a Sentinel returned no result for {summary["waiting"]} host(s): they stay due')
    return summary


def _ask(project, names, found, scan_for, send, summary):
    """Claim ``names``, send them in tasks within the contract's bounds through ``send(project, web, jdwp)`` and store every answer."""
    from cveFeed import ledger
    from cveFeed.exclusions import excluded_names, normalize
    with ledger.claim_many(f'{SERVICE}@{project.pk}', names) as won:
        won = {ledger._norm(n) for n in won}
        names = [n for n in names if ledger._norm(n) in won]
        start = 0
        while start < len(names):
            chunk, jdwp_count = [], 0
            while start < len(names) and len(chunk) < MAX_WEB_PER_TASK and jdwp_count + len(found[names[start]]['jdwp']) <= MAX_JDWP_PER_TASK:
                chunk.append(names[start])
                jdwp_count += len(found[names[start]]['jdwp'])
                start += 1
            if not chunk:  # one host with more endpoints than a task takes: its first ones are asked, the rest next time
                found[names[start]]['jdwp'] = found[names[start]]['jdwp'][:MAX_JDWP_PER_TASK]
                continue
            banned = excluded_names(project.pk, strict=True)
            chunk = [n for n in chunk if normalize(n) not in banned]  # excluded since the plan was made: not sent
            if not chunk:
                continue
            web, jdwp, owner = _entries(found, chunk)
            web_rows, jdwp_rows = send(project, web, jdwp)
            answered = {}
            for (part, ident), name in owner.items():
                row = (web_rows if part == 'web' else jdwp_rows).get(ident)
                answered.setdefault(name, []).append((part, ident, row))
            for name in chunk:
                rows = answered.get(name, [])
                if not rows or any(row is None for _p, _i, row in rows):
                    summary['waiting'] += 1  # no answer for part of this host: unknown, due again, nothing recorded as done
                    complete = False
                else:
                    complete = all(not row.get('error') for _p, _i, row in rows)
                scan = scan_for(name)
                stored, exposed = store_answers(project.pk, scan, found[name], [(p, i, r) for p, i, r in rows if r is not None])
                summary['readings'] += stored
                summary['exposed'] += exposed
                if rows and all(row is not None for _p, _i, row in rows):
                    summary['asked'] += 1
                    ledger.record(SERVICE if complete else FAILED_SERVICE, [name], project.pk, scan)


def store_answers(project_id, scan, item, rows):
    """Store the readings of one host's answered entries for every name in ``item['subs']``, file or close the JDWP exposure, and correlate the host
    again when a reading is new or changed. Returns ``(readings stored, exposures filed)``."""
    from cveFeed import probes
    now = timezone.now()
    stored = exposed = 0
    for sub in item['subs']:
        host = sub.name.lower().rstrip('.')
        changed = False
        for part, ident, row in rows:
            readings = row.get('readings') or [] if part == 'web' else ([row['reading']] if row.get('reading') else [])
            for reading in readings:
                key = (f'{reading["source"]}:{reading.get("url") or ""}' if part == 'web' else f'jdwp:{ident.rsplit("|", 1)[1]}')[:200]
                before = _current(project_id, host, key)
                store(project_id, sub.target_domain_id, host, key, reading, now=now)
                stored += 1
                changed = changed or before != (reading['version'], reading['vendor'])
            if part == 'jdwp':
                _jdwp, address, port = ident.split('|')
                if row.get('speaks') is True:
                    exposed += file_jdwp_exposure(scan, sub, address, int(port), (row.get('reading') or {}).get('evidence') or 'JDWP-Handshake echoed')
                elif row.get('speaks') is False and scan is not None:
                    close_jdwp_exposure(scan, sub, address, int(port))
        if changed:
            probes.recorrelate(sub)
    return stored, exposed


def _current(project_id, host, key):
    from cveFeed.models import JavaRuntime
    row = JavaRuntime.objects.filter(project_id=project_id, host=host, key=key).values_list('version', 'vendor').first()
    return tuple(row) if row else None


# ----------------------------------------------------------------------------- correlation

# The product names a CVE record gives the Java runtime (NVD CPE products and the CNAs' own names), normalised the way correlation normalises a
# product. ``None``: any vendor; a tuple: the record's vendor must contain one of these (Oracle's "Java" and "JDK" are the runtime; another
# vendor's "JDK" may be its own SDK).
RUNTIME_PRODUCTS = {
    'jdk': ('oracle', 'sun', 'openjdk', 'azul', 'eclipse', 'adoptium', 'ibm', 'redhat', 'amazon', 'microsoft', 'bellsoft', 'sap'),
    'jre': ('oracle', 'sun', 'openjdk', 'azul', 'eclipse', 'adoptium', 'ibm', 'redhat', 'amazon', 'microsoft', 'bellsoft', 'sap'),
    'java': ('oracle', 'sun'), 'javase': None, 'javasejdkandjre': None, 'oraclejavase': None, 'javasejdk': None, 'javasejre': None,
    'javasedevelopmentkit': None, 'javaseruntimeenvironment': None, 'jrockit': ('oracle',), 'openjdk': None, 'openjdkjdk': None,
    'temurin': None, 'eclipsetemurin': None, 'zulu': ('azul',), 'zuluopenjdk': None, 'azulzulu': None, 'zing': ('azul',), 'zingjdk': None,
    'corretto': None, 'amazoncorretto': None, 'semeru': None, 'semeruruntime': None, 'ibmsemeruruntime': None, 'ibmsemeruruntimes': None,
    'sdkjavatechnologyedition': ('ibm',), 'ibmsdkjavatechnologyedition': None, 'redhatbuildofopenjdk': None, 'microsoftbuildofopenjdk': None,
    'libericajdk': None, 'liberica': ('bellsoft',), 'sapmachine': None, 'graalvmforjdk': None, 'oraclegraalvmforjdk': None,
}
_RUNTIME_PACKAGE = re.compile(r'^(?:java-(?:\d{1,2}|1\.[5-8]\.0)-openjdk(?:-[a-z]+)*|openjdk-?\d{1,2}(?:-[a-z]+)*|temurin-\d{1,2}-j[dr][ke]|'
                              r'java-(?:\d{1,2}|1\.8\.0)-(?:amazon-corretto|ibm|zulu)[-a-z]*|zulu\d{1,2}[-a-z]*)$', re.I)


def _token(text):
    return re.sub(r'[^a-z0-9]', '', str(text or '').lower())


def is_runtime_item(item):
    """Whether one affected entry of a CVE names the Java runtime (``RUNTIME_PRODUCTS`` with its vendor rule, or a distribution's runtime
    package: ``java-17-openjdk``, ``openjdk-17``)."""
    if not isinstance(item, dict):
        return False
    vendor = _token(item.get('vendor'))
    for key in ('product', 'package', 'packageName'):
        token = _token(item.get(key))
        if token in RUNTIME_PRODUCTS:
            hints = RUNTIME_PRODUCTS[token]
            if hints is None or any(h in vendor for h in hints):
                return True
        if key != 'product' and _RUNTIME_PACKAGE.match(str(item.get(key) or '').strip()):
            return True
    return False


_RUNTIME_TOKEN = re.compile(r'^(?:java(?:\d{1,2}|180)openjdk\w*|openjdk\d{1,2}\w*|temurin\d{1,2}j[dr][ke])$')


def index_has_runtime(product_index):
    """Whether a correlation product index holds a CVE that names the Java runtime (by product or by a distribution's runtime package)."""
    return any(token in RUNTIME_PRODUCTS or _RUNTIME_TOKEN.match(token) for token in product_index)


def runtime_items(cve):
    return [item for item in (cve.affected or []) if is_runtime_item(item)]


def java_cves(cve_by_id):
    """The CVEs of a pool whose affected products name the Java runtime, memoised per pool."""
    memo = _JAVA_POOL
    if memo.get('id') != id(cve_by_id) or memo.get('size') != len(cve_by_id):
        memo.update(id=id(cve_by_id), size=len(cve_by_id), cves=[c for c in cve_by_id.values() if runtime_items(c)])
    return memo['cves']


_JAVA_POOL = {}


def _dotted_ranges(ranges):
    out = []
    for rng in ranges or []:
        if not isinstance(rng, dict):
            continue
        out.append({**rng, **{k: java.dotted(str(rng[k])) for k in ('introduced', 'fixed', 'lastAffected') if rng.get(k) not in (None, '')}})
    return out


def affected_lines(items):
    """``(intervals, bounded)``: the major lines the CVE's runtime entries cover, as inclusive ``(low, high)`` pairs (None: open), and whether any
    range has a usable bound. A fix at ``18.0.0`` ends the line before 18."""
    from cveFeed.correlation import _bounded, prepared_ranges
    intervals, bounded = [], False
    for item in items:
        for rng in prepared_ranges(_dotted_ranges(item.get('ranges'))):
            if not _bounded(rng):
                continue
            bounded = True
            low = java.major_of(rng.get('introduced') or '') if rng.get('introduced') not in (None, '', '0') else None
            high = None
            if rng.get('lastAffected'):
                high = java.major_of(rng['lastAffected']) or None
            elif rng.get('fixed'):
                fixed = java.normalize_version(rng['fixed'])
                if fixed:
                    tail = [int(x) for x in re.findall(r'\d+', fixed['version'])[1:]]
                    high = fixed['major'] - 1 if not any(tail) else fixed['major']
            intervals.append((low or None, high))
    return intervals, bounded


def line_affected(major, intervals):
    return any((low is None or major >= low) and (high is None or major <= high) for low, high in intervals)


def verdict(version, items):
    """``(in_range, deciding range)`` of one exact Java version against the CVE's runtime entries, by the same rules as every match
    (``correlation.range_verdict``): True inside a bounded range, False outside every one, None when no bound decides."""
    from cveFeed.correlation import parse_version, range_verdict
    ver = parse_version(java.dotted(version))
    if ver is None:
        return None, None
    unknown = False
    for item in items:
        result, rng, _nolow = range_verdict(ver, _dotted_ranges(item.get('ranges')))
        if result is True:
            return True, rng
        unknown = unknown or result is None
    return (None if unknown else False), None


def _fresh(rows, now):
    cutoff = now - timedelta(days=STALE_DAYS)
    return [r for r in rows if r.last_seen and r.last_seen >= cutoff]


def host_runtimes(sub):
    """The fresh ``JavaRuntime`` rows of a host (one query; ``sub._java_runtimes`` when a caller loaded them for a batch)."""
    rows = getattr(sub, '_java_runtimes', None)
    if rows is None:
        from cveFeed.models import JavaRuntime
        if sub.target_domain_id is None:
            return []
        rows = list(JavaRuntime.objects.filter(project_id=sub.target_domain.project_id, host=sub.name.lower().rstrip('.')))
    return _fresh(rows, timezone.now())


def _inferred_now(subdomain, stored_keys):
    """The inferences of what ``subdomain`` shows now that are not stored yet (``infer`` of its products and versions), as unsaved rows: correlation
    reads them the same way, so a host is judged right before the stage or the catch-up stored them."""
    from cveFeed.models import JavaRuntime
    out, now = [], timezone.now()
    for name, version in host_products(subdomain):
        for key, reading in infer(name, version):
            if key in stored_keys:
                continue
            stored_keys = stored_keys | {key}
            out.append(JavaRuntime(key=key, version=reading['version'], major=reading['major'], vendor=reading['vendor'], line_only=reading['line_only'],
                                   source=reading['source'], confidence=reading['confidence'], detail=reading.get('detail') or {}, last_seen=now))
    return out


def _reading_text(row):
    what = row.version if not row.line_only else f'the {row.major} line'
    return f'{what} ({row.vendor}, {row.source.replace("_", " ")}, {row.confidence})'


def _distro_info(row, host):
    """The distribution of an exact reading made by a distribution's build (Red Hat, Debian, Ubuntu), as correlation's distro info, or None."""
    from cveFeed import distro as distro_lib
    family = java.DISTRO_VENDORS.get(row.vendor)
    if not family:
        return None
    major = row.major
    if family == 'rhel':
        package = 'java-1.8.0-openjdk' if major == 8 else f'java-{major}-openjdk'
        release = (host or {}).get('release', '') if (host or {}).get('distro') in distro_lib.RHEL_FAMILY else ''
    else:
        package = f'openjdk-{major}'
        release = ''
    return {'distro': family, 'release': release, 'package': package, 'package_release': '', 'upstream_version': java.dotted(row.version),
            'basis': 'java-vendor'}


def collect_matches(subdomain, cve_by_id, rows, scan_history=None, min_confidence=0.0, fix_lookup=None, host_distro=None):
    """Append the Java runtime matches of ``subdomain`` to ``rows`` (see the module docstring). Returns how many."""
    from cveFeed import distro as distro_lib
    from cveFeed.correlation import BACKPORT_CONFIDENCE, confidence_for, distro_fix_evidence, parse_version
    cves = java_cves(cve_by_id)
    if not cves:
        return 0
    runtimes = host_runtimes(subdomain)
    runtimes = runtimes + _inferred_now(subdomain, {r.key for r in runtimes})
    if not is_java_host(subdomain, runtimes):
        return 0
    exact = [r for r in runtimes if r.confidence == 'exact' and not r.line_only and r.version]
    lines = sorted({r.major for r in runtimes if r.confidence == 'exact' and r.line_only and r.major})
    floor = max([r.major for r in runtimes if r.source == 'jenkins_minimum'] or [0])
    inferred = [r for r in runtimes if r.confidence in ('inferred', 'weak') and r.source != 'jenkins_minimum']
    found = 0
    for cve in cves:
        items = runtime_items(cve)
        intervals, bounded = affected_lines(items)
        base = {'source': MATCH_SOURCE, 'java': [{'version': r.version, 'major': r.major, 'vendor': r.vendor, 'source': r.source,
                                                  'confidence': r.confidence, 'port': r.port, 'url': r.url[:120], 'line_only': r.line_only}
                                                 for r in runtimes][:10]}
        row = None
        if exact:
            results = [(r, *verdict(r.version, items)) for r in exact]
            hit = next(((r, rng) for r, result, rng in results if result is True), None)
            if hit is None:
                if all(result is False for _r, result, _rng in results):
                    continue  # every runtime read on the host is outside the range: no match
                if not cve.kev:
                    continue  # no bound decides, and only an actively exploited CVE is kept without one (match_policy)
                r = exact[0]
                row = _row(cve, subdomain, scan_history, r.version, None, UNKNOWN_CONFIDENCE,
                           {**base, 'raw_version': r.version, 'unbounded': True, 'reading': _reading_text(r)})
            else:
                r, rng = hit
                confidence = confidence_for(parse_version(java.dotted(r.version)), True, cve.kev)
                status, fixed, fix = distro_lib.NO_DATA, '', None
                info = _distro_info(r, host_distro)
                if info and fix_lookup:
                    rows_for = fix_lookup(distro_lib.fix_distro(info['distro']), info['package'], getattr(cve, 'cve_id', ''))
                    status, fixed, fix_row = distro_lib.judge_row(info, rows_for)
                    fix = distro_fix_evidence(info, fix_row, fixed)
                    if status == distro_lib.PATCHED:
                        confidence = 0.2
                    elif status == distro_lib.VULNERABLE:
                        confidence = 0.95
                    elif status in (distro_lib.BACKPORT, distro_lib.UNKNOWN):
                        confidence = min(confidence, BACKPORT_CONFIDENCE)
                evidence = {**base, 'raw_version': r.version, 'range': rng or {}, 'reading': _reading_text(r), 'java_source': r.source,
                            'port': r.port, **({'distro': {k: v for k, v in info.items() if v}} if info else {}), **({'distro_fix': fix} if fix else {})}
                row = _row(cve, subdomain, scan_history, r.version, True, confidence, evidence, status=status, fixed=fixed)
        else:
            if not bounded and not cve.kev:
                continue
            possible = lines or None
            if possible and bounded and not any(line_affected(m, intervals) for m in possible):
                continue  # the host states a Java line the CVE does not affect
            if floor and bounded and not any(high is None or high >= floor for _low, high in intervals):
                continue  # every affected line is older than the oldest Java this Jenkins starts on
            confidence, note = UNKNOWN_CONFIDENCE, ''
            judged = [(r, *verdict(r.version, items)) for r in inferred if r.version and not r.line_only]
            inside = [r for r, result, _rng in judged if result is True]
            outside = [r for r, result, _rng in judged if result is False]
            weak_lines = [r for r in inferred if r.line_only]
            if inside:
                confidence, note = INFERRED_IN_RANGE_CONFIDENCE, f'inferred {_reading_text(inside[0])} is inside the affected range'
            elif outside:
                confidence = INFERRED_OUT_CONFIDENCE
                note = f'inferred {_reading_text(outside[0])} is outside the affected range: affected only if that runtime was replaced'
            elif weak_lines and bounded:
                majors = [r.major for r in weak_lines]
                note = ('the vendor\'s supported Java line ' + ', '.join(str(m) for m in majors)
                        + (' is among the affected lines' if any(line_affected(m, intervals) for m in majors) else ' is not among the affected lines'))
            evidence = {**base, 'java_unknown': True, 'raw_version': '', 'affected_lines': [[lo, hi] for lo, hi in intervals][:20],
                        **({'java_lines': lines} if lines else {}), **({'java_floor': floor} if floor else {}), **({'java_note': note} if note else {}),
                        **({'unbounded': True} if not bounded else {})}
            row = _row(cve, subdomain, scan_history, '', None, confidence, evidence)
        if row is None or row['confidence'] < min_confidence or row['confidence'] <= 0.0:
            continue
        rows.append(row)
        found += 1
    return found


def _row(cve, subdomain, scan_history, version, in_range, confidence, evidence, status='no_data', fixed=''):
    return {'cve_entry_id': cve.id, 'subdomain_id': subdomain.id, 'source': MATCH_SOURCE, 'matched_product': MATCHED_PRODUCT,
            'matched_version': (version or '')[:100], 'version_in_range': in_range, 'confidence': confidence,
            'scan_history_id': scan_history.id if scan_history else subdomain.scan_history_id, 'distro_status': status,
            'distro_fixed_version': (fixed or '')[:64], 'evidence': evidence}


def java_host_ids(base_qs):
    """The ids of the Subdomain rows of ``base_qs`` where Java is clear: a stored reading, or a technology or port product that runs on a JVM. For
    the candidate hosts of a runtime CVE (``correlation.candidate_subdomains``). The host search's ``tech:java`` (and ``java:any``) reads the
    same products through ``cveFeed.tech_search``'s Java entry (``data/runs_on.json``)."""
    from django.db.models import Exists, OuterRef, Q
    from cveFeed.models import JavaRuntime
    from startScan.models import IpAddress, Subdomain, Technology
    pattern = JAVA_PRODUCT_RE.pattern.replace(r'\b', r'\y')  # PostgreSQL's word boundary
    tech_ids = Technology.objects.filter(name__iregex=pattern).values('id')
    by_tech = Subdomain.technologies.through.objects.filter(technology_id__in=tech_ids).values('subdomain_id')
    ips = IpAddress.ports.through.objects.filter(port__product__iregex=pattern).values('ipaddress_id')
    by_port = Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values('subdomain_id')
    readings = JavaRuntime.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'))
    return base_qs.filter(Q(id__in=by_tech) | Q(id__in=by_port) | Q(Exists(readings))).values('id')


# ----------------------------------------------------------------------------- what the host payload and the search show

def as_dict(row):
    """One reading as the host payload (REST and MCP ``java_runtimes``) and the host page show it. ``evidence`` is what the host said: untrusted text."""
    detail = row.detail if isinstance(row.detail, dict) else {}
    return {'version': row.version, 'major': row.major, 'vendor': row.vendor, 'runtime': row.runtime, 'line_only': row.line_only,
            'source': row.source, 'confidence': row.confidence, 'port': row.port or None, 'url': row.url, 'evidence': row.evidence,
            'basis': detail.get('basis', ''), 'citation': detail.get('source', ''), 'product': detail.get('product', ''),
            'minimum': detail.get('minimum'), 'first_seen': row.first_seen.isoformat() if row.first_seen else None,
            'last_seen': row.last_seen.isoformat() if row.last_seen else None,
            'stale': bool(row.last_seen and row.last_seen < timezone.now() - timedelta(days=STALE_DAYS))}


_ORDER = {'exact': 0, 'inferred': 1, 'weak': 2}


def runtimes_for(project_ids, hosts):
    """``{(project id, host): [as_dict]}`` for a page of hosts, exact readings first (one query)."""
    from cveFeed.models import JavaRuntime
    out = {}
    if not hosts:
        return out
    rows = JavaRuntime.objects.filter(project_id__in=list(project_ids), host__in=list(hosts)).order_by('host', '-last_seen')
    for row in rows:
        out.setdefault((row.project_id, row.host), []).append(row)
    return {key: [as_dict(r) for r in sorted(rows, key=lambda r: (_ORDER.get(r.confidence, 3), -r.major))][:20] for key, rows in out.items()}


def search_rows(value):
    """The ``JavaRuntime`` rows a ``java:`` search value names: a line (``java:17``), a version (``java:17.0.9``, ``java:8u392``, ``java:1.8.0_392``;
    a dotted prefix also finds the releases under it: ``java:17.0`` finds 17.0.9), ``any``, a vendor (``java:temurin``) or a source
    (``java:jdwp``). ``None`` for a value it cannot read."""
    from django.db.models import Q

    from cveFeed.models import JavaRuntime
    text = (value or '').strip().lower()
    if not text:
        return None
    rows = JavaRuntime.objects.all()
    if text in ('any', 'yes', 'all'):
        return rows
    if text in JavaRuntime.SOURCES or text in JavaRuntime.CONFIDENCES:
        return rows.filter(Q(source=text) | Q(confidence=text))
    if re.fullmatch(r'\d{1,2}', text):
        return rows.filter(major=int(text))
    if re.fullmatch(r'(?:[2-9]|[1-9]\d)(?:\.\d{1,5}){1,3}', text):  # a dotted release or a prefix of one: 17.0 finds 17.0.9, never 17.01
        return rows.filter(Q(version=text) | Q(version__startswith=text + '.'))
    norm = java.normalize_version(text)
    if norm is not None:
        version = norm['version']
        if norm['line_only']:
            return rows.filter(major=norm['major'])
        return rows.filter(Q(version=version) | Q(version__startswith=version + '.'))
    vendor = next((v for v in java.VENDORS if text in v.lower()), None)
    if vendor:
        return rows.filter(vendor=vendor)
    return None


# ----------------------------------------------------------------------------- the catch-up after an update, and new CVEs

def runtime_cves_among(pks, exclude=()):
    """The stored CVEs among ``pks`` that name the Java runtime (not rejected, not local only), less ``exclude``: a CVE in the runtime is
    correlated the moment it is ingested, whatever its heat (``tasks.auto_fire_new_cves``)."""
    from cveFeed.correlation import _CVE_FIELDS, clean_affected
    from cveFeed.models import CVEEntry
    pks = [pk for pk in (pks or ()) if pk not in set(exclude)]
    if not pks:
        return []
    rows = list(CVEEntry.objects.filter(pk__in=pks).exclude(status__iregex=r'reject|withdrawn|merged|superseded').exclude(local_only=True).only(*_CVE_FIELDS))
    for row in rows:
        row.affected = clean_affected(row.affected)
    return [row for row in rows if runtime_items(row)]


def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_java_runtimes --apply``, an upgrade backfill): for every current host where Java is
    clear, store the readings it gives away without a request (``refresh_host``: an nmap JDWP port and its exposure finding, a stored header, the
    runtime its product version bundles), then correlate those hosts against the stored runtime CVEs. The active reads are the work planner's (the
    ``java-runtime`` check is due on every such host that never had it). Idempotent. Returns ``{'hosts', 'readings', 'matches'}``."""
    from cveFeed import correlation
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    ids = list(Subdomain.objects.filter(id__in=java_host_ids(base)).order_by('id').values_list('id', flat=True))
    out = {'hosts': len(ids), 'readings': 0, 'matches': 0}
    if not apply or not ids:
        return out
    cve_by_id, _index = correlation.cve_pool()
    pool = {c.id: c for c in java_cves(cve_by_id)}
    index = correlation.build_product_index(pool.values())
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        for sub in subs:
            try:
                out['readings'] += len(refresh_host(sub))
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('Java runtime catch-up of host %s failed', sub.pk)
        if pool:
            out['matches'] += correlation.correlate_subdomains(subs, index, pool, min_confidence=0.4)[1]
    return out
