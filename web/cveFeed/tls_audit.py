"""TLS configuration audit: schedules the audit of each TLS port on a Sentinel and stores what the Sentinel reports.

``hygiene`` reads a server's certificate and checks whether it still accepts TLS 1.0 / 1.1. The TLS audit tests what a handshake cannot show: the
protocols and cipher categories a server offers, forward secrecy, renegotiation, and the TLS vulnerabilities that have names (Heartbleed, CCS
injection, ROBOT, POODLE, FREAK, DROWN, Logjam, SWEET32, Ticketbleed, RC4, CRIME, Winshock and the rest). The test itself runs on a Sentinel (task kind
``testssl``, never on this server: ``agentapi.sentinel_dispatch.NEVER_LOCAL``); this module chooses the targets, hands each to a Sentinel
(``agentapi.sentinel_dispatch.try_testssl``) and reads the report items that come back through ``evaluate()``. With no scanner able to take the work
the sweep waits and the targets stay due.

This is a slow, polite background sweep, never part of a scan: one target at a time, the longest-waiting first, at most
``CVENGINE_TESTSSL_MAX_TARGETS`` per run, one sweep at a time, and it stops when scans are paused. Each target is tested at its newest stored
address that a scanner may touch (``_address``); this server looks no name up, and the Sentinel judges that address again before it connects.

What it records:

* configuration findings (``HygieneFinding``, check names ``tlsa_*``): SSLv2/SSLv3 offered, NULL, anonymous, export, low-strength and
  3DES ciphers, no forward secrecy, insecure renegotiation, and every named vulnerability the report gives as vulnerable or
  potentially vulnerable. A finding resolves only when a later test of the same port ran and no longer reports it. A listener that
  completes no handshake with any protocol gets one low "TLS listener does not negotiate" finding (``tlsa_no_handshake``) in place of its
  cipher results, and a fallback test whose downgraded handshake never completed (a refusal without the standard alert) is no finding;
* a durable ``ProbeObservation`` per vulnerability test (kind ``tls-vuln``), found or absent, which is the evidence;
* hard CVE evidence: a vulnerability the audit proved (Heartbleed answered with memory, a ROBOT oracle, an accepted export cipher)
  is a ``CVEMatch`` (source ``testssl``, ``template_result`` ``vulnerable``) for each CVE the test names. A later test that finds it
  gone closes it; a rescan's new host row gets it back from the stored observation until then.

Tests that could not run or came back inconclusive change nothing.

How a finding reads (``build_finding``, with ``tls_catalogue`` holding what each test means, how to confirm it and how to fix it):

* A result is **proven** when the test answered plainly VULNERABLE (or a configuration result states a direct observation); its title reads
  "OpenSSL CCS injection (CVE-2014-0224) confirmed on host:port". A "likely", "probably", "seems" or "potentially" result is a heuristic: its title
  reads "Possible OpenSSL CCS injection (CVE-2014-0224) on host:port, not confirmed", its confidence is ``unconfirmed``, its severity is at most
  Medium whatever testssl.sh rated it (kept in ``evidence['testssl_severity']``), and it is never hard evidence for the AI triage.
* The description is one plain sentence; testssl.sh's own string is evidence (``evidence['result']``, shown as "testssl.sh output").
* A proven result is rated at testssl.sh's severity held to a ceiling per test (``tls_catalogue.CATALOGUE[...].ceiling``): Heartbleed Critical,
  CCS injection, ROBOT, FREAK, DROWN, Logjam and Ticketbleed High, the rest Medium or Low.
* ``rewrite_open`` says the same about the findings already stored (the upgrade backfill ``rewrite_tls_findings``)."""
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import timedelta

from django.utils import timezone

from cveFeed import tls_catalogue

logger = logging.getLogger(__name__)

SERVICE = 'testssl'
FAILED_SERVICE = 'testssl-failed'  # a target that could not be tested: asked again in three days, not at every sweep
PROBE = 'testssl'
OBS_VULN = 'tls-vuln'
OBS_AUDIT = 'tls-audit'
SOURCE = 'testssl'  # CVEMatch.source
QUEUE = 'testssl_queue'
DEFAULT_MAX_TARGETS = 40
FRESH_DAYS = 21  # an observation older than this is not carried onto a new scan's host row

STARTTLS_PORTS = {25: 'smtp', 587: 'smtp', 143: 'imap', 110: 'pop3', 21: 'ftp', 389: 'ldap'}
IMPLICIT_PORTS = (443, 8443, 9443, 993, 995, 465, 636)

SEVERITY = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
LEVELS = ('info', 'low', 'medium', 'high', 'critical')

# Vulnerability tests: testssl id -> (name, whether a "VULNERABLE" result is proof strong enough to be CVE evidence). BEAST, LUCKY13 and
# BREACH are findings only: they are mitigated by modern clients or depend on the application, so they never become a CVE match.
VULNS = {
    'heartbleed': ('Heartbleed', True), 'CCS': ('CCS injection', True), 'ticketbleed': ('Ticketbleed', True), 'ROBOT': ('ROBOT', True),
    'secure_client_renego': ('Client-initiated renegotiation', True), 'CRIME_TLS': ('CRIME (TLS compression)', True),
    'POODLE_SSL': ('POODLE (SSLv3)', True), 'POODLE_TLS': ('POODLE (TLS)', True), 'FREAK': ('FREAK', True), 'DROWN': ('DROWN', True),
    'LOGJAM': ('Logjam', True), 'winshock': ('Winshock', True), 'SWEET32': ('SWEET32', True), 'RC4': ('RC4 ciphers', True),
    'BEAST': ('BEAST', False), 'LUCKY13': ('Lucky13', False), 'BREACH': ('BREACH', False),
}
# Configuration tests: testssl id -> what the finding says. Reported at testssl.sh's own severity, low and up.
CONFIG = {
    'SSLv2': 'offers SSLv2', 'SSLv3': 'offers SSLv3', 'cipherlist_NULL': 'offers NULL ciphers (no encryption)',
    'cipherlist_aNULL': 'offers anonymous ciphers (no authentication)', 'cipherlist_EXPORT': 'offers export-grade ciphers',
    'cipherlist_LOW': 'offers low-strength ciphers', 'cipherlist_3DES_IDEA': 'offers 3DES or IDEA ciphers',
    'secure_renego': 'does not support secure renegotiation', 'FS': 'does not offer forward secrecy',
    'fallback_SCSV': 'does not support TLS_FALLBACK_SCSV', 'DH_groups': 'uses weak Diffie-Hellman parameters',
}
GOOD = re.compile(r'^(not vulnerable|not offered|supported|ok\b)', re.I)
PROTOCOL_IDS = ('TLS1', 'TLS1_1', 'TLS1_2', 'TLS1_3', 'SSLv2', 'SSLv3')
# A listener that completes no handshake at all (every protocol "not offered"): testssl.sh still reports "no forward secrecy" and the other
# cipher tests as failed, which says nothing about a cipher setup. It gets this one finding instead.
NO_HANDSHAKE = 'tlsa_no_handshake'
# testssl.sh's fallback test when the downgraded handshake was refused without the standard alert: no downgraded session was established
FALLBACK_REFUSED = re.compile(r"handshake.?failure|no cipher|did ?n[o']t complete|never completes?|aborted|connection (?:was )?(?:closed|reset)", re.I)


class TlsAuditError(RuntimeError):
    """The target could not be audited (no connection, a timeout, no usable report)."""


def max_targets():
    try:
        return max(1, int(os.environ.get('CVENGINE_TESTSSL_MAX_TARGETS', DEFAULT_MAX_TARGETS)))
    except ValueError:
        return DEFAULT_MAX_TARGETS


# ----------------------------------------------------------------------------- reading the result

@dataclass
class Result:
    findings: list = field(default_factory=list)  # [{'check', 'severity', 'title', 'detail', 'evidence'}]
    vulnerable: dict = field(default_factory=dict)  # testssl id -> {'cves', 'finding', 'severity'}: proven, CVE evidence
    cleared: set = field(default_factory=set)  # testssl ids of the tests that ran and found the target not vulnerable
    inconclusive: set = field(default_factory=set)  # check names whose test did not give an answer: left as they were
    protocols: dict = field(default_factory=dict)  # 'TLS1_2' -> 'offered'
    tested: bool = False  # the run answered at least one test


def check_name(test_id):
    return ('tlsa_' + re.sub(r'[^a-z0-9]+', '_', test_id.lower()).strip('_'))[:40]


def _cves(item):
    return sorted({c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,}', str(item.get('cve') or ''), re.I)})


def evaluate(items, where):
    """Turn a testssl.sh report into findings, proven vulnerabilities and cleared tests. ``where`` is ``host:port``."""
    result = Result()
    for item in items:
        test_id, level, text = str(item['id']), str(item.get('severity') or '').upper(), ' '.join(str(item.get('finding') or '').split())
        if test_id in PROTOCOL_IDS:
            result.protocols[test_id] = 'offered' if text.lower().startswith('offered') else 'not offered'
        if test_id not in VULNS and test_id not in CONFIG:
            continue
        name = check_name(test_id)
        sev = SEVERITY.get(level, 0)
        if level in ('WARN', 'FATAL', 'DEBUG') or not text or text.lower().startswith('test failed'):
            result.inconclusive.add(name)  # the test did not run to an answer: neither proof nor all-clear
            continue
        result.tested = True
        if test_id in VULNS:
            _, hard = VULNS[test_id]
            if GOOD.match(text) and sev == 0:
                result.cleared.add(test_id)
                continue
            if sev == 0:
                result.inconclusive.add(name)
                continue
            finding = build_finding(test_id, level, text, where, _cves(item))
            if finding['evidence']['proven']:
                result.vulnerable[test_id] = {'cves': finding['evidence']['cve'], 'finding': text[:300], 'severity': finding['severity']}
            result.findings.append(finding)
        else:
            if sev == 0:
                continue
            if test_id == 'fallback_SCSV' and FALLBACK_REFUSED.search(text):
                continue  # the downgraded handshake never completed: the server refuses the downgrade, only without the standard alert
            result.findings.append(build_finding(test_id, level, text, where, _cves(item)))
    if negotiates_nothing(result):
        _no_handshake(result, where)
    return result


def build_finding(test_id, level, text, where, cves):
    """The finding of one testssl.sh result that is a problem (``level`` its own severity word, ``text`` its result string, ``where`` ``host:port``):
    ``{'check', 'severity', 'title', 'detail', 'evidence'}``. Used for a fresh report and to rewrite a stored finding (``rewrite_open``), so both say
    the same thing.

    * The title says how sure it is: "... confirmed on host:port" for a proven result, "Possible ... on host:port, not confirmed" for a heuristic.
    * The detail is one plain sentence (``tls_catalogue.describe_result``); testssl.sh's own string is kept in ``evidence['result']``.
    * A result that is not proven is never above Medium. testssl.sh's own severity stays in ``evidence['testssl_severity']``.
    * A configuration result (a protocol or cipher category offered) is a direct observation: it keeps testssl.sh's severity, held to the test's
      ceiling (insecure renegotiation is Medium, not the Critical testssl.sh gives it)."""
    name = check_name(test_id)
    sev = SEVERITY.get(str(level).upper(), 0)
    text = ' '.join(str(text or '').split())
    host, port = tls_catalogue.split_where(where)
    base = {'source': 'testssl.sh', 'test': test_id, 'result': text[:300], 'testssl_severity': tls_catalogue.SEVERITY_WORDS.get(sev, 'info'),
            'host': host, 'port': port}
    if test_id in VULNS:
        _, hard = VULNS[test_id]
        state, severity = tls_catalogue.assess(test_id, text, sev, hard)
        proven = state == tls_catalogue.PROVEN
        title = tls_catalogue.title_for(test_id, state, where)
        base.update(cve=list(cves)[:20], proven=proven, state=state, confidence=tls_catalogue.confidence_of(state))
    else:
        entry = tls_catalogue.CATALOGUE[test_id]
        severity = min(sev, entry.ceiling)
        title = f'{where} {CONFIG[test_id]}'
        base.update(proven=True, state=tls_catalogue.PROVEN, confidence=tls_catalogue.CONFIRMED)
        if entry.cves:
            base['cve'] = list(entry.cves)[:20]
    return {'check': name, 'severity': severity, 'title': title, 'detail': tls_catalogue.describe_result(test_id, text), 'evidence': base}


def negotiates_nothing(result):
    """True when the report tested the protocols and the listener offered none of them: it completed no TLS handshake."""
    return bool(result.protocols) and not any(v == 'offered' for v in result.protocols.values())


def _no_handshake(result, where):
    """A listener that negotiates nothing: its cipher findings ("no forward secrecy" and the like) are artefacts of no handshake, so they
    give way to one low finding that says so. A proven vulnerability stays (it needed an answer from the server)."""
    proven = {check_name(test_id) for test_id in result.vulnerable}
    result.findings = [f for f in result.findings if f['check'] in proven]
    # testssl prints "not vulnerable" for the vulnerability tests of a listener it could not talk to: nothing was tested, so nothing is cleared. A test
    # that is not cleared closes no earlier proven match (``run_for_host`` closes only what an ``absent`` observation names).
    result.inconclusive |= {check_name(test_id) for test_id in result.cleared}
    result.cleared = set()
    result.inconclusive -= {check_name(test_id) for test_id in CONFIG}  # an earlier cipher finding of this port resolves: it never applied
    tested = ', '.join(f'{k}: {v}' for k, v in sorted(result.protocols.items()))
    result.findings.append({
        'check': NO_HANDSHAKE, 'severity': SEVERITY['LOW'], 'title': f'{where}: TLS listener does not negotiate',
        'detail': ('The port accepts a connection but completes no TLS handshake with any protocol version for this server name, so no cipher '
                   'or forward-secrecy result applies. A stale mapping (a CNAME to a service that no longer serves this name) or a listener '
                   'that is not TLS looks like this. Fix: remove the name or the listener, or serve a certificate for the name.'),
        'evidence': {'source': 'testssl.sh', 'test': 'protocols', 'result': tested[:300], 'protocols': dict(result.protocols)}})


# ----------------------------------------------------------------------------- storing it

def record_observations(project_id, domain_id, host, port, result, ip):
    """The durable record of one tested port: one observation per vulnerability test (found or absent) and one summary."""
    from cveFeed import probes
    now = timezone.now()
    host = host.lower()
    rows = []

    def upsert(kind, product, outcome, evidence):
        rows.append(({'project_id': project_id, 'host': host, 'probe': PROBE, 'port': port, 'kind': kind, 'product': product},
                     {'domain_id': domain_id, 'outcome': outcome, 'confidence': 0.95 if outcome == 'found' else 0.0, 'source': 'testssl.sh',
                      'evidence': evidence, 'observed_at': now}))
    for test_id, found in result.vulnerable.items():
        upsert(OBS_VULN, test_id, 'found', {'cves': found['cves'][:20], 'finding': found['finding'], 'ip': ip})
    for test_id in result.cleared:
        upsert(OBS_VULN, test_id, 'absent', {'ip': ip})
    upsert(OBS_AUDIT, '', 'found', {'protocols': result.protocols, 'issues': len(result.findings), 'ip': ip})
    probes.upsert_many(rows)  # one read and batched writes; a test found again unchanged only has its observed_at moved


def store_banners(sub, port, items):
    """The Server and application headers testssl.sh read on the port (its ``banner_server`` and ``banner_application`` items), stored as version
    readings of the host (cveFeed.source_versions, probe ``vsrc:testssl``); the host is correlated again when one is new, changed or gone. Never fatal."""
    from cveFeed import probes, source_versions
    try:
        if source_versions.store_testssl(sub, port, items):
            probes.recorrelate(sub)
    except Exception:  # noqa: BLE001 - the audit's own result stands without the banner readings
        logger.exception('could not store the testssl.sh banners of %s:%s', getattr(sub, 'name', ''), port)


def store(domain, host, port, result, where):
    """Upsert this port's findings; resolve the ones the test ran for and no longer reports. Returns the rows resolved."""
    from cveFeed.hygiene import Finding, store_findings
    found = [Finding(f['check'], f['severity'], f['title'], f['detail'], where, f['evidence']) for f in result.findings]
    skip = result.inconclusive
    return store_findings(domain, found, hosts={where}, owns=lambda check: check.startswith('tlsa_') and check not in skip, live_cnames=True)


# ----------------------------------------------------------------------------- rewriting what is stored

REWRITE_LIMIT = 20000  # rows one run reads: the open TLS audit findings of an install are a few thousand at most


def confidence_of(check, evidence, severity=0):
    """``'confirmed'``, ``'unconfirmed'`` or ``''`` (not a testssl.sh finding) for a stored ``tlsa_*`` hygiene finding. The finding's own record
    says (``evidence['confidence']``); one stored before that was recorded is judged again from its test and result string, so the triage rule
    (``triage.hard_evidence``) holds for it before the rewrite has run."""
    ev = evidence if isinstance(evidence, dict) else {}
    if not str(check or '').startswith('tlsa_') or ev.get('source') != 'testssl.sh':
        return ''
    if ev.get('confidence') in (tls_catalogue.CONFIRMED, tls_catalogue.UNCONFIRMED):
        return ev['confidence']
    test_id = ev.get('test')
    if test_id in VULNS:
        rating = ev.get('rating') if isinstance(ev.get('rating'), dict) else {}
        sev = rating.get('from') if isinstance(rating.get('from'), int) else severity
        state, _ = tls_catalogue.assess(test_id, str(ev.get('result') or ''), sev, VULNS[test_id][1])
        return tls_catalogue.confidence_of(state)
    return tls_catalogue.CONFIRMED if test_id in CONFIG else ''


def rebuilt(row):
    """What an open ``tlsa_*`` finding says now, from the evidence it stored: ``(severity, title, detail, evidence)``, or None when it holds no
    testssl.sh result to rebuild from. testssl.sh's own severity is the one it recorded (``evidence['testssl_severity']``), else the one the
    finding was rated from before an endpoint rule lowered it (``rating.from``), else the stored one; a severity an endpoint rule lowered
    (``hygiene_rating``) stays lowered."""
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    test_id, text = ev.get('test'), str(ev.get('result') or '')
    if ev.get('source') != 'testssl.sh' or (test_id not in VULNS and test_id not in CONFIG) or not text:
        return None
    rating = ev.get('rating') if isinstance(ev.get('rating'), dict) else {}
    if ev.get('testssl_severity') in LEVELS:
        sev = LEVELS.index(ev['testssl_severity'])
    else:
        sev = rating['from'] if isinstance(rating.get('from'), int) else row.severity
    cves = ev.get('cve') if isinstance(ev.get('cve'), list) else []
    new = build_finding(test_id, LEVELS[min(max(sev, 0), 4)].upper(), text, row.host, [str(c) for c in cves])
    severity = min(new['severity'], row.severity) if rating else new['severity']
    return severity, new['title'][:300], new['detail'], {**ev, **new['evidence']}


def rewrite_open(apply=False, limit=REWRITE_LIMIT):
    """Say the open TLS audit findings the way ``evaluate`` does now (plain detail, a title that states the confidence, the severity cap, the
    confidence in the evidence), from their stored evidence and with no new test. Idempotent: a finding already worded this way is not touched.
    Bounded: at most ``limit`` open rows are read, in id order. A resolved finding is left as it was; so are a person's status, assignee and
    notes. Nothing is written unless ``apply``. Returns ``{'rows', 'changed', 'lowered'}``; the touched hosts are rescored."""
    from cveFeed import scoring
    from cveFeed.models import HygieneFinding
    out = {'rows': 0, 'changed': 0, 'lowered': 0}
    touched = {}
    rows = (HygieneFinding.objects.filter(status='open', check_name__startswith='tlsa_').exclude(check_name=NO_HANDSHAKE)
            .select_related('domain').order_by('id')[:max(1, int(limit))])
    for row in rows:
        out['rows'] += 1
        new = rebuilt(row)
        if new is None:
            continue
        severity, title, detail, evidence = new
        if (row.severity, row.title, row.detail, row.evidence) == (severity, title, detail, evidence):
            continue
        out['changed'] += 1
        out['lowered'] += severity < row.severity
        if apply:
            HygieneFinding.objects.filter(pk=row.pk, status='open').update(severity=severity, title=title, detail=detail, evidence=evidence)
            touched.setdefault(row.domain.project_id, set()).add(row.host.lower())
    if apply:
        for project_id, hosts in touched.items():
            hosts = sorted(hosts)
            for i in range(0, len(hosts), scoring.CHUNK):
                scoring.rescore_quietly(project_id, hosts[i:i + scoring.CHUNK])
    return out


# ----------------------------------------------------------------------------- CVE evidence

def _product(port):
    return f'TLS service on port {port}'


def sightings(project_id, host):
    """``[(port, test id, outcome, evidence, observed_at)]`` of the vulnerability observations of ``host`` fresh enough to carry forward."""
    from cveFeed.models import ProbeObservation
    cutoff = timezone.now() - timedelta(days=FRESH_DAYS)
    rows = ProbeObservation.objects.filter(project_id=project_id, host=host.lower(), probe=PROBE, kind=OBS_VULN, observed_at__gte=cutoff)
    return [(r.port, r.product, r.outcome, r.evidence or {}, r.observed_at) for r in rows]


def match_rows(sub, found):
    """CVEMatch rows for the vulnerabilities proven on ``sub``: one per CVE the test names that the catalog knows."""
    from cveFeed.models import CVEEntry
    wanted = {}
    for port, test_id, outcome, evidence, seen in found:
        if outcome != 'found':
            continue
        for cve_id in evidence.get('cves') or []:
            wanted.setdefault(cve_id, []).append((port, test_id, evidence, seen))
    if not wanted:
        return []
    known = {c.cve_id: c for c in CVEEntry.objects.filter(cve_id__in=list(wanted)).exclude(status__iregex=r'reject|withdrawn|merged|superseded').exclude(local_only=True)
             .only('id', 'cve_id')}
    rows = []
    for cve_id, hits in wanted.items():
        cve = known.get(cve_id)
        if cve is None:
            continue
        for port, test_id, evidence, seen in hits:
            rows.append({
                'cve_entry_id': cve.id, 'subdomain_id': sub.id, 'source': SOURCE, 'matched_product': _product(port), 'matched_version': '',
                'version_in_range': True, 'confidence': 0.95, 'scan_history_id': sub.scan_history_id, 'distro_status': 'no_data',
                'distro_fixed_version': '',
                'evidence': {'source': 'testssl.sh', 'test': test_id, 'port': port, 'result': str(evidence.get('finding') or '')[:300],
                             'tested_at': seen.isoformat()}})
    return rows


def run_for_host(sub):
    """Make the CVE matches of ``sub`` agree with the stored TLS observations: record what is proven, close what a later test cleared.
    Never fatal: a failure leaves the observations for the next pass. Returns the number of matches recorded."""
    from cveFeed import correlation
    from cveFeed.models import CVEMatch
    try:
        found = sightings(sub.target_domain.project_id, sub.name)
        rows = match_rows(sub, found)
        correlation.save_matches(rows)
        now = timezone.now()
        for row in rows:
            CVEMatch.objects.filter(subdomain_id=sub.id, cve_entry_id=row['cve_entry_id'], source=SOURCE, matched_product=row['matched_product']).update(
                template_result='vulnerable', template_id=('testssl:' + row['evidence']['test'])[:128], template_tested_at=now)
        cleared = {_product(port) for port, _test, outcome, _ev, _seen in found if outcome == 'absent'} - {r['matched_product'] for r in rows}
        _close_cleared(sub, cleared)
        return len(rows)
    except Exception:  # noqa: BLE001
        logger.exception('could not correlate the TLS results of host %s', sub.pk)
        return 0


def _close_cleared(sub, products):
    """A target that a later test found no longer vulnerable: the match stays as a record, closed, unless a person already works it."""
    from cveFeed.models import CVEMatch
    if not products:
        return 0
    every = CVEMatch.objects.filter(subdomain=sub, source=SOURCE, matched_product__in=products)
    every.update(template_result='no_match', template_tested_at=timezone.now())  # the test result is a fact, whoever works the match
    open_ = every.filter(remediation_status='open', assignee__isnull=True)
    return open_.update(ai_verdict='not_affected', confidence=0.0,
                        ai_reason='Closed automatically: a later testssl.sh test of this service no longer finds it vulnerable.',
                        updated_at=timezone.now())


def carry_forward(scan):
    """Hosts are stored once per scan, so a fresh row has no TLS matches until this runs, even when the sweep is not due again."""
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    cutoff = timezone.now() - timedelta(days=FRESH_DAYS)
    hosts = set(ProbeObservation.objects.filter(project_id=scan.domain.project_id, probe=PROBE, kind=OBS_VULN, outcome='found', observed_at__gte=cutoff)
                .values_list('host', flat=True))
    if not hosts:
        return 0
    return sum(run_for_host(sub) for sub in Subdomain.objects.filter(scan_history=scan, name__in=hosts).select_related('target_domain'))


# ----------------------------------------------------------------------------- choosing targets

def _starttls_of(number):
    return STARTTLS_PORTS.get(number)


def tls_ports(ports):
    """``[(port, starttls)]`` to test for a host whose open ports are ``ports`` (``{number: Port}``): the implicit-TLS and TLS-named ones,
    the STARTTLS ones, and 443 for a host with no port data."""
    wanted = []
    for number, port in sorted(ports.items()):
        name = (port.service_name or '').lower()
        if number in IMPLICIT_PORTS or 'ssl' in name or name.startswith('https'):
            wanted.append((number, None))
        elif number in STARTTLS_PORTS:
            wanted.append((number, _starttls_of(number)))
    if not ports:
        wanted.append((443, None))
    return wanted


def targets(project_id):
    """``[(host, port, starttls, domain_id)]`` for the project's hosts: the TLS ports found open, and 443 for a host with no port data.
    Names a scanner must not be pointed at (excluded, or resolving to a prohibited range) are dropped, and so are the hosts of a target set to
    manual only and the names under a target set to exactly one host."""
    from startScan.models import Subdomain, open_ports
    from targetApp.models import Domain, in_target_scope_q
    from targetApp.target_types import scannable_hosts
    found, seen = [], set()
    rows = (Subdomain.objects.filter(target_domain__project_id=project_id).exclude(target_domain__discovery_mode=Domain.DISCOVERY_MANUAL)  # manual only: never audited on a schedule
            .filter(in_target_scope_q())  # a name kept under a target that is now exactly one host is never audited through it
            .order_by('-id').select_related('target_domain')
            .prefetch_related('ip_addresses__ports'))
    for sub in rows.iterator(chunk_size=500):
        if sub.name in seen:
            continue
        seen.add(sub.name)
        ports = {p.number: p for ip in sub.ip_addresses.all() for p in open_ports(ip)}
        found += [(sub.name, number, starttls, sub.target_domain_id) for number, starttls in tls_ports(ports)]
    allowed = set(scannable_hosts(sorted({t[0] for t in found}), project=project_id))
    return [t for t in found if t[0] in allowed]


def due(project_id, limit=None):
    """The targets whose last test is older than the TTL, never-tested first then longest-waiting, minus those that failed recently."""
    from cveFeed import ledger
    by_asset = {f'{host}:{port}': (host, port, starttls, domain_id) for host, port, starttls, domain_id in targets(project_id)}
    rows = ledger.stale_first(SERVICE, [(0, asset, project_id) for asset in by_asset])
    failed = ledger.fresh(FAILED_SERVICE, [r[1] for r in rows], project_id)
    wanted = [by_asset[r[1]] for r in rows if r[1] not in failed]
    return wanted[:limit] if limit else wanted


# ----------------------------------------------------------------------------- the sweep

def _latest_row(project_id, host):
    from startScan.models import Subdomain
    from cveFeed.manual_only import held_expr
    return (Subdomain.objects.filter(target_domain__project_id=project_id, name=host).select_related('scan_history', 'target_domain')
            .annotate(held=held_expr()).order_by('held', '-scan_history_id').first())


def _address(host, port, project_id):
    """The one address the audit is pinned to (IPv4 first): the host's newest stored address that a scanner may touch (what a Sentinel's passes
    recorded for it). This server looks no name up; the Sentinel judges the address again before testssl.sh connects to it (``scope.check_ip``).
    Raises ``ValueError`` when the host has no such address yet."""
    from targetApp.target_types import is_scannable_ip
    sub = _latest_row(project_id, host)
    addresses = [ip.address for ip in sub.ip_addresses.all() if ip.address] if sub is not None else []
    usable = sorted((a for a in addresses if is_scannable_ip(a, project=project_id)), key=lambda a: ':' in a)
    if not usable:
        raise ValueError('no stored address of this host is one a scanner may use (it is looked up by a Sentinel at the next discovery)')
    return usable[0]


def sweep(project_id, resolve=None):
    """Audit the due targets of one project on a Sentinel, one at a time. Returns ``{'tested', 'failed', 'issues', 'proven'}`` (and ``skipped``
    with the reason when nothing ran). Nothing runs on this server: with no scanner able to take a target it stays due."""
    from cveFeed import activity, exclusions, ledger
    from cvengine import resources
    summary = {'tested': 0, 'failed': 0, 'issues': 0, 'proven': 0}
    from agentapi import scanner_state
    waiting = scanner_state.skip_note('testssl')  # no scanner can run it and this server may not: no dispatch, no raise, no activity line
    if waiting:
        return {**summary, 'skipped': waiting}
    from cveFeed.conductor import bounty_blocked_projects
    if project_id in bounty_blocked_projects():
        return {**summary, 'skipped': 'the bug bounty engagement has not confirmed automated testing'}
    resolve = resolve or _address
    from agentapi import stage_runs
    claim = stage_runs.claim_kwargs('testssl-project', f'testssl-{os.getpid()}')
    with resources.redis_claim(f'cvengine:testssl:{project_id}', claim.pop('owner'), 300, **claim) as holder:
        if holder is not True:
            return {**summary, 'skipped': 'another TLS audit is running for this project'}
        # When a target waits on a Sentinel without the worker (agentapi.stage_runs), the pass that continues the sweep takes the same batch up at
        # the target it stopped at: the ones before it are done
        batch = stage_runs.once(f'testssl:{project_id}:batch', lambda: due(project_id, limit=max_targets()))
        start = stage_runs.recall(f'testssl:{project_id}:at', 0)
        for index, (host, port, starttls, domain_id) in enumerate(batch):
            if index < start:
                continue
            stage_runs.remember(f'testssl:{project_id}:at', index)
            if resources.global_pause_requested(fail_closed=True):
                return {**summary, 'skipped': 'scanning is paused: the targets stay due'}
            sub = _latest_row(project_id, host)
            names = exclusions.excluded_names(project_id)
            if sub is None or (names and exclusions.normalize(host) in names):
                continue
            where, asset = f'{host}:{port}', f'{host}:{port}'
            running = activity.log('run_check', f'TLS audit of {where}', project=project_id, status='running', scan_id=sub.scan_history_id)
            try:
                ip = resolve(host, port, project_id)
                from agentapi import sentinel_dispatch
                items = sentinel_dispatch.try_testssl(sub.target_domain.project, host, ip, port, starttls, scan=sub.scan_history)
                if items is None:  # a Sentinel took it and did not finish: asked again at the next sweep (nothing runs here)
                    activity.settle(running, 'done', message=f'TLS audit of {where} did not finish on a scanner; the target stays due')
                    continue
                result = evaluate(items, where)
                if not result.tested:
                    raise TlsAuditError(_why(items))
            except (resources.ScanAborted, resources.MemoryBusy) as exc:  # stopped, or no scanner: not the target's failure
                if isinstance(exc, resources.ScannerUnavailable):  # a scanner that is offline is not memory pressure
                    activity.settle(running, 'done', message=f'TLS audit of {where} is waiting: no scanner could take this work ({exc.kind}); the target stays due until one can')
                    return {**summary, 'skipped': f'no scanner could take this work ({exc.kind}): the targets stay due until one can'}
                activity.settle(running, 'done', message=f'TLS audit of {where} stopped before it finished ({type(exc).__name__}); the target stays due')
                return {**summary, 'skipped': 'scanning was stopped or memory was short: the targets stay due'}
            except (TlsAuditError, OSError, ValueError) as exc:
                ledger.record(FAILED_SERVICE, [asset], project_id, sub.scan_history)
                summary['failed'] += 1
                activity.settle(running, 'done', message=activity.diagnostic(f'TLS audit of {where}', str(exc)))
                continue
            record_observations(project_id, domain_id, host, port, result, ip)
            store(sub.target_domain, host, port, result, where)
            run_for_host(sub)
            store_banners(sub, port, items)
            ledger.record(SERVICE, [asset], project_id, sub.scan_history)
            summary['tested'] += 1
            summary['issues'] += len(result.findings)
            summary['proven'] += len(result.vulnerable)
            activity.settle(running, 'done', message=(
                f'TLS audit of {where}: {len(result.findings)} issue{"s" if len(result.findings) != 1 else ""}'
                + (f', {len(result.vulnerable)} proven vulnerabilit{"ies" if len(result.vulnerable) != 1 else "y"}' if result.vulnerable else '')))
    return summary


def _why(items):
    for item in items:
        if str(item.get('id')) in ('scanProblem', 'engine_problem', 'service') and item.get('finding'):
            text = str(item['finding'])
            if 'engine' not in text.lower():
                return text[:200]
    return 'the audit could not connect or answered no test'


def sweep_all():
    """Every project's due targets. One sweep at a time; the work is spread over days by ``max_targets`` per run. A target a Sentinel tests is
    waited for without holding the worker (``agentapi.stage_runs``): the sweep's callback goes on with the next one."""
    from cveFeed import ledger
    from agentapi import scanner_state, stage_runs
    waiting = scanner_state.skip_note('testssl')
    if waiting:
        return {'skipped': waiting}
    if stage_runs.enabled() and stage_runs.busy('sweep.testssl'):
        return {'skipped': 'another sweep is running (it waits on a Sentinel)'}
    if not ledger.sweep_claim('testssl', 3 * 60 * 60):
        return {'skipped': 'another sweep is running'}
    return stage_runs.run('sweep.testssl', {}, first=_sweep_projects)


def _resume_sweep(context):
    return _sweep_projects()


def _sweep_projects():
    from dashboard.models import Project
    totals = {'tested': 0, 'failed': 0, 'issues': 0, 'proven': 0}
    for project_id in Project.objects.values_list('id', flat=True):
        part = sweep(project_id)
        for key in totals:
            totals[key] += part.get(key, 0)
        if part.get('skipped', '').startswith('scanning is paused'):
            totals['skipped'] = part['skipped']
            break
    return totals


def _register():
    from agentapi import stage_runs
    stage_runs.adapter('sweep.testssl', queue='testssl_queue')(_resume_sweep)


_register()
