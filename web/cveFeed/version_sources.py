"""Version sources: the exact versions hosts state anonymously from outside, read through one data-driven catalogue
(``cveFeed.version_catalogue``), stored, and matched against CVEs.

What it reads. The catalogue's entries (an application's version endpoint, a platform API's ``/version``, a Prometheus ``/metrics`` page, an
ASP.NET error page) and the headers the scans already stored (a Server header naming Python under Werkzeug, X-Jenkins, Nexus's Server
header, X-AspNet-Version). Nothing is read on this server: the active reads are the Sentinel kind ``version_read`` (contract version 7),
which only fetches the GETs listed and returns the parts of each answer the entry names; this module parses them.

Where readings go. One table, ``ProbeObservation`` (the store of what a probe read about a host), one row per (host, source, port, kind,
product), probe ``vsrc:<entry>`` (``vsrc:passive`` for the readings made from stored headers):

  product   kind ``version``: the reading is also a technology of the host (``Grafana:10.2.3``), so correlation matches it like any product it
            knows (name, aliases, CPE, a distribution's tracker on a Red Hat host), version only: it never proves a version on its own
            (``match_policy.version_read_from_component``), and heat, triage ceilings and the heat cap treat it as every banner.
  runtime   kind ``runtime``: a language runtime (Python, Go, Node.js, PHP, Ruby, .NET Framework, Erlang/OTP), never a technology. Matched here
            (``collect_matches``) against the CVEs whose own record names the runtime by vendor and product (``version_catalogue.RUNTIMES``),
            by the Java runtime's rules: an exact version inside a range is a version match; a line, an inferred reading or a runtime clearly
            present with no version is at most a "runtime of unknown version" candidate (``evidence.runtime_unknown``: needs validation,
            ice, never fire, with the host owner's commands), and never ``version_in_range`` True; a weak presence (``X-Powered-By: ASP.NET``,
            a Go expvar page) matches nothing.
  java      a ``jvm_info`` metric is a Java runtime reading (``cveFeed.java_runtime``, source ``metrics``): the Java family keeps its own table
            and matcher, with the same confidence words and rules.

Exposures. An entry with an ``Exposure`` (the Docker Engine API, etcd's client API, Nomad's API, Envoy's admin interface, the Kubernetes API
server, an anonymous ``/metrics`` or ``/debug/vars``) files a finding (``save_vulnerability``, source ``version-source``) when the answer has
its shape, and closes it when a later complete read shows it gone. A template check's finding that already reports the same exposure on the host
(``Exposure.twins``) is not filed twice.

Gates. A host is asked only when an entry's product shows on it (a technology or a port product) or a port whose number belongs to the entry
answers with a generic service; it passes the organization's exclusions (fail closed), archived hosts, a bug bounty program's scope and, on the
work planner's path, its automated-testing confirmation, the address rules (a host that points at an address a scanner may not use is left
out) and the dispatcher's do-not-scan list. It is a stage of the host pipeline after the Java runtime reads, and the work planner keeps it
going (check ``version-sources``): once a week per host, again after a day when a read failed.
"""
import logging
import os
import re
import secrets
from datetime import timedelta

from django.utils import timezone

from cveFeed import version_catalogue as catalogue

logger = logging.getLogger(__name__)

KIND = 'version_read'                     # the Sentinel task kind
SERVICE = 'version-source'                # the ledger service: one row per host name, a week
FAILED_SERVICE = 'version-source-failed'  # a host whose read could not complete: asked again after a day
MATCH_SOURCE = 'runtime'                  # CVEMatch.source of a runtime match
FINDING_SOURCE = 'version-source'         # Vulnerability.source of an exposure
PROBE_PREFIX = 'vsrc:'
PASSIVE_PROBE = 'vsrc:passive'
RUNTIME_KIND = 'runtime'
MAX_READS_PER_TASK = 100                  # the contract's bound
MAX_ENTRIES_PER_HOST = 6
MAX_BASES_PER_ENTRY = 2
MAX_PER_SCAN = 60                         # hosts one scan sends; the rest are due on the next pass or the work planner's
STALE_DAYS = 90                           # a reading not seen again for this long is not used to match (the Java runtime's rule)
UNKNOWN_CONFIDENCE = 0.4                  # a runtime of unknown version (the correlation floor)
INFERRED_IN_RANGE_CONFIDENCE = 0.5
CONFIDENCE_SCORE = {'exact': 0.95, 'inferred': 0.6, 'weak': 0.3}
GENERIC_SERVICES = re.compile(r'^(?:|unknown|tcpwrapped|http|https|ssl/http|ssl/https|http-proxy|http-alt|https-alt|ssl/unknown|ssl)$')


def enabled():
    return os.environ.get('CVENGINE_VERSION_SOURCES', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def _split(name):
    from cveFeed.correlation import split_name_version
    return split_name_version(name or '')


# ----------------------------------------------------------------------------- which entries a host warrants (pure)

def _port_base(host, port):
    from cveFeed.route_auth import _base
    service = (getattr(port, 'service_name', '') or '').lower()
    tunnel = (getattr(port, 'extra', None) or {}).get('tunnel') if isinstance(getattr(port, 'extra', None), dict) else None
    https = 'https' in service or 'ssl' in service or tunnel == 'ssl' or port.number in (443, 2376, 6443, 8443, 9443)
    return _base('https' if https else 'http', host, port.number)


def wanted(host, products, ports, web_bases):
    """``[(source, base)]``: the catalogue entries a host warrants and the base each is asked on. ``products`` is ``[(name, version)]`` of its
    technologies and port products, ``ports`` its open TCP ports (rows with number, service_name, product, extra), ``web_bases`` its web
    bases. An entry is warranted by a product its ``leads`` names (asked on the port that product answers on, else on the host's first web
    base) or by an open port of its own (``ports``) whose service the port scan left generic or named the product. At most ``MAX_ENTRIES_PER_HOST``."""
    host = (host or '').strip().lower().rstrip('.')
    tcp = [p for p in ports if (getattr(p, 'protocol', 'tcp') or 'tcp') in ('tcp', '') and (getattr(p, 'state', 'open') or 'open') == 'open']
    out = []
    for source in catalogue.SOURCES:
        lead = source.lead_re()
        bases = []
        if lead is not None:
            for port in tcp:
                if lead.search(getattr(port, 'product', '') or '') or lead.search(getattr(port, 'service_name', '') or ''):
                    bases.append(_port_base(host, port))
            if not bases and web_bases and any(lead.search(name or '') for name, _v in products):
                bases.append(web_bases[0])
        for port in tcp:
            product = (getattr(port, 'product', '') or '').strip()
            generic = GENERIC_SERVICES.match((getattr(port, 'service_name', '') or '').lower()) and (not product or re.search(r'golang|net/http', product, re.I))
            if port.number in source.ports and (generic or (lead is not None and lead.search(product))):
                bases.append(_port_base(host, port))
        for base in list(dict.fromkeys(bases))[:MAX_BASES_PER_ENTRY]:
            out.append((source, base.rstrip('/')))
    return out[:MAX_ENTRIES_PER_HOST]


def host_products(sub, ports):
    out = [_split(t.name) for t in sub.technologies.all() if t.name]
    out += [((p.product or '').strip(), (p.version or '').strip()) for p in ports if (p.product or '').strip()]
    return out


def _ports(sub):
    from startScan.models import open_services
    return [(ip.address, p) for ip in sub.ip_addresses.all() for p in open_services(ip)]


def applies(sub, ports=None):
    """Whether the version source reads apply to ``sub`` (``check_coverage``)."""
    from cveFeed import route_auth
    ports = [p for _a, p in _ports(sub)] if ports is None else ports
    return bool(wanted(sub.name, host_products(sub, ports), ports, route_auth.web_bases(sub)))


# ----------------------------------------------------------------------------- plan

def _gate():
    from cveFeed.bounty_gate import Gate
    return Gate(blocked=())


def plan(project_id, subdomains, unattended=False):
    """``{host: {'subs': [Subdomain], 'reads': [(source, base)]}}`` for the hosts of ``subdomains`` that warrant an entry, less what the
    organization excluded (fail closed), archived hosts, what a bug bounty program's scope does not name (and, ``unattended``, a project whose
    engagement has not confirmed automated testing) and a host that points at an address a scanner may not use."""
    from cveFeed import route_auth
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.exclusions import excluded_names, normalize
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
        addresses = [ip.address for ip in sub.ip_addresses.all() if ip.address]
        if any(not is_scannable_ip(a, project=project_id) for a in addresses):
            continue  # the name points at an address a scanner must never be used on
        if any(gate.refusal(project_id, a, unattended=unattended, derived=True) for a in addresses):
            continue
        ports = [p for _a, p in _ports(sub)]
        reads = wanted(name, host_products(sub, ports), ports, route_auth.web_bases(sub))
        if not reads:
            continue
        entry = out.setdefault(name, {'subs': [], 'reads': []})
        entry['subs'].append(sub)
        for item in reads:
            if item not in entry['reads'] and len(entry['reads']) < MAX_ENTRIES_PER_HOST:
                entry['reads'].append(item)
    return out


def candidates(scan, unattended=False):
    from startScan.models import Subdomain
    rows = (Subdomain.objects.filter(scan_history=scan).select_related('target_domain', 'scan_history')
            .prefetch_related('technologies', 'ip_addresses__ports'))
    return plan(scan.domain.project_id, rows, unattended=unattended)


def candidates_for_hosts(project_id, names, unattended=True):
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    rows = (Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id, name__in=sorted({n.lower().rstrip('.') for n in names}))
            .select_related('scan_history', 'target_domain').prefetch_related('technologies', 'ip_addresses__ports'))
    return plan(project_id, rows, unattended=unattended)


def due(project_id, found, force=False, limit=MAX_PER_SCAN):
    """The hosts of ``found`` to ask now, in a stable order: no complete read inside the week and no failed one inside the day."""
    from cveFeed import ledger
    names = sorted(found)
    if force or not names:
        return names[:limit]
    done = ledger.fresh(SERVICE, names, project_id)
    retry_later = ledger.fresh(FAILED_SERVICE, names, project_id)
    return [n for n in names if ledger._norm(n) not in done and ledger._norm(n) not in retry_later][:limit]


def read_id(host, source, base):
    return f'{host}|vsrc|{source.id}|{base}'[:200]


def _entries(found, names):
    """The task's read entries for ``names``: ``([(sub, entry)], {entry id: (host, source, base)})``."""
    from cveFeed import probes
    out, owner = [], {}
    for name in names:
        item = found[name]
        sub = item['subs'][0]
        allowed = sorted(probes.allowed_names(sub))[:20]
        for source, base in item['reads']:
            ident = read_id(name, source, base)
            if ident in owner:
                continue
            out.append((sub, {'id': ident, 'host': name, 'base': base, 'allowed': allowed,
                              'requests': catalogue.request_specs(source, secrets.token_hex(6))}))
            owner[ident] = (name, source, base)
    return out, owner


# ----------------------------------------------------------------------------- run

def run_for_scan(scan_id, force=False, dispatch=None):
    """The host pipeline stage: store what the hosts of the scan give away in stored headers, then send the reads that are due to a Sentinel
    and store what comes back. Returns ``{'hosts', 'asked', 'readings', 'exposed', 'waiting'}``. Raises ``ScannerUnavailable`` when no
    scanner can take the kind (the reads stay due; the passive readings are stored first)."""
    from agentapi import probe_dispatch, sentinel_dispatch
    from cveFeed import activity
    from reNgine.resources import ScannerUnavailable
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain__project').get(pk=scan_id)
    project = scan.domain.project
    summary = {'hosts': 0, 'asked': 0, 'readings': 0, 'exposed': 0, 'waiting': 0}
    for sub in Subdomain.objects.filter(scan_history=scan).select_related('target_domain', 'scan_history').prefetch_related('technologies', 'ip_addresses__ports'):
        try:
            summary['readings'] += len(refresh_host(sub))
        except Exception:  # noqa: BLE001 - one host's stored data never stops the stage
            logger.exception('passive version readings of host %s failed', sub.pk)
    if not enabled():
        return {**summary, 'skipped': 'disabled'}
    found = candidates(scan)
    names = due(project.pk, found, force=force)
    summary['hosts'] = len(found)
    if not names:
        return summary
    if dispatch is None:
        sentinel_dispatch.scanner_or_local(project, KIND)  # raises ScannerUnavailable when none can take it: the kind has no local path
        dispatch = lambda project_, reads: probe_dispatch.try_version_read(project_, reads, scan=scan, unattended=False)  # noqa: E731
    _ask(project, names, found, lambda name: scan, dispatch, summary)
    activity.log('run_check', f'Version source reads of {summary["asked"]} of {len(names)} host(s) of {scan.domain.name}: {summary["readings"]} reading(s)'
                 + (f', {summary["exposed"]} exposure(s)' if summary['exposed'] else '')
                 + (f'; {summary["waiting"]} wait for a scanner' if summary['waiting'] else ''), project=project.pk, scan_id=scan.id)
    if summary['waiting']:
        raise ScannerUnavailable(KIND, f'a Sentinel returned no result for {summary["waiting"]} host(s): they stay due')
    return summary


def run_for_hosts(project, host_names, dispatch=None, priority=1):
    """The work planner's entry: the same plan, gates (unattended: a bug bounty engagement must have confirmed automated testing), ledger
    and storage as ``run_for_scan`` for the named hosts' current inventory rows, with no scan of its own."""
    from agentapi import probe_dispatch, sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    summary = {'hosts': 0, 'asked': 0, 'readings': 0, 'exposed': 0, 'waiting': 0}
    if not enabled():
        return {**summary, 'skipped': 'disabled'}
    found = candidates_for_hosts(project.pk, host_names, unattended=True)
    for item in found.values():
        for sub in item['subs']:
            refresh_host(sub)
    names = due(project.pk, found, limit=MAX_READS_PER_TASK)
    summary['hosts'] = len(found)
    if not names:
        return summary
    if dispatch is None:
        sentinel_dispatch.scanner_or_local(project, KIND)
        dispatch = lambda project_, reads: probe_dispatch.try_version_read(project_, reads, priority=priority, unattended=True)  # noqa: E731
    _ask(project, names, found, lambda name: found[name]['subs'][0].scan_history, dispatch, summary)
    if summary['waiting']:
        raise ScannerUnavailable(KIND, f'a Sentinel returned no result for {summary["waiting"]} host(s): they stay due')
    return summary


def _ask(project, names, found, scan_for, send, summary):
    """Claim ``names``, send them in tasks of at most ``MAX_READS_PER_TASK`` read entries through ``send(project, reads)`` and store every answer."""
    from cveFeed import ledger
    from cveFeed.exclusions import excluded_names, normalize
    with ledger.claim_many(f'{SERVICE}@{project.pk}', names) as won:
        won = {ledger._norm(n) for n in won}
        names = [n for n in names if ledger._norm(n) in won]
        start = 0
        while start < len(names):
            chunk, count = [], 0
            while start < len(names) and count + len(found[names[start]]['reads']) <= MAX_READS_PER_TASK:
                chunk.append(names[start])
                count += len(found[names[start]]['reads'])
                start += 1
            if not chunk:  # cannot happen (a host has at most MAX_ENTRIES_PER_HOST reads); never loop on it
                start += 1
                continue
            banned = excluded_names(project.pk, strict=True)
            chunk = [n for n in chunk if normalize(n) not in banned]  # excluded since the plan was made: not sent
            if not chunk:
                continue
            reads, owner = _entries(found, chunk)
            rows = send(project, reads)
            by_host = {}
            for ident, (name, source, base) in owner.items():
                by_host.setdefault(name, []).append((source, base, rows.get(ident)))
            for name in chunk:
                answered = by_host.get(name, [])
                if not answered or any(row is None for _s, _b, row in answered):
                    summary['waiting'] += 1  # no answer for part of this host: unknown, due again, nothing recorded as done
                stored, exposed, complete = store_answers(project.pk, scan_for(name), found[name], [a for a in answered if a[2] is not None])
                summary['readings'] += stored
                summary['exposed'] += exposed
                if answered and all(row is not None for _s, _b, row in answered):
                    summary['asked'] += 1
                    ledger.record(SERVICE if complete else FAILED_SERVICE, [name], project.pk, scan_for(name))


# ----------------------------------------------------------------------------- store

def _port_of(base):
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(base)
        return parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        return 0


def _observation(r, port):
    from cveFeed import probes
    kind = 'version' if r['kind'] == 'product' else RUNTIME_KIND
    outcome = 'found' if r['version'] else 'hidden'
    evidence = {'confidence': r['confidence'], 'line_only': r['line_only'], 'component': r['component'], 'source': r['source'],
                'said': r['evidence'], 'version_source': True}
    return probes._observation(kind, r['label'], r['version'], '', outcome, CONFIDENCE_SCORE.get(r['confidence'], 0.3),
                               f"{'header' if r['source'] in ('header', 'technology') else 'vsrc'}:{r['source']}"[:48], port=port,
                               url=r['url'], evidence=evidence)


def store_readings(sub, probe_id, readings, port=0, now=None):
    """Store ``readings`` of one host: products and runtimes as ``ProbeObservation`` rows (a product is also added to the host's
    technologies), a Java runtime reading in ``JavaRuntime``. Returns ``(rows stored, whether something new or changed was stored)``."""
    from cveFeed import java_runtime, probes
    from cveFeed.models import ProbeObservation
    from cvengine_scanner import java
    project_id = sub.target_domain.project_id
    host = sub.name.lower().rstrip('.')
    now = now or timezone.now()
    observations, changed, stored = [], False, 0
    for r in readings:
        if r['kind'] == 'java':
            got = java.reading(r['version'], 'metrics', (r.get('vendor') or '',), runtime=r.get('runtime') or '', url=r['url'], port=port,
                               evidence=r['evidence'])
            if got:
                key = f'metrics:{port}'
                changed = changed or java_runtime._current(project_id, host, key) != (got['version'], got['vendor'])
                java_runtime.store(project_id, sub.target_domain_id, host, key, got, now=now)
                stored += 1
            continue
        observations.append(_observation(r, port))
    if observations:
        before = {(o.kind, o.product, o.port): o.version for o in ProbeObservation.objects.filter(project_id=project_id, host=host, probe=probe_id)}
        probes.record(project_id, sub.target_domain_id, host, probe_id, observations, now=now)
        stored += len(observations)
        changed = changed or any(before.get((o['kind'], o['product'], o['port'])) != o['version'] for o in observations)
        if probes.apply_to_subdomain(sub, observations):
            changed = True
    return stored, changed


def store_answers(project_id, scan, item, answered):
    """Store what one host's answered read entries say, for every name in ``item['subs']``; file or close the exposures; correlate the host
    again when a reading is new or changed. Returns ``(readings stored, exposures filed, complete)``: ``complete`` is False when an entry's
    answers could not be read (unknown), so the host is asked again after a day."""
    from cveFeed import probes
    stored = exposed = 0
    complete = True
    verdicts = []
    for source, base, row in answered:
        answers = row.get('answers') if isinstance(row.get('answers'), list) else []
        verdict = catalogue.read_entry(source, answers) if not row.get('error') else {'state': 'unknown', 'readings': [], 'exposed': None}
        verdict['answers'] = answers
        complete = complete and verdict['state'] != 'unknown'
        heard = []
        for answer in answers[:len(source.requests)]:  # the headers of the entry's own answers: what the passive readers read anyway
            if isinstance(answer, dict) and isinstance(answer.get('headers'), dict) and not answer.get('error'):
                heard += catalogue.from_headers(answer['headers'], url=answer.get('path') or '/')
        verdicts.append((source, base, verdict, heard))
    for sub in item['subs']:
        changed = False
        for source, base, verdict, heard in verdicts:
            port = _port_of(base)
            if verdict['readings'] or heard:
                count, moved = store_readings(sub, f'{PROBE_PREFIX}{source.id}'[:48], verdict['readings'] + heard, port=port)
                stored += count
                changed = changed or moved
            if source.exposure and scan is not None:
                path = source.requests[0].path
                if verdict['exposed'] is True:
                    # a Nomad agent with ACLs on answers anonymously only when its anonymous policy may read the agent: medium, not critical
                    severity = 2 if source.id == 'nomad' and catalogue.nomad_acl_enabled(verdict.get('answers') or []) is True else None
                    exposed += file_exposure(scan, sub, source, base + path, verdict['readings'], severity=severity)
                elif verdict['exposed'] is False:
                    close_exposure(scan, sub, source, base + path)
        if changed:
            probes.recorrelate(sub)
    return stored, exposed, complete


def passive_readings(sub, ports=None):
    """``[(port, reading)]`` a host gives away in what the scans already stored, no request made: the headers the port scan's http-headers script
    read on each port, the host's Server header, and the runtime a stored technology is (``Python:3.11.4``, ``.NET Framework CLR:4.0.30319``)."""
    ports = _ports(sub) if ports is None else ports
    out = []
    for _address, port in ports:
        scripts = ((port.extra or {}).get('scripts') or {}) if isinstance(port.extra, dict) else {}
        text = str(scripts.get('http-headers') or '')[:8000] if isinstance(scripts, dict) else ''
        if text:
            out += [(port.number, r) for r in catalogue.from_headers(catalogue.header_lines(text), url=f'port {port.number}')]
    if getattr(sub, 'webserver', ''):
        out += [(0, r) for r in catalogue.from_headers({'server': sub.webserver}, url='/')]
    for tech in sub.technologies.all():
        name, version = _split(tech.name)
        got = catalogue.from_technology(name, version)
        if got:
            out.append((0, got))
    seen, unique = set(), []
    for port, r in out:
        key = (port, r['component'], r['kind'])
        if key not in seen:
            seen.add(key)
            unique.append((port, r))
    return unique


def refresh_host(sub, now=None):
    """Store the readings ``sub`` gives away in stored data (``passive_readings``) and drop the ones it no longer gives. Returns them."""
    from cveFeed.models import ProbeObservation
    found = passive_readings(sub)
    now = now or timezone.now()
    by_port = {}
    for port, r in found:
        by_port.setdefault(port, []).append(r)
    kept = set()
    for port, readings in by_port.items():
        store_readings(sub, PASSIVE_PROBE, readings, port=port, now=now)
        kept |= {(port, 'version' if r['kind'] == 'product' else RUNTIME_KIND, r['label']) for r in readings if r['kind'] != 'java'}
    project_id = sub.target_domain.project_id
    for row in ProbeObservation.objects.filter(project_id=project_id, host=sub.name.lower().rstrip('.'), probe=PASSIVE_PROBE):
        if (row.port, row.kind, row.product) not in kept:
            row.delete()  # derived from what the host shows now: gone when that is gone
    return found


# ----------------------------------------------------------------------------- exposures

def _twin(sub, source):
    """Whether a template check's finding already reports this exposure on the host (``Exposure.twins``): then it is not filed again."""
    from startScan.models import Vulnerability
    twins = source.exposure.twins
    if not twins:
        return False
    return Vulnerability.objects.filter(target_domain__project_id=sub.target_domain.project_id, subdomain__name=sub.name, open_status=True,
                                        template_id__in=list(twins)).exclude(source=FINDING_SOURCE).exists()


def file_exposure(scan, sub, source, url, readings=(), severity=None):
    """The finding of an exposure ``source`` answered in its shape: one row per host name, entry and URL (a rescan updates it). Returns 1
    when it is new."""
    from reNgine.tasks import save_vulnerability
    if scan is None or _twin(sub, source):
        return 0
    exposure = source.exposure
    said = '; '.join(r['evidence'] for r in readings if r.get('evidence'))[:300]
    detail = exposure.description
    _vuln, created = save_vulnerability(
        target_domain=scan.domain, scan_history=scan, subdomain=sub, source=FINDING_SOURCE, template_id=exposure.template, name=exposure.name,
        severity=exposure.severity if severity is None else severity, http_url=url[:2000], type='exposure',
        description=detail + (f' It said: {said}' if said else ''), impact=exposure.impact, remediation=exposure.remediation,
        extracted_results=[said] if said else [], tags=['exposure', 'version-source', source.id])
    return 1 if created else 0


def close_exposure(scan, sub, source, url):
    """A complete read that found no such answer: the finding of an earlier read is gone. Only the liveness field changes; a status a
    person set is kept."""
    from startScan.models import Vulnerability
    Vulnerability.objects.filter(target_domain__project_id=scan.domain.project_id, subdomain__name=sub.name, source=FINDING_SOURCE,
                                 template_id=source.exposure.template, http_url=url[:2000], open_status=True).update(open_status=False)


# ----------------------------------------------------------------------------- correlation: the language runtimes

def _fresh_rows(rows, now=None):
    cutoff = (now or timezone.now()) - timedelta(days=STALE_DAYS)
    return [r for r in rows if r.observed_at and r.observed_at >= cutoff]


def host_runtimes(sub):
    """The fresh runtime readings of a host (``ProbeObservation`` kind ``runtime``), plus the runtimes its current technologies are (not yet
    stored when correlation runs before the stage), as ``[(component, version, confidence, line_only, source, port)]``."""
    rows = getattr(sub, '_runtime_rows', None)
    if rows is None:
        from cveFeed.models import ProbeObservation
        if sub.target_domain_id is None:
            return []
        rows = list(ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=sub.name.lower().rstrip('.'), kind=RUNTIME_KIND))
    out = []
    for row in _fresh_rows(rows):
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        component = ev.get('component') or ''
        if component in catalogue.RUNTIMES:
            out.append((component, row.version or '', ev.get('confidence') if ev.get('confidence') in catalogue.CONFIDENCES else 'weak',
                        bool(ev.get('line_only')), (ev.get('source') or row.source or '')[:40], row.port or 0))
    for tech in sub.technologies.all():
        got = catalogue.from_technology(*_split(tech.name))
        if got:
            out.append((got['component'], got['version'], got['confidence'], got['line_only'], 'technology', 0))
    return list(dict.fromkeys(out))


_POOL = {}


def runtime_cves(cve_by_id):
    """``{runtime: [(cve, [items])]}`` of a correlation pool: the CVEs whose own affected entries name a language runtime, memoised per pool."""
    memo = _POOL
    if memo.get('id') != id(cve_by_id) or memo.get('size') != len(cve_by_id):
        out = {}
        for cve in cve_by_id.values():
            hits = {}
            for item in cve.affected or []:
                key = catalogue.runtime_of_item(item)
                if key:
                    hits.setdefault(key, []).append(item)
            for key, items in hits.items():
                out.setdefault(key, []).append((cve, items))
        memo.update(id=id(cve_by_id), size=len(cve_by_id), cves=out)
    return memo['cves']


def _plain(version):
    return re.sub(r'^(?:go|v)', '', (version or '').strip())


def verdict(version, items):
    """``(in_range, deciding range)`` of one runtime version against a CVE's entries for that runtime (``correlation.range_verdict``)."""
    from cveFeed.correlation import parse_version, range_verdict
    ver = parse_version(_plain(version))
    if ver is None:
        return None, None
    unknown = False
    for item in items:
        result, rng, _nolow = range_verdict(ver, item.get('ranges') or [])
        if result is True:
            return True, rng
        unknown = unknown or result is None
    return (None if unknown else False), None


def _bounded(items):
    from cveFeed.correlation import _bounded as bounded, prepared_ranges
    return any(bounded(rng) for item in items for rng in prepared_ranges(item.get('ranges') or []))


def line_possible(line, items):
    """Whether a runtime line (``4.8``, ``26``) can be inside one of the CVE's ranges: either end of the line tested, or no bound decides."""
    low, high = verdict(f'{line}.0', items)[0], verdict(f'{line}.99999', items)[0]
    return low is not False or high is not False


def collect_matches(subdomain, cve_by_id, rows, scan_history=None, min_confidence=0.0, fix_lookup=None):
    """Append the runtime matches of ``subdomain`` to ``rows`` (see the module docstring). A CVE ``rows`` already holds for the host (its
    technology, port or Java match) is not matched twice. Returns how many."""
    from cveFeed import distro as distro_lib
    from cveFeed.correlation import BACKPORT_CONFIDENCE, confidence_for, distro_fix_evidence, parse_version
    pool = runtime_cves(cve_by_id)
    if not pool:
        return 0
    readings = host_runtimes(subdomain)
    if not readings:
        return 0
    taken = {r['cve_entry_id'] for r in rows if r.get('subdomain_id') == subdomain.id}
    found = 0
    for key, runtime in catalogue.RUNTIMES.items():
        mine = [r for r in readings if r[0] == key]
        if not mine or key not in pool:
            continue
        exact = [r for r in mine if r[2] == 'exact' and r[1] and not r[3]]
        lines = [r for r in mine if r[1] and (r[3] or r[2] != 'exact')]
        present = any(r[2] in ('exact', 'inferred') for r in mine)
        listed = [{'version': v, 'confidence': c, 'line_only': lo, 'source': s, 'port': p} for _k, v, c, lo, s, p in mine][:10]
        base = {'source': MATCH_SOURCE, 'runtime': key, 'runtime_label': runtime.label, 'readings': listed}
        for cve, items in pool[key]:
            if cve.id in taken:
                continue
            row = None
            bounded = _bounded(items)
            if exact:
                results = [(r, *verdict(r[1], items)) for r in exact]
                hit = next(((r, rng) for r, result, rng in results if result is True), None)
                if hit is None:
                    if all(result is False for _r, result, _rng in results) or not cve.kev:
                        continue  # every version read is outside the range, or no bound decides and only an actively exploited CVE is kept
                    r = exact[0]
                    row = _row(cve, subdomain, scan_history, runtime.label, r[1], None, UNKNOWN_CONFIDENCE,
                               {**base, 'raw_version': r[1], 'unbounded': True, 'reading': _text(runtime, r)})
                else:
                    r, rng = hit
                    confidence = confidence_for(parse_version(_plain(r[1])), True, cve.kev)
                    status, fixed, fix = distro_lib.NO_DATA, '', None
                    info = distro_lib.parse_distro(runtime.label, r[1], '')
                    if info.get('distro'):
                        info['package'] = distro_lib.package_for(runtime.label, info['distro'], info.get('upstream_version') or '')
                    if info.get('distro') and info.get('package') and fix_lookup:
                        rows_for = fix_lookup(distro_lib.fix_distro(info['distro']), info['package'], getattr(cve, 'cve_id', ''))
                        status, fixed, fix_row = distro_lib.judge_row(info, rows_for)
                        fix = distro_fix_evidence(info, fix_row, fixed)
                        if status == distro_lib.PATCHED:
                            confidence = 0.2
                        elif status == distro_lib.VULNERABLE:
                            confidence = 0.95
                        elif status in (distro_lib.BACKPORT, distro_lib.UNKNOWN):
                            confidence = min(confidence, BACKPORT_CONFIDENCE)
                    evidence = {**base, 'raw_version': r[1], 'range': rng or {}, 'reading': _text(runtime, r), 'port': r[5],
                                **({'distro': {k: v for k, v in info.items() if v}} if info.get('distro') else {}),
                                **({'distro_fix': fix} if fix else {})}
                    row = _row(cve, subdomain, scan_history, runtime.label, r[1], True, confidence, evidence, status=status, fixed=fixed)
            else:
                if not bounded and not cve.kev:
                    continue
                if not (lines or (present and runtime.unknown)):
                    continue  # a weak presence (a header any stack may send) matches nothing
                possible = [r for r in lines if line_possible(_plain(r[1]), items)] if lines else None
                if lines and bounded and not possible:
                    continue  # the host states a line no affected range reaches
                confidence, note = UNKNOWN_CONFIDENCE, ''
                inside = [r for r in (possible or []) if not r[3] and verdict(r[1], items)[0] is True]
                if inside:
                    confidence, note = INFERRED_IN_RANGE_CONFIDENCE, f'inferred {_text(runtime, inside[0])} is inside the affected range'
                elif possible:
                    note = f'the line read, {_text(runtime, possible[0])}, can be inside the affected range'
                evidence = {**base, 'runtime_unknown': True, 'raw_version': '', **({'runtime_note': note} if note else {}),
                            **({'unbounded': True} if not bounded else {})}
                row = _row(cve, subdomain, scan_history, runtime.label, '', None, confidence, evidence)
            if row is None or row['confidence'] < min_confidence or row['confidence'] <= 0.0:
                continue
            rows.append(row)
            found += 1
    return found


def _text(runtime, r):
    what = r[1] if not r[3] else f'the {r[1]} line'
    return f'{runtime.label} {what} ({r[4]}, {r[2]})'


def _row(cve, subdomain, scan_history, label, version, in_range, confidence, evidence, status='no_data', fixed=''):
    return {'cve_entry_id': cve.id, 'subdomain_id': subdomain.id, 'source': MATCH_SOURCE, 'matched_product': label[:255],
            'matched_version': (version or '')[:100], 'version_in_range': in_range, 'confidence': confidence,
            'scan_history_id': scan_history.id if scan_history else subdomain.scan_history_id, 'distro_status': status,
            'distro_fixed_version': (fixed or '')[:64], 'evidence': evidence}


def index_has_runtime(product_index):
    """Whether a correlation product index may hold a CVE in a language runtime. The Go CNA names each standard library package (``net/http``,
    ``crypto/tls``) rather than Go, so no product token tells: any pool may, and the hosts with a runtime reading are always candidates (a
    bounded set: only hosts a version source or a stored header gave a runtime)."""
    return bool(product_index)


def runtime_host_ids(base_qs):
    """The ids of the Subdomain rows of ``base_qs`` with a runtime reading (``correlation.candidate_subdomains``)."""
    from django.db.models import Exists, OuterRef
    from cveFeed.models import ProbeObservation
    readings = ProbeObservation.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'), kind=RUNTIME_KIND)
    return base_qs.filter(Exists(readings)).values('id')


def runtime_cves_among(pks, exclude=()):
    """The stored CVEs among ``pks`` that name a language runtime (``tasks.auto_fire_new_cves`` correlates them the moment they land)."""
    from cveFeed.correlation import _CVE_FIELDS, clean_affected
    from cveFeed.models import CVEEntry
    pks = [pk for pk in (pks or ()) if pk not in set(exclude)]
    if not pks:
        return []
    rows = list(CVEEntry.objects.filter(pk__in=pks).exclude(status__icontains='reject').exclude(local_only=True).only(*_CVE_FIELDS))
    for row in rows:
        row.affected = clean_affected(row.affected)
    return [row for row in rows if any(catalogue.runtime_of_item(item) for item in row.affected or [])]


# ----------------------------------------------------------------------------- what the host payload and the search show

def as_dict(row):
    """One reading as the host payload (REST and MCP ``version_sources``) and the host page show it. ``evidence`` is what the host said."""
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    source = row.probe[len(PROBE_PREFIX):] if row.probe.startswith(PROBE_PREFIX) else row.probe
    return {'component': ev.get('component') or '', 'product': row.product, 'kind': 'runtime' if row.kind == RUNTIME_KIND else 'product',
            'version': row.version, 'confidence': ev.get('confidence') or 'weak', 'line_only': bool(ev.get('line_only')),
            'source': source, 'read_by': ev.get('source') or '', 'port': row.port or None, 'url': row.url, 'evidence': ev.get('said') or '',
            'first_seen': row.first_seen.isoformat() if row.first_seen else None, 'last_seen': row.observed_at.isoformat() if row.observed_at else None,
            'stale': bool(row.observed_at and row.observed_at < timezone.now() - timedelta(days=STALE_DAYS))}


_ORDER = {'exact': 0, 'inferred': 1, 'weak': 2}


def readings_qs():
    from django.db.models import Q
    from cveFeed.models import ProbeObservation
    return ProbeObservation.objects.filter(Q(probe__startswith=PROBE_PREFIX)).filter(evidence__version_source=True)


def readings_for(project_ids, hosts):
    """``{(project id, host): [as_dict]}`` for a page of hosts, exact readings first (one query)."""
    out = {}
    if not hosts:
        return out
    rows = readings_qs().filter(project_id__in=list(project_ids), host__in=list(hosts)).order_by('host', '-observed_at')
    for row in rows:
        out.setdefault((row.project_id, row.host), []).append(row)
    return {key: [as_dict(r) for r in sorted(rs, key=lambda r: (_ORDER.get((r.evidence or {}).get('confidence'), 3), r.product))][:30]
            for key, rs in out.items()}


def search_rows(field, value):
    """The reading rows a search term names, or None for a value it cannot read.

    ``component:<name>`` (a product or runtime read from a version source: ``component:grafana``, ``component:docker``; ``component:any``),
    ``runtime:<name>`` (a language runtime: ``runtime:python``, ``runtime:go``, ``runtime:dotnet``; ``runtime:any``), each optionally with a
    version prefix after ``@`` (``runtime:python@3.8`` finds 3.8.10, never 3.80); ``vsource:<entry>`` (where it was read: ``vsource:prometheus-metrics``,
    ``vsource:header``)."""
    from django.db.models import Q
    text = (value or '').strip().lower()
    if not text or len(text) > 80:
        return None
    rows = readings_qs()
    if field == 'vsource':
        if text == 'any':
            return rows
        if text in ('header', 'passive', 'technology'):
            return rows.filter(probe=PASSIVE_PROBE)
        if text not in catalogue.BY_ID:
            return None
        return rows.filter(probe=f'{PROBE_PREFIX}{text}')
    name, _sep, version = text.partition('@')
    if field == 'runtime':
        rows = rows.filter(kind=RUNTIME_KIND)
        aliases = {'dotnet': 'dotnet-framework', '.net': 'dotnet-framework', 'net': 'dotnet-framework', 'golang': 'go', 'node': 'nodejs',
                   'node.js': 'nodejs', 'otp': 'erlang'}
        name = aliases.get(name, name)
        if name != 'any' and name not in catalogue.RUNTIMES:
            return None
    if name != 'any':
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,40}', name):
            return None
        rows = rows.filter(Q(evidence__component=name) | Q(product__iexact=name))
    if version:
        if not re.fullmatch(r'\d{1,4}(?:\.\d{1,9}){0,3}', version):
            return None
        rows = rows.filter(Q(version=version) | Q(version__startswith=version + '.'))
    return rows


# ----------------------------------------------------------------------------- the catch-up after an update

def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_version_sources --apply``, an upgrade backfill): for every current host,
    store the readings it already gives away in stored data (``refresh_host``: the headers the port scan's http-headers script read, the Server header, the
    runtime a technology is), then correlate the hosts that gained a runtime reading against the runtime CVEs. The active reads are the work
    planner's (the ``version-sources`` check is due on every host it applies to). Idempotent. Returns ``{'hosts', 'readings', 'matches'}``."""
    from cveFeed import correlation
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    ids = list(base.order_by('id').values_list('id', flat=True))
    out = {'hosts': len(ids), 'readings': 0, 'matches': 0}
    if not apply or not ids:
        return out
    cve_by_id, _index = correlation.cve_pool()
    pool = {cve.id: cve for entries in runtime_cves(cve_by_id).values() for cve, _items in entries}
    index = correlation.build_product_index(pool.values())
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        gained = []
        for sub in subs:
            try:
                found = refresh_host(sub)
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('version source catch-up of host %s failed', sub.pk)
                continue
            out['readings'] += len(found)
            if any(r['kind'] == 'runtime' for _p, r in found):
                gained.append(sub)
        if pool and gained:
            out['matches'] += correlation.correlate_subdomains(gained, index, pool, min_confidence=0.4)[1]
    return out
