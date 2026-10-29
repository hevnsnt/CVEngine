"""What goes into a PDF report: one project's (or one host's) hosts and findings, read for the report and cleaned for printing.

Everything here runs in a worker as a named user (cveFeed.report_export re-checks that user's role first) and is filtered to the
project explicitly, never by the request scope, which a worker does not have. The functions return plain dicts of short strings and
numbers: every string that came from a scanned host, a feed or a person is stripped of control characters and clipped here, and
HTML-escaped by the template (cveFeed/templates/cveFeed/report.html, autoescape on, no ``safe``), so a hostile banner or finding title
reaches the PDF as inert text.

The caps (hosts, detailed findings, hygiene rows) keep one report bounded: the totals and the heat and severity counts always cover
every finding, and the report says what the caps left out.
"""
import os
import re
from collections import Counter
from datetime import datetime, timezone as dt_timezone

from django.db.models import Count, Max, Min, Q
from django.utils import timezone

HEAT_NAMES = {3: 'fire', 2: 'smoke', 1: 'ice'}
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low')
STATUS_LABELS = {'open': 'Open', 'in_progress': 'In progress', 'fixed': 'Fixed', 'accepted_risk': 'Accepted risk'}
PROVING = ('hit', 'observed', 'reaffirmed')  # the validation results that show the finding on the host
FALSE_POSITIVES = ('likely_false_positive', 'not_applicable')  # triage classes a client report leaves out
HOST_PAGE = 100

DEFAULT_MAX_HOSTS, CEILING_HOSTS = 500, 5000
DEFAULT_MAX_FINDINGS, CEILING_FINDINGS = 1000, 5000
DEFAULT_MAX_HYGIENE, CEILING_HYGIENE = 500, 5000
TOP_RISKS = 10

# a short, plain reading of what each ledger service is, for the method page
SERVICE_LABELS = {
    'nmap-fast': 'nmap service detection on the common ports', 'nmap-full': 'nmap on every one of the 65,535 ports',
    'nmap': 'nmap service detection', 'naabu': 'naabu full-port discovery', 'bbot': 'bbot discovery of hosts and subdomains',
    'bbot-deep': 'bbot deep discovery', 'nuclei': 'nuclei template checks', 'route_auth': 'web route authentication checks',
    'hygiene': 'TLS, certificate and email checks', 'ct_watch': 'certificate transparency watch', 'wpscan': 'WPScan of WordPress sites',
    'testssl': 'TLS protocol and cipher review',
}

# control characters, line and paragraph separators, and the bidirectional overrides and isolates that can make text read differently
_CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]')


def clean(value, limit=300):
    """``value`` as printable text: control characters removed, whitespace runs folded, clipped to ``limit`` with an ellipsis."""
    if value is None:
        return ''
    text = _CONTROL.sub('', str(value)).replace('\r', '')
    text = '\n'.join(' '.join(line.split()) for line in text.split('\n')).strip()
    return text if len(text) <= limit else text[:max(0, limit - 1)].rstrip() + '…'


def _env_int(name, default, ceiling):
    try:
        value = int(os.environ.get(name, ''))
    except ValueError:
        return default
    return min(ceiling, max(1, value))


def limits():
    """The caps of one report, from the environment (docs/CONFIGURATION.md), each held under a hard ceiling."""
    return {'hosts': _env_int('CVENGINE_REPORT_MAX_HOSTS', DEFAULT_MAX_HOSTS, CEILING_HOSTS),
            'findings': _env_int('CVENGINE_REPORT_MAX_FINDINGS', DEFAULT_MAX_FINDINGS, CEILING_FINDINGS),
            'hygiene': _env_int('CVENGINE_REPORT_MAX_HYGIENE', DEFAULT_MAX_HYGIENE, CEILING_HYGIENE)}


def _date(value):
    return value.strftime('%Y-%m-%d') if value else ''


def _stamp(value):
    return value.strftime('%Y-%m-%d %H:%M UTC') if value else ''


def _person(user):
    return clean(user.get_full_name() or user.username, 80) if user else ''


def _branding():
    """Company name, accent colour and footer from Settings > Reports. The colour goes into a stylesheet, so it must be exactly #RRGGBB."""
    from scanEngine.models import VulnerabilityReportSetting
    row = VulnerabilityReportSetting.objects.first()
    color = row.primary_color if row and re.fullmatch(r'#[0-9a-fA-F]{6}', row.primary_color or '') else '#c2410c'
    return {'company': clean(row.company_name, 100) if row else '', 'accent': color,
            'footer': clean(row.footer_text, 200) if row and row.show_footer else ''}


# --- findings ------------------------------------------------------------------------------------------------------------------

def _host_names_q(prefix, names):
    q = Q(pk__in=[])
    for name in names:
        q |= Q(**{f'{prefix}__iexact': name})
    return q


def _sources(project, include_closed, names=None):
    """``({cve, scanner, hygiene: queryset}, ruled_out)``: the project's findings in the order the Findings page uses (hottest first),
    open ones only unless ``include_closed``. Matches the AI ruled out, and findings triage classed as a false positive or not
    applicable, are never listed; ``ruled_out`` counts them so the report can say so. ``names`` limits it to those hosts."""
    from agentapi import services as svc
    sources = svc._finding_sources(project, {'status': 'all' if include_closed else 'actionable'})
    out, ruled_out = {}, 0
    for key, qs in sources.items():
        if key == 'cve':
            qs = qs.exclude(ai_verdict='not_affected')
        elif include_closed:
            qs = qs.filter(severity__gte=1)  # a closed informational detection is not a finding to report
        if names is not None:
            qs = qs.filter(_host_names_q('host' if key == 'hygiene' else 'subdomain__name', names))
        false_positive = Q(triage__classification__in=FALSE_POSITIVES)
        ruled_out += qs.filter(false_positive).count()
        out[key] = qs.exclude(false_positive)
    return out, ruled_out


def _tally(sources):
    """Counts of the whole set by heat and by severity: exact, whatever the caps later leave out of the sections."""
    heat, severity, total = Counter(), Counter(), 0
    from agentapi.services import SEVERITY_NAMES
    for qs in sources.values():
        for row in qs.order_by().values('heat_rank', 'sev').annotate(n=Count('id')):
            if row['heat_rank'] in HEAT_NAMES:
                heat[HEAT_NAMES[row['heat_rank']]] += row['n']
            name = SEVERITY_NAMES.get(row['sev'])
            if name in SEVERITY_ORDER:
                severity[name] += row['n']
            total += row['n']
    return total, {k: heat[k] for k in ('fire', 'smoke', 'ice')}, {k: severity[k] for k in SEVERITY_ORDER}


def _per_host(sources):
    """``{lowercase host: how many findings it has}`` over the whole set, for the host table."""
    out = Counter()
    for key, qs in sources.items():
        field = 'host' if key == 'hygiene' else 'subdomain__name'
        for row in qs.order_by().values(field).annotate(n=Count('id')):
            if row[field]:
                out[row[field].lower()] += row['n']
    return out


def _proof(triage):
    """What ran against the host, newest evidence of it first: the steps that showed the finding (with the exact command a person can
    repeat), then what else was checked. Each is {label, command, result, when, summary}."""
    steps = list((triage.validation_steps if triage else None) or [])
    steps.sort(key=lambda s: str(s.get('ran_at') or ''), reverse=True)
    steps.sort(key=lambda s: s.get('result') not in PROVING)  # stable: the steps that showed it first, each group newest first
    out = []
    for step in steps[:4]:
        out.append({'label': clean(step.get('label'), 120), 'command': clean(step.get('display'), 500),
                    'result': clean(step.get('result'), 24), 'proved': step.get('result') in PROVING,
                    'when': clean(str(step.get('ran_at') or '')[:16].replace('T', ' '), 20), 'summary': clean(step.get('summary'), 240)})
    return out


def _tracking(obj):
    """The remediation state a person or agent recorded: status, assignee, note and when it last changed."""
    return {'status': STATUS_LABELS.get(obj.remediation_status, clean(obj.remediation_status, 24)),
            'assignee': _person(getattr(obj, 'assignee', None)), 'note': clean(obj.remediation_note, 800),
            'changed': _stamp(obj.remediation_updated_at), 'changed_by': _person(getattr(obj, 'remediation_by', None))}


_ISO = re.compile(r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})[\d:.]*(?:\+00:00|Z)?')


def _steps(how, cap=8):
    """The evidence lines of a finding's "how it was found", with ISO timestamps shortened to a date and a time."""
    return [{'label': clean(s['label'], 60), 'value': _ISO.sub(r'\1 \2', clean(s['value'], 240))} for s in how['steps'] if s.get('value')][:cap]


def _match_entry(m, heat):
    from agentapi import services as svc
    cve, t = m.cve_entry, svc._triage_of(m)
    verdict = t.verdict if t else None
    confirmed = m.template_result == 'vulnerable' or bool(t and t.validation_status == 'hit')
    basis = ('Confirmed: a check on the host reproduced it' if confirmed else
             'Reported by the host itself (its own inventory)' if m.source == 'host' else
             'Version-based: the detected version is inside the advisory range; not reproduced')
    flags = [text for on, text in ((cve.kev, 'listed as exploited (CISA KEV)'), (cve.exploit_db, 'public exploit'),
                                   (cve.epss_reached, 'high exploitation probability (EPSS)')) if on]
    product = ' '.join(x for x in (m.matched_product, m.matched_version) if x)
    fixed = svc._fixed_versions(cve, m.matched_product)
    sub = m.subdomain
    return {'kind': 'CVE match', 'title': clean(f'{cve.cve_id} in {product}' if product else cve.cve_id, 200), 'subtitle': clean(cve.title, 200),
            'host': clean(sub.name if sub else '', 200), 'heat': heat, 'severity': svc.SEVERITY_NAMES.get(m.sev, ''),
            'cves': [clean(cve.cve_id, 40)], 'cvss': cve.cvss, 'signals': flags, 'basis': basis, 'confirmed': confirmed,
            'description': clean(svc._cve_description(cve, 500), 500), 'impact': clean(verdict.impact if verdict else '', 600),
            'evidence': _steps(svc._how_found_match(m)), 'proof': _proof(t),
            'remediation': clean(verdict.remediation if verdict else '', 1200), 'fixed_in': [clean(v, 60) for v in fixed[:6]],
            'tracking': _tracking(m), 'first_seen': _date(svc._seen(m, 'first_seen', m.created_at)),
            'last_seen': _date(svc._seen(m, 'last_seen', m.updated_at))}


def _vulnerability_entry(v, heat):
    from agentapi import services as svc
    t = svc._triage_of(v)
    verdict = t.verdict if t else None
    confirmed = bool(t and t.validation_status == 'hit')
    proof = _proof(t)
    if v.curl_command:
        proof.append({'label': 'Request the scanner sent', 'command': clean(v.curl_command, 500), 'result': 'detected', 'proved': True,
                      'when': _stamp(v.discovered_date)[:16], 'summary': ''})
    return {'kind': 'Scanner finding', 'title': clean(v.name, 200), 'subtitle': clean(v.source, 60),
            'host': clean(v.subdomain.name if v.subdomain else (v.target_domain.name if v.target_domain else ''), 200), 'heat': heat,
            'severity': svc.SEVERITY_NAMES.get(v.severity, ''), 'cves': [clean(c.name, 40) for c in v.cve_ids.all()][:8],
            'cvss': v.cvss_score, 'signals': [],
            'basis': 'Confirmed: a check on the host reproduced it' if confirmed else 'Detected by the scanner template (a response matched); not independently reproduced',
            'confirmed': confirmed, 'description': clean(v.description, 500), 'impact': clean((verdict.impact if verdict else '') or v.impact, 600),
            'evidence': _steps(svc._how_found_vulnerability(v)), 'proof': proof[:5],
            'remediation': clean((verdict.remediation if verdict else '') or v.remediation, 1200), 'fixed_in': [],
            'tracking': {**_tracking(v), **({'status': 'No longer detected'} if not v.open_status and v.remediation_status == 'open' else {})},
            'first_seen': _date(svc._seen(v, 'first_seen', v.discovered_date)), 'last_seen': _date(svc._seen(v, 'last_seen', v.discovered_date))}


def _findings(sources, cap):
    """The top ``cap`` CVE matches and scanner findings together, hottest first, as report entries."""
    epoch = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
    merged = [('cve', o) for o in sources['cve'][:cap]] + [('scanner', o) for o in sources['scanner'].prefetch_related('cve_ids')[:cap]]
    merged.sort(key=lambda p: (p[1].heat_rank, p[1].sev, p[1].when or epoch, p[1].id), reverse=True)
    return [(_match_entry if key == 'cve' else _vulnerability_entry)(obj, HEAT_NAMES.get(obj.heat_rank, '')) for key, obj in merged[:cap]]


def _hygiene_group(check):
    if check.startswith(('tls_', 'tlsa_', 'cert')):  # tlsa_* are the testssl findings (cveFeed.testssl_scan)
        return 'TLS and certificates'
    if check.startswith(('spf_', 'dmarc_', 'dkim_', 'mx_', 'mta_', 'bimi_', 'smtp_')):
        return 'Email'
    return 'Other configuration'


def _hygiene(qs, cap):
    """Hygiene findings (TLS, certificates, email) grouped by kind; each is {title, host, severity, detail, evidence, tracking}."""
    from agentapi import services as svc
    groups = {}
    for f in qs[:cap]:
        t = svc._triage_of(f)
        verdict = t.verdict if t else None
        groups.setdefault(_hygiene_group(f.check_name), []).append({
            'title': clean(f.title, 200), 'host': clean(f.host, 200), 'severity': svc.SEVERITY_NAMES.get(f.sev, ''),
            'heat': HEAT_NAMES.get(f.heat_rank, ''), 'check': clean(f.check_name, 40), 'detail': clean(f.detail, 600),
            'evidence': [{'label': clean(k, 40), 'value': clean(v, 160)} for k, v in list((f.evidence or {}).items())[:6]],
            'remediation': clean(verdict.remediation if verdict else '', 800), 'tracking': _tracking(f),
            'first_seen': _date(f.first_seen)})
    return [{'name': name, 'items': groups[name]} for name in ('TLS and certificates', 'Email', 'Other configuration') if name in groups]


# --- hosts ---------------------------------------------------------------------------------------------------------------------

def _host_row(h, findings_by_host, detail):
    ports = sorted({(p['number'], p['protocol'] or '') for ip in h['ips'] for p in ip['ports']})
    row = {'host': clean(h['host'], 200), 'heat': h['heat'] if h['heat'] in ('fire', 'smoke', 'ice', 'clean', 'unscanned') else 'unscanned',
           'score': int(h['score'] or 0), 'findings': findings_by_host.get(h['host'].lower(), 0), 'addresses': len(h['ips']),
           'ports': [f'{n}/{proto}' if proto else str(n) for n, proto in ports][:14], 'port_count': len(ports), 'ports_more': max(0, len(ports) - 14),
           'owner': clean(h['profile'].get('owner'), 80), 'criticality': clean(h['profile'].get('criticality'), 12),
           'technologies': [clean(t, 40) for t in h['technologies'][:6]]}
    if detail:
        row['title'] = clean(h['title'], 200)
        row['http_status'] = h['http_status'] or ''
        row['aliases'] = [clean(a, 200) for a in h['aliases'][:10]]
        row['address_list'] = [clean(ip['address'], 64) for ip in h['ips'][:20]]
        row['purpose'] = clean(h['profile'].get('purpose'), 300)
        row['score_lines'] = [{'label': clean(d.get('label'), 120), 'points': int(d.get('points') or 0)} for d in h['score_detail'][:12]]
        row['services'] = [{'address': clean(ip['address'], 64), 'port': f"{p['number']}/{p['protocol']}", 'service': clean(p['service'], 30),
                            'product': clean(' '.join(x for x in (p['product'], p['version']) if x), 80), 'banner': clean(p['banner'], 160)}
                           for ip in h['ips'] for p in ip['ports']][:40]
    return row


def _hosts(project, host, findings_by_host, cap):
    """``(total hosts, the top ``cap`` host rows by score)``. A host report reads the one host with its services and score lines."""
    from agentapi import services as svc
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    qs = svc._scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q())
    if host:
        qs = qs.filter(name__iexact=host)
    qs = svc._one_per_host(qs).select_related('target_domain').prefetch_related(
        'ip_addresses__ports', 'cve_matches__cve_entry', 'cve_matches__triage', 'vulnerability_set', 'vulnerability_set__triage',
        'technologies').order_by('-score', 'name')
    total, rows, page = qs.count(), [], 1
    while len(rows) < min(cap, total):
        got = svc._hosts_page(project, qs, {'page': page, 'page_size': HOST_PAGE}, coverage=False)['results']
        if not got:
            break
        rows += got
        page += 1
    return total, [_host_row(h, findings_by_host, detail=bool(host)) for h in rows[:cap]]


# --- scope and method ----------------------------------------------------------------------------------------------------------

def _scope(project, host):
    from targetApp.models import Domain
    domains = Domain.objects.filter(project=project).order_by('name')
    count = domains.count()
    return {'targets': count, 'target_names': [clean(n, 120) for n in domains.values_list('name', flat=True)[:15]], 'targets_more': max(0, count - 15)}


SCAN_DONE = 2


def _method(project, names, addresses):
    """What was scanned and when: scan counts and dates, and the last run of each scanner (the service ledger) on this scope. ``names`` and
    ``addresses`` narrow it to one host's names and IPs; None is the whole project."""
    from cveFeed.models import ServiceRun
    from startScan.models import IpAddress, ScanHistory
    scans = ScanHistory.objects.filter(domain__project=project, scan_status=SCAN_DONE).aggregate(
        n=Count('id'), first=Min('start_scan_date'), last=Max('start_scan_date'))
    runs = ServiceRun.objects.filter(status='done')
    if names is None:  # the global nmap rows (no project) count when they are about one of this project's addresses
        mine = IpAddress.objects.filter(ip_addresses__target_domain__project=project).values('address')
        runs = runs.filter(Q(project=project) | Q(project__isnull=True, asset__in=mine))
    else:
        assets = {n.lower() for n in names} | set(addresses)
        q = Q(asset__in=sorted(assets))
        for asset in sorted(assets):
            q |= Q(asset__startswith=f'{asset}:')  # a host:port asset
        runs = runs.filter(Q(project=project) | Q(project__isnull=True)).filter(q)
    by_service = {}
    for row in runs.order_by().values('service').annotate(assets=Count('asset', distinct=True), last=Max('finished_at')):
        entry = by_service.setdefault(row['service'].split(':')[0], {'assets': 0, 'last': None})
        entry['assets'] += row['assets']
        entry['last'] = max(filter(None, [entry['last'], row['last']]), default=None)
    services = [{'name': SERVICE_LABELS.get(k, clean(k, 60)), 'assets': v['assets'], 'last': _stamp(v['last'])}
                for k, v in sorted(by_service.items())]
    return {'scans': scans['n'] or 0, 'first_scan': _date(scans['first']), 'last_scan': _date(scans['last']), 'services': services}


# --- the whole report ----------------------------------------------------------------------------------------------------------

def collect(project, host=None, include_closed=False, now=None):
    """Everything one report prints, for the whole project or for one host (``host``: its exact name). Raises LookupError for a host the
    project's current inventory does not hold."""
    from startScan.models import Subdomain
    now = now or timezone.now()
    caps = limits()
    names = None
    if host:
        from cveFeed.correlation import latest_scan_q
        from agentapi import services as svc
        if not svc._scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q()).filter(name__iexact=host).exists():
            raise LookupError('host not found')
        names = {host.lower()}
    sources, ruled_out = _sources(project, include_closed, names=None if names is None else sorted(names))
    host_total, hosts = _hosts(project, host, _per_host(sources), caps['hosts'])
    if host and hosts:  # the host may answer to other names (same addresses): their findings are this host's too
        names |= {a.lower() for a in hosts[0].get('aliases', [])}
        sources, ruled_out = _sources(project, include_closed, names=sorted(names))
    total, heat, severity = _tally({k: v for k, v in sources.items() if k != 'hygiene'})
    hygiene_total, _, hygiene_severity = _tally({'hygiene': sources['hygiene']})
    detailed = _findings(sources, caps['findings'])
    hygiene = _hygiene(sources['hygiene'], caps['hygiene'])
    org = project.org
    return {
        'title': 'Host security report' if host else 'Security exposure report', 'subject': clean(host or project.name, 200),
        'project': clean(project.name, 200), 'organization': clean(org.name if org else '', 200), 'host': clean(host or '', 200),
        'generated': _stamp(now), 'generated_date': _date(now), 'include_closed': include_closed, 'branding': _branding(),
        'scope': {**_scope(project, host), 'hosts_total': host_total, 'hosts_listed': len(hosts)},
        'summary': {'findings': total, 'heat': heat, 'severity': severity, 'hygiene': hygiene_total, 'hygiene_severity': hygiene_severity,
                    'hosts_exposed': sum(1 for h in hosts if h['heat'] in ('fire', 'smoke')), 'ruled_out': ruled_out,
                    'top': detailed[:TOP_RISKS]},
        'hosts': hosts, 'findings': detailed, 'hygiene': hygiene,
        'caps': {**caps, 'findings_omitted': max(0, total - len(detailed)), 'hosts_omitted': max(0, host_total - len(hosts)),
                 'hygiene_omitted': max(0, hygiene_total - sum(len(g['items']) for g in hygiene)),
                 'hygiene_shown': sum(len(g['items']) for g in hygiene)},
        'method': _method(project, names, [a for h in hosts for a in h.get('address_list', [])]),
    }
