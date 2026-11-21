"""What goes into a report: one project's (or one host's) hosts and findings, or an organization's, read for the report and cleaned for printing.

Everything here runs in a worker as a named user (cveFeed.report_export re-checks that user's access first) and is filtered to the
project (or to the organization's project ids the user can read) explicitly, never by the request scope, which a worker does not have.
``project`` below is a Project, or ``svc.AllProjects`` over the ids of an organization report. The functions return plain dicts of short strings and
numbers: every string that came from a scanned host, a feed or a person is stripped of control characters and clipped here, and
HTML-escaped by the template (cveFeed/templates/cveFeed/report.html, autoescape on, no ``safe``), so a hostile banner or finding title
reaches the PDF as inert text.

The caps (hosts, detailed findings, hygiene rows) keep one report bounded: the totals and the heat and severity counts always cover
every finding, and the report says what the caps left out.
"""
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone as dt_timezone

from django.db.models import Count, Max, Min, Q
from django.utils import timezone

from cveFeed import closure
from targetApp.alias_note import ALIAS_MAX, NOTE_MAX

HEAT_NAMES = {3: 'fire', 2: 'smoke', 1: 'ice'}
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low')
STATUS_LABELS = closure.LABELS  # Open, In progress, Fixed, Accepted risk, False positive
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
    'hygiene': 'TLS, certificate and email checks', 'ct_watch': 'certificate transparency watch', 'wpscan': 'WordPress scan of WordPress sites',
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


def _status_counts(sources):
    """``{status label: count}`` over the whole set (CVE matches, scanner and hygiene findings), in the order of closure.STATUSES: the
    report's status legend when it includes closed findings."""
    tally = Counter()
    for qs in sources.values():
        for row in qs.order_by().values('remediation_status', 'triage__retest_state').annotate(n=Count('id')):
            # fixed is two rows of the legend: what a retest verified, and what was only marked fixed
            key = 'verified_fixed' if row['remediation_status'] == 'fixed' and row['triage__retest_state'] == 'verified_fixed' else row['remediation_status']
            tally[key] += row['n']
    labels = {**STATUS_LABELS, 'fixed': 'Marked fixed, not verified', 'verified_fixed': 'Verified fixed'}
    order = (*closure.STATUSES[:2], 'verified_fixed', *closure.STATUSES[2:])
    return {labels.get(k, clean(k, 24)): tally[k] for k in (*order, *sorted(set(tally) - set(order))) if tally[k]}


_PROJECT_SLUG = {'cve': 'subdomain__target_domain__project__slug', 'scanner': 'target_domain__project__slug', 'hygiene': 'domain__project__slug'}


def _per_host(sources, everywhere=False):
    """``{lowercase host: how many findings it has}`` over the whole set, for the host table. For an organization the key is ``(project slug,
    host)``: the same name in two projects is two hosts."""
    out = Counter()
    for key, qs in sources.items():
        field = 'host' if key == 'hygiene' else 'subdomain__name'
        fields = (field, _PROJECT_SLUG[key]) if everywhere else (field,)
        for row in qs.order_by().values(*fields).annotate(n=Count('id')):
            if row[field]:
                out[(row[_PROJECT_SLUG[key]], row[field].lower()) if everywhere else row[field].lower()] += row['n']
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


def _status_label(status, triage):
    """The status a report prints: a finding a retest verified is "Verified fixed", one only marked fixed is "Marked fixed, not verified" (or "... cannot be
    re-checked" when no check could repeat it), and one a retest reopened says so (``cveFeed.fix_retest``); every other status keeps its name."""
    from cveFeed import fix_retest
    state = fix_retest.summary(status, triage)['state']
    return {fix_retest.VERIFIED: 'Verified fixed', fix_retest.REPRODUCES: 'Open, reopened: a retest still reproduced it',
            fix_retest.NO_CHECK: 'Marked fixed, cannot be re-checked'}.get(state) or (
        'Marked fixed, not verified' if status == 'fixed' else STATUS_LABELS.get(status, clean(status, 24)))


def _tracking(obj):
    """The remediation state a person or agent recorded: status, assignee, note and when it last changed. ``closed``: the status closes the
    finding (fixed, accepted risk, false positive), so the note is printed as why it was closed."""
    from agentapi import services as svc
    return {'status': _status_label(obj.remediation_status, svc._triage_of(obj)), 'closed': closure.is_closed(obj.remediation_status),
            'assignee': _person(getattr(obj, 'assignee', None)), 'note': clean(obj.remediation_note, 800),
            'changed': _stamp(obj.remediation_updated_at), 'changed_by': _person(getattr(obj, 'remediation_by', None))}


_ISO = re.compile(r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})[\d:.]*(?:\+00:00|Z)?')


def _steps(how, cap=8):
    """The evidence lines of a finding's "how it was found", with ISO timestamps shortened to a date and a time."""
    return [{'label': clean(s['label'], 60), 'value': _ISO.sub(r'\1 \2', clean(s['value'], 240))} for s in how['steps'] if s.get('value')][:cap]


def _heat_policy():
    """``kev`` or ``legacy``: which rule the report's fire, smoke and ice counts follow (``threat.heat_policy``), for its legend."""
    from cveFeed.threat import heat_policy
    return heat_policy()


COMMAND_LIMIT = 2400


def _confirm(m):
    """A short "how to confirm it" for a version-based match in the report (cveFeed.confirm_guide): where to look, what to look for, the
    first commands and how to read the answer. Every command is the guide's own, built from the match's validated host, port and URL."""
    from agentapi import services as svc
    guide = svc._confirm_guide(m)
    if not guide:
        return None
    where = [clean(f"{w['label']}: {w.get('url') or w.get('text') or w.get('quote') or ''}", 300) for w in guide.get('where', [])[:3]]
    look = [clean(f"{x['label']}: {x.get('text') or x.get('quote') or ''}", 300) for x in guide.get('look_for', [])[:2]]
    # a command is printed whole (the guide built it from validated values, at most a 2,000-character URL in it): a cut command could leave a
    # quote open. One that is longer still is left out, and the reader is sent to the page
    steps, omitted = [], 0
    for st in [st for st in guide.get('steps', []) if st.get('command') and st.get('run_in') != 'active'][:3]:
        command = str(st['command'])
        if len(command) > COMMAND_LIMIT or '\n' in command:
            omitted += 1
            continue
        steps.append({'title': clean(st['title'], 120), 'command': command})
    verdict = guide.get('verdict') or {}
    precondition = guide.get('precondition') or {}
    return {'where': where, 'look_for': look, 'steps': steps,
            'omitted': 'A longer command is on the finding\'s page in cvENGINE (Confirm it yourself).' if omitted else '', 'affected': clean(verdict.get('affected', ''), 300),
            'not_affected': clean(verdict.get('not_affected', ''), 300),
            'needs': clean(precondition.get('needs') or (f"The advisory says: {precondition['quote']}" if precondition.get('quote') else ''), 400)}


def match_basis(m):
    """``(basis sentence, confirmed)`` of a CVE match: what the finding rests on, as the report and the CSV say it."""
    from agentapi import services as svc
    t = svc._triage_of(m)
    confirmed = m.template_result == 'vulnerable' or bool(t and t.validation_status == 'hit')
    return ('Confirmed: a check on the host reproduced it' if confirmed else
            'Reported by the host itself (its own inventory)' if m.source == 'host' else
            'Version-based: the detected version is inside the advisory range; not reproduced'), confirmed


def _match_entry(m, heat):
    from agentapi import services as svc
    from cveFeed.triage import verdict_text
    cve, t = m.cve_entry, svc._triage_of(m)
    text = verdict_text(t.verdict if t else None, t)  # the model's words only in the project the answer was reached in (task 256)
    basis, confirmed = match_basis(m)
    flags = [text for on, text in ((cve.kev, 'listed as exploited (CISA KEV)'), (cve.exploit_db, 'public exploit'),
                                   (cve.epss_reached, 'high exploitation probability (EPSS)')) if on]
    product = ' '.join(x for x in (m.matched_product, m.matched_version) if x)
    fixed = svc._fixed_versions(cve, m.matched_product)
    sub = m.subdomain
    from cveFeed.threat import heat_reason
    return {'kind': 'CVE match', 'title': clean(f'{cve.cve_id} in {product}' if product else cve.cve_id, 200), 'subtitle': clean(cve.title, 200),
            'host': clean(sub.name if sub else '', 200), 'heat': heat, 'severity': svc.SEVERITY_NAMES.get(m.sev, ''),
            'cves': [clean(cve.cve_id, 40)], 'cvss': cve.cvss, 'signals': flags, 'basis': basis, 'confirmed': confirmed,
            'heat_reason': clean(heat_reason(m, heat) if heat else '', 200),
            'description': clean(svc._cve_description(cve, 500), 500), 'impact': clean(text['impact'], 600),
            'evidence': _steps(svc._how_found_match(m)), 'proof': _proof(t), 'confirm': None if confirmed else _confirm(m),
            'remediation': clean(text['remediation'], 1200), 'fixed_in': [clean(v, 60) for v in fixed[:6]],
            'tracking': _tracking(m), 'first_seen': _date(svc._seen(m, 'first_seen', m.created_at)),
            'last_seen': _date(svc._seen(m, 'last_seen', m.updated_at))}


def _vulnerability_entry(v, heat):
    from agentapi import services as svc
    from cveFeed.triage import verdict_text
    t = svc._triage_of(v)
    text = verdict_text(t.verdict if t else None, t)
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
            'confirmed': confirmed, 'description': clean(v.description, 500), 'impact': clean(text['impact'] or v.impact, 600),
            'evidence': _steps(svc._how_found_vulnerability(v)), 'proof': proof[:5],
            'remediation': clean(text['remediation'] or v.remediation, 1200), 'fixed_in': [],
            'tracking': {**_tracking(v), **({'status': 'No longer detected'} if not v.open_status and v.remediation_status == 'open' else {})},
            'first_seen': _date(svc._seen(v, 'first_seen', v.discovered_date)), 'last_seen': _date(svc._seen(v, 'last_seen', v.discovered_date))}


def _tag_project(entry, project):
    """Name the project of an entry of an organization report (the rows were read with their project joined, so this is no query)."""
    entry['project'], entry['project_slug'] = clean(project.name, 200), project.slug
    return entry


def _findings(sources, cap, everywhere=False):
    """The top ``cap`` CVE matches and scanner findings together, hottest first, as report entries. ``everywhere``: an organization report, so each entry names its project."""
    epoch = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
    merged = [('cve', o) for o in sources['cve'][:cap]] + [('scanner', o) for o in sources['scanner'].prefetch_related('cve_ids')[:cap]]
    merged.sort(key=lambda p: (p[1].heat_rank, p[1].sev, p[1].when or epoch, p[1].id), reverse=True)
    out = []
    for key, obj in merged[:cap]:
        entry = (_match_entry if key == 'cve' else _vulnerability_entry)(obj, HEAT_NAMES.get(obj.heat_rank, ''))
        if everywhere:
            _tag_project(entry, obj.subdomain.target_domain.project if key == 'cve' else obj.target_domain.project)
        out.append(entry)
    return out


def _hygiene_group(check):
    if check.startswith(('tls_', 'tlsa_', 'cert')):  # tlsa_* are the TLS audit findings (cveFeed.tls_audit)
        return 'TLS and certificates'
    if check.startswith(('spf_', 'dmarc_', 'dkim_', 'mx_', 'mta_', 'bimi_', 'smtp_')):
        return 'Email'
    if check.startswith('cleartext_'):  # Telnet, FTP, rlogin and a plain-HTTP login (cveFeed.cleartext)
        return 'Cleartext services'
    return 'Other configuration'


def _hygiene(qs, cap, everywhere=False):
    """Hygiene findings (TLS, certificates, email, cleartext services) grouped by kind; each is {title, host, severity, detail, evidence, tracking}."""
    from agentapi import services as svc
    from cveFeed.triage import verdict_text
    groups = {}
    for f in qs[:cap]:
        t = svc._triage_of(f)
        text = verdict_text(t.verdict if t else None, t)
        entry = {
            'title': clean(f.title, 200), 'host': clean(f.host, 200), 'severity': svc.SEVERITY_NAMES.get(f.sev, ''),
            'heat': HEAT_NAMES.get(f.heat_rank, ''), 'check': clean(f.check_name, 40), 'detail': clean(f.detail, 600),
            'evidence': [{'label': clean(k, 40), 'value': clean(v, 160)} for k, v in list((f.evidence or {}).items())[:6]],
            'remediation': clean(text['remediation'], 800), 'tracking': _tracking(f),
            'first_seen': _date(f.first_seen)}
        groups.setdefault(_hygiene_group(f.check_name), []).append(_tag_project(entry, f.domain.project) if everywhere else entry)
    return [{'name': name, 'items': groups[name]} for name in ('TLS and certificates', 'Email', 'Cleartext services', 'Other configuration') if name in groups]


# --- hosts ---------------------------------------------------------------------------------------------------------------------

def _host_row(h, findings_by_host, detail, everywhere=False):
    ports = sorted({(p['number'], p['protocol'] or '') for ip in h['ips'] for p in ip['ports']})
    names = {h['host'].lower()} | {alias.lower() for alias in h['aliases']}
    if everywhere:
        names = {(h['project'], name) for name in names}
    row = {'host': clean(h['host'], 200), 'alias': clean(h['alias'], ALIAS_MAX), 'heat': h['heat'] if h['heat'] in ('fire', 'smoke', 'ice', 'clean', 'unscanned') else 'unscanned',
           'score': int(h['score'] or 0), 'findings': sum(findings_by_host.get(name, 0) for name in names), 'addresses': len(h['ips']),
           'ports': [f'{n}/{proto}' if proto else str(n) for n, proto in ports][:14], 'port_count': len(ports), 'ports_more': max(0, len(ports) - 14),
           'owner': clean(h['profile'].get('owner'), 80), 'criticality': clean(h['profile'].get('criticality'), 12),
           'technologies': [clean(t, 40) for t in h['technologies'][:6]]}
    if everywhere:
        row['project'], row['project_slug'] = clean(h['project_name'], 200), h['project']
    if detail:
        row['title'] = clean(h['title'], 200)
        row['http_status'] = h['http_status'] or ''
        row['aliases'] = [clean(a, 200) for a in h['aliases'][:10]]
        row['address_list'] = [clean(ip['address'], 64) for ip in h['ips'][:20]]
        row['purpose'] = clean(h['profile'].get('purpose'), 300)
        row['note'] = clean(h['note'], NOTE_MAX)
        row['score_lines'] = [{'label': clean(d.get('label'), 120), 'points': int(d.get('points') or 0)} for d in h['score_detail'][:12]]
        row['services'] = [{'address': clean(ip['address'], 64), 'port': f"{p['number']}/{p['protocol']}", 'service': clean(p['service'], 30),
                            'product': clean(' '.join(x for x in (p['product'], p['version']) if x), 80), 'banner': clean(p['banner'], 160)}
                           for ip in h['ips'] for p in ip['ports']][:40]
    return row


def _host_qs(project, host=None):
    """The current inventory's hosts of the scope as a queryset, one row per machine (a project: its own; an organization: one per project and name), with what a host row reads prefetched."""
    from agentapi import services as svc
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    everywhere = svc._is_all(project)
    qs = svc._scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q())
    if host:
        qs = qs.filter(name__iexact=host)
    return svc._one_per_host(qs, per_project=everywhere).select_related('target_domain__project' if everywhere else 'target_domain').prefetch_related(
        'ip_addresses__ports', 'cve_matches__cve_entry', svc.triage_prefetch('cve_matches__triage'), 'vulnerability_set', svc.triage_prefetch('vulnerability_set__triage'), 'vulnerability_set__cve_ids', 'vulnerability_set__tags',
        'technologies').order_by('-score', 'name', 'id')


def host_pages(project, qs, cap):
    """The host dicts of ``qs`` (``_host_qs``), hottest score first, a page of ``HOST_PAGE`` at a time, at most ``cap`` of them: a generator, so a CSV never holds them all."""
    from agentapi import services as svc
    total, sent, page = qs.count(), 0, 1
    while sent < min(cap, total):
        got = svc._hosts_page(project, qs, {'page': page, 'page_size': HOST_PAGE}, coverage=False)['results']
        if not got:
            break
        for row in got[:cap - sent]:
            yield row
        sent += len(got)
        page += 1


def _hosts(project, host, findings_by_host, cap):
    """``(total, host rows, aliases, raw)``. A host report reads one host and keeps its full alias list for finding scope. ``raw`` are the host dicts the rows were made from."""
    from agentapi import services as svc
    qs = _host_qs(project, host)
    raw = list(host_pages(project, qs, cap))
    aliases = raw[0]['aliases'] if host and raw else []
    everywhere = svc._is_all(project)
    return qs.count(), [_host_row(h, findings_by_host, detail=bool(host), everywhere=everywhere) for h in raw], aliases, raw


def _hosts_overview(raw, hosts, new_hosts):
    """The hosts report's summary over the hosts it lists: how many are on fire, smoke or ice, the technologies and open ports most of them share, and the hosts found in the last 30 days."""
    heat = Counter(h['heat'] for h in hosts)
    techs = Counter(clean(t, 40) for h in raw for t in h['technologies'])
    ports = Counter(f'{n}/{proto}' if proto else str(n) for h in raw for n, proto in {(p['number'], p['protocol'] or '') for ip in h['ips'] for p in ip['ports']})
    return {'heat': {k: heat[k] for k in ('fire', 'smoke', 'ice', 'clean', 'unscanned')},
            'technologies': [{'name': name, 'hosts': n} for name, n in sorted(techs.items(), key=lambda kv: (-kv[1], kv[0]))[:10]],
            'ports': [{'port': port, 'hosts': n} for port, n in sorted(ports.items(), key=lambda kv: (-kv[1], kv[0]))[:10]],
            'new_30d': new_hosts}


def _new_hosts(project, now):
    """How many machines the scope's projects found in the 30 days to ``now`` (an AssetChange ``host_new`` row each, a name once per project)."""
    from agentapi import services as svc
    from cveFeed.models import AssetChange
    qs = svc._scoped(AssetChange.objects.all(), project, 'project').filter(kind='host_new', detected_at__gte=now - timedelta(days=30), detected_at__lte=now)
    return len({(pid, host.lower()) for pid, host in qs.values_list('project_id', 'host')})


def _label_hosts(project, hosts, entries):
    """Set ``host_alias`` on each of ``entries`` (findings, hygiene rows): the alias of the host it names, from the listed hosts (which resolve it
    across the names on one set of addresses) or else the host's own profile, one query. Display only; ``host`` stays the name. In an
    organization report a host is its project and its name."""
    from agentapi import services as svc
    from cveFeed.models import HostProfile
    everywhere = svc._is_all(project)
    key = (lambda e_or_h, name: (e_or_h.get('project_slug', ''), name.lower())) if everywhere else (lambda e_or_h, name: name.lower())
    known = {key(h, h['host']): h['alias'] for h in hosts if h['alias']}
    for h in hosts:
        known.update({key(h, a): h['alias'] for a in h.get('aliases', ()) if h['alias']})
    named = {key(e, e['host']) for e in entries if e['host']} - set(known)
    if named:
        qs = HostProfile.objects.filter(project_id__in=list(project.ids), host__in={n[1] for n in named}).select_related('project') if everywhere else \
            HostProfile.objects.filter(project=project, host__in=named)
        known.update({((row.project.slug, row.host) if everywhere else row.host): clean(row.alias, ALIAS_MAX) for row in qs.exclude(alias='')})
    for e in entries:
        e['host_alias'] = known.get(key(e, e['host'] or ''), '')


# --- scope and method ----------------------------------------------------------------------------------------------------------

def _pq(project, field):
    """A filter on ``field`` (a foreign key to a project): that project, or the organization report's project ids."""
    from agentapi import services as svc
    return Q(**{f'{field}_id__in': list(project.ids)}) if svc._is_all(project) else Q(**{field: project})


def _scope(project, host):
    from agentapi import services as svc
    from targetApp.models import Domain
    domains = svc._scoped(Domain.objects.all(), project, 'project').order_by('name')
    count = domains.count()
    return {'targets': count, 'targets_more': max(0, count - 15),
            'target_names': [clean(f'{n} ({a})' if a else n, 180) for n, a in domains.values_list('name', 'alias')[:15]]}  # a target's alias beside its name


SCAN_DONE = 2


def _method(project, names, addresses):
    """What was scanned and when: scan counts and dates, and the last run of each scanner (the service ledger) on this scope. ``names`` and
    ``addresses`` narrow it to one host's names and IPs; None is the whole project."""
    from cveFeed.models import ServiceRun
    from startScan.models import IpAddress, ScanHistory
    scans = ScanHistory.objects.filter(_pq(project, 'domain__project'), scan_status=SCAN_DONE).aggregate(
        n=Count('id'), first=Min('start_scan_date'), last=Max('start_scan_date'))
    runs = ServiceRun.objects.filter(status='done')
    if names is None:  # the global nmap rows (no project) count when they are about one of this project's addresses
        mine = IpAddress.objects.filter(_pq(project, 'ip_addresses__target_domain__project')).values('address')
        runs = runs.filter(_pq(project, 'project') | Q(project__isnull=True, asset__in=mine))
    else:
        assets = {n.lower() for n in names} | set(addresses)
        q = Q(asset__in=sorted(assets))
        for asset in sorted(assets):
            q |= Q(asset__startswith=f'{asset}:')  # a host:port asset
        runs = runs.filter(_pq(project, 'project') | Q(project__isnull=True)).filter(q)
    by_service = {}
    for row in runs.order_by().values('service').annotate(assets=Count('asset', distinct=True), last=Max('finished_at')):
        entry = by_service.setdefault(row['service'].split(':')[0], {'assets': 0, 'last': None})
        entry['assets'] += row['assets']
        entry['last'] = max(filter(None, [entry['last'], row['last']]), default=None)
    services = [{'name': SERVICE_LABELS.get(k, clean(k, 60)), 'assets': v['assets'], 'last': _stamp(v['last'])}
                for k, v in sorted(by_service.items())]
    return {'scans': scans['n'] or 0, 'first_scan': _date(scans['first']), 'last_scan': _date(scans['last']), 'services': services}


# --- the whole report ----------------------------------------------------------------------------------------------------------

MAX_SECRETS = 100  # inventory rows printed in one report, worst first


def _secrets(project, names, include_closed):
    """``(total, rows)``: the project's exposed secrets (cveFeed.secrets_inventory), worst first, at most MAX_SECRETS. Masked values only: the
    report never holds a secret. For a host report, the ones that host serves."""
    from cveFeed import secrets_catalog, secrets_inventory
    from cveFeed.models import SecretFinding
    from agentapi import services as svc
    qs = svc._scoped(SecretFinding.objects.all(), project, 'project')
    if not include_closed:
        qs = qs.exclude(status__in=secrets_catalog.QUIET_STATUSES)
    if names is not None:
        qs = qs.filter(occurrences__host__in=sorted(names), occurrences__retired_at__isnull=True).distinct()
    total = qs.count()
    rows = []
    for s in qs.order_by('-severity', '-last_seen', 'id')[:MAX_SECRETS]:
        kind = secrets_inventory.kind_of(s)
        hosts = sorted(set(s.occurrences.filter(retired_at__isnull=True).values_list('host', flat=True)))
        rows.append({'severity': secrets_catalog.LEVELS[max(0, min(4, s.severity))], 'label': clean(kind.label, 120), 'masked': clean(s.masked, 80),
                     'class': secrets_catalog.CLASS_WORDS.get(s.klass, ''), 'status': s.status.replace('_', ' '), 'basis': clean(s.severity_basis, 300),
                     'remediation': clean(kind.remediation, 400), 'hosts': ', '.join(clean(h, 120) for h in hosts[:5]) + (f' and {len(hosts) - 5} more' if len(hosts) > 5 else '')})
    return total, rows


def collect(project, host=None, include_closed=False, now=None, kind='findings', org=None, whole=True):
    """Everything one report prints, for the whole project or for one host (``host``: its exact name). Raises LookupError for a host the
    project's current inventory does not hold.

    ``project`` is a Project, or ``svc.AllProjects`` over the ids of an organization report (``org``: the Organization; ``whole`` False when the person
    can read only some of its projects, which the cover says). ``kind='hosts'`` makes the discovered hosts report: the host table and its summary,
    with no finding, hygiene or secret sections (a host row still counts its open findings)."""
    from agentapi import services as svc
    from startScan.models import Subdomain
    now = now or timezone.now()
    caps = limits()
    names = None
    everywhere = svc._is_all(project)
    if kind not in ('findings', 'hosts') or (everywhere and (host or org is None)):
        raise ValueError('a report is of one project or one organization, as a findings or a hosts report; a host report is of one project')
    if host:
        from cveFeed.correlation import latest_scan_q
        if not svc._scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q()).filter(name__iexact=host).exists():
            raise LookupError('host not found')
        names = {host.lower()}
    hosts_report = kind == 'hosts'
    sources, ruled_out = _sources(project, False if hosts_report else include_closed, names=None if names is None else sorted(names))
    host_total, hosts, aliases, raw = _hosts(project, host, _per_host(sources, everywhere), caps['hosts'])
    if host and hosts:  # the host may answer to other names (same addresses): their findings are this host's too
        names |= {a.lower() for a in aliases}
        sources, ruled_out = _sources(project, include_closed, names=sorted(names))
        hosts[0]['findings'] = sum(_per_host(sources).values())
    total, heat, severity = _tally({k: v for k, v in sources.items() if k != 'hygiene'})
    hygiene_total, _, hygiene_severity = _tally({'hygiene': sources['hygiene']})
    if hosts_report:
        detailed, hygiene, secrets_total, secrets = [], [], 0, []
        _label_hosts(project, hosts, [])
    else:
        detailed = _findings(sources, caps['findings'], everywhere)
        hygiene = _hygiene(sources['hygiene'], caps['hygiene'], everywhere)
        _label_hosts(project, hosts, [*detailed, *(item for g in hygiene for item in g['items'])])
        secrets_total, secrets = _secrets(project, names, include_closed)
    if everywhere:
        from dashboard.models import Project
        project_names = [clean(n, 200) for n in Project._base_manager.filter(pk__in=list(project.ids)).order_by('name').values_list('name', flat=True)]
        label, organization = clean(org.name, 200), clean(org.name, 200)
        scope_projects = {'count': len(project_names), 'names': project_names[:15], 'more': max(0, len(project_names) - 15), 'whole': bool(whole)}
        project_line = f"{len(project_names)} project{'' if len(project_names) == 1 else 's'}"
    else:
        label, organization = clean(host or project.name, 200), clean(project.org.name if project.org else '', 200)
        scope_projects = None
        project_line = clean(project.name, 200)
    return {
        'kind': kind, 'scope_kind': 'org' if everywhere else 'project', 'scope_projects': scope_projects,
        'title': 'Discovered hosts report' if hosts_report else 'Host security report' if host else 'Security exposure report', 'subject': label,
        'project': project_line, 'organization': organization, 'host': clean(host or '', 200),
        'host_alias': hosts[0]['alias'] if host and hosts else '', 'host_note': hosts[0].get('note', '') if host and hosts else '',
        'generated': _stamp(now), 'generated_date': _date(now), 'include_closed': False if hosts_report else include_closed, 'branding': _branding(),
        'scope': {**_scope(project, host), 'hosts_total': host_total, 'hosts_listed': len(hosts)},
        'summary': {'findings': total, 'heat': heat, 'heat_policy': _heat_policy(), 'severity': severity, 'hygiene': hygiene_total,
                    'hygiene_severity': hygiene_severity,
                    'hosts_exposed': sum(1 for h in hosts if h['heat'] in ('fire', 'smoke')), 'ruled_out': ruled_out,
                    'status_counts': _status_counts(sources) if not hosts_report else {},
                    'top': detailed[:TOP_RISKS]},
        'hosts_summary': _hosts_overview(raw, hosts, _new_hosts(project, now)) if hosts_report else None,
        'hosts': hosts, 'findings': detailed, 'hygiene': hygiene, 'secrets': secrets, 'secrets_total': secrets_total,
        'caps': {**caps, 'findings_omitted': max(0, total - len(detailed)), 'hosts_omitted': max(0, host_total - len(hosts)),
                 'hygiene_omitted': max(0, hygiene_total - sum(len(g['items']) for g in hygiene)),
                 'hygiene_shown': sum(len(g['items']) for g in hygiene)},
        'method': _method(project, names, [a for h in hosts for a in h.get('address_list', [])]),
    }
