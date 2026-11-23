"""What goes into a report: one project's (or one host's) hosts and findings, or an organization's, read for the report and cleaned for printing.

Everything here runs in a worker as a named user (cveFeed.report_export re-checks that user's access first) and is filtered to the
project (or to the organization's project ids the user can read) explicitly, never by the request scope, which a worker does not have.
``project`` below is a Project, or ``svc.AllProjects`` over the ids of an organization report. The functions return plain dicts of short strings and
numbers: every string that came from a scanned host, a feed or a person is stripped of control characters and clipped here, and
HTML-escaped by the template (cveFeed/templates/cveFeed/report.html, autoescape on, no ``safe``), so a hostile banner or finding title
reaches the PDF as inert text.

The findings report reads like a penetration test report. The open findings are grouped into ISSUES (``_issues``): one CVE on five hosts
is one issue that lists the five hosts, a scanner finding is grouped by its template and title, a hygiene finding by its check. Each issue
gets one of five professional severities (``rate``, documented there and on the report's methodology page), the issues are numbered and
ordered by severity and then by how many hosts they affect, and only the critical, high and medium ones get a full write-up; low and
informational issues are one line each in an appendix. The caps (``limits``) bound the write-ups, the host rows of one issue, the appendix
tables and the rows read; the counts always cover every finding read, and the report says what the caps left out.
"""
import os
import re
from collections import Counter
from datetime import timedelta

from django.db.models import Count, Max, Min, Q
from django.utils import timezone

from cveFeed import closure
from targetApp.alias_note import ALIAS_MAX, NOTE_MAX

HEAT_NAMES = {3: 'fire', 2: 'smoke', 1: 'ice'}
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low')
STATUS_LABELS = closure.LABELS  # Open, In progress, Fixed, Accepted risk, False positive
PROVING = ('hit', 'observed', 'reaffirmed')  # the validation results that show the finding on the host
FALSE_POSITIVES = ('likely_false_positive', 'not_applicable')  # triage classes no count calls open (cveFeed.counts.TRIAGE_DISMISSED)
HOST_PAGE = 100

# the caps of one report: (environment variable, default, ceiling). docs/CONFIGURATION.md lists them.
CAPS = {
    'hosts': ('CVENGINE_REPORT_MAX_HOSTS', 500, 5000),  # rows of the discovered hosts report
    'writeups': ('CVENGINE_REPORT_MAX_WRITEUPS', 50, 500),  # detailed write-ups (critical, high and medium issues)
    'issue_hosts': ('CVENGINE_REPORT_MAX_ISSUE_HOSTS', 25, 500),  # affected-host rows printed under one issue
    'minor': ('CVENGINE_REPORT_MAX_MINOR', 200, 5000),  # rows of the low and informational appendix
    'inventory': ('CVENGINE_REPORT_MAX_INVENTORY', 200, 5000),  # rows of the asset inventory appendix of a findings report
    'closed': ('CVENGINE_REPORT_MAX_CLOSED', 300, 5000),  # rows of the closed findings appendix
    'rows': ('CVENGINE_REPORT_MAX_ROWS', 20000, 100000),  # findings read per kind (CVE, scanner, hygiene) to group
}
SUMMARY_ROWS = 150  # rows of the summary of findings table (critical, high and medium issues)
TRACKING_ROWS = 10  # hosts whose assignee or note an issue prints
PROOF_HOSTS = 3  # confirmed hosts whose proof an issue prints
TOP_ISSUES = 4  # issues the executive summary names
TOP_ACTIONS = 5  # key recommendations

# --- severity -----------------------------------------------------------------------------------------------------------------

LEVELS = ('critical', 'high', 'medium', 'low', 'info')
LEVEL_LABELS = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Informational'}
LEVEL_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
DETAILED = ('critical', 'high', 'medium')  # the levels that get a full write-up
SCANNER_LEVELS = {0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
HYGIENE_CEILING = 'high'  # a configuration finding is at most High, whatever its check says

# what a finding rests on, strongest first
BASIS = ('Confirmed', 'Likely', 'Detected', 'Version match')
BASIS_TEXT = {
    'Confirmed': 'Confirmed: a check on the host reproduced it.',
    'Likely': 'Likely: the version was proven on the host (its own inventory, its distribution or the component itself), but the flaw was not reproduced.',
    'Detected': 'Detected: a scanner check or configuration check observed it directly; not independently reproduced.',
    'Version match': 'Version match: the version the service reports is inside the affected range. This suggests the flaw is present but does not prove it.',
}


def cve_base(cvss, kev):
    """The severity a CVE carries on its own, before what cvENGINE knows about the host: Critical when it is on CISA's KEV list or rated
    CVSS 9.0 or higher, High from 7.0, Medium from 4.0, Low below; Medium when the advisory has no CVSS score."""
    if kev or (cvss is not None and cvss >= 9.0):
        return 'critical'
    if cvss is None:
        return 'medium'
    return 'high' if cvss >= 7.0 else 'medium' if cvss >= 4.0 else 'low'


def rate(kind, heat, base, kev=False, confirmed=False, version_only=False, weak=False):
    """The report's severity of one finding: one of ``LEVELS``. The one place the five professional levels come from; the methodology page
    of the report says the same in words.

    ``base`` is the finding's own severity: a CVE's from its CVSS and KEV listing (``cve_base``), a scanner or hygiene finding's the one its
    check states. ``heat`` is cvENGINE's fire, smoke or ice for it (``threat``: how dangerous it is on THIS host, from exploitation
    signals and proof), and caps the base so the report agrees with the rest of cvENGINE:

      * fire: the base stands;
      * smoke: at most High;
      * ice: Low (not known to be exploited, or not proven); Informational for a CVE match that is weak on its face (a fix the
        distribution backported, a version that could not be read, CVSS below 4.0) or a finding whose check rates it informational;
        Medium when a check confirmed it and its base is High or Critical (proof outranks the missing exploitation signal);
      * no heat: Informational.

    Two rules on top: a CVE match that rests on its version alone is never Critical unless the CVE is on the KEV list (a version is no
    proof), and a hygiene (configuration) finding is at most High."""
    if heat == 'fire':
        level = base
    elif heat == 'smoke':
        level = base if LEVEL_RANK[base] <= LEVEL_RANK['high'] else 'high'
    elif heat == 'ice':
        if weak or base == 'info':
            level = 'info'
        elif confirmed and LEVEL_RANK[base] >= LEVEL_RANK['high']:
            level = 'medium'
        else:
            level = 'low'
    else:
        level = 'info'
    if level == 'critical' and kind == 'cve' and version_only and not kev:
        level = 'high'
    if kind == 'hygiene' and LEVEL_RANK[level] > LEVEL_RANK[HYGIENE_CEILING]:
        level = HYGIENE_CEILING
    return level


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
    return {key: _env_int(name, default, ceiling) for key, (name, default, ceiling) in CAPS.items()}


def _date(value):
    return value.strftime('%Y-%m-%d') if value else ''


def _long_date(value):
    return f'{value:%B} {value.day}, {value:%Y}' if value else ''


def _stamp(value):
    return value.strftime('%Y-%m-%d %H:%M UTC') if value else ''


def _person(user):
    return clean(user.get_full_name() or user.username, 80) if user else ''


def _plural(n, word, plural=None):
    return f'{n:,} {word if n == 1 else plural or word + "s"}'


def _first_sentence(text, limit=240):
    text = ' '.join((text or '').split())
    m = re.match(r'(.+?[.!?])(\s|$)', text)
    return clean(m.group(1) if m else text, limit)


def _branding():
    """Company name, accent colour and footer from Settings > Reports. The colour goes into a stylesheet, so it must be exactly #RRGGBB."""
    from scanEngine.models import VulnerabilityReportSetting
    row = VulnerabilityReportSetting.objects.first()
    color = row.primary_color if row and re.fullmatch(r'#[0-9a-fA-F]{6}', row.primary_color or '') else '#c2410c'
    return {'company': clean(row.company_name, 100) if row else '', 'accent': color,
            'footer': clean(row.footer_text, 200) if row and row.show_footer else ''}


# --- findings ------------------------------------------------------------------------------------------------------------------

def _host_names_q(prefix, names, endpoints=False):
    """The rows of these host names; with ``endpoints`` (a hygiene finding's ``host``) also a certificate or TLS finding of ``name:port``."""
    q = Q(pk__in=[])
    for name in names:
        q |= Q(**{f'{prefix}__iexact': name})
        if endpoints:
            q |= Q(**{f'{prefix}__iregex': '^' + re.escape(name) + ':[0-9]+$'})
    return q


def _sources(project, include_closed, names=None):
    """``({cve, scanner, hygiene: queryset}, ruled_out)``: the project's findings in the order the Findings page uses (hottest first),
    open ones only unless ``include_closed``. Matches the AI ruled out, and findings triage classed as a false positive or not
    applicable, are never listed; ``ruled_out`` counts them so the report can say so. ``names`` limits it to those hosts."""
    from agentapi import services as svc
    sources = svc._finding_sources(project, {'status': 'all' if include_closed else 'actionable'}, keep_dismissed=True)
    out, ruled_out = {}, 0
    for key, qs in sources.items():
        if key == 'cve':
            qs = qs.exclude(ai_verdict='not_affected')
        elif include_closed:
            qs = qs.filter(severity__gte=1)  # a closed informational detection is not a finding to report
        if names is not None:
            qs = qs.filter(_host_names_q('host' if key == 'hygiene' else 'subdomain__name', names, endpoints=key == 'hygiene'))
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


def open_counts(sources):
    """``{findings, heat, severity, by_kind}`` of the open CVE matches and scanner findings of ``sources`` (``_sources(..., False)``): the one
    definition of a heat line (``cveFeed.counts.HEAT_KINDS``) that the PDF report's summary and the weekly email both print, so they cannot
    disagree. Hygiene findings have no heat of their own and are counted apart."""
    from cveFeed.counts import HEAT_KINDS
    kinds = {k: v for k, v in sources.items() if k in HEAT_KINDS}
    by_kind = {}
    for kind, qs in kinds.items():
        by_kind[kind] = _tally({kind: qs})
    heat = {k: sum(t[1][k] for t in by_kind.values()) for k in ('fire', 'smoke', 'ice')}
    severity = {k: sum(t[2][k] for t in by_kind.values()) for k in SEVERITY_ORDER}
    return {'findings': sum(t[0] for t in by_kind.values()), 'heat': heat, 'severity': severity,
            'by_kind': {k: t[0] for k, t in by_kind.items()}}


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
    host)``: the same name in two projects is two hosts. A certificate or TLS finding of ``name:443`` counts for ``name`` (``host_resolver.base_name``)."""
    from cveFeed.host_resolver import base_name
    out = Counter()
    for key, qs in sources.items():
        field = 'host' if key == 'hygiene' else 'subdomain__name'
        fields = (field, _PROJECT_SLUG[key]) if everywhere else (field,)
        for row in qs.order_by().values(*fields).annotate(n=Count('id')):
            if row[field]:
                name = base_name(row[field])
                out[(row[_PROJECT_SLUG[key]], name) if everywhere else name] += row['n']
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


def _cve_references(cve, cap=3):
    """Up to ``cap`` https links the advisory lists (printed as text; the renderer fetches nothing), the NVD page first."""
    out = [f'https://nvd.nist.gov/vuln/detail/{cve.cve_id}'] if re.fullmatch(r'CVE-\d{4}-\d{4,}', cve.cve_id or '') else []
    for ref in (cve.references if isinstance(cve.references, list) else [])[:40]:
        url = ref if isinstance(ref, str) else ref.get('url', '') if isinstance(ref, dict) else ''
        if isinstance(url, str) and url.startswith('https://') and len(url) <= 200 and '@' not in url.split('/')[2] and url not in out:
            out.append(clean(url, 200))
        if len(out) >= cap:
            break
    return out


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
            'host': clean(sub.name if sub else '', 200), 'heat': heat, 'severity': svc.SEVERITY_NAMES.get(getattr(m, 'sev', None), ''),
            'cves': [clean(cve.cve_id, 40)], 'cvss': cve.cvss, 'signals': flags, 'basis': basis, 'confirmed': confirmed,
            'heat_reason': clean(heat_reason(m, heat) if heat else '', 200),
            'description': clean(svc._cve_description(cve, 700), 700), 'impact': clean(text['impact'], 600),
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
            'confirmed': confirmed, 'description': clean(v.description, 700), 'impact': clean(text['impact'] or v.impact, 600),
            'evidence': _steps(svc._how_found_vulnerability(v)), 'proof': proof[:5],
            'remediation': clean(text['remediation'] or v.remediation, 1200), 'fixed_in': [],
            'tracking': {**_tracking(v), **({'status': 'No longer detected'} if not v.open_status and v.remediation_status == 'open' else {})},
            'first_seen': _date(svc._seen(v, 'first_seen', v.discovered_date)), 'last_seen': _date(svc._seen(v, 'last_seen', v.discovered_date))}


def _hygiene_group(check):
    if check.startswith(('tls_', 'tlsa_', 'cert')):  # tlsa_* are the TLS audit findings (cveFeed.tls_audit)
        return 'TLS and certificates'
    if check.startswith(('spf_', 'dmarc_', 'dkim_', 'mx_', 'mta_', 'bimi_', 'smtp_')):
        return 'Email'
    if check.startswith('cleartext_'):  # Telnet, FTP, rlogin and a plain-HTTP login (cveFeed.cleartext)
        return 'Cleartext services'
    return 'Other configuration'


# the common hygiene checks in a report's words: (issue title, why it matters, what to do). A check not listed takes its own title.
_CERT_EXPIRED = ('Expired TLS certificate',
                 'Clients reject the certificate or show a warning. People learn to click through warnings, which makes it easier for an attacker on the network path to impersonate the service.',
                 'Renew the certificate and install it with its full chain. Automate renewal (for example with ACME) and monitor expiry dates.')
_CERT_EXPIRING = ('TLS certificate about to expire',
                  'When the certificate expires, clients will reject it or show a warning, and the service may become unusable.',
                  'Renew the certificate before it expires, and automate renewal so it does not lapse again.')
CHECK_TEXT = {
    'tls_expired': _CERT_EXPIRED, 'cert_expired': _CERT_EXPIRED, 'tls_expiring': _CERT_EXPIRING, 'cert_expiring': _CERT_EXPIRING,
    'tls_self_signed': ('Self-signed TLS certificate',
                        'Users cannot verify that they are talking to the real service, so an attacker on the network path can intercept the connection without a warning that stands out.',
                        'Replace the certificate with one issued by a trusted certificate authority.'),
    'tls_untrusted_chain': ('Untrusted TLS certificate chain', 'Clients cannot build a path to a trusted root, so they reject the connection or warn the user.',
                            'Install the intermediate certificates the issuing authority provides, or replace the certificate with one from a trusted authority.'),
    'tls_hostname_mismatch': ('TLS certificate does not match the host name', 'Clients warn that the certificate is for another name, which trains users to ignore warnings.',
                              'Issue a certificate that names this host, or stop serving TLS on a name the certificate does not cover.'),
    'tls_weak_key': ('Weak TLS certificate key', 'A short key can be broken with enough computing power, which would let an attacker impersonate the service.',
                     'Reissue the certificate with an RSA key of at least 2048 bits or an ECDSA key of at least 256 bits.'),
    'tls_weak_signature': ('Weak TLS certificate signature', 'A weak signature algorithm (such as SHA-1) can allow a forged certificate.',
                           'Reissue the certificate with a SHA-256 or stronger signature.'),
    'tls_legacy_protocol': ('Legacy TLS protocol versions enabled', 'Old protocol versions (SSLv3, TLS 1.0 and 1.1) have known weaknesses that can expose traffic.',
                            'Disable SSLv3, TLS 1.0 and TLS 1.1 and offer TLS 1.2 and 1.3 only.'),
    'hsts_missing': ('No HTTP Strict Transport Security policy', 'Browsers may connect over plain HTTP first, which lets an attacker on the network path downgrade the connection.',
                     'Send a Strict-Transport-Security header with a max-age of at least six months on every HTTPS response.'),
    'hsts_weak': ('Weak HTTP Strict Transport Security policy', 'A short max-age leaves gaps in which browsers may connect over plain HTTP.',
                  'Raise the Strict-Transport-Security max-age to at least six months.'),
    'spf_missing': ('No SPF record', 'Receiving mail servers cannot tell which servers may send mail for the domain, which makes spoofed mail from it easier to deliver.',
                    'Publish an SPF record that lists the servers allowed to send mail for the domain and ends in -all or ~all.'),
    'spf_allow_all': ('SPF record allows any sender', 'An SPF record ending in +all lets any server send mail as the domain.',
                      'End the SPF record in -all or ~all and list only the servers that send mail for the domain.'),
    'spf_softfail': ('SPF record ends in a soft fail', 'Receivers accept mail that fails SPF, so the record does little to stop spoofing on its own.',
                     'Move to -all once every legitimate sender is listed, and enforce DMARC.'),
    'spf_too_many_lookups': ('SPF record needs too many DNS lookups', 'Receivers stop after 10 lookups and treat the record as broken, so legitimate mail can fail SPF.',
                             'Flatten or reduce the include chain so the record needs at most 10 lookups.'),
    'dmarc_missing': ('No DMARC record', 'Receivers have no policy for mail that fails SPF and DKIM, so spoofed mail from the domain is more likely to be delivered.',
                      'Publish a DMARC record, start with p=none and reports, then move to p=quarantine or p=reject.'),
    'dmarc_none': ('DMARC policy does not act on failing mail (p=none)', 'Mail that fails authentication is still delivered, so the domain can be spoofed.',
                   'Move the DMARC policy to p=quarantine and then p=reject once legitimate senders pass.'),
    'dkim_not_found': ('No DKIM key found', 'Without DKIM, receivers cannot verify that mail from the domain was not altered or forged.',
                       'Sign outgoing mail with DKIM and publish the public key in DNS.'),
    'mta_sts_missing': ('No MTA-STS policy', 'Mail servers sending to the domain may fall back to unencrypted delivery if an attacker interferes with STARTTLS.',
                        'Publish an MTA-STS policy and a TLS-RPT record for the domain.'),
    'cleartext_telnet': ('Telnet service reachable', 'Telnet sends logins and commands in clear text, so anyone on the network path can read them.',
                         'Turn Telnet off and use SSH. If it must stay, limit it to a management network.'),
    'cleartext_ftp': ('FTP service reachable', 'FTP sends logins and files in clear text, so anyone on the network path can read them.',
                      'Replace FTP with SFTP or FTPS, or limit it to a trusted network.'),
    'cleartext_rservices': ('rlogin or rsh service reachable', 'The r-services send logins in clear text and trust addresses that can be spoofed.',
                            'Turn the r-services off and use SSH.'),
}


def _hygiene_title(check, titles):
    if check in CHECK_TEXT:
        return CHECK_TEXT[check][0]
    distinct = {t for t in titles if t}
    if len(distinct) == 1:
        return next(iter(distinct))
    return clean(check.replace('_', ' ').strip().capitalize() or 'Configuration finding', 120)


def _hygiene_entry(f):
    """One hygiene finding as a report entry (description, evidence, remediation), for the write-up of its issue."""
    from agentapi import services as svc
    from cveFeed.triage import verdict_text
    t = svc._triage_of(f)
    text = verdict_text(t.verdict if t else None, t)
    known = CHECK_TEXT.get(f.check_name)
    return {'description': clean(f.detail, 700), 'impact': clean(text['impact'] or (known[1] if known else ''), 600),
            'remediation': clean(text['remediation'] or (known[2] if known else ''), 800),
            'evidence': [{'label': clean(k, 40), 'value': clean(v, 160)} for k, v in list((f.evidence or {}).items())[:6]]}


# --- issues: the findings grouped across hosts -----------------------------------------------------------------------------------

def _host_of(kind, obj):
    if kind == 'hygiene':
        return obj.host or ''
    if obj.subdomain_id:
        return obj.subdomain.name
    return obj.target_domain.name if kind == 'scanner' and obj.target_domain_id else ''


def _project_of(kind, obj):
    if kind == 'cve':
        return obj.subdomain.target_domain.project if obj.subdomain_id else None
    return obj.target_domain.project if kind == 'scanner' else obj.domain.project


def _is_open(kind, obj):
    if closure.is_closed(obj.remediation_status):
        return False
    if kind == 'scanner':
        return bool(obj.open_status)
    if kind == 'hygiene':
        return obj.status == 'open'
    return True


def _instance(kind, obj, everywhere):
    """One finding as a row of its issue: the grouping key, the report severity and basis, the host and where it was seen, and its
    tracking. ``obj`` stays on the row (``_obj``) for the write-up; it is dropped before the data leaves ``collect``."""
    from agentapi import services as svc
    from cveFeed import match_policy
    heat = HEAT_NAMES.get(obj.heat_rank, '')
    host = clean(_host_of(kind, obj), 200)
    detail, cvss, kev, exploit, cve_ids = '', None, False, False, []
    if kind == 'cve':
        cve = obj.cve_entry
        _, confirmed = match_basis(obj)
        version_only = match_policy.is_version_only(obj)
        basis = 'Confirmed' if confirmed else 'Likely' if (not version_only or match_policy.version_proven(obj)) else 'Version match'
        weak = obj.distro_status == 'patched' or match_policy.version_unknown(obj) or (cve.cvss is not None and cve.cvss < 4.0)
        base = cve_base(cve.cvss, cve.kev)
        level = rate('cve', heat, base, kev=bool(cve.kev), confirmed=confirmed, version_only=version_only, weak=weak)
        product = ' '.join(x for x in (obj.matched_product, obj.matched_version) if x)
        ev = obj.evidence if isinstance(obj.evidence, dict) else {}
        where = f"port {ev['port']}" if obj.source == 'port' and ev.get('port') else 'host inventory' if obj.source == 'host' else ''
        detail = clean(', '.join(x for x in (product, where) if x), 160)
        key = ('cve', cve.cve_id.upper())
        title = clean(f'{cve.cve_id} in {product}' if product else cve.cve_id, 200)
        cvss, kev, cve_ids = cve.cvss, bool(cve.kev), [clean(cve.cve_id, 40)]
        exploit = bool(cve.exploit_db)
        first = svc._seen(obj, 'first_seen', obj.created_at)
        product_key = clean((obj.matched_product or '').strip(), 80)
    elif kind == 'scanner':
        t = svc._triage_of(obj)
        confirmed = bool(t and t.validation_status == 'hit')
        basis = 'Confirmed' if confirmed else 'Detected'
        base = SCANNER_LEVELS.get(obj.severity, 'info')
        level = rate('scanner', heat, base, confirmed=confirmed)
        key = ('scanner', (obj.template_id or '').strip().lower(), ' '.join((obj.name or '').split()).lower())
        title = clean(obj.name, 200)
        detail = clean(obj.http_url, 160)
        cvss = obj.cvss_score
        first = svc._seen(obj, 'first_seen', obj.discovered_date)
        product_key = ''
    else:
        confirmed = False
        basis = 'Detected'
        base = SCANNER_LEVELS.get(obj.severity, 'info')
        level = rate('hygiene', heat, base)
        key = ('hygiene', obj.check_name)
        title = clean(obj.title, 200)
        ev = obj.evidence if isinstance(obj.evidence, dict) else {}
        detail = clean('; '.join(f'{k}: {v}' for k, v in list(ev.items())[:2]), 160)
        first = obj.first_seen
        product_key = ''
    row = {'kind': kind, 'key': key, 'title': title, 'host': host, 'host_alias': '', 'level': level, 'base': base, 'heat': heat, 'basis': basis,
           'confirmed': confirmed, 'detail': detail, 'cvss': cvss, 'kev': kev, 'exploit': exploit, 'cves': cve_ids, 'product_key': product_key,
           'open': _is_open(kind, obj), 'first_seen': _date(first), 'tracking': _tracking(obj), '_obj': obj}
    if kind == 'scanner' and not obj.open_status and obj.remediation_status == 'open':
        row['tracking']['status'] = 'No longer detected'
    if kind == 'hygiene' and obj.status == 'resolved' and obj.remediation_status == 'open':
        row['tracking']['status'] = 'No longer detected'
    if everywhere:
        project = _project_of(kind, obj)
        row['project'], row['project_slug'] = (clean(project.name, 200), project.slug) if project else ('', '')
    return row


def _read(sources, cap, everywhere):
    """Every finding of ``sources`` as an instance row, at most ``cap`` of each kind (hottest first). Returns ``(rows, cut)``: ``cut`` is how
    many the read cap left out."""
    rows, cut = [], 0
    for kind in ('cve', 'scanner', 'hygiene'):
        qs = sources[kind]
        if kind == 'scanner':
            qs = qs.prefetch_related('cve_ids')
        got = list(qs[:cap + 1])
        if len(got) > cap:
            cut += qs.count() - cap
            got = got[:cap]
        rows.extend(_instance(kind, obj, everywhere) for obj in got)
    return rows, cut


def _host_key(row):
    return (row.get('project_slug', ''), row['host'].lower())


def _basis_summary(members):
    """The basis of an issue: its strongest, and how many hosts that covers when the hosts differ ("Confirmed on 1 of 5 hosts")."""
    best = min((m['basis'] for m in members), key=BASIS.index)
    hosts = {_host_key(m) for m in members}
    on = {_host_key(m) for m in members if m['basis'] == best}
    note = '' if len(on) == len(hosts) else f'{best} on {len(on)} of {len(hosts)} hosts'
    return best, note


def _issues(rows):
    """The open instance rows grouped into issues, in report order (severity, then hosts affected, then the strength of the basis, CVSS
    and title), numbered from 1. Each issue is a dict with its members (hottest first)."""
    groups = {}
    for row in rows:
        if row['open']:
            groups.setdefault(row['key'], []).append(row)
    issues = []
    for key, members in groups.items():
        members.sort(key=lambda m: (-LEVEL_RANK[m['level']], BASIS.index(m['basis']), m['host']))
        top = members[0]
        level = top['level']
        basis, basis_note = _basis_summary(members)
        hosts = {_host_key(m) for m in members}
        title = top['title']
        if top['kind'] == 'hygiene':
            title = _hygiene_title(key[1], [m['title'] for m in members])
        elif top['kind'] == 'cve':
            products = Counter(m['product_key'] for m in members if m['product_key'])
            title = clean(f'{key[1]} in {products.most_common(1)[0][0]}' if products else key[1], 200)
        cvss = max((m['cvss'] for m in members if m['cvss'] is not None), default=None)
        issues.append({'kind': top['kind'], 'key': key, 'title': title, 'level': level, 'level_label': LEVEL_LABELS[level],
                       'basis': basis, 'basis_note': basis_note, 'host_count': len(hosts), 'instances': len(members),
                       'cvss': cvss, 'kev': any(m['kev'] for m in members), 'members': members})
    issues.sort(key=lambda i: (-LEVEL_RANK[i['level']], -i['host_count'], BASIS.index(i['basis']), -(i['cvss'] or 0), i['title'].lower()))
    for n, issue in enumerate(issues, 1):
        issue['number'] = n
        issue['anchor'] = f'issue-{n}'
    return issues


KIND_LABELS = {'cve': 'Known vulnerability (CVE)', 'scanner': 'Scanner finding', 'hygiene': 'Configuration'}


def _cve_impact(cve, product, confirmed):
    """A plain impact statement for a CVE when the triage wrote none, from the advisory's own signals only."""
    reach = product or 'the service'
    parts = [f'An attacker who can reach {reach} on the confirmed hosts can exploit {cve.cve_id}.' if confirmed else
             f'If the version on these hosts is affected, an attacker who can reach {reach} could exploit {cve.cve_id}.']
    if cve.cvss is not None:
        parts.append(f'The advisory rates it CVSS {cve.cvss:.1f}.')
    if cve.kev:
        parts.append('CISA lists it as exploited in the wild, so working attacks exist.')
    elif cve.exploit_db:
        parts.append('A public exploit is available.')
    else:
        parts.append('It is not known to be exploited and no public exploit is recorded.')
    return ' '.join(parts)


def _upgrade_text(product, fixed):
    if fixed:
        return f'Upgrade {product or "the affected software"} to {" or ".join(fixed[:3])} or later (whichever matches the branch in use) on each affected host.'
    return f'Apply the vendor\'s fix for this issue to {product or "the affected software"} on each affected host.'


def _rating_reason(issue):
    """Why the issue has its rating, in one or two plain sentences: its own severity, what is known about exploitation and proof, and why
    it was rated below its own severity when it was (``rate``)."""
    top = issue['members'][0]
    level, base = LEVEL_LABELS[issue['level']], LEVEL_LABELS[top['base']]
    if issue['kind'] == 'cve':
        cvss = f'CVSS {top["cvss"]:.1f}' if top['cvss'] is not None else 'no CVSS score'
        exploited = ('listed by CISA as exploited in the wild' if top['kev'] else 'a public exploit exists' if top['exploit']
                     else 'not known to be exploited and no public exploit is recorded')
        proof = {'Confirmed': f'a check reproduced it on {_plural(sum(1 for m in issue["members"] if m["confirmed"]), "host")}',
                 'Likely': 'the version is proven on the host but the flaw was not reproduced',
                 'Version match': 'it rests on the detected version only'}.get(issue['basis'], '')
        by_score = LEVEL_LABELS[cve_base(top['cvss'], False)] if top['cvss'] is not None else ''
        if top['kev'] and by_score and by_score != base:  # the KEV listing, not the score, makes it Critical: say so instead of "CVSS 5.7 (Critical)"
            text = f'{cvss} ({by_score} by score, {base} because CISA lists it as exploited in the wild); {proof}.'
        else:
            text = f'{cvss} ({base} on its own); {exploited}; {proof}.'
        if level != base:
            why = ('the version is not proven and the flaw not reproduced' if issue['level'] == 'high' else
                   'it is not known to be exploited' if top['heat'] == 'ice' and issue['basis'] != 'Confirmed' else
                   'it is not known to be exploited, though a check confirmed it' if top['heat'] == 'ice' else
                   'the fix may be backported, the version could not be read, or its CVSS is below 4.0' if issue['level'] == 'info' else
                   'of what is known about these hosts')
            text += f' Rated {level} rather than {base} because {why}.'
        return text
    if issue['kind'] == 'scanner':
        text = f'The scanner rates it {base}.'
        if level != base:
            text += (f' Held at {level} until a check on the host confirms it.' if top['heat'] == 'smoke' else
                     f' Rated {level} because it is not known to be exploited or a check did not reproduce it.')
        return text
    text = f'The configuration check rates it {base}.'
    if level != base and LEVEL_RANK[top['base']] > LEVEL_RANK[HYGIENE_CEILING]:
        text += f' Configuration findings are rated at most {LEVEL_LABELS[HYGIENE_CEILING]}.'
    return text


def _writeup(issue, caps):
    """Fill in a full write-up of ``issue``: description, impact, evidence, the affected hosts, the recommendation, how to confirm it and the
    references. Read from the issue's strongest member, with the other members' proof, tracking and confirm guide where they add to it."""
    members = issue['members']
    rep = members[0]
    obj = rep['_obj']
    kind = issue['kind']
    out = {'kind_label': KIND_LABELS[kind], 'confirm': None, 'proof': [], 'references': [], 'signals': [], 'cves': [], 'fixed_in': [],
           'subtitle': '', 'rating_reason': _rating_reason(issue)}
    if kind == 'cve':
        entry = _match_entry(obj, rep['heat'])
        cve = obj.cve_entry
        product = clean(obj.matched_product, 80)
        out.update(description=entry['description'] or entry['subtitle'], subtitle=entry['subtitle'], signals=entry['signals'], cves=entry['cves'],
                   fixed_in=entry['fixed_in'], evidence=entry['evidence'], references=_cve_references(cve))
        out['impact'] = entry['impact'] or _cve_impact(cve, product, issue['basis'] == 'Confirmed')
        out['remediation'] = entry['remediation']
        # the generic upgrade line, unless the remediation text already names a fixed release
        named = any(v and v in out['remediation'] for v in entry['fixed_in'])
        out['upgrade'] = '' if named else _upgrade_text(product, entry['fixed_in'])
        unconfirmed = next((m for m in members if not m['confirmed']), None)
        if unconfirmed is not None:
            out['confirm'] = _confirm(unconfirmed['_obj']) if unconfirmed is not rep else entry['confirm']
    elif kind == 'scanner':
        entry = _vulnerability_entry(obj, rep['heat'])
        out.update(description=entry['description'], subtitle=entry['subtitle'], cves=entry['cves'], evidence=entry['evidence'],
                   impact=entry['impact'], remediation=entry['remediation'], upgrade='')
        out['proof'] = [{**p, 'host': rep['host']} for p in entry['proof'] if p['proved']][:3]
    else:
        entry = _hygiene_entry(obj)
        description = entry['description']
        if issue['host_count'] > 1 and description:  # the check's text is about one host: say so
            description = f'Found on {_plural(issue["host_count"], "host")}. For example, on {rep["host"]}: {description}'
        out.update(description=description, impact=entry['impact'], remediation=entry['remediation'], upgrade='',
                   evidence=entry['evidence'], subtitle=_hygiene_group(obj.check_name))
    if not out['remediation'] and not out['upgrade']:
        out['remediation'] = 'No remediation text is recorded for this issue. Review the affected hosts and correct the condition described above.'
    # the proof each confirmed host has (the exact command that showed it), a few hosts at most
    if kind != 'hygiene':
        from agentapi import services as svc
        seen = {p['command'] for p in out['proof']}
        for m in members:
            if len(out['proof']) >= PROOF_HOSTS + 2:
                break
            if not m['confirmed']:
                continue
            for p in _proof(svc._triage_of(m['_obj'])):
                if p['proved'] and p['command'] not in seen:
                    out['proof'].append({**p, 'host': m['host']})
                    seen.add(p['command'])
                    break
    out['hosts_more'] = max(0, len(members) - caps['issue_hosts'])
    out['mixed_basis'] = len({m['basis'] for m in members}) > 1
    issue.update(out)


# --- the executive summary -----------------------------------------------------------------------------------------------------

def _version_tuple(text):
    from cveFeed.correlation import parse_version
    try:
        parsed = parse_version(text)
    except Exception:  # noqa: BLE001 - a version that does not parse is simply not compared
        return None
    return tuple(parsed) if parsed else None


def _fix_for(detected, fixed):
    """The fixed version that applies to ``detected``: the lowest fixed release above it on the same branch (major.minor), else on the same
    major version, else the lowest above it."""
    have = _version_tuple(detected)
    options = sorted(((v, f) for f in fixed if (v := _version_tuple(f))), key=lambda p: p[0])
    if not options:
        return ''
    if have is None:
        return options[-1][1]
    above = [p for p in options if p[0] > have]
    branch = [p for p in above if p[0][:2] == have[:2]]
    major = [p for p in above if p[0][:1] == have[:1]]
    return (branch or major or above or [options[-1]])[0][1]


def _key_actions(issues):
    """The top actions, built from the critical, high and medium issues: CVE issues of one product become one upgrade ("Upgrade PHP on 5
    hosts to 8.3.37 or later"), the others take their issue's recommendation. Strongest severity first, then the most hosts."""
    from agentapi import services as svc
    products, others = {}, []
    for issue in issues:
        if issue['level'] not in DETAILED:
            continue
        if issue['kind'] == 'cve' and issue['members'][0]['product_key']:
            name = issue['members'][0]['product_key']
            p = products.setdefault(name.lower(), {'name': name, 'hosts': set(), 'issues': 0, 'level': issue['level'], 'fix': [], 'likely': True})
            p['issues'] += 1
            p['hosts'] |= {_host_key(m) for m in issue['members']}
            if LEVEL_RANK[issue['level']] > LEVEL_RANK[p['level']]:
                p['level'] = issue['level']
            p['likely'] = p['likely'] and issue['basis'] == 'Version match'
            for m in issue['members']:
                obj = m['_obj']
                fix = _fix_for(obj.matched_version, svc._fixed_versions(obj.cve_entry, obj.matched_product))
                if fix:
                    p['fix'].append(fix)
        else:
            others.append(issue)
    actions = []
    for p in products.values():
        hosts = len(p['hosts'])
        fix = max(p['fix'], key=lambda f: _version_tuple(f) or (), default='')
        text = (f'Upgrade {p["name"]} on {_plural(hosts, "host")} to {fix} or later' if fix else
                f'Upgrade {p["name"]} on {_plural(hosts, "host")} to a supported, patched release')
        text += f' ({_plural(p["issues"], "issue")} in this report' + (', based on the detected version' if p['likely'] else '') + ').'
        actions.append((LEVEL_RANK[p['level']], hosts, text))
    for issue in others:
        hosts = issue['host_count']
        rec = _first_sentence(issue.get('remediation') or '', 200) if issue.get('remediation') else ''
        text = f'{issue["title"]} ({_plural(hosts, "host")}): {rec[0].lower() + rec[1:] if rec else "correct it on each affected host."}'
        actions.append((LEVEL_RANK[issue['level']], hosts, clean(text, 300)))
    actions.sort(key=lambda a: (-a[0], -a[1]))
    out = [a[2] for a in actions[:TOP_ACTIONS]]
    if any(i['level'] in DETAILED and i['basis'] == 'Version match' for i in issues) and len(out) < TOP_ACTIONS + 1:
        out.append('Confirm the findings that rest on a version match (each write-up says how) and record fixes the vendor or the '
                   'distribution backported, so the list reflects real exposure.')
    return out


def _basis_words(issue):
    return {'Confirmed': 'confirmed by a check', 'Likely': 'likely: the version is proven on the host but the flaw was not reproduced',
            'Detected': 'detected by a scanner or configuration check', 'Version match': 'likely, based on the detected version only; not proven'}[issue['basis']]


def _executive(issues, summary, scope, method, host):
    """The executive summary in plain sentences: the posture, the most serious issues with how many hosts each affects and how sure we are,
    and the positive notes the data supports. Deterministic: no AI model writes it."""
    counts = Counter(i['level'] for i in issues)
    serious = [i for i in issues if i['level'] in DETAILED]
    where = 'this host' if host else _plural(scope['hosts_total'], 'host') + ' in scope'
    paragraphs = []
    if not issues:
        paragraphs.append(f'No open security issues were found on {where}. ' +
                          ('No CVE match, scanner finding or configuration finding is open at the time of this report.'))
        posture = 'No open issues.'
    else:
        if counts['critical']:
            posture = 'The external security posture needs urgent attention.'
        elif counts['high']:
            posture = 'The external security posture needs attention: some issues should be fixed promptly.'
        elif counts['medium']:
            posture = 'The external security posture is fair: no critical or high issues were found, but some medium issues should be planned for.'
        else:
            posture = 'The external security posture is good: no critical, high or medium issues were found.'
        levels = ', '.join(f'{counts[k]} {LEVEL_LABELS[k].lower()}' for k in DETAILED if counts[k]) or 'none of them critical, high or medium'
        minor = counts['low'] + counts['info']
        text = (f'{posture} cvENGINE grouped {_plural(summary["findings"] + summary["hygiene"], "open finding")} on {where} into '
                f'{_plural(len(issues), "distinct issue")}: {levels}.')
        if minor:
            text += f' A further {_plural(minor, "low or informational issue", "low or informational issues")} {"is" if minor == 1 else "are"} listed in Appendix A.'
        paragraphs.append(text)
        sentences = []
        on = (lambda i: 'on this host') if host else (lambda i: f'on {_plural(i["host_count"], "host")}')
        for n, issue in enumerate(serious[:2]):
            lead = 'The most serious issue is' if n == 0 else 'The next is'
            sentence = f'{lead} {issue["title"]} ({issue["level_label"]}, {on(issue)}), {_basis_words(issue)}.'
            impact = _first_sentence(issue.get('impact') or '', 260)
            if impact:
                sentence += f' {impact}'
            sentences.append(sentence)
        rest = serious[2:TOP_ISSUES]
        if rest:
            named = [f'{i["title"]} ({i["level_label"]}, {on(i)})' for i in rest]
            sentences.append('Other issues that need attention include ' + (', '.join(named[:-1]) + ' and ' + named[-1] if len(named) > 1 else named[0]) + '.')
        if len(serious) > TOP_ISSUES:
            more = len(serious) - TOP_ISSUES
            sentences.append(f'{_plural(more, "further critical, high or medium issue", "further critical, high or medium issues")} '
                             f'{"is" if more == 1 else "are"} listed in the summary of findings.')
        if sentences:
            paragraphs.append(' '.join(sentences))
        likely = sum(1 for i in serious if i['basis'] == 'Version match')
        if likely:
            paragraphs.append(f'{_plural(likely, "of these issues rests", "of these issues rest")} on a version match: the version a service reports is in the '
                              'affected range. Vendors and Linux distributions often fix a flaw without changing the version number, so each of '
                              'these needs to be confirmed on the host before it is treated as proven.')
    positives = []
    hygiene_ran = 'hygiene' in method.get('keys', ())
    open_checks = {i['key'][1] for i in issues if i['kind'] == 'hygiene'}
    if issues and not any(i['basis'] == 'Confirmed' for i in issues):
        positives.append('No issue was reproduced by an active check; the issues rest on version information, scanner detections and configuration checks.')
    if not any(i['kind'] == 'cve' and i['kev'] for i in issues):
        positives.append('No CVE listed in CISA\'s Known Exploited Vulnerabilities catalog was matched to these hosts.')
    if hygiene_ran and not open_checks & {'tls_expired', 'cert_expired'}:
        positives.append('No expired TLS certificates were found.')
    if hygiene_ran and not any(c.startswith('cleartext_') for c in open_checks):
        positives.append('No cleartext login services (Telnet, FTP, rlogin or rsh) were found.')
    if issues and not counts['critical']:
        positives.append('No critical issues were found.')
    return {'posture': posture, 'paragraphs': paragraphs, 'positives': positives}


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
        qs = qs.filter(name__iexact=host)  # a report on one host is made whether or not it is archived
    else:
        qs = svc._archived_filter(qs, svc.ARCHIVED_HIDE)  # an archived host is not one of the scope's hosts (archiving closed its findings)
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
        yield from got[:cap - sent]
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
    ``addresses`` narrow it to one host's names and IPs; None is the whole project. ``keys`` are the ledger services that ran."""
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
    return {'scans': scans['n'] or 0, 'first_scan': _date(scans['first']), 'last_scan': _date(scans['last']), 'services': services,
            'first_scan_long': _long_date(scans['first']), 'last_scan_long': _long_date(scans['last']), 'keys': sorted(by_service)}


# --- the whole report ----------------------------------------------------------------------------------------------------------

MAX_SECRETS = 100  # inventory rows printed in one report, worst first


def _secrets(project, names, include_closed):
    """``(total, rows)``: the project's exposed secrets (cveFeed.secrets_inventory), worst first, at most MAX_SECRETS. Masked values only: the
    report never holds a secret. For a host report, the ones that host serves."""
    from agentapi import services as svc
    from cveFeed import secrets_catalog, secrets_inventory
    from cveFeed.models import SecretFinding
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


def _public(row):
    """An instance row without the ORM object it was read from."""
    return {k: v for k, v in row.items() if k != '_obj'}


def _severity_table(issues):
    """``[{level, label, issues, hosts, findings}]`` for the five levels: issues, distinct hosts and findings at each."""
    out = []
    for level in LEVELS:
        mine = [i for i in issues if i['level'] == level]
        hosts = {_host_key(m) for i in mine for m in i['members']}
        out.append({'level': level, 'label': LEVEL_LABELS[level], 'issues': len(mine), 'hosts': len(hosts), 'findings': sum(i['instances'] for i in mine)})
    return out


def _appendices(secrets_total, include_closed, host):
    """The appendices this report has, lettered in order: ``{key: letter}`` and the list for the table of contents."""
    keys = [('minor', 'Low and informational findings'), ('inventory', 'Host detail' if host else 'Asset inventory')]
    if secrets_total:
        keys.append(('secrets', 'Exposed secrets'))
    if include_closed:
        keys.append(('closed', 'Closed findings'))
    out = [{'key': k, 'letter': chr(ord('A') + n), 'title': t, 'anchor': f'appendix-{k}'} for n, (k, t) in enumerate(keys)]
    return {a['key']: a['letter'] for a in out}, out


REPORT_TITLES = {'findings': 'External Attack Surface Assessment', 'host': 'Host Security Assessment', 'hosts': 'Discovered Hosts Report'}


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
    host_cap = caps['hosts'] if hosts_report or host else caps['inventory']
    sources, ruled_out = _sources(project, False if hosts_report else include_closed, names=None if names is None else sorted(names))
    host_total, hosts, aliases, raw = _hosts(project, host, _per_host(sources, everywhere), host_cap)
    if host and hosts:  # the host may answer to other names (same addresses): their findings are this host's too
        names |= {a.lower() for a in aliases}
        sources, ruled_out = _sources(project, include_closed, names=sorted(names))
        hosts[0]['findings'] = sum(_per_host(sources).values())
    open_sources = sources
    if include_closed and not hosts_report:
        open_sources, _ = _sources(project, False, names=None if names is None else sorted(names))
    opened = open_counts(open_sources)
    total, heat, severity = opened['findings'], opened['heat'], opened['severity']
    hygiene_total, _, hygiene_severity = _tally({'hygiene': open_sources['hygiene']})
    rows, issues, closed, rows_cut = [], [], [], 0
    secrets_total, secrets = 0, []
    if hosts_report:
        _label_hosts(project, hosts, [])
    else:
        rows, rows_cut = _read(sources, caps['rows'], everywhere)
        _label_hosts(project, hosts, rows)
        issues = _issues(rows)
        major = [i for i in issues if i['level'] in DETAILED]
        for issue in major[:caps['writeups']]:
            _writeup(issue, caps)
            issue['detailed'] = True
        closed = [r for r in rows if not r['open']]
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
    scope = {**_scope(project, host), 'hosts_total': host_total, 'hosts_listed': len(hosts)}
    method = _method(project, names, [a for h in hosts for a in h.get('address_list', [])])
    major = [i for i in issues if i['level'] in DETAILED]
    minor = [i for i in issues if i['level'] not in DETAILED]
    detailed = [i for i in major if i.get('detailed')]
    letters, appendices = _appendices(secrets_total, include_closed and not hosts_report, host)
    summary = {'findings': total, 'heat': heat, 'heat_policy': _heat_policy(), 'severity': severity, 'by_kind': opened['by_kind'], 'hygiene': hygiene_total,
               'hygiene_severity': hygiene_severity, 'ruled_out': ruled_out,
               'hosts_exposed': sum(1 for h in hosts if h['heat'] in ('fire', 'smoke')),
               'status_counts': _status_counts(sources) if not hosts_report else {},
               'issues': len(issues), 'levels': _severity_table(issues)}
    executive = None if hosts_report else _executive(issues, summary, scope, method, host)
    actions = [] if hosts_report else _key_actions(issues)
    if host:
        client = organization or project_line
    else:
        client = label
    title = REPORT_TITLES['hosts' if hosts_report else 'host' if host else 'findings']
    # the ORM objects stay here: what leaves is plain data
    for issue in issues:
        issue['members'] = [_public(m) for m in issue['members']]
        if issue.get('detailed'):
            issue['hosts'] = issue['members'][:caps['issue_hosts']]
            issue['tracking'] = [m for m in issue['members'] if m['tracking']['assignee'] or m['tracking']['note']][:TRACKING_ROWS]
    findings = [_public(r) for r in rows]
    closed = [_public(r) for r in closed]
    return {
        'kind': kind, 'scope_kind': 'org' if everywhere else 'project', 'scope_projects': scope_projects,
        'title': title, 'subject': label, 'client': client, 'header': clean(host, 200) if host else client,
        'project': project_line, 'organization': organization, 'host': clean(host or '', 200),
        'host_alias': hosts[0]['alias'] if host and hosts else '', 'host_note': hosts[0].get('note', '') if host and hosts else '',
        'generated': _stamp(now), 'generated_date': _date(now), 'report_date': _long_date(now),
        'include_closed': False if hosts_report else include_closed, 'branding': _branding(),
        'scope': scope, 'summary': summary, 'executive': executive,
        'hosts_summary': _hosts_overview(raw, hosts, _new_hosts(project, now)) if hosts_report else None,
        'hosts': hosts, 'findings': findings, 'issues': issues, 'major': major[:SUMMARY_ROWS], 'major_more': max(0, len(major) - SUMMARY_ROWS),
        'detailed': detailed, 'minor': minor[:caps['minor']], 'minor_more': max(0, len(minor) - caps['minor']), 'minor_total': len(minor),
        'actions': actions,
        'closed': closed[:caps['closed']], 'closed_more': max(0, len(closed) - caps['closed']),
        'secrets': secrets, 'secrets_total': secrets_total, 'appendix': letters, 'appendices': appendices,
        'caps': {**caps, 'hosts_omitted': max(0, host_total - len(hosts)), 'host_cap': host_cap,
                 'writeups_omitted': max(0, len(major) - len(detailed)), 'minor_omitted': max(0, len(minor) - caps['minor']),
                 'closed_omitted': max(0, len(closed) - caps['closed']), 'rows_omitted': rows_cut,
                 'issue_hosts_cut': sum(1 for i in detailed if i['hosts_more'])},
        'levels': [{'level': k, 'label': LEVEL_LABELS[k]} for k in LEVELS],
        'method': method,
    }
