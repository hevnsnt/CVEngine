"""The content of an email report: what one weekly or monthly email says about a project or an organization, and how it is written.

``build`` reads stored results only (nothing here scans, probes or resolves a host) and filters by the scope's project ids explicitly, because it
runs in a worker with no request scope. It returns plain data: every string that came from a scanned host, a feed or a person goes through
``report_data.clean``, and the templates (``cveFeed/email/report_digest.html`` and ``.txt``) escape it again, so a hostile host name reaches the
inbox as inert text. Links start with ``mailer.base_url()`` (never a request's Host header) and slugs and ids are quoted.

``render`` turns the data into a subject, a plain-text part and an HTML part for one recipient. The HTML is table-based with inline styles, no
image, font or tracking pixel, and stays far under the 100 KB at which Gmail clips a message.

The ``threats`` list ("This week's most important vulnerabilities") is filled by ``cveFeed.report_threats``; with none, the section still shows
``threats_empty`` so readers know it was checked. ``threats_note`` is its attribution footnote. An entry is ``{source: 'zero_wire' | 'kev' | 'critical', title, summary, link, badges: [str], cve_ids: [str],
impact_line, impact: 'matched' | 'product' | 'none', fixed_in: [str]}``: ``source`` says where it came from, ``link`` is where its title goes (a
briefing or the CVE catalog) and ``summary`` is a short plain sentence.
"""
import logging
from datetime import datetime, timezone as dt_timezone
from urllib.parse import quote

from django.template.loader import render_to_string
from django.urls import reverse

from agentapi import services as svc
from cveFeed import mailer, report_data, report_schedule, report_threats
from cveFeed.report_data import HEAT_NAMES, clean

TOP_FINDINGS = 5
NEW_HOSTS_SHOWN = 5
# the colours of the app's heat semantics (static/cve/cve.css), inlined because an email carries no stylesheet of ours
HEAT_COLOURS = {'fire': '#b3261e', 'smoke': '#b9822a', 'ice': '#7a8594'}
SOURCE_FIELD = {'cve': 'created_at', 'scanner': 'discovered_date', 'hygiene': 'first_seen'}  # when a finding of each kind first appeared
EPOCH = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
HASH_KIND = {'cve': 'match', 'scanner': 'vulnerability', 'hygiene': 'hygiene'}  # a finding's address on the Findings page


def _links(scope, base):
    """The addresses the email points at: the findings page, the Reporting page and the page that manages email reports."""
    if scope.kind == 'project':
        slug = quote(scope.project.slug, safe='')
        findings = f'{base}/cve/{slug}/vulns/'
        reporting = f'{base}{reverse("cve_reports")}?project={slug}'
    else:
        org = quote(scope.org.slug, safe='')
        findings = f'{base}/cve/_all/vulns/?org={org}'
        reporting = f'{base}{reverse("cve_reports")}?org={org}'
    return {'open_app': findings, 'findings': findings, 'reporting': reporting, 'manage': f'{reporting}#email'}


def _finding_link(base, scope, kind, obj_id, project):
    anchor = f'{HASH_KIND[kind]}-{obj_id}'
    if scope.kind == 'project':
        return f'{base}/cve/{quote(project.slug, safe="")}/vulns/#{anchor}'
    return f'{base}/cve/_all/vulns/?org={quote(scope.org.slug, safe="")}#{quote(project.slug, safe="")}:{anchor}'


def _previous(scope, start):
    """The latest snapshot of each scope project taken on or before ``start``'s date, summed; None unless every project has one (a partial sum would
    compare unlike things)."""
    from cveFeed.models import StatsSnapshot
    rows = list(StatsSnapshot._base_manager.filter(project_id__in=scope.ids, date__lte=start.date()).order_by('project_id', '-date').distinct('project_id'))
    if not scope.ids or len(rows) != len(scope.ids):
        return None
    return {'open_findings': sum(sum(r.open_findings.get(b, 0) for b in ('critical', 'high', 'medium', 'low')) for r in rows),
            'exposed_hosts': sum(r.exposed_hosts for r in rows), 'hosts': sum(r.hosts for r in rows)}


def _current(scope):
    from cveFeed import stats_history
    total = {'open_findings': 0, 'exposed_hosts': 0, 'hosts': 0, 'heat': {'fire': 0, 'smoke': 0, 'ice': 0}}
    for project in scope.projects:
        snap = stats_history.compute_snapshot(project, with_fixed=False)
        total['open_findings'] += sum(snap['open_findings'].get(b, 0) for b in ('critical', 'high', 'medium', 'low'))
        total['exposed_hosts'] += snap['exposed_hosts']
        total['hosts'] += snap['hosts']
        for heat in total['heat']:
            total['heat'][heat] += snap['cve_matches'].get(heat, 0)
    return total


def _in_period(qs, field, start, end):
    return qs.filter(**{f'{field}__gte': start, f'{field}__lt': end})


def _top_findings(scope, sources, base, now):
    """The hottest open findings (at most TOP_FINDINGS), CVE matches and scanner findings merged the way the Findings page orders them."""
    everywhere = scope.kind == 'org'
    merged = [('cve', o) for o in sources['cve'][:TOP_FINDINGS]] + [('scanner', o) for o in sources['scanner'][:TOP_FINDINGS]]
    merged.sort(key=lambda p: (p[1].heat_rank, p[1].sev, p[1].when or EPOCH, p[1].id), reverse=True)
    out = []
    for kind, obj in merged[:TOP_FINDINGS]:
        if kind == 'cve':
            sub = obj.subdomain
            project = sub.target_domain.project if everywhere else scope.project
            product = ' '.join(x for x in (obj.matched_product, obj.matched_version) if x)
            title = f'{obj.cve_entry.cve_id} in {product}' if product else obj.cve_entry.cve_id
            host = sub.name
        else:
            project = obj.target_domain.project if everywhere else scope.project
            title = obj.name
            host = obj.subdomain.name if obj.subdomain else obj.target_domain.name
        since = obj.when
        out.append({'heat': HEAT_NAMES.get(obj.heat_rank, 'ice'), 'title': clean(title, 160), 'host': clean(host, 120),
                    'project': clean(project.name, 80) if everywhere else '', 'status': report_data._tracking(obj)['status'],
                    'age_days': max(0, (now - since).days) if since else None, 'link': _finding_link(base, scope, kind, obj.pk, project)})
    return out


def _new_hosts(scope, start, end):
    from cveFeed.models import AssetChange
    new, gone = {}, set()
    labels = {p.pk: p.name for p in scope.projects}
    rows = AssetChange._base_manager.filter(project_id__in=scope.ids, kind__in=('host_new', 'host_retired'), detected_at__gte=start, detected_at__lt=end)
    for project_id, host, kind in rows.order_by('detected_at', 'id').values_list('project_id', 'host', 'kind'):
        key = (project_id, host.lower())
        if kind == 'host_new':
            new.setdefault(key, host)  # a name once per project, however many times it was found
        else:
            gone.add(key)
    gone -= set(new)  # a host that went away and came back in the same period is not "gone"
    ordered = sorted(new.items(), key=lambda kv: (kv[1].lower(), kv[0][0]))
    return {'count': len(new), 'more': max(0, len(new) - NEW_HOSTS_SHOWN), 'gone': len(gone),
            'names': [{'host': clean(host, 120), 'project': clean(labels.get(pid, ''), 80) if scope.kind == 'org' else ''} for (pid, _), host in ordered[:NEW_HOSTS_SHOWN]]}


def _hygiene(scope, sources):
    from cveFeed import counts
    from cveFeed.models import TlsCertificate
    certs = counts.expiring_certificates(TlsCertificate._base_manager.filter(domain__project_id__in=scope.ids)).count()
    return {'open': sources['hygiene'].count(), 'certs_expiring': certs}


def build(scope, start, end, cadence, now, tz='UTC'):
    """The digest of ``scope`` (an ``agentapi.report_scope.ReportScope``) for the period from ``start`` to ``end`` (aware datetimes). ``tz``: the
    zone the period and the "as of" line are written in."""
    base = mailer.base_url()
    sources, _ = report_data._sources(scope.svc_scope(), False)
    closed, _ = report_data._sources(scope.svc_scope(), True)
    new_findings = sum(_in_period(sources[key], field, start, end).count() for key, field in SOURCE_FIELD.items())
    fixed = sum(_in_period(closed[key].filter(remediation_status='fixed'), 'remediation_updated_at', start, end).count() for key in SOURCE_FIELD)
    try:
        threats, note = report_threats.top(scope, start, end)
    except Exception:  # noqa: BLE001 - the section is a bonus: a failure in it never stops the email
        logging.getLogger(__name__).warning('could not build the most important vulnerabilities', exc_info=True)
        threats, note = [], ''
    now_numbers = _current(scope)
    before = _previous(scope, start)
    monthly = cadence == 'monthly'
    local_end = end.astimezone(report_schedule.zone(tz))
    label = report_schedule.period_label(start, end, tz, monthly=monthly)
    headline = {'open_findings': now_numbers['open_findings'], 'exposed_hosts': now_numbers['exposed_hosts'], 'hosts': now_numbers['hosts'],
                'heat': now_numbers['heat'], 'new_findings': new_findings, 'fixed': fixed, 'compared': before is not None,
                'compared_note': '' if before is not None else 'First report: no comparison yet',
                **{f'{k}_prev': (before or {}).get(k) for k in ('open_findings', 'exposed_hosts', 'hosts')}}
    return {
        'title': 'Monthly report' if monthly else 'Weekly report', 'cadence': cadence, 'scope_name': clean(scope.label, 120), 'scope_kind': scope.kind,
        'org_name': clean(scope.org.name if scope.kind == 'org' else (scope.project.org.name if scope.project.org_id else ''), 120),
        'project_names': [clean(n, 80) for n in sorted(p.name for p in scope.projects)],
        'period': {'start': start.isoformat(), 'end': end.isoformat(), 'label': label,
                   'short': label if label != report_schedule.period_label(start, end, tz) else report_schedule.short_label(start, end, tz)},
        'headline': headline, 'threats': threats, 'threats_note': note, 'threats_empty': '' if threats else
        f"No newly exploited or critical vulnerabilities were announced this {'month' if monthly else 'week'}.", 'top_findings': _top_findings(scope, sources, base, now),
        'new_hosts': _new_hosts(scope, start, end), 'hygiene': _hygiene(scope, sources), 'links': _links(scope, base),
        'instance': mailer._instance(mailer.row()), 'as_of': f'{local_end:%b} {local_end.day}, {local_end:%H:%M} ({tz})',
    }


# --- writing it ----------------------------------------------------------------------------------------------------------------

def _delta(now, before, unit):
    """``(text, tone)`` for a figure that is better when it is lower: "▼ 4 since last week" in green, "▲ 3 since last week" in red, a word as well as
    a colour so it reads without one. Empty when there is nothing to compare with."""
    if before is None:
        return '', ''
    diff = now - before
    if diff == 0:
        return f'no change since {unit}', 'flat'
    return (f'▼ {-diff} since {unit}', 'good') if diff < 0 else (f'▲ {diff} since {unit}', 'bad')


def _tiles(digest):
    h = digest['headline']
    unit = 'last month' if digest['cadence'] == 'monthly' else 'last week'
    period = 'this month' if digest['cadence'] == 'monthly' else 'this week'
    findings, f_tone = _delta(h['open_findings'], h['open_findings_prev'], unit)
    exposed, e_tone = _delta(h['exposed_hosts'], h['exposed_hosts_prev'], unit)
    return [{'label': 'Open findings', 'value': h['open_findings'], 'delta': findings, 'tone': f_tone},
            {'label': 'Exposed hosts', 'value': h['exposed_hosts'], 'delta': exposed, 'tone': e_tone},
            {'label': f'New {period}', 'value': h['new_findings'], 'delta': '', 'tone': ''},
            {'label': f'Fixed {period}', 'value': h['fixed'], 'delta': '', 'tone': ''}]


def _preheader(digest):
    h = digest['headline']
    bits = [f"{h['heat']['fire']} on fire" if h['heat']['fire'] else f"{h['open_findings']} open finding{'' if h['open_findings'] == 1 else 's'}"]
    if h['open_findings_prev'] is not None and h['heat']['fire']:
        bits.append(f"{h['open_findings']} open finding{'' if h['open_findings'] == 1 else 's'}")
    if digest['threats']:
        n = len(digest['threats'])
        bits.append(f"{n} important vulnerabilit{'y' if n == 1 else 'ies'}")
    return ', '.join(bits) + f" in {digest['scope_name']}."


def subject(digest):
    text = f"cvENGINE {digest['cadence']} report: {digest['scope_name']} ({digest['period']['short']})"
    fire = digest['headline']['heat']['fire']
    if fire:
        text += f': {fire} on fire'
    return text if len(text) <= 120 else text[:119].rstrip() + '…'


def render(digest, sub=None, recipient='', unsubscribe_url='', attachment=None, owner_name=''):
    """``(subject, text, html)`` of the email for one recipient. ``sub``: the ReportSubscription (its name and owner go in the footer), None for a
    preview of unsaved settings. ``attachment``: how the full report went, ``{state: 'attached'|'too_large'|'failed', kind, filename, mb, limit_mb}``
    or None for none."""
    h = digest['headline']
    tiles = _tiles(digest)
    context = {'d': digest, 'tiles': tiles, 'tile_rows': [tiles[i:i + 2] for i in range(0, len(tiles), 2)],  'sub_name': clean(sub.name, 80) if sub is not None else digest['title'],
               'owner': clean(owner_name, 80), 'unsubscribe_url': unsubscribe_url, 'attachment': attachment, 'preheader': _preheader(digest),
               'fire': h['heat']['fire'], 'smoke': h['heat']['smoke'], 'ice': h['heat']['ice'], 'colours': HEAT_COLOURS,
               'period_word': 'month' if digest['cadence'] == 'monthly' else 'week', 'cadence_upper': digest['cadence'].upper()}
    return (subject(digest), render_to_string('cveFeed/email/report_digest.txt', context), render_to_string('cveFeed/email/report_digest.html', context))
