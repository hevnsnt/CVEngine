"""The content of an email report: what one weekly or monthly email says about a project or an organization, and how it is written.

``build`` reads stored results only (nothing here scans, probes or resolves a host) and filters by the scope's project ids explicitly, because it
runs in a worker with no request scope. It returns plain data: every string that came from a scanned host, a feed or a person goes through
``report_data.clean``, and the templates (``cveFeed/email/report_digest.html`` and ``.txt``) escape it again, so a hostile host name reaches the
inbox as inert text. Links start with ``mailer.base_url()`` (never a request's Host header) and slugs and ids are quoted.

``render`` turns the data into a subject, a plain-text part and an HTML part for one recipient. The HTML is table-based with inline styles, no
image, font or tracking pixel, and stays far under the 100 KB at which Gmail clips a message.

**At a glance** is calm by design: it opens with the Overview's own status sentence (``cveFeed.overview.status_block``, one implementation of the words), then four
tiles (hosts that need attention, externally facing hosts, new issues worth a look, fixed), then one quiet line with the big totals and the Fire / Smoke / Ice line
explained. The raw totals are never a headline.

The ``threats`` list ("This week's most important vulnerabilities") is filled by ``cveFeed.report_threats`` and holds only what was found on the scope's own hosts
(``matched`` or ``confirmed`` above zero), grouped by product the way the Overview's threat cards are (``overview.threat_groups``), at most THREATS_SHOWN of them;
``threats_more`` counts the groups left out. With none, the section shows ``threats_empty`` (one calm line) so readers know it was checked. ``threats_note`` is its
attribution footnote. An item is ``{source, title, summary, link, badges: [str], cves: [{id, link}], fixed_in: [str], hosts: [{host, project}] (at most HOSTS_SHOWN),
hosts_more, hosts_total, unknown: hosts that run the product with no version read, proven: hosts a check proved}``.
"""
import logging
from datetime import datetime, timezone as dt_timezone
from urllib.parse import quote

from django.db.models import Count, F, Max, Min
from django.db.models.functions import Coalesce
from django.template.loader import render_to_string
from django.urls import reverse

from agentapi import services as svc
from cveFeed import mailer, overview, report_data, report_schedule, report_threats, situations
from cveFeed.report_data import HEAT_NAMES, clean

TOP_FINDINGS = 5  # grouped rows of the top findings
FINDING_HOSTS_SHOWN = 5  # host names listed under a grouped row
THREATS_SHOWN = 5  # vulnerability items in the email; the rest are "plus N more"
HOSTS_SHOWN = 5  # hosts named under a vulnerability item
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
    overview_page = f'{base}{reverse("cve_dashboard")}' + (f'?project={slug}' if scope.kind == 'project' else '')
    return {'open_app': findings, 'findings': findings, 'reporting': reporting, 'manage': f'{reporting}#email', 'overview': overview_page}


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
            'exposed_hosts': sum(r.exposed_hosts for r in rows), 'hosts': sum(r.hosts for r in rows),
            'needs': sum(r.needs_hosts for r in rows) if all(r.needs_hosts is not None for r in rows) else None}  # days before needs_hosts was recorded have none


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


def _short_finding_title(title):
    """A finding's name as the email's row says it: without the check's trailing "with known impact" (the Fire badge already says that)."""
    text = clean(title, 160)
    return text[:-len(' with known impact')].rstrip() if text.lower().endswith(' with known impact') else text


def _group_rows(qs, keys, host_expr, project_field):
    """The hottest groups of a finding queryset: ``keys`` (finding fields) plus the project, with the hosts they reach, the hottest heat, the worst severity and the oldest
    date. One grouped query; the heat, severity and date are the Findings page's own (``heat_rank``, ``sev``, ``when``)."""
    return list(qs.order_by().values(*keys, pid=F(project_field)).annotate(g_hosts=Count(host_expr, distinct=True), g_heat=Max('heat_rank'), g_sev=Max('sev'), g_since=Min('when'))
                .order_by('-g_heat', '-g_hosts', '-g_sev')[:TOP_FINDINGS])


def _top_findings(scope, sources, base, now):
    """The hottest open findings, grouped: findings of one title in one project are one row ("Dangling NS records: 5 hosts in Endless") with the host names under it
    (``FINDING_HOSTS_SHOWN``, then "+N more"). At most TOP_FINDINGS rows, ordered by heat, then by how many hosts, then by severity."""
    everywhere = scope.kind == 'org'
    names = {p.pk: p.name for p in scope.projects}
    cve = sources['cve'].select_related('cve_entry', 'subdomain__target_domain__project')
    scanner = sources['scanner'].select_related('subdomain', 'target_domain__project')
    cve_host, scanner_host = F('subdomain__name'), Coalesce(F('subdomain__name'), F('target_domain__name'))
    groups = []
    for row in _group_rows(sources['cve'], ('cve_entry_id', 'matched_product', 'matched_version'), cve_host, 'subdomain__target_domain__project_id'):
        where = {'cve_entry_id': row['cve_entry_id'], 'matched_product': row['matched_product'], 'matched_version': row['matched_version'],
                 'subdomain__target_domain__project_id': row['pid']}
        groups.append(('cve', row, cve.filter(**where), cve_host))
    for row in _group_rows(sources['scanner'], ('name',), scanner_host, 'target_domain__project_id'):
        groups.append(('scanner', row, scanner.filter(name=row['name'], target_domain__project_id=row['pid']), scanner_host))
    groups.sort(key=lambda g: (g[1]['g_heat'], g[1]['g_hosts'], g[1]['g_sev']), reverse=True)
    out = []
    for kind, row, qs, host_expr in groups[:TOP_FINDINGS]:
        rep = qs.order_by('-heat_rank', '-sev', '-id').first()
        if rep is None:
            continue
        hosts = list(qs.order_by().annotate(host_label=host_expr).values_list('host_label', flat=True).distinct().order_by('host_label')[:FINDING_HOSTS_SHOWN])
        if kind == 'cve':
            product = ' '.join(x for x in (rep.matched_product, rep.matched_version) if x)
            title = f'{rep.cve_entry.cve_id} in {product}' if product else rep.cve_entry.cve_id
            project = rep.subdomain.target_domain.project
        else:
            title, project = _short_finding_title(rep.name), rep.target_domain.project
        total = row['g_hosts']
        out.append({'heat': HEAT_NAMES.get(row['g_heat'], 'ice'), 'title': clean(title, 160), 'count': total, 'hosts': [clean(h, 120) for h in hosts],
                    'more': max(0, total - len(hosts)), 'host': clean(hosts[0], 120) if hosts else '', 'project': clean(names.get(row['pid'], project.name), 80) if everywhere else '',
                    'status': report_data._tracking(rep)['status'] if total == 1 else '',
                    'age_days': max(0, (now - row['g_since']).days) if row['g_since'] and total == 1 else None,
                    'link': _finding_link(base, scope, kind, rep.pk, project)})
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


def _two_sentences(text, limit=260):
    """The first two sentences of ``text``, at most ``limit`` characters (cut at a word)."""
    parts = report_threats.SENTENCE.split(clean(text, 1200))
    short = ' '.join(parts[:2]).strip()
    if len(short) > limit:
        short = short[:limit].rsplit(' ', 1)[0].rstrip(',;:') + '…'
    return short


def _threat_item(group, base, monthly):
    """One email item from an ``overview.threat_groups`` group (see the module text)."""
    shown = group['hosts'][:HOSTS_SHOWN]
    badges = [b['text'] for b in group['badges']]
    if group['confirmed']:
        badges.insert(1, f"Proven on {group['confirmed']:,} host{'' if group['confirmed'] == 1 else 's'}")
    ids = group['cve_ids']
    link = group['link'] or (f'{base}/cve/cves/?id={quote(ids[0], safe="")}' if len(ids) == 1 else '')
    summary = _two_sentences(group['summary'])
    return {'source': 'zero_wire' if group['link'] else 'cve', 'title': clean(group['title'], 200), 'summary': summary.replace(' this week', ' this month') if monthly else summary,
            'link': link, 'badges': badges, 'cves': [{'id': c, 'link': f'{base}/cve/cves/?id={quote(c, safe="")}'} for c in ids[:12]], 'cve_ids': ids[:12],
            'fixed_in': [clean(v, 60) for v in group['fixed_in'][:4]], 'hosts': [{'host': h['host'], 'project': h['project']} for h in shown],
            'hosts_more': max(0, group['matched'] - len(shown)), 'hosts_total': group['matched'], 'unknown': group['product_only'] if group['matched'] else 0,
            'proven': group['confirmed'], 'product': group['product']}


def _threats(scope, start, end, base, monthly):
    """``(items, more, checked, note, ok)``: the vulnerabilities of the period found on the scope's own hosts, grouped, at most THREATS_SHOWN; ``more`` the groups
    left out; ``checked`` how many announced items were looked at in all; ``ok`` False when the section could not be built."""
    try:
        entries, note = report_threats.top(scope, start, end, limit=overview.THREAT_LIMIT, keep_hosts=True, with_hosts=True)
    except Exception:  # noqa: BLE001 - the section is a bonus: a failure in it never stops the email
        logging.getLogger(__name__).warning('could not build the most important vulnerabilities', exc_info=True)
        return [], 0, 0, '', False, []
    found = [e for e in entries if e['matched'] or e['confirmed']]  # only what is on a host of the scope: a product that merely runs somewhere is not news here
    names = {p.pk: p.name for p in scope.projects}
    groups, _ = overview.threat_groups(found, names, len(scope.ids) > 1)
    items = [_threat_item(g, base, monthly) for g in groups[:THREATS_SHOWN]]
    return items, max(0, len(groups) - THREATS_SHOWN), len(entries), note if items else '', True, groups


def _status(scope, now, groups):
    """``(status, counts)`` from the Overview's own functions: the sentence of the top of the Overview, and the hosts by what leads them."""
    ids = list(scope.ids)
    ranking, hosts = situations.ranked(ids)
    counts = overview.host_counts(ranking)
    lead = next((g for g in groups if g['matched']), None)
    status = overview.status_block(hosts, counts, situations.last_scan(ids) if hosts else None, now, lead, None)
    return status, counts


def build(scope, start, end, cadence, now, tz='UTC'):
    """The digest of ``scope`` (an ``agentapi.report_scope.ReportScope``) for the period from ``start`` to ``end`` (aware datetimes). ``tz``: the
    zone the period and the "as of" line are written in."""
    base = mailer.base_url()
    sources, _ = report_data._sources(scope.svc_scope(), False)
    closed, _ = report_data._sources(scope.svc_scope(), True)
    new_findings = sum(_in_period(sources[key], field, start, end).count() for key, field in SOURCE_FIELD.items())
    fixed = sum(_in_period(closed[key].filter(remediation_status='fixed'), 'remediation_updated_at', start, end).count() for key in SOURCE_FIELD)
    monthly = cadence == 'monthly'
    threats, more, checked, note, ok, groups = _threats(scope, start, end, base, monthly)
    status, host_groups = _status(scope, now, groups)
    if monthly:
        status = {**status, 'headline': status['headline'].replace(' this week', ' this month'), 'sub': status['sub'].replace(' this week', ' this month')}
    now_numbers = _current(scope)
    before = _previous(scope, start)
    local_end = end.astimezone(report_schedule.zone(tz))
    label = report_schedule.period_label(start, end, tz, monthly=monthly)
    hygiene = _hygiene(scope, sources)
    period_word = 'month' if monthly else 'week'
    headline = {'open_findings': now_numbers['open_findings'], 'exposed_hosts': now_numbers['exposed_hosts'], 'hosts': now_numbers['hosts'],
                'heat': now_numbers['heat'], 'new_findings': new_findings, 'new_worth_a_look': situations.new_worth_a_look(scope.ids, start, end), 'fixed': fixed,
                'needs': host_groups['needs'], 'proven': host_groups['proven'], 'likely': host_groups['likely'], 'hygiene_high': host_groups['hygiene'],
                'hygiene_open': hygiene['open'], 'compared': before is not None, 'compared_note': '' if before is not None else 'First report: no comparison yet',
                'needs_prev': (before or {}).get('needs'), **{f'{k}_prev': (before or {}).get(k) for k in ('open_findings', 'exposed_hosts', 'hosts')}}
    return {
        'title': 'Monthly report' if monthly else 'Weekly report', 'cadence': cadence, 'scope_name': clean(scope.label, 120), 'scope_kind': scope.kind,
        'org_name': clean(scope.org.name if scope.kind == 'org' else (scope.project.org.name if scope.project.org_id else ''), 120),
        'project_names': [clean(n, 80) for n in sorted(p.name for p in scope.projects)],
        'period': {'start': start.isoformat(), 'end': end.isoformat(), 'label': label,
                   'short': label if label != report_schedule.period_label(start, end, tz) else report_schedule.short_label(start, end, tz)},
        'status': {k: clean(status[k], 400) for k in ('tone', 'pill', 'headline', 'sub', 'state')},
        'headline': headline, 'threats': threats, 'threats_more': more, 'threats_checked': checked, 'threats_note': note, 'threats_ok': ok,
        'threats_empty': '' if (threats or not ok) else (f"None of this {period_word}'s newly exploited or critical vulnerabilities were found on your hosts." + (f' We checked {checked}.' if checked else '')
                                                           if checked else f'No newly exploited or critical vulnerabilities were announced this {period_word}.'),
        'top_findings': _top_findings(scope, sources, base, now),
        'new_hosts': _new_hosts(scope, start, end), 'hygiene': hygiene, 'links': _links(scope, base),
        'instance': mailer._instance(mailer.row()), 'as_of': f'{local_end:%b} {local_end.day}, {local_end:%H:%M} ({tz})',
    }


# --- writing it ----------------------------------------------------------------------------------------------------------------

def _delta(now, before, unit, rise='bad'):
    """``(text, tone)`` for a figure: "▼ 4 since last week" and "▲ 3 since last week", a word as well as a colour so it reads without one. ``rise`` is the tone of a
    rise: ``'bad'`` (red; a fall is green) for a figure that is better when lower, ``'neutral'`` (grey either way) for one that is not news either way, such as the
    number of discovered hosts. Empty when there is nothing to compare with."""
    if before is None:
        return '', ''
    diff = now - before
    if diff == 0:
        return f'no change since {unit}', 'flat'
    if rise == 'neutral':
        return (f'▼ {-diff} since {unit}' if diff < 0 else f'▲ {diff} since {unit}'), 'neutral'
    return (f'▼ {-diff} since {unit}', 'good') if diff < 0 else (f'▲ {diff} since {unit}', 'bad')


def _tiles(digest):
    h = digest['headline']
    unit = 'last month' if digest['cadence'] == 'monthly' else 'last week'
    period = 'this month' if digest['cadence'] == 'monthly' else 'this week'
    needs, n_tone = _delta(h['needs'], h['needs_prev'], unit)
    facing, e_tone = _delta(h['exposed_hosts'], h['exposed_hosts_prev'], unit, rise='neutral')
    of_hosts = f"of {h['hosts']:,} host{'' if h['hosts'] == 1 else 's'}" if h['hosts'] else ''
    return [{'label': 'Needs attention', 'value': f"{h['needs']:,}", 'delta': needs, 'tone': n_tone, 'note': f"host{'' if h['needs'] == 1 else 's'} to look at"},
            {'label': 'Externally facing hosts', 'value': f"{h['exposed_hosts']:,}", 'delta': facing, 'tone': e_tone, 'note': of_hosts},
            {'label': 'New issues worth a look', 'value': f"{h['new_worth_a_look']:,}", 'delta': '', 'tone': '', 'note': period},
            {'label': f'Fixed {period}', 'value': f"{h['fixed']:,}", 'delta': '', 'tone': '', 'note': ''}]


def heat_line(digest):
    """``[{'heat', 'text', 'gloss'}]``: Fire, Smoke and Ice in words: "No Fire", "14 Smoke (worth a look)", "643 Ice (low priority)"."""
    heat = digest['headline']['heat']
    spec = (('fire', 'Fire', 'needs action now'), ('smoke', 'Smoke', 'worth a look'), ('ice', 'Ice', 'low priority'))
    return [{'heat': key, 'text': f'{heat[key]:,} {name}' if heat[key] else f'No {name}', 'gloss': f'({gloss})' if heat[key] else ''} for key, name, gloss in spec]


def totals_line(digest):
    """The big totals as one quiet sentence, never a tile: "1,712 lower-priority items are tracked in cvENGINE (643 low-priority CVE matches, 673 hygiene notes)"."""
    h = digest['headline']
    total = h['open_findings']
    if not total:
        return ''
    quiet = not (h['needs'] or h['heat']['fire'] or h['heat']['smoke'])
    parts = []
    if h['heat']['ice']:
        parts.append(f"{h['heat']['ice']:,} low-priority CVE match{'' if h['heat']['ice'] == 1 else 'es'}")
    if h['hygiene_open']:
        parts.append(f"{h['hygiene_open']:,} hygiene note{'' if h['hygiene_open'] == 1 else 's'}")
    return f"{total:,} {'lower-priority ' if quiet else ''}item{'' if total == 1 else 's'} {'is' if total == 1 else 'are'} tracked in cvENGINE" + (f" ({', '.join(parts)})" if parts else '') + '.'


def _preheader(digest):
    status = digest['status']['headline'].rstrip('.')
    text = f"{digest['scope_name']}: {status}."
    if digest['threats']:
        n = len(digest['threats']) + digest['threats_more']
        text += f" {n} important vulnerabilit{'y' if n == 1 else 'ies'} found on your hosts."
    elif digest['threats_empty']:
        text += ' None of the new vulnerabilities are on your hosts.' if digest['threats_checked'] else ''
    return text


def subject(digest):
    """The subject: the scope and period, then one calm clause that says what is true: fire, something proven, hosts worth a look or nothing."""
    h = digest['headline']
    text = f"cvENGINE {digest['cadence']} report: {digest['scope_name']} ({digest['period']['short']})"
    fire = h['heat']['fire']
    if fire:
        text += f': {fire} on fire'
    elif h['proven']:
        text += f": {h['proven']} proven"
    elif h['needs']:
        text += f": {h['needs']} host{'' if h['needs'] == 1 else 's'} worth a look"
    else:
        text += ': nothing needs you'
    return text if len(text) <= 120 else text[:119].rstrip() + '…'


def render(digest, sub=None, recipient='', unsubscribe_url='', attachment=None, owner_name=''):
    """``(subject, text, html)`` of the email for one recipient. ``sub``: the ReportSubscription (its name and owner go in the footer), None for a
    preview of unsaved settings. ``attachment``: how the full report went, ``{state: 'attached'|'too_large'|'failed', kind, filename, mb, limit_mb}``
    or None for none."""
    tiles = _tiles(digest)
    context = {'d': digest, 'tiles': tiles, 'tile_rows': [tiles[i:i + 2] for i in range(0, len(tiles), 2)], 'sub_name': clean(sub.name, 80) if sub is not None else digest['title'],
               'owner': clean(owner_name, 80), 'unsubscribe_url': unsubscribe_url, 'attachment': attachment, 'preheader': _preheader(digest),
               'heat_line': heat_line(digest), 'totals_line': totals_line(digest), 'colours': HEAT_COLOURS,
               'tone_colour': {'fire': HEAT_COLOURS['fire'], 'smoke': HEAT_COLOURS['smoke'], 'ok': '#2f6048'}.get(digest['status']['tone'], HEAT_COLOURS['ice']),
               'period_word': 'month' if digest['cadence'] == 'monthly' else 'week', 'cadence_upper': digest['cadence'].upper()}
    return (subject(digest), render_to_string('cveFeed/email/report_digest.txt', context), render_to_string('cveFeed/email/report_digest.html', context))
