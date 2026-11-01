"""CVEngine UI: dashboard + live CVE feed, onboarding, and the live asset graph.

Pages are server-rendered shells; the live parts poll the small JSON endpoints
below, so the UI updates on its own without a reload.
"""
import json
import logging
import re
from urllib.parse import quote
from collections import Counter

from django.db.models import F
from django.db.models import Count
from django.http import JsonResponse
from django.http import Http404, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_GET, require_POST
from rolepermissions.decorators import has_permission_decorator

from cveFeed import match_policy, snapshot_cache
from cveFeed.discovery import NUCLEI_SCAN_ACTIVITY_NAMES
from cveFeed.models import (AgentActivity, AutoFireRun, CVEEntry, CVEMatch, DiscoveryEvent, GeneratedTemplate, HygieneFinding,
                            TlsCertificate)
from cveFeed.threat import FIRE, ICE, SMOKE, classify_threat_tier, host_heat, match_temperature
from startScan.models import OPEN_PORT_STATES, open_services
from targetApp.target_types import is_public_address
from reNgine.definitions import FOUR_OH_FOUR_URL, PERM_MODIFY_SYSTEM_CONFIGURATIONS

logger = logging.getLogger(__name__)

FEED_PAGE = 30
FEED_MAX = 100
ALL_PROJECTS = '_all'  # reserved slug of the read-only combined view (tenancy.roles.ALL_PROJECTS)
GRAPH_NODE_CAP = 1500


def _tier(entry):
    return classify_threat_tier(
        kev=entry.kev, epss_reached=entry.epss_reached,
        exploit_db=entry.exploit_db, cvss=entry.cvss)


def serialize_cve(entry, match_count=0):
    return {
        'id': entry.pk,
        'cve_id': entry.cve_id,
        'title': (entry.title or entry.original_description or '')[:140],
        'cvss': entry.cvss,
        'tier': _tier(entry),
        'kev': bool(entry.kev),
        'exploit_db': bool(entry.exploit_db),
        'epss': bool(entry.epss_reached),
        'published_at': entry.published_at.isoformat() if entry.published_at else None,
        'matches': match_count,
    }


def asset_status(sub, scanned_ids, vulnerable_ids, nuclei_done=()):
    """How far along a discovered host is, for the graph's colour coding.

    unscanned: known (from discovery or certificate transparency) but nuclei has not looked at it yet.
    scanned: nuclei has run over it (its scan's nuclei stage finished, or it has a nuclei finding) and flagged nothing worth acting on.
    vulnerable: an open, non-informational finding or a CVE match the AI has not ruled out.
    """
    if sub.pk in vulnerable_ids:
        return 'vulnerable'
    if sub.pk in scanned_ids or sub.scan_history_id in nuclei_done:
        return 'scanned'
    return 'unscanned'


_SEV_NAME = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'}
TIER_RANK = {FIRE: 3, SMOKE: 2, ICE: 1}


def _host_tip(sub, live_matches, severities, aliases=()):
    """A compact summary for the attack-surface hover card: no extra queries, only the prefetched matches/ips and the
    host's stored score reasons. Severities is the list of open-finding severities already gathered for this host."""
    worst = None
    for match in live_matches:
        tier = match_temperature(_tier(match.cve_entry), match.cve_entry.cvss, match.ai_verdict, match.distro_status, match_policy.version_unknown(match))
        if worst is None or TIER_RANK.get(tier, 0) > TIER_RANK.get(worst[1], 0):
            worst = (match.cve_entry.cve_id, tier)
    reasons = [r.get('label', '') for r in (sub.score_detail or [])][:3] if hasattr(sub, 'score_detail') else []
    score_parts = [{'label': str(r.get('label', ''))[:140], 'points': int(r.get('points') or 0)}
                   for r in (sub.score_detail or [])[:8]] if hasattr(sub, 'score_detail') else []
    return {
        'project': sub.target_domain.project.name if sub.target_domain_id and sub.target_domain.project_id else '',
        'org': (sub.target_domain.project.org.name if sub.target_domain_id and sub.target_domain.project_id
                and sub.target_domain.project.org_id else ''),
        'ips': len({ip.address for ip in sub.ip_addresses.all()}),
        'cves': len(live_matches),
        'top_cve': worst[0] if worst else '',
        'top_tier': worst[1] if worst else '',
        'findings': len(severities),
        'max_sev': _SEV_NAME.get(max(severities), '') if severities else '',
        'reasons': [r for r in reasons if r],
        'score_parts': score_parts,
        'aliases': list(aliases)[:12],
    }


def graph_payload(domain_id=None, scan_id=None):
    """Nodes/edges for the asset graph: domain > subdomain > ip, and subdomain > cve. Only live hosts are drawn (they resolved
    to an IP, or something saw them answer); names that never resolved are left out. Ports belong on the host's detail card."""
    from startScan.models import Subdomain, Vulnerability
    from cveFeed import internal_view
    from cveFeed.graph_overview import root_for

    from django.db.models import Prefetch
    # a match needs its CVE's tier fields only: never the prose columns
    matches = CVEMatch.objects.only('subdomain_id', 'ai_verdict', 'evidence', 'version_in_range', 'template_result', 'distro_status', 'cve_entry__cve_id', 'cve_entry__kev',
                                    'cve_entry__epss_reached', 'cve_entry__exploit_db', 'cve_entry__cvss').select_related('cve_entry')
    subs = Subdomain.objects.select_related('target_domain__project__org').prefetch_related(
        'ip_addresses', Prefetch('cve_matches', queryset=matches))
    if domain_id:
        subs = subs.filter(target_domain_id=domain_id)
    if scan_id:
        subs = subs.filter(scan_history_id=scan_id)  # one scan asked for by id: exactly its rows
    else:
        from cveFeed.counts import host_reps
        subs = subs.filter(pk__in=host_reps(domain_id).values('pk'))  # otherwise each host once: the row the Hosts page shows
    nodes, edges = {}, set()
    by_name = {}

    def node(node_id, kind, label, **extra):
        if len(nodes) < GRAPH_NODE_CAP or node_id in nodes:
            nodes.setdefault(node_id, {'id': node_id, 'kind': kind, 'label': label, **extra})
            return True
        return False

    from cveFeed.counts import CLOSED, LIVE_HOST_Q, match_is_live
    from django.db.models import F
    subs = subs.filter(LIVE_HOST_Q).distinct()
    # the riskiest hosts first, then by name: past the node cap the drawn hosts are the ones that matter, and the same ones on every poll
    sub_list = list(subs.order_by(F('score').desc(nulls_last=True), 'name', 'pk')[:GRAPH_NODE_CAP])
    sub_ids = [s.pk for s in sub_list]
    # "scanned" = at least one finding exists at all, even an info-only one (something looked); a
    # second query narrows to the ones severe enough, open, and not ruled out, to call "vulnerable".
    scanned_ids = set(Vulnerability.objects.filter(subdomain_id__in=sub_ids).values_list('subdomain_id', flat=True))
    vulnerable_ids = set(Vulnerability.objects.filter(
        subdomain_id__in=sub_ids, open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED).values_list('subdomain_id', flat=True))
    vulnerable_ids |= {s.pk for s in sub_list if any(match_is_live(m) for m in s.cve_matches.all())}

    severities = {}
    for sub_id, severity in Vulnerability.objects.filter(subdomain_id__in=sub_ids, open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED).values_list('subdomain_id', 'severity'):
        severities.setdefault(sub_id, []).append(severity)

    # one host, several names: the evidence of the other names on the same addresses counts for the host drawn
    from cveFeed.counts import host_siblings
    siblings = host_siblings(sub_ids)
    sibling_ids = {i for rows in siblings.values() for i, _ in rows}
    sibling_matches, sibling_findings, sibling_seen = {}, {}, set()
    if sibling_ids:
        for m in CVEMatch.objects.filter(subdomain_id__in=sibling_ids).exclude(ai_verdict='not_affected').exclude(remediation_status__in=CLOSED).only(
                'subdomain_id', 'ai_verdict', 'evidence', 'version_in_range', 'template_result', 'distro_status', 'cve_entry__cve_id', 'cve_entry__kev', 'cve_entry__epss_reached',
                'cve_entry__exploit_db', 'cve_entry__cvss').select_related('cve_entry'):
            sibling_matches.setdefault(m.subdomain_id, []).append(m)
        for sid, severity, name in Vulnerability.objects.filter(subdomain_id__in=sibling_ids, open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED) \
                .values_list('subdomain_id', 'severity', 'name'):
            sibling_findings.setdefault(sid, []).append((severity, name))
    own_findings = {}
    if sibling_ids:
        for sid, severity, name in Vulnerability.objects.filter(subdomain_id__in=sub_ids, open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED) \
                .values_list('subdomain_id', 'severity', 'name'):
            own_findings.setdefault(sid, set()).add((severity, name))

    from startScan.models import ScanActivity
    nuclei_done = set(ScanActivity.objects.filter(scan_of_id__in={s.scan_history_id for s in sub_list if s.scan_history_id},
                                                  name__in=NUCLEI_SCAN_ACTIVITY_NAMES, status=2).values_list('scan_of_id', flat=True))
    # the alias and note a person gave each host (one query): the node's label stays the name, the tooltip and card add them
    from types import SimpleNamespace
    from agentapi.services import alias_and_note
    from cveFeed.models import HostProfile
    wanted = {s.name.lower() for s in sub_list} | {n.lower() for rows in siblings.values() for _, n in rows}
    tags = {(row.project_id, row.host): {'alias': row.alias, 'note': row.note}
            for row in HostProfile.objects.filter(host__in=wanted).exclude(alias='', note='')}
    cut = False  # the node cap stopped the drawing before every host was in
    for sub in sub_list:
        sid = f'sub:{sub.pk}'
        status = asset_status(sub, scanned_ids, vulnerable_ids, nuclei_done)
        live = [m for m in sub.cve_matches.all() if match_is_live(m)]
        sev = list(severities.get(sub.pk, []))
        sibs = siblings.get(sub.pk, [])
        have = {m.cve_entry.cve_id for m in live}
        seen_findings = set(own_findings.get(sub.pk, ()))
        for other_id, _ in sibs:
            for m in sibling_matches.get(other_id, []):
                if m.cve_entry.cve_id not in have:
                    have.add(m.cve_entry.cve_id)
                    live.append(m)
            for severity, name in sibling_findings.get(other_id, []):
                if (severity, name) not in seen_findings:
                    seen_findings.add((severity, name))
                    sev.append(severity)
        if status != 'vulnerable' and (live or sev):
            status = 'vulnerable'
        tiers = [match_temperature(_tier(m.cve_entry), m.cve_entry.cvss, m.ai_verdict, m.distro_status, match_policy.version_unknown(m)) for m in live]
        heat = host_heat(status, tiers, sev)
        given = alias_and_note(sub, [SimpleNamespace(name=n, target_domain=sub.target_domain) for _, n in sibs], tags)
        if not node(sid, 'subdomain', sub.name, target=sub.target_domain.name if sub.target_domain_id else '',
                    **{k: given[k] for k in ('alias', 'note') if given[k]},
                    project=sub.target_domain.project.slug if sub.target_domain_id and sub.target_domain.project_id else '',
                    status=status, heat=heat, score=sub.score, info=_host_tip(sub, live, sev, [n for _, n in sibs if n.lower() != sub.name.lower()]),
                    internal=internal_view.is_internal(sub.target_domain.project_id if sub.target_domain_id else None, sub.name),
                    network=internal_view.network_of(sub.target_domain.project_id if sub.target_domain_id else None, sub.name)):
            cut = True
            break
        by_name[sub.name.lower()] = sid
        if sub.target_domain_id and node(f'dom:{sub.target_domain_id}', 'domain', sub.target_domain.name,
                **{k: getattr(sub.target_domain, k) for k in ('alias', 'note') if getattr(sub.target_domain, k)},
                project=sub.target_domain.project.slug if sub.target_domain.project_id else '',
                project_name=sub.target_domain.project.name if sub.target_domain.project_id else '',
                root=root_for(sub.target_domain)):
            edges.add((f'dom:{sub.target_domain_id}', sid))
        for ip in sub.ip_addresses.all():
            if node(f'ip:{ip.pk}', 'ip', ip.address):
                edges.add((sid, f'ip:{ip.pk}'))
        for match in sub.cve_matches.all():
            if not match_is_live(match):
                continue
            cve = match.cve_entry
            if node(f'cve:{cve.pk}', 'cve', cve.cve_id, tier=_tier(cve)):
                edges.add((sid, f'cve:{cve.pk}'))
    # bbot's own discovery relationships (which host revealed which); scoped the same as the node query above,
    # and otherwise spans every scan the caller can see so the whole project's history draws as one graph.
    events = DiscoveryEvent.objects.exclude(parent_host='')
    if scan_id:
        events = events.filter(scan_id=scan_id)
    elif domain_id:
        events = events.filter(domain_id=domain_id)  # includes CT-monitor finds, which have no scan
    # only an edge between two drawn hosts is ever kept, so read only those (a name in the case the host row spells it and lower case, which
    # is how bbot reports it), in a fixed order: an arbitrary 1500 of every pair ever stored dropped edges of drawn hosts at random
    drawn = {n for s in sub_list for n in (s.name, s.name.lower())}
    events = events.filter(host__in=drawn, parent_host__in=drawn)
    for parent, host in events.values_list('parent_host', 'host').distinct().order_by('parent_host', 'host')[:GRAPH_NODE_CAP]:
        a, b = by_name.get((parent or '').lower()), by_name.get((host or '').lower())
        if a and b and a != b:
            edges.add((a, b))
    drawn_hosts = sum(1 for n in nodes.values() if n['kind'] == 'subdomain')
    capped = cut or len(sub_list) >= GRAPH_NODE_CAP  # counted only when the cap may have cut the list
    total_hosts, per_project = drawn_hosts, {}
    if capped:
        from django.db.models import Count
        per_project = {slug or '': n for slug, n in subs.order_by().values_list('target_domain__project__slug').annotate(n=Count('pk', distinct=True))}
        total_hosts = max(sum(per_project.values()), drawn_hosts)
    return {'nodes': list(nodes.values()), 'edges': [{'from': a, 'to': b} for a, b in sorted(edges)],
            'hosts': {'drawn': drawn_hosts, 'total': total_hosts, 'projects': per_project},
            'projects': _graph_projects(domain_id, scan_id)}


def _graph_projects(domain_id=None, scan_id=None):
    """``{slug: {'name', 'hygiene'}}`` for every project the caller sees: its open, actionable hygiene findings (the dashboard's Hygiene
    tile), which the graph hangs off the project's cloud beside its fire, smoke and ice hosts. Hygiene findings belong to a target, not
    a host row, so they are counted here rather than from the drawn hosts. One query."""
    from django.db.models import Count
    from cveFeed import counts
    from dashboard.models import Project
    hygiene = counts.actionable_hygiene(HygieneFinding.objects.all())
    if domain_id:
        hygiene = hygiene.filter(domain_id=domain_id)
    if scan_id:
        hygiene = hygiene.none()  # one scan's graph: its hosts only
    found = dict(hygiene.order_by().values_list('domain__project__slug').annotate(n=Count('id')))
    return {slug: {'name': name, 'hygiene': found.get(slug, 0)} for slug, name in Project.objects.values_list('slug', 'name')}


def _running_scans(ScanHistory):
    from cveFeed.counts import running_scans
    return running_scans(ScanHistory.objects.all())


def tier_counts():
    """fire / smoke / ice over every stored CVE, counted by the database (see cveFeed.threat.classify_threat_tier)."""
    from cveFeed.threat import fire_tier_q, hot_tier_q
    total, n_fire, n_hot = (CVEEntry.objects.count(), CVEEntry.objects.filter(fire_tier_q()).count(),
                            CVEEntry.objects.filter(hot_tier_q()).count())
    return {FIRE: n_fire, SMOKE: n_hot - n_fire, ICE: total - n_hot}


def live_scan_counts():
    """Running and queued scans, and the background jobs in progress under finished scan records, read fresh on every poll (they are cheap and
    the first thing a person watches). The running window (a settings lookup) is read once for all three."""
    from cveFeed import counts
    window = counts.running_window()
    return {'scans_running': counts.running_scans(window=window).count(), 'scans_queued': counts.queued_scans().count(),
            'scans_background_running': counts.background_running(window=window).count()}


def _oldest_open_what(kind, row_id):
    """What the oldest open item is, in plain words for the Live tile: ``{'severity', 'title', 'host'}``, or None when the row is gone."""
    from startScan.models import Vulnerability
    names = {4: 'Critical', 3: 'High'}
    if kind == 'cve':
        m = CVEMatch.objects.filter(pk=row_id).select_related('cve_entry', 'subdomain').first()
        if m:
            cvss = m.cve_entry.cvss or 0
            return {'severity': 'Critical' if cvss >= 9 else 'High', 'title': m.cve_entry.cve_id, 'host': m.subdomain.name if m.subdomain else ''}
    elif kind == 'scanner':
        v = Vulnerability.objects.filter(pk=row_id).select_related('subdomain').first()
        if v:
            return {'severity': names.get(v.severity, 'High'), 'title': v.name or '', 'host': v.subdomain.name if v.subdomain else ''}
    elif kind == 'hygiene':
        h = HygieneFinding.objects.filter(pk=row_id).first()
        if h:
            return {'severity': names.get(h.severity, 'High'), 'title': h.title, 'host': h.host}
    return None


def stats_payload():
    """Every headline number, defined once in ``cveFeed.counts`` (what each one counts is in that module's docstring)."""
    from cveFeed import counts, internal_view
    from startScan.models import Vulnerability
    from targetApp.models import Domain
    tiers = tier_counts()
    reps = counts.host_reps()
    from django.db.models import Count
    host_counts = reps.aggregate(total=Count('pk', distinct=True), live=Count('pk', filter=counts.LIVE_HOST_Q, distinct=True))  # one pass over the hosts, not two
    oldest = counts.oldest_open()
    return {
        'targets': Domain.objects.count(),
        'certs_expiring': counts.expiring_certificates(TlsCertificate.objects.all()).count(),
        'certs_total': TlsCertificate.objects.count(),
        'hygiene_open': counts.actionable_hygiene(HygieneFinding.objects.all()).count(),
        'hosts': host_counts['total'],
        'hosts_live': host_counts['live'],
        **live_scan_counts(),
        'tiers': {FIRE: tiers[FIRE], SMOKE: tiers[SMOKE], ICE: tiers[ICE]},
        'cves': CVEEntry.objects.count(),
        'matches': counts.exposed_matches().count(),
        'scanner_findings': counts.actionable_findings(Vulnerability.objects.all()).count(),
        'exposed_hosts': counts.exposed_host_count(),
        'oldest_open_days': oldest['days'],  # the longest a critical or high item has sat open, across CVE matches, scanner and hygiene findings
        'oldest_open_kind': oldest['kind'],  # 'cve', 'scanner' or 'hygiene'
        'oldest_open_id': oldest['id'],  # the row of that kind to link to
        'oldest_open_what': _oldest_open_what(oldest['kind'], oldest['id']) if oldest['id'] else None,  # {severity, title, host}
        'internal': internal_view.summary(),  # the declared internal networks and their share of the numbers above (cveFeed.internal_view)
        'autofire_runs': AutoFireRun.objects.count(),
        'templates': GeneratedTemplate.objects.filter(status=GeneratedTemplate.STATUS_VALID).count(),
    }


# --- pages -------------------------------------------------------------------

SECTIONS = {
    'targets': 'Targets',
    'scans': 'Scans',
    'hosts': 'Hosts',
    'changes': 'Changes',
    'activity': 'Activity',
    'vulns': 'Findings',
    'matches': 'CVE matches',
    'hygiene': 'Hygiene',
    'suppliers': 'Suppliers',
    'keys': 'API keys',
    'sentinels': 'Sentinels',
}


SCOPE_KEY = 'cve_scope'  # the session's last chosen project (or ALL_PROJECTS): pages with no project in their address keep it


def remembered_scope(request, visible):
    """The project (or ALL_PROJECTS) this session last chose, when the caller can still see it; otherwise None. ``visible`` is
    the slugs the caller can see."""
    want = request.session.get(SCOPE_KEY) if hasattr(request, 'session') else None
    if want == ALL_PROJECTS:
        return want if len(visible) >= 2 else None
    return want if want in visible else None


def remember_scope(request, slug):
    if slug and hasattr(request, 'session') and request.session.get(SCOPE_KEY) != slug:
        request.session[SCOPE_KEY] = slug


def ui_context(request, active, slug=None, remember=True):
    """Shell context shared by every UI page: active nav item and the project switcher. ``slug`` may be the reserved ``_all``
    (the read-only combined view): the switcher then marks "All projects" selected. That option is offered only to a caller who
    can see two or more projects; with one there is nothing to combine. A page that names a project remembers it for the
    session (unless ``remember`` is false: a page that fell back to a project nobody chose); a page that names none (Sentinels,
    Settings, About ...) shows the remembered one, so the switcher and the section links carry the choice everywhere."""
    from dashboard.models import Project
    projects = list(Project.objects.order_by('name').values('slug', 'name', org_slug=F('org__slug'), org_name=F('org__name')))  # scoped to the caller
    if slug:
        if remember:
            remember_scope(request, slug)
    else:
        slug = remembered_scope(request, [p['slug'] for p in projects]) or (ALL_PROJECTS if len(projects) >= 2 else None)
    current = slug or (projects[0]['slug'] if projects else None)
    # the organizations the caller's projects belong to; the switcher shows an organization choice only when there are two or more
    orgs = []
    for p in projects:
        p['org_slug'] = p['org_slug'] or ''
        if p['org_slug'] not in [o['slug'] for o in orgs]:
            orgs.append({'slug': p['org_slug'], 'name': p['org_name'] or 'No organization'})
    orgs.sort(key=lambda o: o['name'].lower())
    current_org = next((p['org_slug'] for p in projects if p['slug'] == current), '') if slug != ALL_PROJECTS else None
    # All projects narrowed to one organization (chosen in the switcher; ?org= names it and the session keeps it)
    scope_org = ''
    if slug == ALL_PROJECTS and len(orgs) >= 2:
        from tenancy.roles import SCOPE_ORG_KEY, scope_org as requested_org
        want = requested_org(request)
        scope_org = want if any(o['slug'] == want and want for o in orgs) else ''
        if remember and 'org' in request.GET and hasattr(request, 'session') and request.session.get(SCOPE_ORG_KEY, '') != scope_org:
            request.session[SCOPE_ORG_KEY] = scope_org
    in_scope = [p for p in projects if p['org_slug'] == scope_org] if scope_org else projects
    from tenancy.roles import is_admin_anywhere
    from dashboard.models import AIProviderSettings
    ai_cfg = AIProviderSettings.objects.first()
    ai_connected = bool(ai_cfg and ai_cfg.enabled)
    from agentapi.sentinel_broker import has_sentinels
    here = next((p for p in projects if p['slug'] == current), None) if slug != ALL_PROJECTS else None
    return {'active': active, 'slug': current, 'projects': projects, 'orgs': orgs if len(orgs) >= 2 else [], 'current_org': current_org, 'sections': SECTIONS, 'is_admin': is_admin_anywhere(request.user),
            'is_app_admin': request.user.is_superuser,
            'bounty_enabled': _bounty_allowed(request.user),
            'sentinels_enabled': bool(here and has_sentinels(here['slug'], here['org_slug'])),
            'ai_usage_connected': ai_connected,
            'ai_usage_provider': ai_cfg.provider if ai_connected else '',
            'ai_usage_model': ai_cfg.model if ai_connected else '',
            'all_projects': slug == ALL_PROJECTS, 'show_all_option': len(projects) >= 2,
            'scope_org': scope_org, 'scope_org_name': next((o['name'] for o in orgs if o['slug'] == scope_org), '') if scope_org else '',
            'scope_projects': len(in_scope)}


def _bounty_allowed(user):
    from cveFeed.bounty_api import allowed
    return allowed(user)


def bounty_page(request):
    """The bug bounty page. The middleware has already refused users an App Admin has not authorized; the check here is the second layer.
    The project comes from ?project=, like the dashboard; the combined view has no meaning for engagements, so it falls back to the first project."""
    from django.core.exceptions import PermissionDenied

    from dashboard.models import Project
    if not _bounty_allowed(request.user):
        raise PermissionDenied
    projects = list(Project.objects.values_list('slug', flat=True))  # scoped to the caller
    want = request.GET.get('project') or ''
    if not (want in projects and want != ALL_PROJECTS):
        want = remembered_scope(request, projects) or ''
    chosen = want in projects and want != ALL_PROJECTS
    slug = want if chosen else (projects[0] if projects else None)
    return render(request, 'cveFeed/bounty.html', ui_context(request, 'bounty', slug, remember=chosen))


def dashboard(request):
    from cveFeed.welcome import needs_welcome
    from dashboard.models import AIProviderSettings, Project
    if needs_welcome(request.user) and request.GET.get('skip') != '1':
        return redirect('cve_welcome')  # first run: the guided setup
    cfg = AIProviderSettings.objects.first()
    # The dashboard spans every project the viewer can see by default (the combined "All projects" view); a
    # ?project=<slug> they may see narrows every panel to that one. The switcher stays here when it changes.
    projects = list(Project.objects.values_list('slug', flat=True))  # scoped to the caller
    want = request.GET.get('project') or remembered_scope(request, projects) or ''  # no ?project: the session's last choice
    if want and want != ALL_PROJECTS and want in projects:
        slug = want
    elif len(projects) >= 2:
        slug = ALL_PROJECTS
    else:
        slug = projects[0] if projects else None
    return render(request, 'cveFeed/dashboard.html', {
        'ai_ready': bool(cfg and cfg.enabled), **ui_context(request, 'dashboard', slug),
    })


def graph(request):
    from targetApp.models import Domain
    from dashboard.models import Project
    allowed = set(Project.objects.values_list('slug', flat=True))
    project = request.GET.get('project') or remembered_scope(request, allowed) or ''  # no ?project: the session's last choice
    selected = project if project in allowed else ALL_PROJECTS if len(allowed) > 1 else next(iter(allowed), None)
    shell = ui_context(request, 'graph', selected)
    domains = Domain.objects.select_related('project').order_by('name')
    if selected != ALL_PROJECTS:
        domains = domains.filter(project__slug=selected)
    elif shell['scope_org']:
        domains = domains.filter(project__org__slug=shell['scope_org'])
    return render(request, 'cveFeed/graph.html', {'domains': domains, **shell})


def scan_page(request, slug, scan_id):
    from dashboard.models import Project
    project = Project.objects.filter(slug=slug).first()
    if not project:
        raise Http404
    return render(request, 'cveFeed/section.html', {
        'section': 'scan', 'title': f'Scan #{scan_id}', 'project': project, 'scan_id': scan_id,
        **ui_context(request, 'scans', slug),
    })


def project_page(request, slug, section):
    """Targets, scans, hosts, vulnerabilities and matches: shells that the page script fills from /api/v1. The reserved slug
    ``_all`` is the same shell over every project the caller may see (read-only; the script reads /api/v1/projects/_all/...)."""
    from dashboard.models import Project
    if section == 'keys':
        # the keys now live in Settings > API keys (App Admins) and Administration (organization admins); an old link lands there
        from tenancy.roles import is_admin_anywhere
        if request.user.is_superuser:
            return redirect('/cve/settings/#keys')
        if is_admin_anywhere(request.user):
            return redirect('/cve/admin/')
        raise Http404
    if slug == ALL_PROJECTS:
        from tenancy.roles import user_best_role
        if not user_best_role(request.user):
            raise Http404  # no organization or project access: same answer as an unknown project
        project = {'slug': ALL_PROJECTS, 'name': 'All projects'}
    else:
        project = Project.objects.filter(slug=slug).first()
    if not project:
        raise Http404
    if section == 'sentinels':
        if slug == ALL_PROJECTS:
            raise Http404  # a Sentinel's scope is per project; there is no combined view
        return render(request, 'cveFeed/project_sentinels.html', {'title': SECTIONS[section], 'project': project, **ui_context(request, 'project-sentinels', slug)})
    return render(request, 'cveFeed/section.html', {
        'section': section, 'title': SECTIONS[section], 'project': project, **ui_context(request, section, slug),
    })


def host_screenshot(request, slug, subdomain_id):
    """Serve a gowitness screenshot for a host. The tenancy middleware already confirmed the caller may
    see ``slug``; this only needs to confirm the subdomain actually belongs to that project."""
    import os

    from django.conf import settings
    from django.http import FileResponse

    from dashboard.models import Project
    from startScan.models import Subdomain
    project = Project.objects.filter(slug=slug).first()
    if not project:
        raise Http404
    sub = Subdomain.objects.filter(pk=subdomain_id, scan_history__domain__project=project).first() or \
        Subdomain.objects.filter(pk=subdomain_id, target_domain__project=project).first()
    if not sub or not sub.screenshot_path:
        raise Http404
    media_root = os.path.realpath(settings.MEDIA_ROOT)
    path = os.path.realpath(os.path.join(media_root, sub.screenshot_path))
    if not (path == media_root or path.startswith(media_root + os.sep)) or not os.path.isfile(path):
        raise Http404
    size = request.GET.get('size', 'full')
    if size not in ('full', 'thumb'):
        return HttpResponseBadRequest('size must be full or thumb')
    if size == 'thumb':
        from cveFeed import shots
        thumb = shots.thumbnail_path(path)
        if thumb:
            return _cacheable_file(request, thumb, 'image/jpeg')
    return _cacheable_file(request, path)


def _cacheable_file(request, path, content_type=None):
    """A file with an ETag (mtime and size) and a day of private caching, so a gallery grid revisits for a 304, not the bytes."""
    import mimetypes
    import os

    from django.http import FileResponse, HttpResponseNotModified
    from django.utils.http import http_date
    info = os.stat(path)
    etag = f'"{int(info.st_mtime)}-{info.st_size}"'
    if request.META.get('HTTP_IF_NONE_MATCH') == etag:
        response = HttpResponseNotModified()
    else:
        response = FileResponse(open(path, 'rb'), content_type=content_type or mimetypes.guess_type(path)[0] or 'application/octet-stream')
        response['Last-Modified'] = http_date(info.st_mtime)
    response['ETag'] = etag
    response['Cache-Control'] = 'private, max-age=86400'
    return response


def host_rdp_screenshot(request, slug, subdomain_id, port):
    """Serve a stored RDP login-screen capture (cveFeed.rdp_shot). Same tenancy check as host_screenshot: the caller's
    access to ``slug`` is already confirmed, this only needs to confirm the subdomain belongs to that project."""
    import os

    from django.conf import settings
    from django.http import FileResponse

    from cveFeed.models import RdpScreenshot
    from dashboard.models import Project
    from startScan.models import Subdomain
    project = Project.objects.filter(slug=slug).first()
    if not project:
        raise Http404
    sub = Subdomain.objects.filter(pk=subdomain_id, scan_history__domain__project=project).first() or \
        Subdomain.objects.filter(pk=subdomain_id, target_domain__project=project).first()
    if not sub:
        raise Http404
    shot = RdpScreenshot.objects.filter(project=project, host=sub.name, port=port).first()
    if not shot or not shot.image_path:
        raise Http404
    media_root = os.path.realpath(settings.MEDIA_ROOT)
    path = os.path.realpath(os.path.join(media_root, shot.image_path))
    if not (path == media_root or path.startswith(media_root + os.sep)) or not os.path.isfile(path):
        raise Http404
    return FileResponse(open(path, 'rb'))


def welcome_page(request):
    return render(request, 'cveFeed/welcome.html', ui_context(request, 'welcome'))


def account_page(request):
    return render(request, 'cveFeed/account.html', ui_context(request, 'account'))


# The version this page's claims were last checked against. Bump it, after rereading cveFeed/how.html, whenever web/.version moves
# (tests/test_how_it_works.py fails until it matches, so a release cannot ship a stale page).
HOW_REVIEWED_VERSION = '1.3.1'


def how_page(request):
    return render(request, 'cveFeed/how.html', {**ui_context(request, 'about'), 'how_reviewed_version': HOW_REVIEWED_VERSION})


def about_page(request):
    return render(request, 'cveFeed/about.html', ui_context(request, 'about'))


def admin_page(request):
    from django.core.exceptions import PermissionDenied

    from tenancy.roles import is_admin_anywhere
    if not is_admin_anywhere(request.user):
        raise PermissionDenied
    return render(request, 'cveFeed/admin.html', ui_context(request, 'admin'))


def settings_page(request):
    return render(request, 'cveFeed/settings.html', ui_context(request, 'settings'))


def agents_page(request):
    return render(request, 'cveFeed/agents.html', {'host': request.get_host(), **ui_context(request, 'agents')})


def sentinels_page(request):
    from dashboard.models import Org
    from tenancy import roles
    # the organizations this person may provision an organization-wide Sentinel for: the same check the enroll endpoint applies
    enroll_orgs = list(Org.objects.filter(pk__in=roles.managed_org_ids(request.user)).order_by('name').values('slug', 'name'))
    return render(request, 'cveFeed/sentinels.html', {'host': request.get_host(), 'enroll_orgs': enroll_orgs,
                                                      **ui_context(request, 'sentinels')})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def onboarding(request):
    return render(request, 'cveFeed/onboarding.html', ui_context(request, 'setup'))


# --- JSON --------------------------------------------------------------------

def project_scoped(view):
    """``?project=<slug>`` narrows the request to that one project, so the dashboard shows what the Hosts page and the
    rest of the selected project show (without it, everything the caller may see). A slug the caller may not see is a 404,
    the same as a project that does not exist."""
    from functools import wraps

    @wraps(view)
    def wrapped(request, *args, **kwargs):
        slug = request.GET.get('project', '')
        from dashboard.models import Project
        from tenancy import roles, scope
        allowed = scope.current_allowed()
        if not slug or slug == ALL_PROJECTS:  # "_all": everything the caller may see, which is the default
            org = roles.scope_org(request)  # unless the switcher narrowed All projects to one organization
            ids = set(Project.objects.filter(org__slug=org).values_list('id', flat=True)) if org else set()
            if allowed is not None:
                ids &= set(allowed)
            if not ids:
                return view(request, *args, **kwargs)
            tokens = scope.set_scope(ids, scope.current_user())
            try:
                return view(request, *args, **kwargs)
            finally:
                scope.reset_scope(tokens)
        project = Project.objects.filter(slug=slug).only('id').first()
        if not project or (allowed is not None and project.id not in allowed):
            return JsonResponse({'error': 'project not found'}, status=404)
        tokens = scope.set_scope({project.id}, scope.current_user())
        try:
            return view(request, *args, **kwargs)
        finally:
            scope.reset_scope(tokens)
    return wrapped

@require_GET
def api_feed(request):
    """Newest CVEs; with ?after=<pk> only entries newer than that pk (for live polling)."""
    qs = CVEEntry.objects.order_by('-pk')
    after = request.GET.get('after', '')
    limit = FEED_PAGE
    if after.isdigit():
        qs, limit = qs.filter(pk__gt=int(after)), FEED_MAX
    entries = list(qs[:limit])
    counts = dict(
        CVEMatch.objects.filter(cve_entry__in=entries).exclude(ai_verdict='not_affected')
        .values_list('cve_entry').annotate(n=Count('id')))
    return JsonResponse({'items': [serialize_cve(e, counts.get(e.pk, 0)) for e in entries]})


STATS_CACHE_SECONDS = 10  # how long a headline snapshot is fresh; it is kept three times as long to serve while one request refreshes it
STATS_REVISION_KEY = snapshot_cache.REVISION_KEY


def bump_stats_revision():
    """Make every dashboard snapshot (headline counts, discovery counts, the graph's version) stale in every web worker after a finding is
    closed: the next poll of each scope rebuilds it."""
    snapshot_cache.bump_revision()


def clear_stats_cache():
    """Make every shared live-screen snapshot stale (tests, and a factory reset): the next poll of each scope rebuilds its own."""
    snapshot_cache.bump_revision()


def cached_stats_snapshot(params=(), scope=None):
    """The headline counts snapshot (``{'payload', 'etag', ...}``) of the current scope, shared by every viewer of that scope in every worker for
    STATS_CACHE_SECONDS. Run it inside ``project_scoped``: ``scope_hash`` reads the scope the counts are filtered by, so the key is who may see
    the rows, not who asks."""
    return snapshot_cache.snapshot('stats', scope or snapshot_cache.scope_hash(*params), stats_payload, STATS_CACHE_SECONDS)


def cached_stats(params=()):
    """``stats_payload`` of the current scope from the shared snapshot (see ``cached_stats_snapshot``)."""
    return cached_stats_snapshot(params)['payload']


@require_GET
def api_alive(request):
    """Answers for as long as the web service does, and touches nothing else: every page asks it now and then (static/cve/sitewatch.js)
    and covers itself with the rebuilding scene when it stops answering, during an update or a restart."""
    response = JsonResponse({'ok': True})
    response['Cache-Control'] = 'no-store'
    return response


@require_GET
@project_scoped
def api_stats(request):
    from tenancy.roles import scope_org
    snap = cached_stats_snapshot((request.GET.get('project', ''), scope_org(request)))
    live = live_scan_counts()  # fresh on every poll: five cheap counts, and the first thing a person watches
    # the ETag is the snapshot's (computed once, when it was built) and the live counts: a poll that finds both unchanged gets a 304 and no body
    return snapshot_cache.respond(request, snapshot_cache.token_of([snap['etag'], live]), lambda: {**snap['payload'], **live})


GRAPH_CACHE_SECONDS = 30
GRAPH_LIVE_SECONDS = 2  # how long what the running scans are doing is shared between tabs
GRAPH_VERSION_SECONDS = 5  # the version token is itself kept this long per scope: the 304 path of every open graph asked eight aggregate queries per poll
GRAPH_VERSION_WINDOW = 300  # a graph that "has not changed" is still re-sent this often: edits to existing rows move no id


def _label_version():
    """What the graph shows of the aliases and notes people gave hosts and targets, as a token: an edit moves no id, so the newest change of the
    host rows and the labelled targets' own text stand for them. The graph would otherwise show an old tooltip until the time window passes."""
    from django.contrib.postgres.aggregates import StringAgg
    from django.db.models import Count, Max
    from cveFeed.models import HostProfile
    from targetApp.models import Domain
    hosts = HostProfile.objects.aggregate(m=Max('updated_at'), n=Count('id'))
    targets = Domain.objects.exclude(alias='', note='').aggregate(a=StringAgg('alias', '\x1f', ordering='id'), n=StringAgg('note', '\x1f', ordering='id'))
    return hosts, targets


def graph_version(domain_id=None, scan_id=None):
    """A cheap token that changes when the graph's inputs do: the newest hosts, IPs, findings, scan steps, discovery events
    and CVE matches, plus when a match was last touched (an AI verdict rewrites a row without adding one). Queried
    through the tenancy-scoped managers, so it is per caller."""
    import hashlib
    from django.db.models import Max
    from startScan.models import ScanActivity, Subdomain, Vulnerability
    subs = Subdomain.objects.all()
    if domain_id:
        subs = subs.filter(target_domain_id=domain_id)
    if scan_id:
        subs = subs.filter(scan_history_id=scan_id)
    parts = [
        subs.aggregate(m=Max('id'), s=Max('scored_at')),
        Subdomain.ip_addresses.through.objects.filter(subdomain_id__in=subs.values('id')).aggregate(m=Max('id'))['m'],
        Vulnerability.objects.aggregate(m=Max('id'))['m'],
        ScanActivity.objects.aggregate(m=Max('id'), t=Max('time')),
        DiscoveryEvent.objects.aggregate(m=Max('id'))['m'],
        CVEMatch.objects.aggregate(m=Max('id'), u=Max('updated_at')),
        _label_version(),
        int(timezone.now().timestamp() // GRAPH_VERSION_WINDOW),
    ]
    return hashlib.sha1(repr(parts).encode()).hexdigest()[:16]


@require_GET
@project_scoped
def api_graph(request):
    """The asset graph. ``?v=<version>`` equal to the current version answers 304, so the dashboard's poller costs a few
    aggregate queries when nothing changed; otherwise the payload is served from a short per-scope cache (shared by every viewer of the
    same projects). The version is itself a snapshot kept GRAPH_VERSION_SECONDS per scope, so a change shows within that many seconds (at once
    after ``bump_stats_revision``) and a poll in between costs no aggregate query at all."""
    from django.core.cache import cache
    from django.http import HttpResponseNotModified
    from tenancy.roles import scope_org
    domain, scan = request.GET.get('domain', ''), request.GET.get('scan', '')
    domain_id, scan_id = int(domain) if domain.isdigit() else None, int(scan) if scan.isdigit() else None
    scope = snapshot_cache.scope_hash(request.GET.get('project', ''), scope_org(request), domain_id, scan_id)
    version = snapshot_cache.snapshot('graph-version', scope, lambda: graph_version(domain_id, scan_id), GRAPH_VERSION_SECONDS)['payload']
    if request.GET.get('v') == version:
        return HttpResponseNotModified()
    key = f'cve-graph:{scope}:{snapshot_cache.revision()}:{version}'  # a revision bump (a finding was closed) drops it with the snapshots
    try:
        payload = cache.get(key)
    except Exception:  # noqa: BLE001 - the graph is computed when the cache is down
        payload = None
    if payload is None:
        payload = {**graph_payload(domain_id, scan_id), 'version': version}
        try:
            cache.set(key, payload, GRAPH_CACHE_SECONDS)
        except Exception:  # noqa: BLE001
            pass
    return JsonResponse(payload)


@require_GET
@project_scoped
def api_graph_live(request):
    """Running scans, their current step and the hosts they are working on: what the graph pulses and SOC mode lists. A snapshot kept two seconds
    per scope (the page polls every three: every open tab of a project shares one set of queries), with an ETag of what the scans are doing, so
    an unchanged poll is a 304. ``elapsed`` and ``at`` move every second and are left out of the ETag: the page counts the time from ``started``."""
    from cveFeed import graph_live
    from tenancy.roles import scope_org
    slug, domain = request.GET.get('project', ''), request.GET.get('domain', '')
    project = slug if slug and slug != ALL_PROJECTS else None
    domain_id = int(domain) if domain.isdigit() else None
    snap = snapshot_cache.snapshot('graph-live', snapshot_cache.scope_hash(slug, scope_org(request), domain_id),
                                   lambda: graph_live.live(project, domain_id), GRAPH_LIVE_SECONDS, etag_of=_graph_live_token)
    return snapshot_cache.respond(request, snap['etag'], lambda: snap['payload'])


def _graph_live_token(payload):
    """What the running scans are doing, without the clock (``at``, and each scan's ``elapsed``), as an ETag."""
    return snapshot_cache.token_of({**{k: v for k, v in payload.items() if k != 'at'},
                                    'scans': [{k: v for k, v in s.items() if k != 'elapsed'} for s in payload['scans']]})


def _kv(*pairs):
    """Rows of a node's detail card. A value is text, or a list of ``(text, href)`` pairs: each item then links to its record."""
    rows = []
    for k, v in pairs:
        if v in (None, '', []):
            continue
        if isinstance(v, list):
            rows.append({'k': k, 'v': ', '.join(text for text, _ in v), 'links': [{'text': text, 'href': href} for text, href in v]})
        else:
            rows.append({'k': k, 'v': v})
    return rows


def _host_href(project_slug, name):
    return f'/cve/{quote(project_slug)}/hosts/?host={quote(name)}'


def _ip_href(project_slug, address):
    return f'/cve/{quote(project_slug)}/hosts/?q={quote("ip:" + address)}'


def _match_href(project_slug, match_id):
    return f'/cve/{quote(project_slug)}/matches/#{match_id}'



def _classification_suffix(match):
    """", confirmed" after a match's tier in the graph's node details; nothing when the match is not triaged."""
    from django.core.exceptions import ObjectDoesNotExist
    try:
        label = match.triage.classification
    except ObjectDoesNotExist:
        return ''
    return f', {label.replace("_", " ")}' if label else ''


def node_detail(node_id):
    """Details for one graph node, or None. Every lookup goes through the tenancy-scoped managers and ports/IPs
    are only reachable through a host the caller can see, so ids cannot be guessed across projects."""
    from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
    from targetApp.models import Domain
    kind, _, rest = node_id.partition(':')
    if kind == 'dom' and rest.isdigit():
        d = Domain.objects.filter(pk=int(rest)).first()
        if not d:
            return None
        return {'kind': 'domain', 'title': d.name, 'rows': _kv(
            ('Alias', d.alias), ('Note', d.note),
            ('Hosts', Subdomain.objects.filter(target_domain=d).count()),
            ('Scans', ScanHistory.objects.filter(domain=d).count()),
            ('Findings', Vulnerability.objects.filter(target_domain=d).count()),
            ('Added', d.insert_date.strftime('%Y-%m-%d %H:%M') if d.insert_date else ''))}
    if kind == 'sub' and rest.isdigit():
        s = Subdomain.objects.filter(pk=int(rest)).select_related('target_domain').first()
        if not s:
            return None
        first = DiscoveryEvent.objects.filter(scan_id=s.scan_history_id, host__iexact=s.name).order_by('id').first()
        ports = [f'{p.number}{"/udp" if p.protocol == "udp" else ""} {p.product} {p.version}'.strip() for ip in s.ip_addresses.all() for p in open_services(ip)]
        matches = list(CVEMatch.objects.filter(subdomain=s).exclude(ai_verdict='not_affected').select_related('cve_entry', 'triage'))
        vulns = Vulnerability.objects.filter(subdomain=s).order_by('-severity')[:8]
        from agentapi.services import _host_heat, alias_and_note
        from cveFeed.models import HostProfile
        project = s.target_domain.project if s.target_domain else None
        mine = HostProfile.objects.filter(project=project, host=s.name.lower()).first() if project else None
        given = alias_and_note(s, [], {(project.id, s.name.lower()): {'alias': mine.alias, 'note': mine.note}} if mine else {})  # what a person calls it
        return {'kind': 'host', 'title': s.name, 'heat': _host_heat(s),
                'link': f'/cve/{project.slug}/hosts/?host={quote(s.name)}' if project else '', 'rows': _kv(
            ('Alias', given['alias']), ('Note', given['note']),
            ('Target', [(s.target_domain.name, _host_href(project.slug, s.target_domain.name))] if project else (s.target_domain.name if s.target_domain else '')),
            ('IP addresses', [(ip.address, _ip_href(project.slug, ip.address)) for ip in s.ip_addresses.all()] if project
             else ', '.join(ip.address for ip in s.ip_addresses.all())),
            ('Heat', _host_heat(s)), ('Score', s.score),
            ('Open ports', ', '.join(ports)),
            ('HTTP', f'{s.http_status} {s.page_title or ""}'.strip() if s.http_status else ''),
            ('Web server', s.webserver), ('CDN', s.cdn_name if s.is_cdn else ''),
            ('Technologies', ', '.join(t.name for t in s.technologies.all() if t.name)),
            ('Found by', f'{first.module} ({first.type.replace("_", " ").lower()})' if first else ''),
            ('CVE matches', [(f'{m.cve_entry.cve_id} ({_tier(m.cve_entry)}{_classification_suffix(m)})', _match_href(project.slug, m.id))
                             for m in matches] if project else
             ', '.join(f'{m.cve_entry.cve_id} ({_tier(m.cve_entry)}{_classification_suffix(m)})' for m in matches)),
            ('Findings', ', '.join(f'{v.name} [{SEVERITY_LABEL.get(v.severity, v.severity)}]' for v in vulns)))}
    if kind == 'ip' and rest.isdigit():
        ip = IpAddress.objects.filter(pk=int(rest)).first()
        hosts = Subdomain.objects.filter(ip_addresses=ip).select_related('target_domain__project') if ip else Subdomain.objects.none()
        if not ip or not hosts.exists():
            return None
        shown = list(hosts[:10])
        first = next((h.target_domain.project.slug for h in shown if h.target_domain_id and h.target_domain.project_id), '')
        return {'kind': 'ip', 'title': ip.address, 'link': _ip_href(first, ip.address) if first else '', 'rows': _kv(
            ('Hosts', [(h.name, _host_href(h.target_domain.project.slug, h.name)) if h.target_domain_id and h.target_domain.project_id
                       else (h.name, '') for h in shown]),
            ('Open ports', ', '.join(f'{p.number}{"/udp" if p.protocol == "udp" else ""} {p.product}'.strip() for p in open_services(ip))),
            ('OS guess', ip.os_guess), ('Reverse pointer', ip.reverse_pointer),
            ('Full port scan', f'{timezone.localtime(ip.full_scanned_at):%Y-%m-%d %H:%M} ({ip.full_scan_ports} open)'
             if ip.full_scanned_at else 'never'),
            ('CDN', 'yes' if ip.is_cdn else ''), ('Private range', 'yes' if ip.is_private or not is_public_address(ip.address) else ''))}
    if kind == 'port':
        parts = rest.split(':')
        if len(parts) == 2 and all(p.isdigit() for p in parts):
            ip = IpAddress.objects.filter(pk=int(parts[0])).first()
            port = Port.objects.filter(pk=int(parts[1])).first()
            if ip and port and Subdomain.objects.filter(ip_addresses=ip).exists() and ip.ports.filter(pk=port.pk).exists():
                return {'kind': 'port', 'title': f'{ip.address}:{port.number}', 'rows': _kv(
                    ('Service', port.service_name), ('Product', port.product), ('Version', port.version), ('CPE', port.cpe),
                    ('Banner', (port.banner or '')[:300]), ('Source', port.source),
                    ('Uncommon port', 'yes' if port.is_uncommon else ''))}
        return None
    if kind == 'cve' and rest.isdigit():
        c = CVEEntry.objects.filter(pk=int(rest)).first()
        if not c:
            return None
        hosts = list(CVEMatch.objects.filter(cve_entry=c).exclude(ai_verdict='not_affected')
                     .select_related('subdomain__target_domain__project'))
        slugs = sorted({m.subdomain.target_domain.project.slug for m in hosts if m.subdomain and m.subdomain.target_domain_id
                        and m.subdomain.target_domain.project_id})
        where = slugs[0] if len(slugs) == 1 else ALL_PROJECTS if slugs else ''
        return {'kind': 'cve', 'title': c.cve_id, 'link': f'/cve/{quote(where)}/matches/?cve={quote(c.cve_id)}' if where else '',
                'link_label': 'Open the matches', 'rows': _kv(
            ('Tier', _tier(c)), ('CVSS', c.cvss), ('Summary', (c.title or c.original_description or '')[:300]),
            ('KEV', 'yes' if c.kev else ''), ('Exploit-DB', 'yes' if c.exploit_db else ''),
            ('Matched hosts', [(m.subdomain.name, _host_href(m.subdomain.target_domain.project.slug, m.subdomain.name)
                                if m.subdomain.target_domain_id and m.subdomain.target_domain.project_id else '')
                               for m in hosts if m.subdomain]))}
    return None


SEVERITY_LABEL = {-1: 'unknown', 0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}


@require_GET
def api_node(request):
    detail = node_detail(request.GET.get('id', ''))
    if detail is None:
        return JsonResponse({'error': 'not found'}, status=404)
    return JsonResponse(detail)


def _public_error(text):
    """The first line of a stored failure reason, clipped, for the live ticker: whatever follows (a traceback's frames, paths, a long chain) stays in the log."""
    first = (text or '').strip().splitlines()[:1]
    return first[0][:200] if first else ''


def _serialize_activity(a):
    return {'id': a.id, 'kind': a.kind, 'message': a.message, 'status': a.status, 'cve_id': a.cve_id,
            'project': a.project.slug if a.project_id else None,  # the project a line's hosts and CVEs link into
            'repeat': a.repeat, 'created': a.created_at.isoformat(),
            'finished': a.finished_at.isoformat() if a.finished_at else None}


@require_GET
@project_scoped
def api_activity(request):
    """The AI activity feed starts with the latest 100 rows. With ?after=<id>: newer rows, oldest first. Also returns
    entries that were running and have since settled (?since_running=<ids>) so spinners resolve."""
    after = request.GET.get('after', '')
    activity = AgentActivity.objects.select_related('project')
    qs = activity.order_by('-id')
    if after.isdigit() and int(after) > 0:
        items = list(activity.filter(id__gt=int(after)).order_by('id')[:100])  # the oldest above the cursor, so a client far behind catches up without gaps
    else:
        items = list(qs[:100])
        items.reverse()
    running_ids = [int(i) for i in request.GET.get('running', '').split(',') if i.isdigit()][:50]
    settled = list(activity.filter(id__in=running_ids).exclude(status='running')) if running_ids else []
    # a line reported again is the same row with a new time and a higher repeat count: send those the client already has
    bumped = []
    try:
        since = parse_datetime(request.GET.get('since', ''))
    except ValueError:  # an impossible date is no cursor, not a server error
        since = None
    if since and after.isdigit() and int(after) > 0:
        bumped = list(activity.filter(id__lte=int(after), repeat__gt=1, created_at__gt=since).order_by('id')[:50])
    body = {'items': [_serialize_activity(a) for a in items], 'settled': [_serialize_activity(a) for a in settled],
            'bumped': [_serialize_activity(a) for a in bumped]}
    # the ETag is the lines themselves, never ``now``: a poll that finds the same lines gets a 304 (the page keeps its cursor, and asks again)
    return snapshot_cache.respond(request, snapshot_cache.token_of(body), lambda: {**body, 'now': timezone.now().isoformat()})


def discovery_counts():
    """The three counts under the live ticker: live hosts, their IP addresses and open ports, over everything the caller can see."""
    from cveFeed.counts import LIVE_HOST_Q, host_reps
    from startScan.models import IpAddress, Port
    live_subs = host_reps().filter(LIVE_HOST_Q).distinct()
    ips = IpAddress.objects.filter(ip_addresses__in=live_subs).distinct()
    return {'hosts': live_subs.count(), 'ips': ips.count(), 'ports': Port.objects.filter(ports__in=ips, state__in=OPEN_PORT_STATES).distinct().count()}


def cached_discovery_counts(params=()):
    """``discovery_counts`` of the current scope from a snapshot shared by every viewer of that scope in every worker for STATS_CACHE_SECONDS:
    the dashboard polls the ticker every 2.5 s and the three distinct counts walk the caller's whole inventory. Dropped with the headline
    counts by ``bump_stats_revision``. Run it inside ``project_scoped``."""
    return snapshot_cache.snapshot('discovery-counts', snapshot_cache.scope_hash(*params), discovery_counts, STATS_CACHE_SECONDS)['payload']


@require_GET
@project_scoped
def api_discovery(request):
    """Live discovery: the scan being followed (given, else the latest running, else the latest) and its new events."""
    from cveFeed.discovery import queue_position
    from startScan.models import ScanHistory
    scan_id = request.GET.get('scan', '')
    if scan_id.isdigit():
        scan = ScanHistory.objects.filter(id=int(scan_id)).select_related('domain', 'scan_type').first()
    else:
        qs = ScanHistory.objects.select_related('domain', 'scan_type')
        scan = _running_scans(qs.model).order_by('-id').first() or qs.order_by('-id').first()
    if not scan:
        return snapshot_cache.respond_payload(request, {'scan': None, 'events': [], 'counts': {}})
    after = request.GET.get('after', '')
    events = DiscoveryEvent.objects.filter(scan=scan)
    events = events.filter(id__gt=int(after)) if after.isdigit() and int(after) else events.order_by('-id')[:60]  # after=0 is no cursor: the tail, not every event of the scan
    events = sorted(events, key=lambda e: e.id)
    # The counts describe the same picture the graph above the ticker draws (every live host of the project, not only this
    # scan's own rows), so they read as a total of what's on screen rather than just this run's contribution.
    from tenancy.roles import scope_org
    return snapshot_cache.respond_payload(request, {
        'scan': {'id': scan.id, 'target': scan.domain.name, 'project': scan.domain.project.slug if scan.domain.project else None,
                 'status': scan.scan_status, 'started': scan.start_scan_date.isoformat(), 'error': _public_error(scan.error_message),
                 'queue_position': queue_position(scan.id) if scan.scan_status == -1 else None},
        'events': [{'id': e.id, 'type': e.type, 'label': e.label, 'host': e.host, 'module': e.module} for e in events],
        'counts': cached_discovery_counts((request.GET.get('project', ''), scope_org(request))),
    })


def _json_body(request):
    try:
        return json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        return {}


@require_POST
@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_detect(request):
    from reNgine.ai_providers import ambiguous_key, detect_provider
    key = _json_body(request).get('key')
    return JsonResponse({'provider': detect_provider(key), 'ambiguous': ambiguous_key(key)})  # ambiguous: an sk- key more than one vendor issues


@require_POST
@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_onboarding_save(request):
    """Verify the key against the provider the user chose (or its unambiguous prefix names) with a live call, then save + enable it. A key
    whose vendor is not certain is never tried anywhere: the user is asked to pick the provider."""
    from dashboard.models import AIProviderSettings
    from reNgine.ai_providers import AIProviderError, detect_provider, get_provider, usage_stage

    body = _json_body(request)
    key = (body.get('key') or '').strip()
    previous = AIProviderSettings.objects.first()
    # A pasted key goes only to the provider the user picked or its prefix names; the connected provider is the fallback only when no key was
    # pasted (re-checking the stored one), never for a new key whose vendor is unknown.
    provider_name = body.get('provider') or detect_provider(key) or (previous.provider if not key and previous and previous.enabled else None)
    if not provider_name:
        return JsonResponse({'ok': False, 'error': 'This key does not say which vendor issued it (many do not). Pick the provider it belongs to; '
                                                   'nothing was sent anywhere.'}, status=400)
    model = (body.get('model') or '').strip()
    if not key and previous and previous.provider == provider_name:
        key = previous.api_key or ''
    from reNgine.ai_providers import SELECTABLE
    needs_model = provider_name in SELECTABLE and not model
    try:
        base_url = previous.base_url if previous and previous.provider == provider_name else None
        provider = get_provider(provider_name, model=model or None, api_key=key or None, base_url=base_url)
        with usage_stage('connection_test'):
            if needs_model:
                provider.list_models()  # OpenRouter/Ollama/vLLM/LM Studio: prove the connection, the user picks the model in Settings
            else:
                provider.complete('Reply with the single word: ok', 'ping')
    except AIProviderError as exc:
        logger.warning('AI provider connection test failed for %s: %s', provider_name, re.sub(r'//[^/@\s]+@', '//[redacted]@', str(exc)))  # never log URL credentials
        return JsonResponse({'ok': False, 'provider': provider_name, 'error': 'The connection test failed. Check the address, key and model; the details are in the server log.'}, status=400)
    cfg = previous or AIProviderSettings()
    if cfg.provider != provider_name:
        cfg.base_url = ''
    cfg.provider, cfg.model, cfg.enabled = provider_name, model, not needs_model
    cfg.verified_at, cfg.verified_provider, cfg.verified_model = timezone.now(), provider_name, provider.model if not needs_model else ''
    if key:
        cfg.api_key = key
    cfg.save()
    return JsonResponse({'ok': True, 'provider': provider_name, 'needs_model': needs_model})
