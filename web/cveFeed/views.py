"""CVEngine UI: dashboard + live CVE feed, onboarding, and the live asset graph.

Pages are server-rendered shells; the live parts poll the small JSON endpoints
below, so the UI updates on its own without a reload.
"""
import json
import logging
import re
from urllib.parse import quote
from collections import Counter
from datetime import timedelta

from django.db.models import Count
from django.http import JsonResponse
from django.http import Http404
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_GET, require_POST
from rolepermissions.decorators import has_permission_decorator

from cveFeed.models import (AgentActivity, AutoFireRun, CVEEntry, CVEMatch, DiscoveryEvent, GeneratedTemplate, HygieneFinding,
                            TlsCertificate)
from cveFeed.threat import FIRE, ICE, SMOKE, classify_threat_tier, host_heat, match_temperature
from startScan.models import open_ports
from reNgine.definitions import FOUR_OH_FOUR_URL, PERM_MODIFY_SYSTEM_CONFIGURATIONS

logger = logging.getLogger(__name__)

FEED_PAGE = 30
FEED_MAX = 100
ALL_PROJECTS = '_all'  # reserved slug of the read-only combined view (tenancy.roles.ALL_PROJECTS)
GRAPH_NODE_CAP = 1500
# A scan marked running for longer than this is a casualty of a restart, not live work: never show it as running.
RUNNING_WINDOW = timedelta(hours=11)  # discovery (6h cap) + nuclei (4h cap) + slack; see discovery.py


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


def _host_tip(sub, live_matches, severities):
    """A compact summary for the attack-surface hover card: no extra queries, only the prefetched matches/ips and the
    host's stored score reasons. Severities is the list of open-finding severities already gathered for this host."""
    worst = None
    for match in live_matches:
        tier = match_temperature(_tier(match.cve_entry), match.cve_entry.cvss, match.ai_verdict, match.distro_status)
        if worst is None or TIER_RANK.get(tier, 0) > TIER_RANK.get(worst[1], 0):
            worst = (match.cve_entry.cve_id, tier)
    reasons = [r.get('label', '') for r in (sub.score_detail or [])][:3] if hasattr(sub, 'score_detail') else []
    score_parts = [{'label': str(r.get('label', ''))[:140], 'points': int(r.get('points') or 0)}
                   for r in (sub.score_detail or [])[:8]] if hasattr(sub, 'score_detail') else []
    return {
        'ips': len({ip.address for ip in sub.ip_addresses.all()}),
        'cves': len(live_matches),
        'top_cve': worst[0] if worst else '',
        'top_tier': worst[1] if worst else '',
        'findings': len(severities),
        'max_sev': _SEV_NAME.get(max(severities), '') if severities else '',
        'reasons': [r for r in reasons if r],
        'score_parts': score_parts,
    }


def graph_payload(domain_id=None, scan_id=None):
    """Nodes/edges for the asset graph: domain > subdomain > ip, and subdomain > cve. Only live hosts are drawn (they resolved
    to an IP, or something saw them answer); names that never resolved are left out. Ports belong on the host's detail card."""
    from startScan.models import Subdomain, Vulnerability
    from cveFeed.graph_overview import root_for

    from django.db.models import Prefetch
    # a match needs its CVE's tier fields only: never CVEEntry.raw or the prose columns
    matches = CVEMatch.objects.only('subdomain_id', 'ai_verdict', 'cve_entry__cve_id', 'cve_entry__kev',
                                    'cve_entry__epss_reached', 'cve_entry__exploit_db', 'cve_entry__cvss').select_related('cve_entry')
    subs = Subdomain.objects.select_related('target_domain__project').prefetch_related(
        'ip_addresses', Prefetch('cve_matches', queryset=matches))
    if domain_id:
        subs = subs.filter(target_domain_id=domain_id)
    if scan_id:
        subs = subs.filter(scan_history_id=scan_id)  # one scan asked for by id: exactly its rows
    else:
        from cveFeed.correlation import latest_scan_q
        subs = subs.filter(latest_scan_q())  # otherwise each host once, from its domain's current scan
    nodes, edges = {}, set()
    by_name = {}

    def node(node_id, kind, label, **extra):
        if len(nodes) < GRAPH_NODE_CAP or node_id in nodes:
            nodes.setdefault(node_id, {'id': node_id, 'kind': kind, 'label': label, **extra})
            return True
        return False

    from django.db.models import Q
    subs = subs.filter(Q(ip_addresses__isnull=False) | Q(http_status__gt=0)).distinct()
    sub_list = list(subs[:GRAPH_NODE_CAP])
    sub_ids = [s.pk for s in sub_list]
    # "scanned" = at least one finding exists at all, even an info-only one (something looked); a
    # second query narrows to the ones severe enough, open, and not ruled out, to call "vulnerable".
    scanned_ids = set(Vulnerability.objects.filter(subdomain_id__in=sub_ids).values_list('subdomain_id', flat=True))
    vulnerable_ids = set(Vulnerability.objects.filter(
        subdomain_id__in=sub_ids, open_status=True, severity__gte=1).values_list('subdomain_id', flat=True))
    vulnerable_ids |= {s.pk for s in sub_list if any(m.ai_verdict != 'not_affected' for m in s.cve_matches.all())}

    severities = {}
    for sub_id, severity in Vulnerability.objects.filter(subdomain_id__in=sub_ids, open_status=True, severity__gte=1).values_list('subdomain_id', 'severity'):
        severities.setdefault(sub_id, []).append(severity)

    from startScan.models import ScanActivity
    nuclei_done = set(ScanActivity.objects.filter(scan_of_id__in={s.scan_history_id for s in sub_list if s.scan_history_id},
                                                  name__in=('nuclei_scan', 'nuclei_targeted_scan'), status=2).values_list('scan_of_id', flat=True))
    for sub in sub_list:
        sid = f'sub:{sub.pk}'
        status = asset_status(sub, scanned_ids, vulnerable_ids, nuclei_done)
        live = [m for m in sub.cve_matches.all() if m.ai_verdict != 'not_affected']
        tiers = [match_temperature(_tier(m.cve_entry), m.cve_entry.cvss, m.ai_verdict, m.distro_status) for m in live]
        heat = host_heat(status, tiers, severities.get(sub.pk, []))
        if not node(sid, 'subdomain', sub.name, target=sub.target_domain.name if sub.target_domain_id else '',
                    project=sub.target_domain.project.slug if sub.target_domain_id and sub.target_domain.project_id else '',
                    status=status, heat=heat, score=sub.score, info=_host_tip(sub, live, severities.get(sub.pk, []))):
            break
        by_name[sub.name.lower()] = sid
        if sub.target_domain_id and node(f'dom:{sub.target_domain_id}', 'domain', sub.target_domain.name,
                project=sub.target_domain.project.slug if sub.target_domain.project_id else '',
                project_name=sub.target_domain.project.name if sub.target_domain.project_id else '',
                root=root_for(sub.target_domain)):
            edges.add((f'dom:{sub.target_domain_id}', sid))
        for ip in sub.ip_addresses.all():
            if node(f'ip:{ip.pk}', 'ip', ip.address):
                edges.add((sid, f'ip:{ip.pk}'))
        for match in sub.cve_matches.all():
            if match.ai_verdict == 'not_affected':
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
    for parent, host in events.values_list('parent_host', 'host').distinct()[:GRAPH_NODE_CAP]:
        a, b = by_name.get((parent or '').lower()), by_name.get((host or '').lower())
        if a and b and a != b:
            edges.add((a, b))
    return {'nodes': list(nodes.values()), 'edges': [{'from': a, 'to': b} for a, b in sorted(edges)]}


def _running_scans(ScanHistory):
    return ScanHistory.objects.filter(scan_status=1, start_scan_date__gte=timezone.now() - RUNNING_WINDOW)


def tier_counts():
    """fire / smoke / ice over every stored CVE, counted by the database (see cveFeed.threat.classify_threat_tier)."""
    from cveFeed.threat import fire_tier_q, hot_tier_q
    total, n_fire, n_hot = (CVEEntry.objects.count(), CVEEntry.objects.filter(fire_tier_q()).count(),
                            CVEEntry.objects.filter(hot_tier_q()).count())
    return {FIRE: n_fire, SMOKE: n_hot - n_fire, ICE: total - n_hot}


def stats_payload():
    tiers = tier_counts()
    from cveFeed.correlation import latest_scan_q
    exposed = CVEMatch.objects.exclude(ai_verdict='not_affected').filter(latest_scan_q('subdomain__'))
    from startScan.models import ScanHistory, Subdomain, Vulnerability
    from targetApp.models import Domain
    # exposed: a CVE match the AI has not ruled out, or an open finding that is medium or worse
    from django.db.models import Q
    exposed_hosts = Subdomain.objects.filter(
        Q(pk__in=exposed.exclude(subdomain=None).values('subdomain')) |
        Q(pk__in=Vulnerability.objects.filter(open_status=True, severity__gte=2).exclude(subdomain=None).values('subdomain'))).count()
    return {
        'targets': Domain.objects.count(),
        'certs_expiring': TlsCertificate.objects.filter(not_after__lte=timezone.now() + timedelta(days=30)).count(),
        'hygiene_open': HygieneFinding.objects.filter(status='open', severity__gte=1).count(),
        'hosts': Subdomain.objects.filter(latest_scan_q()).count(),
        'scans_running': _running_scans(ScanHistory).count(),
        'scans_queued': ScanHistory.objects.filter(scan_status=-1).count(),
        'tiers': {FIRE: tiers[FIRE], SMOKE: tiers[SMOKE], ICE: tiers[ICE]},
        'cves': CVEEntry.objects.count(),
        'matches': exposed.count(),
        'scanner_findings': Vulnerability.objects.exclude(severity=0).count(),
        'exposed_hosts': exposed_hosts,
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
    'vulns': 'Scanner findings',
    'matches': 'CVE matches',
    'hygiene': 'Hygiene',
    'keys': 'API keys',
}


def ui_context(request, active, slug=None):
    """Shell context shared by every UI page: active nav item and the project switcher. ``slug`` may be the reserved ``_all``
    (the read-only combined view): the switcher then marks "All projects" selected. That option is offered only to a caller who
    can see two or more projects; with one there is nothing to combine."""
    from dashboard.models import Project
    projects = list(Project.objects.order_by('name').values('slug', 'name'))  # scoped to the caller
    current = slug or (projects[0]['slug'] if projects else None)
    from tenancy.roles import is_admin_anywhere
    from dashboard.models import AIProviderSettings
    ai_cfg = AIProviderSettings.objects.first()
    ai_connected = bool(ai_cfg and ai_cfg.enabled)
    return {'active': active, 'slug': current, 'projects': projects, 'sections': SECTIONS, 'is_admin': is_admin_anywhere(request.user),
            'is_app_admin': request.user.is_superuser,
            'bounty_enabled': _bounty_allowed(request.user),
            'ai_usage_connected': ai_connected,
            'ai_usage_provider': ai_cfg.provider if ai_connected else '',
            'ai_usage_model': ai_cfg.model if ai_connected else '',
            'all_projects': slug == ALL_PROJECTS, 'show_all_option': len(projects) >= 2}


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
    slug = want if want in projects and want != ALL_PROJECTS else (projects[0] if projects else None)
    return render(request, 'cveFeed/bounty.html', ui_context(request, 'bounty', slug))


def dashboard(request):
    from cveFeed.welcome import needs_welcome
    from dashboard.models import AIProviderSettings, Project
    if needs_welcome(request.user) and request.GET.get('skip') != '1':
        return redirect('cve_welcome')  # first run: the guided setup
    cfg = AIProviderSettings.objects.first()
    # The dashboard spans every project the viewer can see by default (the combined "All projects" view); a
    # ?project=<slug> they may see narrows every panel to that one. The switcher stays here when it changes.
    projects = list(Project.objects.values_list('slug', flat=True))  # scoped to the caller
    want = request.GET.get('project') or ''
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
    project = request.GET.get('project', '')
    allowed = set(Project.objects.values_list('slug', flat=True))
    selected = project if project in allowed else ALL_PROJECTS if len(allowed) > 1 else next(iter(allowed), None)
    return render(request, 'cveFeed/graph.html', {
        'domains': Domain.objects.filter(project__slug=selected).select_related('project').order_by('name')
                   if selected != ALL_PROJECTS else Domain.objects.select_related('project').order_by('name'),
        **ui_context(request, 'graph', selected),
    })


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
    if slug == ALL_PROJECTS:
        from tenancy.roles import user_best_role
        if not user_best_role(request.user):
            raise Http404  # no organization or project access: same answer as an unknown project
        project = {'slug': ALL_PROJECTS, 'name': 'All projects'}
    else:
        project = Project.objects.filter(slug=slug).first()
    if not project:
        raise Http404
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
    return FileResponse(open(path, 'rb'))


def welcome_page(request):
    return render(request, 'cveFeed/welcome.html', ui_context(request, 'welcome'))


def account_page(request):
    return render(request, 'cveFeed/account.html', ui_context(request, 'account'))


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
        if not slug or slug == ALL_PROJECTS:  # "_all": everything the caller may see, which is the default
            return view(request, *args, **kwargs)
        from dashboard.models import Project
        from tenancy import scope
        allowed = scope.current_allowed()
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


STATS_CACHE_SECONDS = 10
_STATS_CACHE = {}  # (user id, project slug) -> (computed at, payload)
STATS_CACHE_ENTRIES = 256
STATS_REVISION_KEY = 'cvengine:stats:revision'


def bump_stats_revision():
    """Invalidate every web worker's short dashboard cache after a finding is closed."""
    from django.core.cache import cache
    _STATS_CACHE.clear()
    try:
        cache.set(STATS_REVISION_KEY, timezone.now().isoformat(), timeout=None)
    except Exception:  # noqa: BLE001 - other workers still expire within ten seconds
        pass


def cached_stats(key='', now=None):
    """stats_payload, kept per process for STATS_CACHE_SECONDS: every open dashboard polls it every few seconds and it runs a dozen
    full-table counts, so the polls of one viewer share one computation. The counts go through the tenancy-scoped managers, so they
    differ per caller and per selected project: ``key`` (user id and project slug) is part of the cache key, never shared."""
    import time
    from django.core.cache import cache
    try:
        revision = cache.get(STATS_REVISION_KEY) or ''
    except Exception:  # noqa: BLE001
        revision = ''
    key = (key, revision)
    now = time.monotonic() if now is None else now
    hit = _STATS_CACHE.get(key)
    if hit is None or now - hit[0] >= STATS_CACHE_SECONDS:
        if len(_STATS_CACHE) >= STATS_CACHE_ENTRIES:
            _STATS_CACHE.clear()
        hit = _STATS_CACHE[key] = (now, stats_payload())
    return hit[1]


@require_GET
@project_scoped
def api_stats(request):
    return JsonResponse(cached_stats((request.user.pk, request.GET.get('project', ''))))


GRAPH_CACHE_SECONDS = 30
GRAPH_VERSION_WINDOW = 300  # a graph that "has not changed" is still re-sent this often: edits to existing rows move no id


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
        int(timezone.now().timestamp() // GRAPH_VERSION_WINDOW),
    ]
    return hashlib.sha1(repr(parts).encode()).hexdigest()[:16]


@require_GET
@project_scoped
def api_graph(request):
    """The asset graph. ``?v=<version>`` equal to the current version answers 304, so the dashboard's poller costs a few
    aggregate queries when nothing changed; otherwise the payload is served from a short per-user cache."""
    from django.core.cache import cache
    from django.http import HttpResponseNotModified
    domain, scan = request.GET.get('domain', ''), request.GET.get('scan', '')
    domain_id, scan_id = int(domain) if domain.isdigit() else None, int(scan) if scan.isdigit() else None
    version = graph_version(domain_id, scan_id)
    if request.GET.get('v') == version:
        return HttpResponseNotModified()
    key = f'cve-graph:{request.user.pk}:{request.GET.get("project", "")}:{domain_id}:{scan_id}:{version}'
    payload = cache.get(key)
    if payload is None:
        payload = {**graph_payload(domain_id, scan_id), 'version': version}
        cache.set(key, payload, GRAPH_CACHE_SECONDS)
    return JsonResponse(payload)


@require_GET
@project_scoped
def api_graph_overview(request):
    from cveFeed.graph_overview import groups
    slug = request.GET.get('project', '')
    return JsonResponse(groups(slug if slug and slug != ALL_PROJECTS else None))


@require_GET
@project_scoped
def api_graph_hosts(request):
    from cveFeed.graph_overview import hosts
    project, root = request.GET.get('owner', '')[:100], request.GET.get('root', '')[:255]
    try:
        page = int(request.GET.get('page', 1))
    except (TypeError, ValueError):
        return JsonResponse({'error': 'page must be a number'}, status=400)
    result = hosts(project, root, page=page, q=request.GET.get('q', ''))
    return JsonResponse(result) if result is not None else JsonResponse({'error': 'group not found'}, status=404)


def _kv(*pairs):
    return [{'k': k, 'v': v} for k, v in pairs if v not in (None, '', [])]


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
            ('Hosts', Subdomain.objects.filter(target_domain=d).count()),
            ('Scans', ScanHistory.objects.filter(domain=d).count()),
            ('Findings', Vulnerability.objects.filter(target_domain=d).count()),
            ('Added', d.insert_date.strftime('%Y-%m-%d %H:%M') if d.insert_date else ''))}
    if kind == 'sub' and rest.isdigit():
        s = Subdomain.objects.filter(pk=int(rest)).select_related('target_domain').first()
        if not s:
            return None
        first = DiscoveryEvent.objects.filter(scan_id=s.scan_history_id, host__iexact=s.name).order_by('id').first()
        ports = [f'{p.number} {p.product} {p.version}'.strip() for ip in s.ip_addresses.all() for p in open_ports(ip)]
        matches = CVEMatch.objects.filter(subdomain=s).exclude(ai_verdict='not_affected').select_related('cve_entry', 'triage')
        vulns = Vulnerability.objects.filter(subdomain=s).order_by('-severity')[:8]
        from agentapi.services import _host_heat
        project = s.target_domain.project if s.target_domain else None
        return {'kind': 'host', 'title': s.name, 'heat': _host_heat(s),
                'link': f'/cve/{project.slug}/hosts/?host={quote(s.name)}' if project else '', 'rows': _kv(
            ('Target', s.target_domain.name if s.target_domain else ''),
            ('IP addresses', ', '.join(ip.address for ip in s.ip_addresses.all())),
            ('Heat', _host_heat(s)), ('Score', s.score),
            ('Open ports', ', '.join(ports)),
            ('HTTP', f'{s.http_status} {s.page_title or ""}'.strip() if s.http_status else ''),
            ('Web server', s.webserver), ('CDN', s.cdn_name if s.is_cdn else ''),
            ('Technologies', ', '.join(t.name for t in s.technologies.all() if t.name)),
            ('Found by', f'{first.module} ({first.type.replace("_", " ").lower()})' if first else ''),
            ('CVE matches', ', '.join(f'{m.cve_entry.cve_id} ({_tier(m.cve_entry)}{_classification_suffix(m)})' for m in matches)),
            ('Findings', ', '.join(f'{v.name} [{SEVERITY_LABEL.get(v.severity, v.severity)}]' for v in vulns)))}
    if kind == 'ip' and rest.isdigit():
        ip = IpAddress.objects.filter(pk=int(rest)).first()
        hosts = Subdomain.objects.filter(ip_addresses=ip) if ip else Subdomain.objects.none()
        if not ip or not hosts.exists():
            return None
        return {'kind': 'ip', 'title': ip.address, 'rows': _kv(
            ('Hosts', ', '.join(h.name for h in hosts[:10])),
            ('Open ports', ', '.join(f'{p.number} {p.product}'.strip() for p in open_ports(ip))),
            ('OS guess', ip.os_guess), ('Reverse pointer', ip.reverse_pointer),
            ('Full port scan', f'{timezone.localtime(ip.full_scanned_at):%Y-%m-%d %H:%M} ({ip.full_scan_ports} open)'
             if ip.full_scanned_at else 'never'),
            ('CDN', 'yes' if ip.is_cdn else ''), ('Private range', 'yes' if ip.is_private else ''))}
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
        hosts = CVEMatch.objects.filter(cve_entry=c).exclude(ai_verdict='not_affected').select_related('subdomain')
        return {'kind': 'cve', 'title': c.cve_id, 'rows': _kv(
            ('Tier', _tier(c)), ('CVSS', c.cvss), ('Summary', (c.title or c.original_description or '')[:300]),
            ('KEV', 'yes' if c.kev else ''), ('Exploit-DB', 'yes' if c.exploit_db else ''),
            ('Matched hosts', ', '.join(m.subdomain.name for m in hosts if m.subdomain)))}
    return None


SEVERITY_LABEL = {-1: 'unknown', 0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}


@require_GET
def api_node(request):
    detail = node_detail(request.GET.get('id', ''))
    if detail is None:
        return JsonResponse({'error': 'not found'}, status=404)
    return JsonResponse(detail)


def _serialize_activity(a):
    return {'id': a.id, 'kind': a.kind, 'message': a.message, 'status': a.status, 'cve_id': a.cve_id,
            'repeat': a.repeat, 'created': a.created_at.isoformat(),
            'finished': a.finished_at.isoformat() if a.finished_at else None}


@require_GET
@project_scoped
def api_activity(request):
    """The AI activity feed starts with the latest 100 rows. With ?after=<id>: newer rows, oldest first. Also returns
    entries that were running and have since settled (?since_running=<ids>) so spinners resolve."""
    after = request.GET.get('after', '')
    qs = AgentActivity.objects.order_by('-id')
    if after.isdigit() and int(after) > 0:
        items = list(AgentActivity.objects.filter(id__gt=int(after)).order_by('id')[:100])  # the oldest above the cursor, so a client far behind catches up without gaps
    else:
        items = list(qs[:100])
        items.reverse()
    running_ids = [int(i) for i in request.GET.get('running', '').split(',') if i.isdigit()][:50]
    settled = list(AgentActivity.objects.filter(id__in=running_ids).exclude(status='running')) if running_ids else []
    # a line reported again is the same row with a new time and a higher repeat count: send those the client already has
    bumped = []
    since = parse_datetime(request.GET.get('since', ''))
    if since and after.isdigit() and int(after) > 0:
        bumped = list(AgentActivity.objects.filter(id__lte=int(after), repeat__gt=1, created_at__gt=since).order_by('id')[:50])
    return JsonResponse({'items': [_serialize_activity(a) for a in items],
                         'settled': [_serialize_activity(a) for a in settled],
                         'bumped': [_serialize_activity(a) for a in bumped], 'now': timezone.now().isoformat()})


@require_GET
@project_scoped
def api_discovery(request):
    """Live discovery: the scan being followed (given, else the latest running, else the latest) and its new events."""
    from cveFeed.discovery import queue_position
    from startScan.models import IpAddress, Port, ScanHistory, Subdomain
    scan_id = request.GET.get('scan', '')
    if scan_id.isdigit():
        scan = ScanHistory.objects.filter(id=int(scan_id)).select_related('domain', 'scan_type').first()
    else:
        qs = ScanHistory.objects.select_related('domain', 'scan_type')
        scan = _running_scans(qs.model).order_by('-id').first() or qs.order_by('-id').first()
    if not scan:
        return JsonResponse({'scan': None, 'events': [], 'counts': {}})
    after = request.GET.get('after', '')
    events = DiscoveryEvent.objects.filter(scan=scan)
    events = events.filter(id__gt=int(after)) if after.isdigit() else events.order_by('-id')[:60]
    events = sorted(events, key=lambda e: e.id)
    subs = Subdomain.objects.filter(scan_history=scan)
    ips = IpAddress.objects.filter(ip_addresses__in=subs).distinct()
    return JsonResponse({
        'scan': {'id': scan.id, 'target': scan.domain.name, 'project': scan.domain.project.slug if scan.domain.project else None,
                 'status': scan.scan_status, 'started': scan.start_scan_date.isoformat(),
                 'queue_position': queue_position(scan.id) if scan.scan_status == -1 else None},
        'events': [{'id': e.id, 'type': e.type, 'label': e.label, 'host': e.host, 'module': e.module} for e in events],
        'counts': {'hosts': subs.count(), 'ips': ips.count(), 'ports': Port.objects.filter(ports__in=ips).distinct().count()},
    })


def _json_body(request):
    try:
        return json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        return {}


@require_POST
@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_detect(request):
    from reNgine.ai_providers import detect_provider
    return JsonResponse({'provider': detect_provider(_json_body(request).get('key'))})


@require_POST
@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_onboarding_save(request):
    """Detect the provider from the key, verify it with a live call, then save + enable it."""
    from dashboard.models import AIProviderSettings
    from reNgine.ai_providers import AIProviderError, detect_provider, get_provider, usage_stage

    body = _json_body(request)
    key = (body.get('key') or '').strip()
    previous = AIProviderSettings.objects.first()
    provider_name = body.get('provider') or detect_provider(key) or (previous.provider if previous and previous.enabled else None)
    if not provider_name:
        return JsonResponse({'ok': False, 'error': 'Could not recognise this key. Pick a provider.'}, status=400)
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
                provider.list_models()  # OpenRouter/Ollama/vLLM: prove the connection, the user picks the model in Settings
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
