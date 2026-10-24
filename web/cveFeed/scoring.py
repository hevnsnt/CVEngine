"""Host score: one number (0 to 100) that says which host to look at first, and why.

``score_host`` is a pure function over plain inputs, so every component is unit tested; ``rescore_hosts`` gathers the inputs
for a batch of hosts with a handful of bounded queries and stores the result on the Subdomain rows (and HostState), where
the Hosts page, search and the graph already read.

| Component | Points | Cap |
| --- | --- | --- |
| CVE matches (not ruled out): fire 40, smoke 20, ice 5; AI-confirmed on a fire match adds 10 | worst match | 50 |
| Open findings: critical/high 25, medium 10, low 3 | worst | 25 |
| Route auth: open admin or API-like path 15, open front page 5, login page 5, SSO or session required 0 | worst | 15 |
| Sensitive data on a route (cveFeed.sensitive.sensitive_score) | worst route | 25 |
| Exposure: any public IP 10 | | 10 |
| Recency: new or returned in the last 7 days 10, port opened or version changed 5 | | 10 |
| Zombie host 15, zombie route 5 | | 15 |
"""
import logging
import re
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

CHUNK = 500
RECENT_DAYS = 7
MAX_RESCORE_HOSTS = 20000  # hosts one daily pass rescores per project
CVE_POINTS = {'fire': 40, 'smoke': 20, 'ice': 5}
CVE_CAP, AI_BONUS = 50, 10
FINDING_POINTS = {4: 25, 3: 25, 2: 10, 1: 3}
FINDING_NAMES = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low'}
ROUTE_CAP, SENSITIVE_CAP, EXPOSURE_POINTS, RECENCY_CAP, ZOMBIE_CAP = 15, 25, 10, 10, 15
ADMIN_PATH = re.compile(r'^/(admin|api|actuator|swagger|console|manager)(/|$|\.|\?)', re.I)
RECENT_NEW_KINDS = ('host_new', 'host_returned')
RECENT_CHANGE_KINDS = ('port_opened', 'service_changed')


def _cve_lines(cves):
    rank = {'fire': 3, 'smoke': 2, 'ice': 1}
    usable = [c for c in cves if c.get('temp') in CVE_POINTS]
    if not usable:
        return []
    usable.sort(key=lambda c: (-rank[c['temp']], c.get('id', '')))
    worst = usable[0]
    points = CVE_POINTS[worst['temp']]
    lines = [{'label': f'{worst["temp"].capitalize()} CVE match {worst.get("id", "")}'.strip(), 'points': points}]
    if worst['temp'] == 'fire' and any(c['temp'] == 'fire' and c.get('ai_verdict') == 'affected' for c in usable):
        lines.append({'label': 'AI confirmed the host is affected by a fire CVE', 'points': AI_BONUS})
    return _capped(lines, CVE_CAP)


def _capped(lines, cap):
    """Trim the points of ``lines`` so their sum stays within ``cap``."""
    out, left = [], cap
    for line in lines:
        points = min(line['points'], left)
        if points > 0:
            out.append({'label': line['label'], 'points': points})
            left -= points
    return out


def _route_line(routes):
    best = None
    for route in routes:
        path, state = route.get('path') or '/', route.get('auth_state')
        if state == 'open' and ADMIN_PATH.search(path):
            line = {'label': f'Admin route {path} is open', 'points': 15}
        elif state == 'open' and path == '/':
            line = {'label': 'Front page is open', 'points': 5}
        elif state == 'login':
            line = {'label': f'Login page {path}', 'points': 5}
        else:
            continue
        if best is None or line['points'] > best['points']:
            best = line
    return [best] if best else []


def _sensitive_line(routes):
    worst = max(routes, key=lambda r: r.get('sensitive_score') or 0, default=None)
    points = (worst or {}).get('sensitive_score') or 0
    if points <= 0:
        return []
    what = {25: 'Credentials served', 15: 'Personal data served'}.get(points, 'Contact details or internal identifiers served')
    return [{'label': f'{what} on {worst.get("path") or "/"}', 'points': min(points, SENSITIVE_CAP)}]


def score_host(inputs):
    """``(score, detail)`` for one host. ``inputs``: ``cves`` [{id, temp, ai_verdict}] (matches the AI has not ruled out),
    ``findings`` [{severity, name}] (open), ``routes`` [{path, auth_state, sensitive_score}], ``public_ip`` bool,
    ``recent`` [change kinds in the last 7 days], ``zombie_host`` and ``zombie_route`` bools. ``detail`` is the ordered list of
    ``{'label', 'points'}`` that add up to the score (at most 100)."""
    detail = _cve_lines(inputs.get('cves') or [])
    findings = [f for f in inputs.get('findings') or [] if f.get('severity') in FINDING_POINTS]
    if findings:
        worst = max(findings, key=lambda f: FINDING_POINTS[f['severity']] * 10 + f['severity'])
        detail.append({'label': f'{FINDING_NAMES[worst["severity"]]} finding {worst.get("name") or ""}'.strip(),
                       'points': FINDING_POINTS[worst['severity']]})
    routes = inputs.get('routes') or []
    detail += _capped(_route_line(routes), ROUTE_CAP)
    detail += _sensitive_line(routes)
    if inputs.get('public_ip'):
        detail.append({'label': 'Public IP observed in inventory (service reachability unverified)', 'points': EXPOSURE_POINTS})
    recent = set(inputs.get('recent') or [])
    detail += _capped([{'label': 'New this week', 'points': 10}] if recent & set(RECENT_NEW_KINDS) else
                      [{'label': 'Exposure changed this week', 'points': 5}] if recent & set(RECENT_CHANGE_KINDS) else [], RECENCY_CAP)
    zombies = []
    if inputs.get('zombie_host'):
        zombies.append({'label': 'Zombie host: DNS is gone but it still answers', 'points': 15})
    if inputs.get('zombie_route'):
        zombies.append({'label': 'Zombie route: a retired path answers again', 'points': 5})
    detail += _capped(zombies, ZOMBIE_CAP)
    return min(100, sum(line['points'] for line in detail)), detail


# ----------------------------------------------------------------------------- recompute

def _chunks(items, size=CHUNK):
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _cve_inputs(sub):
    from cveFeed.threat import classify_threat_tier, match_temperature
    out = []
    for m in sub.cve_matches.all():
        if m.ai_verdict == 'not_affected':
            continue
        c = m.cve_entry
        tier = classify_threat_tier(kev=c.kev, epss_reached=c.epss_reached, exploit_db=c.exploit_db, cvss=c.cvss)
        out.append({'id': c.cve_id, 'temp': match_temperature(tier, c.cvss, m.ai_verdict), 'ai_verdict': m.ai_verdict})
    return out


def _has_public_ip(sub):
    from targetApp.target_types import is_scannable_ip
    return any(ip.address and not ip.is_private and is_scannable_ip(ip.address) for ip in sub.ip_addresses.all())


def usable_rows(qs):
    """Subdomain rows whose data can be scored: those of a running or finished scan, and scan-less rows (certificate transparency).
    A failed, aborted or queued scan's row is partial (a name with no ports, findings or matches yet) and must never stand for the
    host."""
    from django.db.models import Q
    return qs.filter(Q(scan_history__scan_status__in=(1, 2)) | Q(scan_history__isnull=True))


def row_preference(scan_id=None):
    """``order_by`` terms that put, per host name, the row of ``scan_id`` first, then the rows of finished scans, then the rest,
    each newest first: after ``name``, so it can be used with ``distinct('name')``."""
    from django.db.models import Case, IntegerField, When
    return (Case(When(scan_history_id=scan_id, then=0) if scan_id else When(pk__isnull=True, then=0),
                 When(scan_history__scan_status=2, then=1), default=2, output_field=IntegerField()), '-id')


def rescore_hosts(project_id, names, now=None, scan_id=None):
    """Recompute the score of these hosts (by name) of a project and store it on every Subdomain row of that name (older
    scans' copies too, so sorting is consistent) and on HostState. The inputs come from one Subdomain row per name: the row of
    ``scan_id`` when it is given (the scan that was just recorded), else that of the newest finished scan; rows of failed, aborted
    or queued scans are never used. Bounded: 500 names per round of queries. Returns how many hosts were scored."""
    from cveFeed.models import AssetChange, HostState, RouteAuth
    from startScan.models import Subdomain
    now = now or timezone.now()
    names = sorted({(n or '').strip().lower() for n in names if n})
    scored = 0
    for chunk in _chunks(names):
        newest = (usable_rows(Subdomain.objects.filter(target_domain__project_id=project_id, name__in=chunk))
                  .order_by('name', *row_preference(scan_id)).distinct('name')
                  .prefetch_related('ip_addresses', 'cve_matches__cve_entry', 'vulnerability_set'))
        subs = {s.name.lower(): s for s in newest}
        routes, recent, zombies = {}, {}, {}
        for r in RouteAuth.objects.filter(project_id=project_id, host__in=chunk).values('host', 'path', 'auth_state', 'sensitive_score', 'zombie_since'):
            routes.setdefault(r['host'], []).append(r)
        since = now - timedelta(days=RECENT_DAYS)
        for r in AssetChange.objects.filter(project_id=project_id, host__in=chunk, detected_at__gte=since,
                                            kind__in=RECENT_NEW_KINDS + RECENT_CHANGE_KINDS).values('host', 'kind'):
            recent.setdefault(r['host'], set()).add(r['kind'])
        for host in HostState.objects.filter(project_id=project_id, host__in=chunk, zombie_since__isnull=False).values_list('host', flat=True):
            zombies.setdefault(host, {})['zombie_host'] = True
        for host, items in routes.items():
            if any(r['zombie_since'] for r in items):
                zombies.setdefault(host, {})['zombie_route'] = True
        scores = {}
        for name, sub in subs.items():
            inputs = {'cves': _cve_inputs(sub),
                      'findings': [{'severity': v.severity, 'name': v.name} for v in sub.vulnerability_set.all() if v.open_status],
                      'routes': routes.get(name, []), 'public_ip': _has_public_ip(sub), 'recent': recent.get(name, ())}
            inputs.update(zombies.get(name, {}))
            scores[name] = score_host(inputs)
        rows = []
        for row in Subdomain.objects.filter(target_domain__project_id=project_id, name__in=chunk).only('id', 'name'):
            if row.name.lower() in scores:
                row.score, row.score_detail = scores[row.name.lower()]
                row.scored_at = now
                rows.append(row)
        Subdomain.objects.bulk_update(rows, ['score', 'score_detail', 'scored_at'], batch_size=CHUNK)
        states = []
        for state in HostState.objects.filter(project_id=project_id, host__in=chunk):
            if state.host in scores:
                state.score = scores[state.host][0]
                states.append(state)
        HostState.objects.bulk_update(states, ['score'], batch_size=CHUNK)
        scored += len(scores)
    return scored


def rescore_quietly(project_id, names, scan_id=None):
    """``rescore_hosts`` for a trigger inside a pipeline: never raises."""
    try:
        return rescore_hosts(project_id, names, scan_id=scan_id)
    except Exception:  # noqa: BLE001 - a scoring problem must not undo the work that triggered it
        logger.exception('could not rescore hosts of project %s', project_id)
        return 0


def rescore_subdomain_ids(subdomain_ids):
    """Rescore the hosts of these Subdomain rows (at most CHUNK of them): used when a match's verdict was reset or a match was closed,
    so the host's score does not keep the AI bonus or the exposure of a verdict that no longer stands. Never raises."""
    try:
        from startScan.models import Subdomain
        by_project = {}
        for name, project_id in Subdomain.objects.filter(pk__in=list(subdomain_ids)[:CHUNK], target_domain__project__isnull=False) \
                .values_list('name', 'target_domain__project_id'):
            by_project.setdefault(project_id, set()).add(name)
        for project_id, names in by_project.items():
            rescore_quietly(project_id, sorted(names)[:CHUNK])
    except Exception:  # noqa: BLE001
        logger.exception('could not rescore after a verdict reset')


def rescore_for_matches(matches):
    """Rescore the hosts of the CVE matches whose verdict was just saved (at most CHUNK hosts)."""
    try:
        by_project = {}
        for m in matches:
            sub = getattr(m, 'subdomain', None)
            domain = getattr(sub, 'target_domain', None) if sub else None
            if sub and domain and domain.project_id:
                by_project.setdefault(domain.project_id, set()).add(sub.name)
        for project_id, names in by_project.items():
            rescore_quietly(project_id, sorted(names)[:CHUNK])
    except Exception:  # noqa: BLE001
        logger.exception('could not rescore after a verdict')
