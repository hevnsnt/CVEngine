"""Host score: one number (0 to 100) that says which host to look at first, and why.

``score_host`` is a pure function over plain inputs, so every component is unit tested; ``rescore_hosts`` gathers the inputs
for a batch of hosts with a handful of bounded queries and stores the result on the Subdomain rows (and HostState), where
the Hosts page, search and the graph already read.

| Component | Points | Cap |
| --- | --- | --- |
| CVE matches (not ruled out), at the heat they show on the host (``threat.match_heat``: a version-only match is smoke at most): fire 40, smoke 20, ice 5; AI-confirmed on a fire match adds 10 | worst match | 50 |
| CVE matches whose affected version range is not known (kept for review): 1 each, KEV or not | all of them | 2 |
| Open findings: critical/high 25, medium 10, low 3 | worst | 25 |
| Route auth: open admin or API-like path 15, open front page 5, login page 5, SSO or session required 0 | worst | 15 |
| Sensitive data on a route (cveFeed.sensitive.sensitive_score) | worst route | 25 |
| Hygiene (expired or weak certificate, SPF, DKIM, DMARC, TLS, cleartext Telnet, FTP and r-services): critical 20, high 15, medium 8, low 3; each further medium or worse issue adds 2 | worst plus extras | 20 |
| Exposure: any public IP 10 | | 10 |
| Recency: new or returned in the last 7 days 10, port opened or version changed 5 | | 10 |
| Zombie host 15, zombie route 5 | | 15 |
"""
import logging
import re
from datetime import timedelta
from itertools import islice

from django.utils import timezone

logger = logging.getLogger(__name__)

CHUNK = 500
RECENT_DAYS = 7
MAX_RESCORE_HOSTS = 20000  # hosts one daily pass rescores per project
CVE_POINTS = {'fire': 40, 'smoke': 20, 'ice': 5}
CVE_CAP, AI_BONUS = 50, 10
VERSION_UNKNOWN_CAP = 2  # the most a host's score takes from CVE matches that have no affected version range (review, not exposure)
FINDING_POINTS = {4: 25, 3: 25, 2: 10, 1: 3}
FINDING_NAMES = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low'}
HYGIENE_POINTS = {4: 20, 3: 15, 2: 8, 1: 3}
HYGIENE_CAP, HYGIENE_EXTRA = 20, 2
ROUTE_CAP, SENSITIVE_CAP, EXPOSURE_POINTS, RECENCY_CAP, ZOMBIE_CAP = 15, 25, 10, 10, 15
ADMIN_PATH = re.compile(r'^/(admin|api|actuator|swagger|console|manager)(/|$|\.|\?)', re.I)
RECENT_NEW_KINDS = ('host_new', 'host_returned')
RECENT_CHANGE_KINDS = ('port_opened', 'service_changed')


def _unknown_line(unknown):
    """One line for the matches whose CVE publishes no affected version range: a point each, at most ``VERSION_UNKNOWN_CAP``."""
    points = min(len(unknown), VERSION_UNKNOWN_CAP)
    if points <= 0:
        return []
    ids = ', '.join(sorted(c.get('id', '') for c in unknown)[:3])
    return [{'label': f'{len(unknown)} CVE match{"es" if len(unknown) != 1 else ""} with unknown affected versions, to review ({ids})',
             'points': points}]


def _cve_lines(cves):
    rank = {'fire': 3, 'smoke': 2, 'ice': 1}
    unknown = [c for c in cves if c.get('version_unknown')]
    usable = [c for c in cves if c.get('temp') in CVE_POINTS and not c.get('version_unknown')]
    if not usable:
        return _capped(_unknown_line(unknown), VERSION_UNKNOWN_CAP)
    usable.sort(key=lambda c: (-rank[c['temp']], c.get('id', '')))
    worst = usable[0]
    points = CVE_POINTS[worst['temp']]
    lines = [{'label': f'{worst["temp"].capitalize()} CVE match {worst.get("id", "")}'.strip(), 'points': points}]
    if worst['temp'] == 'fire' and any(c['temp'] == 'fire' and c.get('ai_verdict') == 'affected' for c in usable):
        lines.append({'label': 'AI confirmed the host is affected by a fire CVE', 'points': AI_BONUS})
    return _capped(lines + _unknown_line(unknown), CVE_CAP)


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


def _hygiene_lines(issues):
    issues = sorted((i for i in issues if i.get('severity') in HYGIENE_POINTS), key=lambda i: (-i['severity'], i.get('title') or ''))
    if not issues:
        return []
    worst = issues[0]
    lines = [{'label': f'{FINDING_NAMES[worst["severity"]]} hygiene issue {worst.get("title") or ""}'.strip(),
              'points': HYGIENE_POINTS[worst['severity']]}]
    more = len([i for i in issues[1:] if i['severity'] >= 2])
    if more:
        lines.append({'label': f'{more} more hygiene issue{"s" if more != 1 else ""} (medium or worse)', 'points': more * HYGIENE_EXTRA})
    return _capped(lines, HYGIENE_CAP)


def score_host(inputs):
    """``(score, detail)`` for one host. ``inputs``: ``cves`` [{id, temp, ai_verdict, version_unknown}] (matches the AI has not ruled out),
    ``findings`` [{severity, name}] (open), ``hygiene`` [{severity, title}] (open hygiene findings of the host), ``routes`` [{path, auth_state, sensitive_score}], ``public_ip`` bool,
    ``recent`` [change kinds in the last 7 days], ``zombie_host`` and ``zombie_route`` bools. ``detail`` is the ordered list of
    ``{'label', 'points'}`` that add up to the score (at most 100)."""
    detail = _cve_lines(inputs.get('cves') or [])
    findings = [f for f in inputs.get('findings') or [] if f.get('severity') in FINDING_POINTS]
    if findings:
        worst = max(findings, key=lambda f: FINDING_POINTS[f['severity']] * 10 + f['severity'])
        detail.append({'label': f'{FINDING_NAMES[worst["severity"]]} finding {worst.get("name") or ""}'.strip(),
                       'points': FINDING_POINTS[worst['severity']]})
    detail += _hygiene_lines(inputs.get('hygiene') or [])
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
    items = iter(items)
    while chunk := list(islice(items, size)):
        yield chunk


def _cve_inputs(sub):
    from cveFeed.counts import match_is_live
    from cveFeed.match_policy import version_unknown
    from cveFeed.threat import match_heat
    out = []
    for m in sub.cve_matches.all():
        if not match_is_live(m):  # ruled out, fixed or an accepted risk
            continue
        # the heat the host card shows: a version-only match is held to CVENGINE_VERSION_ONLY_MAX_HEAT (smoke), KEV or not
        out.append({'id': m.cve_entry.cve_id, 'temp': match_heat(m), 'ai_verdict': m.ai_verdict, 'version_unknown': version_unknown(m)})
    return out


def _has_public_ip(sub):
    from cveFeed.tailscale_scope import is_tailnet_address
    from targetApp.target_types import is_public_address
    # judged from the address alone (issue 212): the stored is_private flag was never set for an address found by a scan, and a scanning
    # policy (blocked ranges, the opt-in for private targets) must not change an exposure score. A tailnet address is reachable only by
    # the tailnet's own devices, so it is never "public"
    return any(ip.address and is_public_address(ip.address) and not is_tailnet_address(ip.address) for ip in sub.ip_addresses.all())


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
    from cveFeed.counts import finding_is_live
    from cveFeed.counts import CLOSED
    from django.db.models import Prefetch

    from cveFeed.models import AssetChange, CVEMatch, HostState, HygieneFinding, RouteAuth
    from startScan.models import Subdomain
    now = now or timezone.now()
    names = sorted({(n or '').strip().lower() for n in names if n})
    scored = 0
    for chunk in _chunks(names):
        newest = (usable_rows(Subdomain.objects.filter(target_domain__project_id=project_id, name__in=chunk))
                  .order_by('name', *row_preference(scan_id)).distinct('name')
                  .prefetch_related('ip_addresses', Prefetch('cve_matches', queryset=CVEMatch.objects.select_related('cve_entry', 'triage')),
                                    'vulnerability_set'))  # a score reads a CVE's tier fields
        subs = {s.name.lower(): s for s in newest}
        routes, recent, zombies, hygiene = {}, {}, {}, {}
        for h in (HygieneFinding.objects.filter(domain__project_id=project_id, host__in=chunk, status='open', severity__gte=1)
                  .exclude(remediation_status__in=CLOSED).values('host', 'severity', 'title')):
            hygiene.setdefault(h['host'].lower(), []).append(h)
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
                      'findings': [{'severity': v.severity, 'name': v.name} for v in sub.vulnerability_set.all() if finding_is_live(v)],
                      'hygiene': hygiene.get(name, []), 'routes': routes.get(name, []), 'public_ip': _has_public_ip(sub), 'recent': recent.get(name, ())}
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


HEAT_CAP_KEY = 'cvengine:scoring:version_only_max_heat'  # the version-only cap the stored scores were last asked to follow


def rescore_if_heat_cap_changed():
    """Queue one full rescore when the version-only cap (``threat.version_only_max_heat``) differs from the one last seen: after the
    upgrade that introduced it (stored scores still count a version-only KEV match as fire) or after the owner changed
    CVENGINE_VERSION_ONLY_MAX_HEAT. Heat itself needs nothing (it is computed when read); a score is stored, so it follows here, or at the
    next daily pass. One GETSET, so of several workers starting together only the first queues it. Returns whether it queued. Never raises."""
    from cveFeed.threat import version_only_max_heat
    from reNgine import resources
    try:
        client = getattr(resources.get_store(), 'r', None)
        if client is None:
            return False
        cap = version_only_max_heat()
        if client.getset(HEAT_CAP_KEY, cap) == cap:
            return False
        from cveFeed.tasks import rescore_all_hosts
        rescore_all_hosts.apply_async(countdown=120)
        return True
    except Exception:  # noqa: BLE001 - the next worker start or the daily pass tries again
        logger.exception('could not queue the rescore for the version-only heat cap')
        return False


def rescore_quietly(project_id, names, scan_id=None):
    """``rescore_hosts`` for a trigger inside a pipeline: never raises."""
    try:
        return rescore_hosts(project_id, names, scan_id=scan_id)
    except Exception:  # noqa: BLE001 - a scoring problem must not undo the work that triggered it
        logger.exception('could not rescore hosts of project %s', project_id)
        return 0


def _rescore_name_pairs(pairs, seen=None):
    """Rescore every (name, project) pair with at most CHUNK distinct names in memory. ``seen``, shared between calls, holds the pairs
    already rescored: a host matched by several of the CVEs a caller walks in chunks is scored once, not once per chunk."""
    pending = {}
    count = 0
    for name, project_id in pairs:
        if not project_id or (seen is not None and (name, project_id) in seen):
            continue
        if seen is not None:
            seen.add((name, project_id))
        names = pending.setdefault(project_id, set())
        if name not in names:
            names.add(name)
            count += 1
        if count >= CHUNK:
            for batch_project, batch_names in pending.items():
                rescore_quietly(batch_project, sorted(batch_names))
            pending.clear()
            count = 0
    for project_id, names in pending.items():
        if names:
            rescore_quietly(project_id, sorted(names))


def rescore_subdomain_ids(subdomain_ids):
    """Rescore every supplied Subdomain's host after verdict resets or match closures. Never raises."""
    try:
        from startScan.models import Subdomain
        for ids in _chunks(subdomain_ids):
            _rescore_name_pairs(Subdomain.objects.filter(pk__in=ids, target_domain__project__isnull=False)
                                .values_list('name', 'target_domain__project_id'))
    except Exception:  # noqa: BLE001
        logger.exception('could not rescore after a verdict reset')


def rescore_for_matches(matches, seen=None):
    """Rescore every host whose CVE match verdict was just saved (``seen``: see ``_rescore_name_pairs``)."""
    try:
        rows = matches.iterator(chunk_size=CHUNK) if hasattr(matches, 'iterator') else matches
        def pairs():
            for match in rows:
                sub = getattr(match, 'subdomain', None)
                domain = getattr(sub, 'target_domain', None) if sub else None
                if sub and domain:
                    yield sub.name, domain.project_id
        _rescore_name_pairs(pairs(), seen)
    except Exception:  # noqa: BLE001
        logger.exception('could not rescore after a verdict')
