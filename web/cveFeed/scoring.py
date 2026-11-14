"""Host score: one number (0 to 100) that says which host to look at first, and why.

``score_host`` is a pure function over plain inputs, so every component is unit tested; ``rescore_hosts`` gathers the inputs
for a batch of hosts with a handful of bounded queries and stores the result on the Subdomain rows (and HostState), where
the Hosts page, search and the graph already read.

| Component | Points | Cap |
| --- | --- | --- |
| CVE matches (not ruled out), at the heat they show on the host (``threat.match_heat``: under the KEV heat policy a KEV or exploited CVE is fire when hard evidence proves the flaw and smoke otherwise, anything else ice): fire 40, smoke 20, ice 5; AI-confirmed on a fire match adds 10 | worst match | 50 |
| CVE matches whose affected version range is not known (kept for review): 1 each, KEV or not | all of them | 2 |
| Open findings: critical/high 25, medium 10, low 3; under the KEV heat policy a finding that names CVEs counts by its heat instead, and so does one a cap holds below its severity (``threat.finding_heat``: fire 25, smoke 10, ice 3) | worst | 25 |
| Route auth: open admin or API-like path 15, open front page 5, login page 5, SSO or session required 0 | worst | 15 |
| Sensitive data on a route (cveFeed.sensitive.sensitive_score); for a host the secrets inventory covers, its worst counting secret instead of the routes' credential samples: server secret (high or critical) 25, medium 10, low or a browser key 5 | worst | 25 |
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
HEAT_WORDS = {'fire': 'it is exploited in the wild (or has a public exploit) and the flaw is confirmed on this host.',
              'smoke': 'it is exploited in the wild (or has a public exploit), but only the software version says the host has it.',
              'ice': 'it is not known to be exploited and has no public exploit.'}
VERSION_UNKNOWN_CAP = 2  # the most a host's score takes from CVE matches that have no affected version range (review, not exposure)
FINDING_POINTS = {4: 25, 3: 25, 2: 10, 1: 3}
FINDING_HEAT_POINTS = {'fire': 25, 'smoke': 10, 'ice': 3}  # a finding that names CVEs, under the KEV heat policy: by its heat, not its severity
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
    many = len(unknown) != 1
    return [{'label': f'{len(unknown)} CVE match{"es" if many else ""} with unknown affected versions, to review ({ids})',
             'points': points, 'kind': 'cve_unknown', 'ref': {'type': 'matches'},
             'text': (f'{len(unknown)} CVE{"s" if many else ""} name software this host runs but publish no affected version range, so '
                      f'{"they" if many else "it"} cannot be confirmed or ruled out. Each adds 1 point (at most {VERSION_UNKNOWN_CAP}) until someone reviews '
                      f'{"them" if many else "it"}.')}]


def _cve_lines(cves):
    rank = {'fire': 3, 'smoke': 2, 'ice': 1}
    unknown = [c for c in cves if c.get('version_unknown')]
    usable = [c for c in cves if c.get('temp') in CVE_POINTS and not c.get('version_unknown')]
    if not usable:
        return _capped(_unknown_line(unknown), VERSION_UNKNOWN_CAP)
    usable.sort(key=lambda c: (-rank[c['temp']], c.get('id', '')))
    worst = usable[0]
    points = CVE_POINTS[worst['temp']]
    lines = [{'label': f'{worst["temp"].capitalize()} CVE match {worst.get("id", "")}'.strip(), 'points': points, 'kind': 'cve',
              'ref': {'type': 'match', 'id': worst['match_id']} if worst.get('match_id') else {'type': 'matches'},
              'text': (f'{worst.get("id") or "A CVE"} matches software on this host and is rated {worst["temp"]}: {HEAT_WORDS[worst["temp"]]} '
                       f'Only the worst match counts ({points} points)' + (f', and {len(usable) - 1} other match{"es" if len(usable) > 2 else ""} score nothing more.'
                                                                             if len(usable) > 1 else '.'))}]
    if worst['temp'] == 'fire' and any(c['temp'] == 'fire' and c.get('ai_verdict') == 'affected' for c in usable):
        lines.append({'label': 'AI confirmed the host is affected by a fire CVE', 'points': AI_BONUS, 'kind': 'ai', 'ref': lines[0]['ref'],
                      'text': 'The AI reviewed a fire CVE match and judged this host affected, which adds 10 points.'})
    return _capped(lines + _unknown_line(unknown), CVE_CAP)


def _capped(lines, cap):
    """Trim the points of ``lines`` so their sum stays within ``cap``."""
    out, left = [], cap
    for line in lines:
        points = min(line['points'], left)
        if points > 0:
            out.append({**line, 'points': points})
            left -= points
    return out


def _route_line(routes):
    best = None
    for route in routes:
        path, state = route.get('path') or '/', route.get('auth_state')
        if state == 'open' and ADMIN_PATH.search(path):
            line = {'label': f'Admin route {path} is open', 'points': 15, 'kind': 'route', 'ref': {'type': 'host_tab', 'tab': 'web'},
                    'text': f'{path} looks like an administration or API path and answered without asking for a login. Scored once, for the worst route (15 points).'}
        elif state == 'open' and path == '/':
            line = {'label': 'Front page is open', 'points': 5, 'kind': 'route', 'ref': {'type': 'host_tab', 'tab': 'web'},
                    'text': 'The front page answers without a login, so the host serves content to anyone (5 points).'}
        elif state == 'login':
            line = {'label': f'Login page {path}', 'points': 5, 'kind': 'route', 'ref': {'type': 'host_tab', 'tab': 'web'},
                    'text': f'{path} is a login page reachable from the internet: an entry point to guess or attack (5 points).'}
        else:
            continue
        if best is None or line['points'] > best['points']:
            best = line
    return [best] if best else []


SECRET_POINTS = {4: 25, 3: 25, 2: 10, 1: 5, 0: 5}  # by the inventory row's severity (cveFeed.secrets_catalog.severity)
SECRET_WORDS = {'S': 'Server credential', 'P': 'Browser key', 'I': 'Token or identifier'}
SEVERITY_WORDS = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'}


def _route_points(route, covered):
    """A route's sensitive score; on a host the secrets inventory covers, without its credentials (the inventory rates those)."""
    if not covered or not route.get('sensitive'):
        return route.get('sensitive_score') or 0
    from cveFeed import sensitive
    return sensitive.sensitive_score({k: v for k, v in route['sensitive'].items() if k not in sensitive.CREDENTIAL_TYPES})


CLASS_SENTENCE = {'S': 'a server credential: it lets whoever reads it act as its owner, and it is not meant to leave the server',
                  'P': 'a browser key: it is meant to sit in a page, and what protects it is the restriction set at its provider',
                  'I': 'a token or identifier: it names an account or session and may grant access on its own'}


def _secret_text(top, path, points):
    """The plain sentence of a secret's score line: what it is, where, why it scores."""
    what = top.get('label') or SECRET_WORDS.get(top.get('klass'), 'secret')
    where = top.get('url') or path
    line = f' (line {top["line"]})' if top.get('line') else ''
    mask = f' ending {top["masked"]}' if top.get('masked') else ''
    basis = (top.get('basis') or '').strip().rstrip('.')
    return (f'{what[:1].upper() + what[1:]}{mask} was found at {where}{line}. It is {CLASS_SENTENCE.get(top.get("klass"), "a secret")}. '
            + (f'Why {SEVERITY_WORDS.get(top.get("severity"), "unrated")}: {basis}. ' if basis else '')
            + f'Only the worst secret on a host counts ({points} points).')


def _sensitive_line(routes, secrets=(), covered=False):
    """The worst of: the routes' sensitive data, and (for a host the inventory covers) its worst counting secret. ``secrets`` [{severity, klass,
    path}] from ``secrets_inventory.host_secrets``."""
    lines = []
    worst = max(routes, key=lambda r: _route_points(r, covered), default=None)
    points = _route_points(worst, covered) if worst else 0
    if points > 0:
        what = {25: 'Credentials served', 15: 'Personal data served'}.get(points, 'Contact details or internal identifiers served')
        path = worst.get('path') or '/'
        shown = min(points, SENSITIVE_CAP)
        lines.append({'label': f'{what} on {path}', 'points': shown, 'kind': 'route_sensitive', 'ref': {'type': 'host_tab', 'tab': 'web'},
                      'text': (f'The page {path} returned {what[:1].lower() + what[1:-7]} when the route check read it, without a login. '
                               f'Only the worst route counts ({shown} points); the Web tab shows the route and what it matched.')})
    if secrets:
        top = max(secrets, key=lambda s: (SECRET_POINTS.get(s.get('severity'), 0), s.get('klass') == 'S', s.get('severity') or 0))
        shown = min(SECRET_POINTS.get(top.get('severity'), 0), SENSITIVE_CAP)
        path = top.get('path') or '/'
        lines.append({'label': f'{SECRET_WORDS.get(top.get("klass"), "Secret")} served on {path}', 'points': shown, 'kind': 'secret',
                      'ref': {'type': 'secret', 'id': top['id']} if top.get('id') else {'type': 'host_tab', 'tab': 'web'},
                      'text': _secret_text(top, path, shown)})
    return [max(lines, key=lambda line: line['points'])] if lines else []


def _hygiene_lines(issues):
    issues = sorted((i for i in issues if i.get('severity') in HYGIENE_POINTS), key=lambda i: (-i['severity'], i.get('title') or ''))
    if not issues:
        return []
    worst = issues[0]
    ref = {'type': 'hygiene', 'id': worst['id']} if worst.get('id') else {'type': 'hygiene_list'}
    lines = [{'label': f'{FINDING_NAMES[worst["severity"]]} hygiene issue {worst.get("title") or ""}'.strip(),
              'points': HYGIENE_POINTS[worst['severity']], 'kind': 'hygiene', 'ref': ref,
              'text': (f'A {FINDING_NAMES[worst["severity"]].lower()} configuration problem on this host: {worst.get("title") or "a hygiene check failed"}. '
                       f'The worst open issue sets {HYGIENE_POINTS[worst["severity"]]} points.')}]
    more = len([i for i in issues[1:] if i['severity'] >= 2])
    if more:
        lines.append({'label': f'{more} more hygiene issue{"s" if more != 1 else ""} (medium or worse)', 'points': more * HYGIENE_EXTRA,
                      'kind': 'hygiene_more', 'ref': {'type': 'hygiene_list'},
                      'text': f'{more} further open issue{"s" if more != 1 else ""} of medium severity or worse; each adds {HYGIENE_EXTRA} points (the hygiene part of a score stops at {HYGIENE_CAP}).'})
    return _capped(lines, HYGIENE_CAP)


def score_host(inputs):
    """``(score, detail)`` for one host. ``inputs``: ``cves`` [{id, match_id, temp, ai_verdict, version_unknown}] (matches the AI has not ruled out),
    ``findings`` [{id, severity, name}] (open), ``hygiene`` [{id, severity, title}] (open hygiene findings of the host), ``routes`` [{path, auth_state, sensitive_score, sensitive}], ``secrets`` [{id, severity, klass, path, url, line, masked, label, basis}] (counting inventory secrets the host
    serves) and ``secrets_covered`` (the inventory covers the host, so route credential samples do not score), ``public_ip`` bool,
    ``recent`` [change kinds in the last 7 days], ``zombie_host`` and ``zombie_route`` bools. ``detail`` is the ordered list of
    ``{'label', 'points', 'kind', 'text', 'ref'}`` that add up to the score (at most 100): ``label`` is the short name, ``text`` the plain
    sentence (what, where, why it scores), ``ref`` what evidence the line links to (``{'type': 'match'|'vulnerability'|'hygiene'|'secret', 'id'}``,
    or a host tab or list: ``web/static/cve/score-detail-logic.js`` turns it into a link). Every line is listed, so the lines are the score."""
    detail = _cve_lines(inputs.get('cves') or [])
    findings = [f for f in inputs.get('findings') or [] if f.get('severity') in FINDING_POINTS]

    def points(f):
        return FINDING_HEAT_POINTS[f['heat']] if f.get('heat') in FINDING_HEAT_POINTS else FINDING_POINTS[f['severity']]
    if findings:
        worst = max(findings, key=lambda f: points(f) * 10 + f['severity'])
        detail.append({'label': f'{FINDING_NAMES[worst["severity"]]} finding {worst.get("name") or ""}'.strip()
                       + ((f' ({worst["heat"]}: held until a validation confirms it)' if worst.get('held') else
                           f' ({worst["heat"]}: its CVE rated by the heat policy)') if worst.get('heat') in FINDING_HEAT_POINTS else ''),
                       'points': points(worst), 'kind': 'finding',
                       'ref': {'type': 'vulnerability', 'id': worst['id']} if worst.get('id') else {'type': 'host_tab', 'tab': 'findings'},
                       'text': (f'The scanner reported "{worst.get("name") or "a finding"}" ({FINDING_NAMES[worst["severity"]].lower()}) and it is still open. '
                                + ('A validation has not confirmed it yet, so it scores by its heat. ' if worst.get('held') else
                                   'It names a CVE, so it scores by that CVE\'s heat. ' if worst.get('heat') in FINDING_HEAT_POINTS else '')
                                + f'Only the worst open finding counts ({points(worst)} points).')})
    detail += _hygiene_lines(inputs.get('hygiene') or [])
    routes = inputs.get('routes') or []
    detail += _capped(_route_line(routes), ROUTE_CAP)
    detail += _sensitive_line(routes, inputs.get('secrets') or (), bool(inputs.get('secrets_covered')))
    if inputs.get('public_ip'):
        detail.append({'label': 'Public IP observed in inventory (service reachability unverified)', 'points': EXPOSURE_POINTS, 'kind': 'exposure',
                       'ref': {'type': 'host_tab', 'tab': 'services'},
                       'text': 'The host has a public IP address in the inventory, so it is reachable from the internet in principle (10 points). No one has checked that a service answers.'})
    recent = set(inputs.get('recent') or [])
    detail += _capped([{'label': 'New this week', 'points': 10, 'kind': 'recent', 'ref': {'type': 'host_tab', 'tab': 'changes'},
                        'text': 'The host appeared (or came back) in the last 7 days. New hosts score higher until they have been looked at (10 points).'}]
                      if recent & set(RECENT_NEW_KINDS) else
                      [{'label': 'Exposure changed this week', 'points': 5, 'kind': 'recent', 'ref': {'type': 'host_tab', 'tab': 'changes'},
                        'text': 'A port opened or a service version changed in the last 7 days (5 points). History lists the change.'}]
                      if recent & set(RECENT_CHANGE_KINDS) else [], RECENCY_CAP)
    zombies = []
    if inputs.get('zombie_host'):
        zombies.append({'label': 'Zombie host: DNS is gone but it still answers', 'points': 15, 'kind': 'zombie', 'ref': {'type': 'host_tab', 'tab': 'changes'},
                        'text': 'The name no longer resolves in DNS but the host still answers on its old address: forgotten infrastructure (15 points).'})
    if inputs.get('zombie_route'):
        zombies.append({'label': 'Zombie route: a retired path answers again', 'points': 5, 'kind': 'zombie', 'ref': {'type': 'host_tab', 'tab': 'web'},
                        'text': 'A path that had been retired answers again (5 points). The Web tab lists the route.'})
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
        if not match_is_live(m):  # ruled out, or closed: fixed, accepted risk or false positive
            continue
        # the heat the host card shows (threat.match_heat: the heat policy)
        out.append({'id': m.cve_entry.cve_id, 'match_id': m.pk, 'temp': match_heat(m), 'ai_verdict': m.ai_verdict, 'version_unknown': version_unknown(m)})
    return out


def _hot_finding_cves(subs):
    """The hot CVE ids among the CVEs the hosts' findings name (one query), or None under the legacy heat policy (severity only)."""
    from cveFeed.threat import LEGACY_POLICY, finding_cve_names, heat_policy, hot_cve_names
    if heat_policy() == LEGACY_POLICY:
        return None
    return hot_cve_names({n for sub in subs for v in sub.vulnerability_set.all() for n in finding_cve_names(v)})


def _finding_input(v, hot):
    """One open finding for ``score_host``: its severity and name, and its heat when that is not its severity's (under the KEV policy a
    finding that names CVEs, under either a finding a cap holds lower: a template match no validation reproduced, a triage still pending or
    needing validation, a validation that came back clean; ``threat.finding_heat``)."""
    from cveFeed.threat import SEVERITY_HEAT, finding_cve_names, finding_heat
    out = {'id': v.pk, 'severity': v.severity, 'name': v.name}
    named = hot is not None and bool(finding_cve_names(v))
    heat = finding_heat(v, hot_names=hot if hot is not None else set())
    if heat and (named or heat != SEVERITY_HEAT.get(v.severity)):
        out['heat'] = heat
        if not named:
            out['held'] = True
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
                                    'vulnerability_set', 'vulnerability_set__cve_ids', 'vulnerability_set__tags',
                                    'vulnerability_set__triage'))  # a score reads a CVE's tier fields, and a finding's CVEs
        subs = {s.name.lower(): s for s in newest}
        routes, recent, zombies, hygiene = {}, {}, {}, {}
        for h in (HygieneFinding.objects.filter(domain__project_id=project_id, host__in=chunk, status='open', severity__gte=1)
                  .exclude(remediation_status__in=CLOSED).values('id', 'host', 'severity', 'title')):
            hygiene.setdefault(h['host'].lower(), []).append(h)
        for r in RouteAuth.objects.filter(project_id=project_id, host__in=chunk).values('host', 'path', 'auth_state', 'sensitive_score', 'sensitive',
                                                                                         'zombie_since'):
            routes.setdefault(r['host'], []).append(r)
        from cveFeed import secrets_inventory
        secrets, covered = secrets_inventory.host_secrets(project_id, chunk)
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
        hot = _hot_finding_cves(subs.values())
        for name, sub in subs.items():
            inputs = {'cves': _cve_inputs(sub),
                      'findings': [_finding_input(v, hot) for v in sub.vulnerability_set.all() if finding_is_live(v)],
                      'hygiene': hygiene.get(name, []), 'routes': routes.get(name, []), 'public_ip': _has_public_ip(sub), 'recent': recent.get(name, ()),
                      'secrets': secrets.get(name, []), 'secrets_covered': name in covered}
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


HEAT_CAP_KEY = 'cvengine:scoring:version_only_max_heat'  # the heat signature (threat.heat_signature) the stored scores were last asked to follow


def rescore_if_heat_cap_changed():
    """Queue one full rescore when the owner changed the heat rule: ``threat.heat_signature()`` (the heat policy, ``CVENGINE_HEAT_POLICY`` or
    the Heat policy card, and under ``legacy`` CVENGINE_VERSION_ONLY_MAX_HEAT) differs from the one last recorded. Called when a worker starts
    and from the 30 second tick, so a policy saved on the page reaches the stored scores within minutes. Heat itself
    needs nothing (it is computed when read); a score is stored, so it follows here, or at the next daily pass. The first time a cap is
    seen (the upgrade that introduced it, or a Redis without a volume that came back empty after ``docker compose down``) it is only
    recorded: a forced rescore of every host on each restart would cost far more than scores that catch up at the daily pass. One GETSET,
    so of several workers starting together only the first queues it (and the value goes back if the broker refuses the task, so the next
    worker start tries again). The rescore it queues runs even when another full rescore holds the hour-long
    sweep claim (``rescore_all_hosts(force=True)``): a claim taken by the daily pass minutes before the change must not leave the scores on
    the old cap until the next day. Returns whether it queued. Never raises."""
    from cveFeed.threat import heat_signature
    from reNgine import resources
    try:
        client = getattr(resources.get_store(), 'r', None)
        if client is None:
            return False
        cap = heat_signature()
        previous = client.getset(HEAT_CAP_KEY, cap)
        if previous is None or previous == cap:
            return False
        from cveFeed.tasks import rescore_all_hosts
        try:
            rescore_all_hosts.apply_async(kwargs={'force': True}, countdown=120)
        except Exception:
            if previous is None:
                client.delete(HEAT_CAP_KEY)
            else:
                client.set(HEAT_CAP_KEY, previous)
            raise
        return True
    except Exception:  # noqa: BLE001 - the next worker start or the daily pass tries again
        logger.exception('could not queue the rescore for the heat rule')
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


def evidence_arrived(match_ids, confirmed=()):
    """Hard evidence (``match_policy.has_hard_evidence``) just reached these CVE matches without a template hit: the host's inventory report
    (``inventory_match``), runZero (``runzero_sync``), or a validation hit recorded, adopted from a sibling row or carried to a rescan's match
    (``validation``, ``triage``); or a version-class template hit proved their version (``templategen.record_outcomes``, KEV rule). Heat is read live, but the score is stored and the dashboards and the graph serve a snapshot: rescore the
    hosts and make every snapshot re-read (``bump_stats_revision``). ``confirmed`` are the matches among them that were version-only just
    before the write (the caller checked, before it wrote): those that are fire now are paged once (``notify.fire_confirmed``). A hit adopted
    from a sibling or carried to a rescan pages nothing: the finding and its hit were announced already. Never raises."""
    ids = sorted({int(i) for i in match_ids if i})
    if not ids:
        return
    try:
        from cveFeed import notify
        from cveFeed.models import CVEMatch
        from cveFeed.views import bump_stats_revision
        for start in range(0, len(ids), CHUNK):
            rescore_for_matches(CVEMatch.objects.filter(pk__in=ids[start:start + CHUNK]).select_related('subdomain__target_domain'))
        bump_stats_revision()
        if confirmed:
            notify.fire_confirmed(confirmed)
    except Exception:  # noqa: BLE001 - the evidence is recorded; the score, snapshots and message follow at the next pass
        logger.exception('could not follow up new evidence on %d CVE matches', len(ids))


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
