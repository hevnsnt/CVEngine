"""Situations: what needs a person, one host at a time, ranked.

A **situation** is one host of a project together with everything open on it that needs a person, in four tiers:

1. **proven**: a CVE match or scanner finding that one of cvENGINE's own checks reproduced (``Triage.validation_status == 'hit'``, the "Proven
   on this host" card), unless a person set its heat to ice;
2. **likely**: a CVE match or scanner finding that shows fire or smoke (``cveFeed.threat``: the one definition of heat, including a heat a
   person set by hand), not proven, and not called a false positive by the AI reviewer;
3. **exposure**: an open database (``source == 'db_exposure'``), a dangling DNS record (the dangling-DNS check), an open admin or cleartext service
   (Telnet, FTP, r-services, a tailnet admin port) or an exposed secret that counts (not public by design, accepted, revoked or a false positive);
4. **minor**: everything else that is still open: hygiene findings and ice-heat matches and findings.

What is closed is not part of it: fixed, accepted risk, false positive (``cveFeed.closure.CLOSED``), a CVE match the AI ruled out, a scanner
finding the scans no longer see, informational findings. The sets are the Overview's own: ``counts.exposed_matches``,
``counts.actionable_findings``, ``counts.actionable_hygiene``, so every host the Overview calls exposed has a situation (``tests/test_situations.py``).
A situation can exist for a host with only hygiene findings, which the Overview does not call exposed.

**One host** is what the Hosts page calls one host: names that resolve to exactly the same addresses are one situation, named like the Hosts
page names it (``agentapi.services._one_per_host``); the other names are ``also_known_as``.

**The rank rule** (the order is the same in the page, REST and MCP; position 1 is the first thing to look at). A situation sorts by, in order:

1. its worst tier: proven, then likely, then exposure, then minor (proof beats likelihood, likelihood beats exposure);
2. known exploited (the CVE is on the KEV) among its proven and likely CVE matches, yes before no (known-exploited beats severity alone);
3. internet-facing before inside a declared internal network (``cveFeed.internal_view``);
4. the worst severity among its items (a CVE by its CVSS band, as the Findings list bands it);
5. how many proven, likely and exposure items it has, more first;
6. the oldest open item, oldest first (age breaks ties);
7. the host name, then the project id, so the order is total and the same data always gives the same list.

A heat a person set by hand is respected in the tiers: ice moves an item to minor (even a proven one), fire or smoke makes it at least likely.
The reason for the rank is the same facts in one short phrase (``rank_reason``).

**The narrative** is two to four plain sentences built by code from the data (no model): what the host is, what is proven or likely and how, what
is exposed, and what to do first. Same data, same text. Free text that came from a scan (a banner, a finding name) is stripped of control and
invisible characters and cut short (``clean``), and a banner is used only when it looks like a product name (``product``), so a hostile string can
neither break a page nor talk to an agent; the page draws every field with ``textContent``.

Set-based: four grouped queries (matches, scanner findings, hygiene findings, secrets) give each host's counts, the two inventory queries give
the hosts, and only the hosts of the page are read item by item (at most ``LIST_ITEMS`` each, one windowed query per source). The number of queries
does not depend on the number of hosts.
"""
import re
from collections import defaultdict
from urllib.parse import quote

from django.db.models import BooleanField, Case, Count, F, IntegerField, Max, Min, Q, Value, When, Window
from django.db.models.functions import Coalesce, Lower, RowNumber

from cveFeed import counts
from cveFeed.closure import CLOSED, _CONTROL
from cveFeed.threat import CRITICAL_CVSS, FIRE, HEAT_RANK, HIGH_CVSS, ICE, SMOKE, VALIDATION_HIT

PROVEN, LIKELY, EXPOSURE, MINOR = 3, 2, 1, 0
TIER_NAMES = {PROVEN: 'proven', LIKELY: 'likely', EXPOSURE: 'exposure', MINOR: 'minor'}
TIER_ORDER = (PROVEN, LIKELY, EXPOSURE, MINOR)
TIER_PHRASE = {PROVEN: 'Proven by a check', LIKELY: 'Likely real', EXPOSURE: 'Exposed', MINOR: 'Lower priority only'}

LIST_ITEMS = 12  # items of one host a list row carries
DETAIL_ITEMS = 200  # items of one host the detail carries
TEXT_MAX = 160  # characters of any text that came from a scan
TITLE_MAX = 90
HEAT_NAMES = {rank: name for name, rank in HEAT_RANK.items()}

# hygiene findings that are an open service (cveFeed.cleartext, cveFeed.tailscale_checks), not a configuration slip
EXPOSURE_HYGIENE = ('cleartext_telnet', 'cleartext_ftp', 'cleartext_rservices', 'ts_remote_admin_exposed')
SOURCE_DB = 'db_exposure'
DANGLING_NAMES = ('dangling ns', 'dangling cname')  # the names the dangling-DNS check gives its findings (cveFeed.dangling_dns)

_PRODUCT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._/+()-]{0,59}$')
_SPACES = re.compile(r'\s+')


def clean(value, limit=TEXT_MAX):
    """``value`` as one line of plain text: control, line-break, zero-width and bidirectional-override characters become a space, runs of
    white space one space, at most ``limit`` characters. Everything a scan wrote that reaches a narrative goes through here."""
    text = _SPACES.sub(' ', _CONTROL.sub(' ', str(value or ''))).strip()
    return text[:limit].rstrip()


def product(value):
    """A web server or product name as a banner gives it ('nginx/1.18.0 (Ubuntu)'), or '' when it is anything else: a banner is the host's own
    words and is told in the narrative only when it is a plain name."""
    text = clean(value, 60)
    return text if text and _PRODUCT.match(text) else ''


# ----------------------------------------------------------------------------------------------------------------- the four sources

def _cve_band():
    return Case(When(cve_entry__cvss__gte=CRITICAL_CVSS, then=Value(4)), When(cve_entry__cvss__gte=HIGH_CVSS, then=Value(3)),
                When(cve_entry__cvss__gte=4.0, then=Value(2)), default=Value(1), output_field=IntegerField())


def _tier_case(proven, manual_ice, manual_hot, likely, exposure=None):
    whens = [When(manual_ice, then=Value(MINOR)), When(proven, then=Value(PROVEN))]
    if exposure is not None:
        whens.append(When(exposure, then=Value(EXPOSURE)))
    whens.append(When(manual_hot | likely, then=Value(LIKELY)))
    return Case(*whens, default=Value(MINOR), output_field=IntegerField())


def _disputed():
    """The AI reviewer's newest verdict is false positive with high confidence and the server did not close the finding for a reason that is
    not about the evidence (a person worked it, a critical scanner finding, closing switched off), and no retest reproduced it: as a flag,
    never NULL. A verdict the server refused because of hard evidence, a floor, or text aimed at an AI in the evidence, one the model was not
    sure of, and a finding a retest reopened never demote it: the ranking does not follow a model the server itself did not believe."""
    refused_for_evidence = (Q(review_outcome='disputed') | Q(review_held__startswith='hard evidence') | Q(review_held__startswith='its evidence carries text')
                            | Q(review_held__startswith='contradicts the earlier verdict'))  # a host review's closure an earlier real verdict holds
    return Case(When(Q(review_verdict='false_positive', review_confidence='high') & ~Q(review_outcome='closed') & ~refused_for_evidence
                     & ~Q(triage__retest_state='still_reproduces'), then=Value(True)), default=Value(False), output_field=BooleanField())


def _matches(ids):
    """The Overview's exposed CVE matches of the projects, annotated with ``pid``, ``lname``, ``tier``, ``sev``, ``heat`` and ``first``."""
    from cveFeed import reviewer
    from cveFeed.threat import match_heat_rank_expr
    qs = counts.exposed_matches().filter(subdomain__target_domain__project_id__in=ids).order_by()
    qs = qs.annotate(pid=F('subdomain__target_domain__project_id'), lname=Lower('subdomain__name'), heat=match_heat_rank_expr(), sev=_cve_band(),
                     first=Coalesce('triage__first_seen', 'created_at'), **reviewer.newest_review_q('triage__'))
    qs = qs.annotate(disputed=_disputed())
    manual_hot = Q(triage__heat_override__in=(FIRE, SMOKE))
    return qs.annotate(tier=_tier_case(Q(triage__validation_status=VALIDATION_HIT), Q(triage__heat_override=ICE), manual_hot,
                                       Q(disputed=False, heat__gte=HEAT_RANK[SMOKE]))), Q(triage__heat_override__in=(FIRE, SMOKE, ICE))


def _exposure_q():
    q = Q(source=SOURCE_DB)
    for prefix in DANGLING_NAMES:
        q |= Q(name__istartswith=prefix)
    return q


def _vulns(ids):
    from cveFeed import reviewer
    from cveFeed.threat import finding_heat_rank_expr
    from startScan.models import Vulnerability
    qs = counts.actionable_findings(Vulnerability.objects.filter(subdomain__isnull=False, target_domain__project_id__in=ids)).order_by()
    qs = qs.filter(counts_latest('subdomain__')).annotate(
        pid=F('target_domain__project_id'), lname=Lower('subdomain__name'), heat=finding_heat_rank_expr(), sev=F('severity'),
        first=Coalesce('triage__first_seen', 'discovered_date'), **reviewer.newest_review_q('triage__'))
    qs = qs.annotate(disputed=_disputed())
    manual_hot = Q(triage__heat_override__in=(FIRE, SMOKE))
    return qs.annotate(tier=_tier_case(Q(triage__validation_status=VALIDATION_HIT), Q(triage__heat_override=ICE), manual_hot,
                                       Q(disputed=False, heat__gte=HEAT_RANK[SMOKE]), exposure=_exposure_q())), Q(triage__heat_override__in=(FIRE, SMOKE, ICE))


def counts_latest(prefix):
    from cveFeed.correlation import latest_scan_q
    return latest_scan_q(prefix)


def _hygiene(ids):
    from cveFeed.models import HygieneFinding
    qs = counts.actionable_hygiene(HygieneFinding.objects.filter(domain__project_id__in=ids)).order_by()
    return qs.annotate(pid=F('domain__project_id'), lname=Lower('host'), sev=F('severity'), first=F('first_seen'), heat=Value(0, output_field=IntegerField()),
                       tier=Case(When(check_name__in=EXPOSURE_HYGIENE, then=Value(EXPOSURE)), default=Value(MINOR), output_field=IntegerField()))


def _secrets(ids):
    """One row per (secret, host) that counts: the Hosts page's Secrets chip, minus the secrets no person needs to act on."""
    from cveFeed import secrets_catalog
    from cveFeed.models import SecretOccurrence
    qs = (SecretOccurrence.objects.filter(project_id__in=ids, retired_at__isnull=True, finding__severity__gte=1).exclude(finding__status__in=secrets_catalog.QUIET_STATUSES)
          .exclude(finding__remediation_status__in=CLOSED).order_by())
    return qs.annotate(pid=F('project_id'), lname=Lower('host'), sev=F('finding__severity'), first=F('finding__first_seen'), heat=Value(0, output_field=IntegerField()),
                       tier=Value(EXPOSURE, output_field=IntegerField()))


def _group_rows(qs, kev=None, manual=None, distinct=None):
    """``[(pid, lname, tier, n, sev, first, kev, manual)]``: the source grouped by host and tier, in one query."""
    aggregates = {'n': Count(distinct or 'pk', distinct=bool(distinct)), 'worst': Max('sev'), 'oldest': Min('first')}
    aggregates['kev_n'] = Count('pk', filter=Q(**{kev: True})) if kev else Value(0, output_field=IntegerField())
    aggregates['manual_n'] = Count('pk', filter=manual) if manual is not None else Value(0, output_field=IntegerField())
    for r in qs.values('pid', 'lname', 'tier').annotate(**aggregates):
        yield r['pid'], r['lname'], r['tier'], r['n'], r['worst'] or 0, r['oldest'], r['kev_n'], r['manual_n']


# ----------------------------------------------------------------------------------------------------------------- hosts

def _inventory(ids):
    """``(reps, names)``: ``reps`` is ``{host key: {id, name, pid, http, server}}``, one entry per host exactly as the Hosts page collapses them, and
    ``names`` maps ``(project id, lower-case name)`` to its host key. Two queries however many hosts."""
    from agentapi.services import _one_per_host
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    current = Subdomain.objects.filter(latest_scan_q(), target_domain__project_id__in=ids)
    reps = {}
    for r in counts.with_host_key(_one_per_host(current, per_project=True)).values('id', 'name', 'target_domain__project_id', 'http_status', 'webserver', 'host_key'):
        reps[r['host_key']] = {'id': r['id'], 'name': r['name'], 'pid': r['target_domain__project_id'], 'http': r['http_status'] or 0, 'server': r['webserver'] or ''}
    names = {}
    for pid, name, key in counts.with_host_key(current).values_list('target_domain__project_id', 'name', 'host_key').distinct():
        names[(pid, name.lower())] = key
    return reps, names


# ----------------------------------------------------------------------------------------------------------------- ranking and words

def _scope_word(internal):
    return 'internal' if internal else 'internet-facing'


def _reason(top, kev, internal, manual):
    parts = [TIER_PHRASE[top]]
    if kev:
        parts.append('known exploited')
    parts.append(_scope_word(internal))
    if manual:
        parts.append('heat set by you')
    return ', '.join(parts)


def _is_internal(pid, names):
    from cveFeed import internal_view
    return any(internal_view.is_internal(pid, n) for n in names)


def _build_groups(ids):
    """``(groups, hosts)``: every situation of the projects in rank order (no items yet) and the number of hosts of the inventory."""
    reps, names = _inventory(ids)
    groups = {}

    def group_of(pid, lname):
        key = names.get((pid, lname))
        gid = key if key is not None else (pid, lname)
        g = groups.get(gid)
        if g is None:
            rep = reps.get(key) if key is not None else None
            g = groups[gid] = {'pid': pid, 'rep': rep, 'names': set(), 'n': dict.fromkeys(TIER_ORDER, 0), 'sev': dict.fromkeys(TIER_ORDER, 0),
                               'kev': 0, 'manual': 0, 'oldest': None}
        g['names'].add(lname)
        return g

    def add(rows):
        for pid, lname, tier, n, worst, oldest, kev, manual in rows:
            g = group_of(pid, lname)
            g['n'][tier] += n
            g['sev'][tier] = max(g['sev'][tier], worst)
            g['manual'] += manual
            if tier >= LIKELY:
                g['kev'] += kev
            if oldest is not None and (g['oldest'] is None or oldest < g['oldest']):
                g['oldest'] = oldest

    qs, manual = _matches(ids)
    add(_group_rows(qs, kev='cve_entry__kev', manual=manual))
    qs, manual = _vulns(ids)
    add(_group_rows(qs, manual=manual))
    add(_group_rows(_hygiene(ids)))
    add(_group_rows(_secrets(ids), distinct='finding_id'))
    by_key = defaultdict(set)
    for (pid, lname), key in names.items():
        by_key[key].add(lname)
    out = []
    for gid, g in groups.items():
        rep = g['rep']
        g['name'] = rep['name'] if rep else sorted(g['names'])[0]
        g['all'] = g['names'] | (by_key[gid] if rep else set())
        g['also'] = sorted(g['all'] - {g['name'].lower()})
        out.append(g)
    return out, len(reps)


def _finish(g):
    """Rank key, tier, counts and reason of one group."""
    n = g['n']
    top = next(t for t in TIER_ORDER if n[t]) if any(n.values()) else MINOR
    g['top'] = top
    g['internal'] = _is_internal(g['pid'], g['all'])
    worst = max((g['sev'][t] for t in TIER_ORDER if n[t] and (t >= EXPOSURE or top == MINOR)), default=0)
    g['key'] = (-top, -(1 if g['kev'] else 0), 1 if g['internal'] else 0, -worst, -(n[PROVEN] + n[LIKELY] + n[EXPOSURE]),
                g['oldest'].timestamp() if g['oldest'] else float('inf'), g['name'].lower(), g['pid'])
    g['reason'] = _reason(top, g['kev'], g['internal'], g['manual'])
    g['counts'] = {TIER_NAMES[t]: n[t] for t in TIER_ORDER}
    return g


# ----------------------------------------------------------------------------------------------------------------- items

def _wanted(groups):
    """Q-free description of the hosts whose items are read: ``{pid: sorted names}``."""
    out = defaultdict(set)
    for g in groups:
        out[g['pid']] |= g['names']
    return out


def _host_filter(wanted, pid='pid', lname='lname'):
    q = Q(pk__in=[])
    for p, names in wanted.items():
        q |= Q(**{pid: p, f'{lname}__in': sorted(names)})
    return q


def _windowed(qs, wanted, cap, extra_order=()):
    order = [F('tier').desc(), F('sev').desc(), F('heat').desc(), F('first').asc(nulls_last=True), *extra_order, F('pk').asc()]
    return (qs.filter(_host_filter(wanted)).annotate(rn=Window(RowNumber(), partition_by=[F('pid'), F('lname')], order_by=order)).filter(rn__lte=cap))


def _item(kind, pk, title, tier, sev, heat, first, what, **extra):
    return {'kind': kind, 'id': pk, 'title': clean(title, TITLE_MAX) or kind, 'tier': tier, 'severity_n': sev or 0, 'heat_n': heat or 0, 'first': first,
            'what': what, **extra}


def _read_items(groups, cap):
    """``{(pid, lname): [item]}`` for the hosts of ``groups``: at most ``cap`` of each host's items per source, read in one query per source."""
    from cveFeed.models import Triage
    wanted = _wanted(groups)
    items = defaultdict(list)
    qs, manual = _matches(list(wanted))
    rows = list(_windowed(qs, wanted, cap).values('pk', 'pid', 'lname', 'tier', 'sev', 'heat', 'first', 'cve_entry__cve_id', 'cve_entry__kev', 'matched_product',
                                                  'triage__heat_override', 'triage__id'))
    for r in rows:
        items[(r['pid'], r['lname'])].append(_item('match', r['pk'], r['cve_entry__cve_id'], r['tier'], r['sev'], r['heat'], r['first'], 'cve',
                                                   kev=bool(r['cve_entry__kev']), product=product(r['matched_product']), manual=bool(r['triage__heat_override']),
                                                   triage=r['triage__id']))
    qs, manual = _vulns(list(wanted))
    rows = list(_windowed(qs, wanted, cap).values('pk', 'pid', 'lname', 'tier', 'sev', 'heat', 'first', 'name', 'source', 'triage__heat_override', 'triage__id'))
    for r in rows:
        what = 'database' if r['source'] == SOURCE_DB else 'dns' if r['tier'] == EXPOSURE else 'finding'
        items[(r['pid'], r['lname'])].append(_item('vulnerability', r['pk'], r['name'], r['tier'], r['sev'], r['heat'], r['first'], what,
                                                   manual=bool(r['triage__heat_override']), triage=r['triage__id']))
    rows = list(_windowed(_hygiene(list(wanted)), wanted, cap).values('pk', 'pid', 'lname', 'tier', 'sev', 'first', 'title', 'check_name'))
    for r in rows:
        items[(r['pid'], r['lname'])].append(_item('hygiene', r['pk'], r['title'], r['tier'], r['sev'], 0, r['first'], 'admin' if r['tier'] == EXPOSURE else 'hygiene',
                                                   check=r['check_name']))
    qs = _secrets(list(wanted)).filter(_host_filter(wanted)).order_by('pid', 'lname', '-finding__severity', 'finding_id').values(
        'pid', 'lname', 'finding_id', 'finding__masked', 'finding__provider', 'finding__kind', 'sev', 'first').distinct()
    seen, per_host = set(), defaultdict(int)
    for r in qs:
        key = (r['pid'], r['lname'])
        if (key, r['finding_id']) in seen or per_host[key] >= cap:
            continue
        seen.add((key, r['finding_id']))
        per_host[key] += 1
        label = ' '.join(filter(None, [clean(r['finding__provider'], 40) or clean(r['finding__kind'], 40), 'secret', clean(r['finding__masked'], 40)]))
        items[key].append(_item('secret', r['finding_id'], label, EXPOSURE, r['sev'], 0, r['first'], 'secret'))
    # the proof of a proven item: the newest check that reproduced it
    proven = [i['triage'] for rows_ in items.values() for i in rows_ if i['tier'] == PROVEN and i.get('triage')]
    steps = dict(Triage.objects.filter(pk__in=proven).values_list('pk', 'validation_steps')) if proven else {}
    for rows_ in items.values():
        for i in rows_:
            i['proof'] = _proof(steps.get(i.get('triage'))) if i['tier'] == PROVEN else None
    for key, rows_ in items.items():
        rows_.sort(key=_item_key)
    return items


def _item_key(i):
    return (-i['tier'], -i['severity_n'], -i['heat_n'], i['first'].timestamp() if i['first'] else float('inf'), ('match', 'vulnerability', 'hygiene', 'secret').index(i['kind']), i['id'])


def _proof(steps):
    """The newest check that reproduced a finding (as ``static/cve/finding-glance-logic.js proofOf`` reads it): ``{check, at}``, or None."""
    hits = [s for s in (steps or []) if isinstance(s, dict) and s.get('result') == 'hit']
    if not hits:
        return None
    latest = max(hits, key=lambda s: str(s.get('ran_at') or ''))
    return {'check': clean(latest.get('label') or latest.get('kind') or 'a check', 60), 'at': clean(latest.get('ran_at'), 40) or None}


# ----------------------------------------------------------------------------------------------------------------- narrative

def _more(n):
    return f' and {n - 1} more' if n > 1 else ''


def _plural(n, one, many):
    return f'{n} {one if n == 1 else many}'


EXPOSURE_WORDS = {'database': 'an open database port', 'dns': 'a dangling DNS record', 'secret': 'a secret that anyone can read',
                  'admin': 'an open admin or cleartext service', 'finding': 'an exposed service'}
TOP = 5  # the items the words are built from: the same first five in a list row (12 items) and in the detail (200), so the text is the same in both


def _exposed_phrase(exposed, total):
    """'an open database port and a dangling DNS record (3 in all)': the kinds among the top items, in a fixed order, and how many there are in all."""
    kinds = [EXPOSURE_WORDS[what] for what in EXPOSURE_WORDS if any(i['what'] == what for i in exposed)]
    if not kinds:
        return ''
    text = ' and '.join([', '.join(kinds[:-1]), kinds[-1]] if len(kinds) > 2 else kinds)
    return f'{text} ({total} in all)' if total > len(kinds) else text


def _action(item):
    """The first thing to do, one imperative phrase, from the top item."""
    kind, what, title = item['kind'], item['what'], item['title']
    if kind == 'match':
        return f"Update {item['product']} (fixes {title})" if item.get('product') else f'Update the software behind {title}'
    if kind == 'secret':
        return 'Revoke the exposed secret and issue a new one'
    if what == 'database':
        return 'Close the open database port or require a login'
    if what == 'dns':
        return 'Remove the dangling DNS record or claim its target'
    if what == 'admin':
        return f'Close or restrict the open service: {title}'
    return f'Fix {title}'


def _headline(top, shown, n):
    if not shown:
        return _plural(sum(n.values()), 'item needs a person', 'items need a person')
    shown = shown[:TOP]
    first = shown[0]
    if top == PROVEN:
        return f"Proven: {first['title']}{_more(n[PROVEN])}"
    if top == LIKELY:
        return f"Likely real: {first['title']}{_more(n[LIKELY])}"
    if top == EXPOSURE:
        return f"Exposed: {_exposed_phrase([i for i in shown if i['tier'] == EXPOSURE], n[EXPOSURE]) or _plural(n[EXPOSURE], 'item', 'items')}"
    return _plural(n[MINOR], 'lower-priority item', 'lower-priority items')


def _what_it_is(g):
    rep = g['rep']
    scope = _scope_word(g['internal'])
    if rep is None:
        return f"{g['name']} is a name with open findings and no scanned host record."
    kind = 'web server' if rep['http'] else 'host'
    server = product(rep['server'])
    return f"{g['name']} is an {scope} {kind}{f' running {server}' if server else ''}."


def narrative(g, items):
    """Two to four plain sentences from a group's numbers and its top items: what the host is, what is proven or likely, what is exposed, what to do first."""
    n, top = g['n'], g['top']
    items = items[:TOP]
    parts = [_what_it_is(g)]
    proven = [i for i in items if i['tier'] == PROVEN]
    likely = [i for i in items if i['tier'] == LIKELY]
    if top == PROVEN and proven:
        first = proven[0]
        how = f" ({first['proof']['check']}{', ' + first['proof']['at'][:10] if first['proof'].get('at') else ''})" if first.get('proof') else ''
        kev = ', and it is on the known-exploited list' if first.get('kev') else ''
        parts.append(f"A check reproduced {first['title']}{_more(n[PROVEN])} on it{how}{kev}.")
    elif top == LIKELY and likely:
        first = likely[0]
        kev = ' (on the known-exploited list)' if first.get('kev') else ''
        if n[LIKELY] == 1:
            parts.append(f"Nothing is proven yet, but 1 finding looks real: {first['title']}{kev}.")
        else:
            parts.append(f"Nothing is proven yet, but {n[LIKELY]} findings look real, the first being {first['title']}{kev}.")
    elif top == MINOR:
        parts.append(f"Only lower-priority items are open ({n[MINOR]}).")
    exposed = [i for i in items if i['tier'] == EXPOSURE]
    if n[EXPOSURE]:
        phrase = _exposed_phrase(exposed, n[EXPOSURE])
        also = 'also ' if top in (PROVEN, LIKELY) else ''
        parts.append(f"It {also}exposes {phrase}." if phrase else f"It also has {_plural(n[EXPOSURE], 'exposed item', 'exposed items')}.")
    parts.append(f"Do this first: {_action(items[0]) if items else 'look at the open findings'}.")
    return ' '.join(parts)


# ----------------------------------------------------------------------------------------------------------------- the result

def _link(slug, item):
    if item['kind'] == 'secret':
        return f"/cve/{slug}/secrets/?open={item['id']}"
    if item['kind'] == 'hygiene':
        return f"/cve/{slug}/hygiene/#hygiene-{item['id']}"
    return f"/cve/{slug}/vulns/#{item['kind']}-{item['id']}"


def _row(g, items, rank, slug, project_name, cap):
    from agentapi.services import SEVERITY_NAMES
    shown = items[:cap]
    rep = g['rep']
    return {
        'rank': rank, 'project': slug, 'project_name': project_name, 'host': g['name'], 'also_known_as': [n for n in g['also'] if n != g['name']],
        'host_id': rep['id'] if rep else None, 'host_link': f"/cve/{slug}/hosts/?host={quote(g['name'], safe='')}", 'internal': g['internal'],
        'headline': clean(_headline(g['top'], items, g['n']), 200), 'rank_reason': g['reason'], 'counts': g['counts'],
        'first_action': clean(_action(items[0]) if items else 'Look at the open findings', 200), 'narrative': narrative(g, items),
        'oldest': g['oldest'].isoformat() if g['oldest'] else None,
        'findings_total': sum(g['n'].values()), 'findings_truncated': sum(g['n'].values()) > len(shown),
        'findings': [{'kind': i['kind'], 'id': i['id'], 'title': i['title'], 'tier': TIER_NAMES[i['tier']], 'severity': SEVERITY_NAMES.get(i['severity_n'], str(i['severity_n'])),
                      'heat': HEAT_NAMES.get(i['heat_n'], ''), 'known_exploited': bool(i.get('kev')), 'set_by_you': bool(i.get('manual')),
                      'first_seen': i['first'].isoformat() if i['first'] else None, 'proof': i.get('proof'), 'link': _link(slug, i)} for i in shown],
    }


def _scope_info(ids):
    from dashboard.models import Project
    return {p['id']: (p['slug'], p['name']) for p in Project.objects.filter(id__in=ids).values('id', 'slug', 'name')}


def _last_scan(ids):
    from startScan.models import ScanHistory
    return ScanHistory.objects.filter(domain__project_id__in=ids, scan_status=2).aggregate(at=Max('start_scan_date'))['at']


SITUATIONS_SECONDS = 10  # how long one scope's ranking is shared (a finding closed or reopened drops it at once: the revision bump)


def _rank(ids):
    groups, hosts = _build_groups(list(ids))
    for g in groups:
        _finish(g)
    groups.sort(key=lambda g: g['key'])
    return groups, hosts


def ranked(ids):
    """Every situation of the projects in rank order, without items: ``(groups, hosts)``. Ranking every host is the dear part (the host collapse, four
    grouped queries over all findings, a sort), and the list, the detail of a host and the REST and MCP calls all need all of it, so it is a shared snapshot
    (``cveFeed.snapshot_cache``: one request computes while the others read the last copy, a finding closed drops it) keyed by the project ids and the
    caller's allowed projects. Only the items of the hosts that are shown are read per request (``_read_items``)."""
    from cveFeed import snapshot_cache
    ids = sorted(ids)
    scope = snapshot_cache.scope_hash('situations', ids)
    return snapshot_cache.snapshot('situations', scope, lambda: _rank(ids), SITUATIONS_SECONDS, etag_of=lambda _ranking: '')['payload']


WORST_AT_LEAST = {'all': MINOR, 'exposure': EXPOSURE, 'likely': LIKELY, 'proven': PROVEN}  # the ``tier`` filter: keep a situation whose worst tier is at least this


def listing(ids, q='', page=1, size=50, tier='all'):
    """The list answer: ``{count, page, page_size, state, hosts, last_scan_at, situations, results}``. ``state`` is ``attention`` (something needs you,
    even when the search matches none of it), ``clear`` (hosts were scanned and nothing needs you) or ``unscanned`` (no host has been scanned)."""
    ids = list(ids)
    groups, hosts = ranked(ids)
    total = len(groups)
    wanted = q.strip().lower()
    floor = WORST_AT_LEAST[tier]
    hits = [(i + 1, g) for i, g in enumerate(groups) if g['top'] >= floor and (not wanted or any(wanted in n for n in g['all']))]
    state = 'attention' if total else ('clear' if hosts else 'unscanned')
    slice_ = hits[(page - 1) * size:page * size] if size else []
    out = {'count': len(hits), 'page': page, 'page_size': size, 'state': state, 'hosts': hosts, 'situations': total,
           'last_scan_at': None, 'results': []}
    if not total and hosts:
        last = _last_scan(ids)
        out['last_scan_at'] = last.isoformat() if last else None
    if slice_:
        info = _scope_info(ids)
        items = _read_items([g for _, g in slice_], LIST_ITEMS)
        for rank, g in slice_:
            out['results'].append(_row(g, _items_of(g, items), rank, *info.get(g['pid'], ('', '')), LIST_ITEMS))
    return out


def _items_of(g, items):
    merged = []
    for lname in g['names']:
        merged += items.get((g['pid'], lname), [])
    merged.sort(key=_item_key)
    return merged


def one(ids, host):
    """The situation of ``host`` (a name of it) with up to ``DETAIL_ITEMS`` items, or None when nothing needs a person there."""
    ids = list(ids)
    groups, _ = ranked(ids)
    wanted = str(host or '').strip().lower()
    for rank, g in enumerate(groups, 1):
        if wanted in g['all']:
            items = _read_items([g], DETAIL_ITEMS)
            info = _scope_info(ids)
            return _row(g, _items_of(g, items), rank, *info.get(g['pid'], ('', '')), DETAIL_ITEMS)
    return None
