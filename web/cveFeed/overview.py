"""The Overview's summary: what the front page says above the live boxes, from data other modules already keep.

``summary(ids)`` is one dict for a list of project ids (one project, or every project a caller can see), cached for ``SUMMARY_SECONDS`` and served by
``GET /cve/api/overview`` (static/cve/overview.js draws it):

- ``status``: a pill (Needs you now, Watch, All clear), one headline sentence and one short paragraph under it. Both are **templates filled from counts**,
  never written by a model: the number of hosts with a proven finding, with likely findings and with high-hygiene items (``situations``), the top threat of the week
  that reaches a host (``report_threats``) and how many hosts were exposed a week ago and now (``stats_history`` snapshots, the live count for today);
- ``kpis``: four tiles (externally facing hosts, needs attention, critical findings open, mean time to fix) with a 7-day change and a 14-day series. Externally
  facing hosts and needs attention are live when the caller passes them (``live``; ``build`` always passes the needs figure, the hosts of the ranking that need a
  person soon, the email report's own number); the others are the daily snapshots' (``StatsSnapshot``: counting them live is the walk over every finding that
  once overloaded the server), each saying which day it is as of;
- ``threats``: this week's digest, grouped by product, with the hosts counted over the whole group (the same hosts in four CVEs are four hosts, not sixteen), and
  for each count a link to the Hosts page that lists exactly the hosts it counts (``host_links``: their names, never a looser search unless they are too many);
- ``fix_first``: the first situations of the ranking (``situations.listing``, at most ``FIX_FIRST_SITUATIONS`` read), the ones in one project that share a first action
  folded into one row;
- ``what_changed``: the week's changes of the inventory (new exposure, personal data on pages, certificates, hosts found and retired);
- ``sentinels``: one line about the live Sentinels and their scan slots, only for an App Admin (the numbers are instance-wide), kept apart from the shared entry;
- ``updated_at``.

Everything filters by the ids it is given, and the cache key is a hash of them and of the caller's allowed projects (``snapshot_cache.scope_hash``), so two callers who see
different projects never read each other's entry. Nothing here reads the AI activity log (the box on the page loads its own) and nothing walks the hosts: the
situations ranking is shared with the Situations page (one snapshot), the threat impact is counted once for ``THREATS_SECONDS`` and the rest is a few grouped queries.
Text that came from a scan or a third-party feed is cleaned here and drawn with ``textContent`` by the page.
"""
import logging
import re
from datetime import date, timedelta
from types import SimpleNamespace
from urllib.parse import quote, urlencode

from django.utils import timezone
from tenancy.roles import ALL_PROJECTS

from cveFeed import report_threats, situations, snapshot_cache
from cveFeed.report_data import clean

logger = logging.getLogger(__name__)

WINDOW_DAYS = 7  # every "this week": the digest, the changes and the comparison of the tiles
SPARK_DAYS = 14
FIX_FIRST_SITUATIONS = 30  # situations read to build the rows (the first page of the ranking, never more)
FIX_FIRST_ROWS = 8
THREAT_LIMIT = 24  # digest entries read; they are grouped by product below
SUMMARY_SECONDS = 60
THREATS_SECONDS = 600  # the digest and its host counts move slowly: they are built less often than the rest
SENTINEL_SECONDS = 30
STALE_SCAN_DAYS = 7  # no finished scan for this long is said in words
NAMES_SHOWN = 3  # host names listed in a folded row
FOLDED_TITLE = 70
LINK_NAMES = 200  # the most hosts one exact link names (the Hosts page's ``names`` takes as many: agentapi.services.MAX_HOST_NAMES)
LINK_CHARS = 3500  # the longest link: the page's request line, and its search's, must stay under the 4 KB a gunicorn worker reads (limit_request_line)
LINK_LABEL = 120
LINK_CVES = 12  # a fallback search names the group's CVEs when there are at most this many (a search term holds 200 characters)
_BUCKETS = (('matched', 'version match'), ('product_only', 'version unknown'))
_LINKABLE = re.compile(r'^[^\s,/]+$')  # a name a ``names`` list can carry as it is (comma separates the names, slash a project from its name)

_WORDS = ('zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten')
_FIXES = re.compile(r'\s*\(fixes [^)]*\)\s*$')
_PLURAL_ACTION = {'Renew the certificate': 'Renew the certificates', 'Renew the certificate before it expires': 'Renew the certificates before they expire',
                  'Revoke the exposed secret and issue a new one': 'Revoke the exposed secrets and issue new ones'}
_SENTENCE_END = re.compile(r'(?<=[.!?])\s+')


# ------------------------------------------------------------------------------------------------------------------------ words

def word(n, capital=False):
    """A count in a sentence: spelled out up to ten, in digits above."""
    text = _WORDS[n] if isinstance(n, int) and 0 <= n <= 10 else f'{n:,}'
    return text.capitalize() if capital else text


def plural(n, one, many):
    return f'{n:,} {one if n == 1 else many}'


def day_text(day):
    return f'{day:%b} {day.day}'


def since_words(base, ref):
    """"last Saturday" when ``base`` is exactly a week before ``ref``, else the date ("Nov 15"): the sentence never claims a week it did not compare."""
    return f'last {base:%A}' if (ref - base).days == WINDOW_DAYS else day_text(base)


def _first_sentence(text):
    return _SENTENCE_END.split(clean(text, 600))[0].strip()


def _list_words(names):
    names = list(names)
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


# ------------------------------------------------------------------------------------------------------------------------ the tiles

def _snapshot_days(ids, today):
    """``{date: {...}}`` summed over the projects, from the daily snapshots of the last three weeks (one query)."""
    from cveFeed.models import StatsSnapshot
    first = today - timedelta(days=SPARK_DAYS + WINDOW_DAYS)
    ids = list(ids)
    rows = StatsSnapshot._base_manager.filter(project_id__in=ids, date__gte=first).values_list(
        'date', 'project_id', 'hosts', 'exposed_hosts', 'open_findings', 'cve_matches', 'fixed', 'mean_days_to_fix', 'needs_hosts')
    days, needs_of = {}, {}
    for date, pid, hosts, exposed, open_findings, matches, fixed, mean, needs in rows:
        d = days.setdefault(date, {'hosts': 0, 'exposed': 0, 'critical': 0, 'high': 0, 'fire': 0, 'smoke': 0, 'fixed': 0, 'weighted': 0.0})
        if needs is not None:
            needs_of.setdefault(date, {})[pid] = needs
        open_findings, matches = open_findings or {}, matches or {}
        d['hosts'] += hosts or 0
        d['exposed'] += exposed or 0
        d['critical'] += int(open_findings.get('critical') or 0)
        d['high'] += int(open_findings.get('high') or 0)
        d['fire'] += int(matches.get('fire') or 0)
        d['smoke'] += int(matches.get('smoke') or 0)
        if mean is not None and fixed:
            d['fixed'] += fixed
            d['weighted'] += mean * fixed
    for day, d in days.items():
        # the hosts that need attention, only for a day every project of the scope has the figure: a partial sum would compare unlike things (as the email does)
        have = needs_of.get(day, {})
        d['needs'] = sum(have.values()) if ids and len(have) == len(set(ids)) else None
        d['mttf'] = round(d['weighted'] / d['fixed'], 2) if d['fixed'] else None
    return days


def _metric(days, key):
    """``{date: value}`` of one figure over the snapshot days that have it."""
    return {d: v[key] for d, v in days.items() if v[key] is not None}


def _series(m, ref):
    """The values over the ``SPARK_DAYS`` days ending ``ref``, the days that have a figure only, oldest first."""
    return [m[d] for d in sorted(m) if ref - timedelta(days=SPARK_DAYS - 1) <= d <= ref]


def _baseline(m, ref, young=True):
    """``(date, value)`` of the day to compare with: the newest figure at or before a week before ``ref``, else the oldest one there is (a young install compares with
    its first day; not with ``young=False``, the email report's rule: no figure a week back is no comparison), ``(None, None)`` when there is nothing before ``ref``."""
    want = ref - timedelta(days=WINDOW_DAYS)
    before = [d for d in m if d <= want]
    if before:
        d = max(before)
        return d, m[d]
    if not young:
        return None, None
    older = [d for d in m if d < ref]
    if older:
        d = min(older)
        return d, m[d]
    return None, None


def _delta_text(delta, digits=0):
    if not delta:
        return 'no change'
    shown = f'{abs(delta):.{digits}f}' if digits else f'{abs(int(delta)):,}'
    return f"{'▲' if delta > 0 else '▼'} {shown}"


def _tile(key, label, m, ref, note, unit='', digits=0, compare=False, young=True):
    """One tile from the figure's ``{date: value}`` map and the day it is read at (``ref``, None when there is no figure). ``compare``: the foot says "slower than"
    rather than "since" (a mean time to fix has no count to be "since"). ``young``: see ``_baseline``."""
    value = m[ref] if ref else None
    base_day, base = _baseline(m, ref, young) if ref else (None, None)
    delta = None if value is None or base is None else round(value - base, 1 if digits else 0)
    if delta is not None and not digits:
        delta = int(delta)
    tone = '' if delta is None else 'flat' if delta == 0 else 'worse' if delta > 0 else 'better'  # more exposure, more findings and a slower fix are all worse
    if delta is None:
        foot = note
    elif compare:
        foot = f"{'slower than' if delta > 0 else 'faster than' if delta < 0 else 'same as'} {day_text(base_day)}" + (f' · {note}' if note else '')
    else:
        foot = f'since {since_words(base_day, ref)}' + (f' · {note}' if note else '')
    return {'key': key, 'label': label, 'value': value, 'value_text': '–' if value is None else (f'{value:.1f}' if digits else f'{int(value):,}'), 'unit': unit,
            'delta': delta, 'delta_text': '' if delta is None else _delta_text(delta, digits), 'tone': tone, 'foot': foot, 'series': _series(m, ref) if ref else [],
            'since': base_day.isoformat() if base_day else None, 'as_of': ref.isoformat() if ref else None}


def kpis(ids, live=None, now=None):
    """The four tiles (see the module text). ``live``: ``{'hosts', 'exposed_hosts', 'needs'}`` of today: the exposed tile reads the first two and the needs tile the
    last as today's figure, the series included (``needs`` is ``host_counts(...)['needs']``, the number the email report's "Needs attention" says)."""
    now = now or timezone.now()
    today = timezone.localdate(now)
    days = _snapshot_days(ids, today)
    live = live or {}
    exposed, hosts = _metric(days, 'exposed'), _metric(days, 'hosts')
    if live.get('exposed_hosts') is not None:
        exposed[today] = live['exposed_hosts']
        if live.get('hosts') is not None:
            hosts[today] = live['hosts']
    ref = max(exposed, default=None)
    tiles = [_tile('exposed', 'Externally facing hosts', exposed, ref, f'of {hosts[ref]:,} hosts' if ref in hosts and hosts[ref] else '')]
    needs = _metric(days, 'needs')
    if live.get('needs') is not None:
        needs[today] = live['needs']
    ref = max(needs, default=None)
    tiles.append(_tile('needs', 'Needs attention', needs, ref, f"host{'' if needs[ref] == 1 else 's'} to look at" if ref else 'hosts to look at',
                       young=False))  # compared only with a day a week back, as the email compares with the week's start: the two never say different changes
    critical = _metric(days, 'critical')
    ref = max(critical, default=None)
    tiles.append(_tile('critical', 'Critical findings open', critical, ref, f"{days[ref]['high']:,} high" if ref else ''))
    mttf = _metric(days, 'mttf')
    ref = max(mttf, default=None)
    tiles.append(_tile('mttf', 'Mean time to fix', mttf, ref, '' if ref else 'nothing marked fixed yet', unit='days', digits=1, compare=True))
    return tiles


# ------------------------------------------------------------------------------------------------------------------------ the status

def threat_sentence(group):
    """"Four new critical PHP flaws this week match 3 of your hosts by version.", or '' when the group reaches no host by version. Counts and the product name only."""
    if not group or not group['matched']:
        return ''
    n, m, product = group['items'], group['matched'], group['product']
    adjective = 'known-exploited' if group['all_kev'] else 'critical' if group['all_critical'] else ''
    noun = ' '.join(x for x in (adjective, product, 'flaw' if n == 1 else 'flaws') if x)
    verb = 'matches' if n == 1 else 'match'
    return f"{word(n, True)} new {noun} this week {verb} {m:,} of your hosts by version." if product or adjective else \
        f"{word(n, True)} new {'threat' if n == 1 else 'threats'} this week {'reaches' if n == 1 else 'reach'} {m:,} of your hosts by version."


def exposure_sentence(tile):
    """"Externally facing hosts went from 26 to 55 since last Saturday.", or '' when there is nothing to compare or nothing moved."""
    if not tile or tile['delta'] in (None, 0) or tile['since'] is None:
        return ''
    base_day = date.fromisoformat(tile['since'])
    ref = date.fromisoformat(tile['as_of']) if tile.get('as_of') else timezone.localdate()
    was = tile['value'] - tile['delta']
    return f"Externally facing hosts went from {was:,} to {tile['value']:,} since {since_words(base_day, ref)}."


def host_counts(groups):
    """Hosts of the ranking by what leads them, counted once each: ``proven``, ``likely`` (findings that look real, none proven), ``hygiene`` (high hygiene only),
    ``exposure`` and ``minor``. ``needs`` is the first three: the hosts that need a person soon."""
    c = {'proven': 0, 'likely': 0, 'hygiene': 0, 'exposure': 0, 'minor': 0}
    for g in groups:
        n = g['n']
        if n[situations.PROVEN]:
            c['proven'] += 1
        elif n[situations.LIKELY]:
            c['likely'] += 1
        elif n[situations.HYGIENE]:
            c['hygiene'] += 1
        elif n[situations.EXPOSURE]:
            c['exposure'] += 1
        elif n[situations.MINOR]:
            c['minor'] += 1
    c['needs'] = c['proven'] + c['likely'] + c['hygiene']
    return c


def needs_hosts(ids):
    """How many hosts of the projects need a person soon (proven, likely or high-priority hygiene): the Overview's own number, for a figure that is not recomputed twice."""
    return host_counts(situations.ranked(list(ids))[0])['needs']


def _hosts_have(n):
    return f"{n:,} host{'' if n == 1 else 's'} {'has' if n == 1 else 'have'}"


def status_block(hosts, counts, last_scan_at, now, threat_group=None, exposed_tile=None):
    """``{'tone', 'pill', 'headline', 'sub', 'state'}`` from numbers (see the module text): ``hosts`` is the inventory, ``counts`` is ``host_counts``, ``last_scan_at`` when
    the newest scan finished (or None). Same numbers, same words."""
    p, l, h = counts['proven'], counts['likely'], counts['hygiene']
    stale = bool(hosts) and (last_scan_at is None or now - last_scan_at > timedelta(days=STALE_SCAN_DAYS))
    if not hosts:
        return {'tone': 'smoke', 'pill': 'Not scanned yet', 'state': 'new', 'headline': 'Nothing has been scanned yet.',
                'sub': 'Add a target to start a first look; hosts appear here as they are found.'}
    sentences = []
    if p and l:
        headline = (f"{_hosts_have(p)} a confirmed vulnerability, and {l:,} more "
                    f"{'likely has one and needs' if l == 1 else 'likely have one and need'} review.")
    elif p:
        headline = f"{_hosts_have(p)} a confirmed vulnerability."
    elif l:
        headline = (f"{l:,} host likely has a vulnerability and needs review." if l == 1
                    else f"{l:,} hosts likely have vulnerabilities and need review.")
    elif h:
        headline = f"{_hosts_have(h)} a high-priority hygiene problem, such as an expired certificate."
    else:
        headline = 'Nothing needs you right now.'
    needs = counts['needs'] > 0
    if p or l:
        if h:
            sentences.append(f"{_hosts_have(h)} a high-priority hygiene problem as well.")
    elif not needs:
        if counts['exposure']:
            sentences.append(f"{_hosts_have(counts['exposure'])} a service open that should not be, but nothing is proven or likely.")
        elif counts['minor']:
            sentences.append(f"{_hosts_have(counts['minor'])} lower-priority items only.")
    threat = threat_sentence(threat_group)
    if threat:
        sentences.append(threat)
    exposure = exposure_sentence(exposed_tile)
    if exposure:
        sentences.append(exposure)
    if stale:
        finished = 'No scan of these hosts has finished yet' if last_scan_at is None else f'The last scan finished {day_text(timezone.localtime(last_scan_at))}'
        if needs:
            sentences.insert(0, f'{finished}, so this may be out of date.')
        else:
            headline = f'Nothing needs you right now, but nothing was scanned in the last {STALE_SCAN_DAYS} days.'
            sentences.insert(0, f'{finished}.')
    if needs:
        tone, pill, state = 'fire', 'Needs you now', 'attention'
    elif stale or counts['exposure'] or counts['minor']:
        tone, pill, state = 'smoke', 'Watch', 'stale' if stale else 'watch'
    else:
        tone, pill, state = 'ok', 'All clear', 'clear'
    return {'tone': tone, 'pill': pill, 'state': state, 'headline': headline, 'sub': ' '.join(sentences)}


# ------------------------------------------------------------------------------------------------------------------------ threats

def _product_key(entry):
    product = (entry.get('product') or '').strip().lower()
    return product or None


def _short_title(entry):
    """What the entry is, short: the CVE's own title without the id in front of it, cut at a word."""
    title = re.sub(r'^CVE-\d{4}-\d+:\s*', '', entry.get('title') or '')
    title = clean(title, 200)
    if len(title) > FOLDED_TITLE:
        title = title[:FOLDED_TITLE].rsplit(' ', 1)[0].rstrip(',;:') + '…'
    return title


def _item_line(entry):
    """"KEV Nov 20 · 0 hosts": what made it news and how many hosts it reaches."""
    n = entry['matched'] + entry['product_only']
    if entry.get('kev_added'):
        why = f"KEV {day_text(date.fromisoformat(entry['kev_added'][:10]))}"
    elif entry['source'] == 'zero_wire':
        why = 'Zero Wire'
    else:
        why = f"CVSS {entry['cvss']:g}" if entry.get('cvss') is not None else 'critical'
    return f"{why} · {plural(n, 'host', 'hosts')}"


def _project_of(key):
    return int(str(key).split(':', 1)[0])


def _project_breakdown(keys, names):
    """``[{'project', 'n'}]`` of host keys (their first part is the project id), biggest first. Each row also holds ``_pid`` until ``threat_groups`` is done
    (``host_links`` reads it to link the row; it is never sent)."""
    by = {}
    for key in keys:
        pid = _project_of(key)
        by[pid] = by.get(pid, 0) + 1
    return [{'project': names.get(pid, ''), 'n': n, '_pid': pid} for pid, n in sorted(by.items(), key=lambda kv: (-kv[1], names.get(kv[0], '')))]


def _entry_title(product, e):
    title = _short_title(e)
    if product and title and product.lower() not in title.lower():
        return f'{product}: {title}'
    return title or product or (e.get('cve_ids') or [''])[0]


def _group_title(product, entries):
    """The card's title, the same words on the Overview and in the email (both build their groups here). A count in it is a count of CVEs: "PHP: four critical
    flaws" only when each entry is one CVE, so the number equals the CVEs listed under it. A group holding a briefing (several CVEs, or none) is titled by its
    leading entry, the first that reaches a host by version, "plus N more advisories" for the rest, never a count of entries that reads as a count of flaws."""
    n = len(entries)
    if n == 1:
        return _entry_title(product, entries[0])
    if not all(len(e.get('cve_ids') or []) == 1 for e in entries) or len({c for e in entries for c in e['cve_ids']}) != n:
        lead = next((e for e in entries if e.get('matched') or e.get('confirmed')), entries[0])
        more = n - 1
        return f"{_entry_title(product, lead)}, plus {more:,} more advisor{'y' if more == 1 else 'ies'}"
    cvss = [e['cvss'] for e in entries if e.get('cvss') is not None]
    kev = sum(1 for e in entries if e.get('kev_added') or 'CISA KEV' in ' '.join(e.get('badges') or []))
    if cvss and all(c >= 9.0 for c in cvss) and len(cvss) == n:
        text = f"{word(n)} critical flaws"
    else:
        text = f"{word(n)} flaws" + (f', worst CVSS {max(cvss):g}' if cvss else '')
    if kev and not (cvss and all(c >= 9.0 for c in cvss)):
        text += f', {kev:,} known exploited'
    return f'{product}: {text}' if product else text.capitalize()


def _group(product_key, entries, names, many_projects):
    first = entries[0]
    product = (first.get('product') or '').replace('"', '')
    matched, confirmed, unknown = set(), set(), set()
    for e in entries:
        hosts = e.get('_hosts') or {}
        matched |= hosts.get('matched', set())
        confirmed |= hosts.get('confirmed', set())
        unknown |= hosts.get('product_only', set())
    unknown -= matched
    cve_ids = []
    for e in entries:
        for c in e.get('cve_ids') or []:
            if c not in cve_ids:
                cve_ids.append(c)
    cvss = [e['cvss'] for e in entries if e.get('cvss') is not None]
    badges = [{'text': f"{plural(len(cve_ids), 'CVE', 'CVEs')}" + (f' · CVSS {max(cvss):g}' if cvss else ''), 'kind': 'count'}]
    seen = set()
    for e in entries:
        for b in e.get('badges') or []:
            if b.startswith('CVSS') or b in seen or b == 'Cloudflare Zero Wire':
                continue
            seen.add(b)
            badges.append({'text': b, 'kind': 'kev' if 'KEV' in b else 'epss' if 'EPSS' in b else 'other'})
    if all(e.get('remote_no_login') for e in entries):
        badges.append({'text': 'Remote, no login', 'kind': 'remote'})
    if any(e['source'] == 'zero_wire' for e in entries):
        badges.append({'text': 'Cloudflare Zero Wire', 'kind': 'other'})
    summaries = []
    for e in entries:
        s = _first_sentence(e.get('summary') or '') if len(entries) > 1 else clean(e.get('summary') or '', 400)
        if s and s not in summaries:
            summaries.append(s)
    summary = clean(' '.join(summaries), 600)
    fixed = []
    for e in entries:
        for v in e.get('fixed_in') or []:
            if v not in fixed:
                fixed.append(v)
    fix = f"update {product} to {_or_list(fixed[:6])}." if fixed and product else ''
    zero = next((e for e in entries if e['source'] == 'zero_wire' and e.get('link')), None)
    named, seen_hosts = [], set()
    for e in entries:  # the hosts an entry was found on, when the caller asked for them (the email does; the Overview shows counts)
        for h in e.get('hosts') or []:
            if (h['host'], h['project']) not in seen_hosts:
                seen_hosts.add((h['host'], h['project']))
                named.append(h)
    hosts_query = f'cve:{cve_ids[0]}' if len(entries) == 1 and cve_ids and matched else f'tech:"{product}"' if product else (f'cve:{cve_ids[0]}' if cve_ids else '')
    return {
        'key': product_key or (cve_ids[0] if cve_ids else first['title'][:40]), 'product': product, 'title': _group_title(product, entries), 'summary': summary, 'fix': fix,
        'cve_ids': cve_ids[:12], 'badges': badges, 'items': len(entries), 'matched': len(matched), 'confirmed': len(confirmed), 'product_only': len(unknown),
        'hosts': named, 'fixed_in': fixed[:6], 'by_project': {'matched': _project_breakdown(matched, names), 'product_only': _project_breakdown(unknown, names)} if many_projects else None,
        'hosts_query': hosts_query, 'links': None, 'link': zero['link'] if zero else None, 'link_label': 'Read the Zero Wire briefing' if zero else '',
        'all_kev': all(e.get('kev_added') or 'CISA KEV' in ' '.join(e.get('badges') or []) for e in entries),
        'all_critical': bool(cvss) and len(cvss) == len(entries) and all(c >= 9.0 for c in cvss),
        'lines': [{'product': e.get('product') or '', 'title': _short_title(e), 'detail': _item_line(e)} for e in entries],
        '_keys': {'matched': matched, 'product_only': unknown, 'cve_ids': cve_ids},
    }


def _or_list(items):
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} or {items[-1]}"


def threat_groups(entries, names, many_projects, links=None):
    """``(groups, folded)`` from digest entries (with ``_hosts``): entries of one product are one group, a group that reaches a host first (most hosts first), then the
    rest in the digest's order; a group that reaches no host is folded into ``folded`` as one line per entry. ``links``: a function given the groups that reach a
    host while they still hold their host keys (``host_links``, which gives each its links to the Hosts page); without it ``links`` stays None."""
    order, by = [], {}
    for e in entries:
        key = _product_key(e) or f"entry:{e.get('title')}"
        if key not in by:
            by[key] = []
            order.append(key)
        by[key].append(e)
    groups = [_group(None if k.startswith('entry:') else k, by[k], names, many_projects) for k in order]
    live = [g for g in groups if g['matched'] or g['product_only']]
    live.sort(key=lambda g: (not g['matched'], -g['matched'], -g['product_only']))  # a stable sort: the digest's order breaks ties
    folded = [line for g in groups if not (g['matched'] or g['product_only']) for line in g['lines']]
    if links and live:
        links(live)
    for g in groups:  # the host keys and project ids are internal: never serialised
        g.pop('_keys', None)
        for row in [r for rows in (g['by_project'] or {}).values() for r in rows]:
            row.pop('_pid', None)
    return live, folded


def hosts_href(slug, **params):
    """A link to the Hosts page of ``slug`` with ``params`` (empty ones left out), every value percent-encoded: only letters, digits and ``-_.~%=&`` follow the ``?``,
    the characters the page's link check accepts (static/cve/overview-logic.js, ``hostsLinkHref``)."""
    return f"/cve/{slug}/hosts/?{urlencode({k: v for k, v in params.items() if v}, quote_via=quote, safe='')}"


def _by_project(keys):
    by = {}
    for key in keys:
        by.setdefault(_project_of(key), set()).add(key)
    return by


def bucket_link(keys, labels, slugs, label, fallback_q):
    """``{'href', 'n', 'exact'}``: the Hosts page listing exactly the hosts ``keys`` name, or None. ``labels`` (``report_threats.host_labels(..., raw=True)``) gives each
    key its stored name; ``slugs`` the slug of each project the viewer reads. One project's hosts are listed on that project's page by name
    (``?names=a.example,b.example``), hosts of several on the all-projects page by project and name (``?names=acme/a.example,widgets/b.example``), so a name two
    projects share is never two hosts. ``label`` is what the page shows as the filter's chip. A key of a project not in ``slugs`` gives no link at all. More hosts
    than LINK_NAMES, a link longer than LINK_CHARS, or a host whose name cannot be listed fall back to the search ``fallback_q`` (``exact`` False), and the chip
    says so; with no search either, None."""
    if not keys:
        return None
    pids = sorted({_project_of(k) for k in keys})
    if any(p not in slugs for p in pids):
        return None
    one = len(pids) == 1
    slug = slugs[pids[0]] if one else ALL_PROJECTS
    if len(keys) <= LINK_NAMES and all(k in labels and _LINKABLE.match(labels[k]['name']) for k in keys):
        listed = sorted({labels[k]['name'] if one else f"{slugs[_project_of(k)]}/{labels[k]['name']}" for k in keys})
        href = hosts_href(slug, names=','.join(listed), label=label)
        if len(href) <= LINK_CHARS:
            return {'href': href, 'n': len(keys), 'exact': True}
    if not fallback_q:
        return None
    broad = clean(f'{label} · {len(keys):,} hosts, too many to list one by one: a broader search', LINK_LABEL + 80)
    return {'href': hosts_href(slug, q=fallback_q, label=broad), 'n': len(keys), 'exact': False}


def _fallback_q(g, bucket):
    """The search a link falls back to when its hosts cannot be listed: the group's CVEs for the hosts that match by version, the product for the others."""
    cves = g['_keys']['cve_ids']
    if bucket == 'matched' and 0 < len(cves) <= LINK_CVES:
        return f"cve:{','.join(cves)}"
    if g['product']:
        return f'tech:"{g["product"]}"'
    return g['hosts_query']


def host_links(groups, ids, slugs, labels_of=None):
    """Give each group ``links``: ``{'matched': link | None, 'product_only': link | None}`` (``bucket_link``) for the hosts that match by version and the hosts that
    run the product with no version read, the very sets the card counts; and each row of ``by_project`` its ``slug`` and ``href`` (that project's hosts of the
    bucket). Only hosts of ``ids``, the projects the summary is built for, are ever named: the keys come from the digest of those ids, ``report_threats.host_labels``
    labels no key of another project, and a key of a project without a slug here gives no link. The names are read once for every group (two queries), and
    only for the parts small enough to be listed."""
    labels_of = labels_of or (lambda keys: report_threats.host_labels(ids, keys, raw=True))
    wanted = set()
    for g in groups:
        for bucket, _ in _BUCKETS:
            for part in _by_project(g['_keys'][bucket]).values():
                if len(part) <= LINK_NAMES:
                    wanted |= part
    labels = labels_of(wanted) if wanted else {}
    for g in groups:
        links = {}
        for bucket, words in _BUCKETS:
            keys = g['_keys'][bucket]
            label = clean(f"{g['title']}, {words}", LINK_LABEL)
            fallback = _fallback_q(g, bucket)
            links[bucket] = bucket_link(keys, labels, slugs, label, fallback)
            parts = _by_project(keys)
            for row in (g['by_project'] or {}).get(bucket) or []:
                pid = row.get('_pid')
                link = bucket_link(parts.get(pid, set()), labels, slugs, clean(f"{g['title']}, {words}, {row['project']}", LINK_LABEL), fallback)
                row['slug'], row['href'] = (slugs.get(pid, ''), link['href']) if link else ('', '')
        g['links'] = links


def _threats(ids, label, names, now, slugs=None):
    """The digest of the week, grouped (cached ``THREATS_SECONDS``, see the module text)."""
    start, end = now - timedelta(days=WINDOW_DAYS), now
    scope = SimpleNamespace(ids=list(ids), label=label)
    try:
        entries, note = report_threats.top(scope, start, end + timedelta(days=1), limit=THREAT_LIMIT, keep_hosts=True)  # the period ends at a day: today's KEV additions count
    except Exception:  # noqa: BLE001 - the section is a bonus: a failure in it never stops the page (as in the email)
        logger.warning('could not build the threats of the week', exc_info=True)
        return {'groups': [], 'folded': [], 'folded_note': '', 'period': f'{day_text(start.date())} – {day_text(end.date())}', 'note': '', 'empty': '', 'failed': True}

    def links(live):
        try:
            host_links(live, ids, slugs or {})
        except Exception:  # the cards still show their counts: a count without its link is drawn as plain text
            logger.warning('could not link the threats of the week to their hosts', exc_info=True)
    groups, folded = threat_groups(entries, names, len(ids) > 1, links=links)
    all_kev = bool(folded) and all('KEV' in f['detail'] for f in folded)
    return {'groups': groups, 'folded': folded, 'folded_note': 'all added to CISA KEV this week' if all_kev else '',
            'period': f'{day_text(start.date())} – {day_text(end.date())}', 'note': note,
            'empty': '' if (groups or folded) else 'No new KEV or critical CVEs this week.'}


def _cached_threats(ids, label, names, now, slugs=None):
    scope = snapshot_cache.scope_hash('overview-threats', list(ids))
    return snapshot_cache.snapshot('overview-threats', scope, lambda: _threats(ids, label, names, now, slugs), THREATS_SECONDS)['payload']


# ------------------------------------------------------------------------------------------------------------------------ fix first

def action_label(action):
    """The button's words: the first action without its "(fixes CVE-...)" tail."""
    return _FIXES.sub('', action or '').strip() or 'Open the host'


def _more(n):
    return f' and {n - 1:,} more' if n > 1 else ''


def row_reason(row):
    """One plain line for a situation row, from its numbers and its first finding (same data, same words)."""
    c, lead = row['counts'], row['lead']
    first = row['findings'][0] if row['findings'] else {}
    title = first.get('title') or ''
    scope = 'Internal' if row['internal'] else 'Internet-facing'
    kev = ' (known exploited)' if first.get('known_exploited') else ''
    if lead == 'proven':
        text = f"A check reproduced {title}{_more(c['proven'])}. {scope}."
        if c['likely']:
            text += f" {plural(c['likely'], 'more finding looks', 'more findings look')} real."
        return text
    if lead == 'likely':
        if c['likely'] == 1:
            return f"{title}{kev}. {scope}."
        return f"{c['likely']:,} findings look real, starting with {title}{kev}."
    if lead == 'hygiene':
        text = f"{title}{_more(c['hygiene'])}."
        if row['first_action'].startswith('Renew the certificate'):
            text += ' Browsers show a warning once it has expired.' if 'expired' in title.lower() else ''
        return text
    if lead == 'exposure':
        return f"{title}{_more(c['exposure'])}. {scope}."
    return 'Lower-priority items only.'


def fix_first_groups(rows, limit=FIX_FIRST_ROWS):
    """Rows of the ranking folded into at most ``limit`` lines: the hosts of one project that share a first action are one line (one rank, the first host's), the rest are one
    line each. ``rows`` are ``situations.listing`` results in rank order."""
    out, by_key = [], {}
    for r in rows:
        generic = r['first_action'] == 'Look at the open findings'
        key = None if generic else (r['project'], r['first_action'])
        if key is not None and key in by_key:
            by_key[key]['members'].append(r)
            continue
        if len(out) >= limit:
            continue
        g = {'members': [r]}
        out.append(g)
        if key is not None:
            by_key[key] = g
    return [_fix_row(g['members']) for g in out]


def _fix_row(members):
    first = members[0]
    n = len(members)
    action = first['first_action']
    label = action_label(action)
    chip = {'proven': 'Proven', 'likely': 'Likely real', 'hygiene': 'Hygiene · high', 'exposure': 'Exposed', 'minor': 'Lower priority'}[first['lead']]
    if n == 1:
        return {'rank': first['rank'], 'title': first['host'], 'hosts': [first['host']], 'n': 1, 'lead': first['lead'], 'chip': chip, 'project': first['project'],
                'project_name': first['project_name'], 'reason': row_reason(first), 'action': label, 'link': first['host_link'], 'internal': first['internal']}
    names = [m['host'] for m in members]
    shown = names[:NAMES_SHOWN]
    listed = _list_words(shown) if n <= NAMES_SHOWN else f"{', '.join(shown)} and {n - NAMES_SHOWN:,} more"
    same = 'The same update fixes' if action.startswith('Update') else 'The same step applies to'
    tail = f"{same} all {word(n)}." if n <= 10 else f'{same} all {n:,}.'
    return {'rank': first['rank'], 'title': f"{n:,} {first['project_name']} hosts".strip(), 'hosts': names, 'n': n, 'lead': first['lead'], 'chip': chip,
            'project': first['project'], 'project_name': first['project_name'], 'reason': f"{listed} all need the same fix: {action}. {tail}",
            'action': _PLURAL_ACTION.get(label, label), 'link': f"/cve/{first['project']}/situations/", 'internal': first['internal']}


def _fix_first(ids, groups, hosts, info=None):
    listing = situations.listing(ids, page=1, size=FIX_FIRST_SITUATIONS, info=info)
    counts = host_counts(groups)
    return {'state': listing['state'], 'hosts': hosts, 'total': listing['situations'], 'needs': counts['needs'],
            'rows': fix_first_groups(listing['results']), 'counts': counts}


# ------------------------------------------------------------------------------------------------------------------------ what changed

def _certs(ids, now):
    from django.db.models import Count, Q

    from cveFeed import counts
    from cveFeed.models import TlsCertificate
    base = TlsCertificate._base_manager.filter(domain__project_id__in=list(ids))
    due = counts.expiring_certificates(base)
    got = due.aggregate(total=Count('pk'), expired=Count('pk', filter=Q(not_after__lt=now)))  # the two counts in one read
    total, expired = got['total'], got['expired']
    nxt = base.filter(not_after__gte=now).order_by('not_after').values_list('host', 'not_after').first() if total else None
    if nxt:
        days = max(0, (nxt[1] - now).days)
        detail = f"next: {clean(nxt[0], 100)} " + ('expires today' if days == 0 else f"in {plural(days, 'day', 'days')}")
    elif total:
        detail = f'{expired:,} already expired'
    else:
        detail = 'none expired or due in 30 days'
    return total, detail


def what_changed(ids, kpi_list, now):
    """The four lines of "What changed" (see the module text): grouped counts over the project's change log and certificates, bounded by the week and the ids."""
    from django.db.models import CharField, Count, Q, Value
    from django.db.models.functions import Cast, Concat

    from cveFeed.models import AssetChange
    since = now - timedelta(days=WINDOW_DAYS)
    log = AssetChange._base_manager.filter(project_id__in=list(ids), detected_at__gte=since)
    exposed = next(k for k in kpi_list if k['key'] == 'exposed')
    if exposed['delta'] is None:
        line_exposed = {'key': 'exposed', 'value': '–', 'title': 'Hosts newly exposed', 'detail': 'no earlier count to compare with yet', 'tone': ''}
    else:
        d = exposed['delta']
        was = exposed['value'] - d
        when = since_words(date.fromisoformat(exposed['since']), date.fromisoformat(exposed['as_of'])) if exposed.get('as_of') else 'a week ago'
        title = 'Hosts newly exposed' if d > 0 else 'Fewer hosts exposed' if d < 0 else 'Hosts exposed'
        line_exposed = {'key': 'exposed', 'value': f'+{d:,}' if d > 0 else f'{d:,}' if d < 0 else '0', 'title': title,
                        'detail': f'{was:,} {when}, {exposed["value"]:,} now' if d else f'{exposed["value"]:,} now, the same as {when}',
                        'tone': 'worse' if d > 0 else 'better' if d < 0 else ''}
    sens = log.filter(kind='sensitive_found')
    # the three counts of the week's log in one read: a host found or retired is counted once per project and name, as ``values(...).distinct()`` did
    pair = Concat(Cast('project_id', CharField()), Value(' '), 'host', output_field=CharField())
    tally = log.aggregate(sens=Count('pk', filter=Q(kind='sensitive_found')), new=Count(pair, distinct=True, filter=Q(kind='host_new')),
                          gone=Count(pair, distinct=True, filter=Q(kind='host_retired')))
    sens_n = tally['sens']
    detail = 'none this week'
    if sens_n:
        types, example = [], ''
        for host, after in sens.order_by('-detected_at', '-id').values_list('host', 'after')[:25]:
            example = example or host
            for t in (after or {}).get('types') or []:
                t = clean(str(t).replace('_', ' '), 30)
                if t and t not in types and len(types) < 3:
                    types.append(t)
        detail = ', '.join(types) + (f' on {clean(example, 100)}' if example else '') if types else (f'on {clean(example, 100)}' if example else '')
    certs, cert_detail = _certs(ids, now)
    new, gone = tally['new'], tally['gone']
    new_host = log.filter(kind='host_new').order_by('-detected_at', '-id').values_list('host', flat=True).first() if new else None
    return {'since': since.isoformat(), 'lines': [
        line_exposed,
        {'key': 'sensitive', 'value': f'{sens_n:,}', 'title': 'Pages showing personal data' if sens_n != 1 else 'Page showing personal data', 'detail': detail, 'tone': 'worse' if sens_n else ''},
        {'key': 'certs', 'value': f'{certs:,}', 'title': 'Certificates expired or due in 30 days' if certs != 1 else 'Certificate expired or due in 30 days', 'detail': cert_detail,
         'tone': 'worse' if certs else ''},
        {'key': 'hosts', 'value': f'{new:,} / {gone:,}', 'title': 'Hosts found / retired', 'detail': f'new: {clean(new_host, 100)}' if new_host else 'none found this week', 'tone': ''}]}


# ------------------------------------------------------------------------------------------------------------------------ Sentinels

def sentinel_line_text(live, slots, held):
    """"2 Sentinels live, all 4 scan slots busy": numbers only, no names."""
    if not live:
        return 'No Sentinel is live'
    who = f"{live:,} Sentinel{'' if live == 1 else 's'} live"
    if slots <= 0:
        return who
    if slots == 1:
        return f"{who}, its scan slot is {'busy' if held else 'free'}"
    if held >= slots:
        return f'{who}, all {slots:,} scan slots busy'
    if held == 0:
        return f'{who}, all {slots:,} scan slots free'
    return f'{who}, {held:,} of {slots:,} scan slots busy'


def sentinels(now=None):
    """``{'text', 'live', 'slots', 'held'}`` over the whole instance (an App Admin's: the Sentinels are not a project's), kept ``SENTINEL_SECONDS`` in the cache under a
    key of its own (never in the entry callers share). Failures say nothing rather than break the page."""
    def compute():
        from agentapi import sentinel_broker
        cap = sentinel_broker.planner_capacity((), now=now, queued=False)  # the line says what is live and busy, never the queue
        slots = sum(a['slots'] for a in cap['agents'])
        return {'text': sentinel_line_text(cap['live'], slots, cap['held_total']), 'live': cap['live'], 'slots': slots, 'held': cap['held_total']}
    try:
        return snapshot_cache.snapshot('overview-sentinels', 'instance', compute, SENTINEL_SECONDS)['payload']
    except Exception:  # noqa: BLE001 - a line of the page, never worth a failed poll
        return None


# ------------------------------------------------------------------------------------------------------------------------ the result

def build(ids, live=None, now=None, label=''):
    """The summary of ``ids`` worked out now, without the shared cache of ``summary`` (the digest keeps its own, see ``_cached_threats``)."""
    from dashboard.models import Project
    ids = sorted(set(ids))
    now = now or timezone.now()
    projects = list(Project._base_manager.filter(id__in=ids).values('id', 'name', 'slug'))
    names = {p['id']: p['name'] for p in projects}
    slugs = {p['id']: p['slug'] for p in projects}
    label = label or (names[ids[0]] if len(ids) == 1 and ids[0] in names else 'your projects')
    groups, hosts = situations.ranked(ids)
    counts = host_counts(groups)
    tiles = kpis(ids, {**(live or {}), 'needs': counts['needs']}, now)  # the needs tile is the ranking's own count, live: the email's "Needs attention"
    threats = _cached_threats(ids, label, names, now, slugs)
    status = status_block(hosts, counts, situations.last_scan(ids) if hosts else None, now, next((g for g in threats['groups'] if g['matched']), None),
                          next(k for k in tiles if k['key'] == 'exposed'))
    return {'status': status, 'kpis': tiles, 'threats': threats, 'fix_first': _fix_first(ids, groups, hosts, {p['id']: (p['slug'], p['name']) for p in projects}), 'what_changed': what_changed(ids, tiles, now),
            'updated_at': now.isoformat(), 'projects': len(ids)}


def summary(ids, live=None, sentinels_too=False, now=None, label=''):
    """``build`` shared for ``SUMMARY_SECONDS`` by every viewer of the same projects (see the module text). ``sentinels_too``: add the Sentinel line (an App Admin only)."""
    ids = sorted(set(ids))
    if not ids:
        return {'status': {'tone': 'smoke', 'pill': 'Not scanned yet', 'state': 'new', 'headline': 'Nothing has been scanned yet.',
                           'sub': 'Add a target to start a first look; hosts appear here as they are found.'}, 'kpis': [], 'threats': {'groups': [], 'folded': [], 'folded_note': '', 'period': '', 'note': '',
                'empty': 'No new KEV or critical CVEs this week.'}, 'fix_first': {'state': 'unscanned', 'hosts': 0, 'total': 0, 'needs': 0, 'rows': [], 'counts': {}},
                'what_changed': {'since': None, 'lines': []}, 'updated_at': timezone.now().isoformat(), 'projects': 0, 'sentinels': None}
    scope = snapshot_cache.scope_hash('overview', ids)  # the live figures are not part of the key: an entry is at most SUMMARY_SECONDS old whatever they were
    payload = dict(snapshot_cache.snapshot('overview', scope, lambda: build(ids, live, now, label), SUMMARY_SECONDS)['payload'])
    payload['sentinels'] = sentinels(now) if sentinels_too else None
    return payload
