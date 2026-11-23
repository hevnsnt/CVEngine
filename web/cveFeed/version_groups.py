"""Many CVEs, one fix: the CVE matches that rest on one product and version reading of one site, shown as one group.

nginx 1.31.1 read from the Server header of ``example.org`` and ``www.example.org`` (two names of one site) matches every advisory whose
range holds 1.31.1: dozens of CVE matches per name, settled by one upgrade. This module groups them for reading only. Nothing is stored,
merged or changed: every match keeps its own row, Triage, heat, remediation status, assignee and audit trail, and an action on a group is
the same action on each member through the ordinary per-finding route (``static/cve/finding-groups-logic.js``).

The rule (``group_key``):

* the key is (project, product, version, site). The product is the one ``cveFeed.match_explain`` and ``cveFeed.detection`` already know a
  name by (``NGINX Open Source`` and ``nginx`` are nginx, ``jQuery`` and ``jquery`` are jQuery), else the name's letters and digits. The
  version is the matched version as stored;
* the site is what the caller says serves the same site (``site_of``): the list callers pass the Hosts page's own fold of names onto one
  host (``agentapi.services.host_of_names``: every copy of a name, and the names on exactly the same addresses, as the host's ``aliases``
  show them). Without it every host name is its own site;
* only a match that rests on the version alone is grouped. A match with hard evidence of its own (``match_policy.hard_evidence_q``: a
  template hit, the distribution tracker, the host's inventory report, runZero, a validation hit) stays its own row, as does one with no
  version or no host. A group therefore always rests on the version read, which its ``note`` says.

A group carries its product and version, the host names, how many CVEs and findings it holds, the worst heat and severity among its
members (a group's heat is the max of its members'; no member's heat changes), the triage mix, the fixed-in version and its members.

The fixed-in version (``fix_summary``) is read from the members' own data and never made up: ``version`` is the highest ``fixed`` bound
of the ranges the members were matched on (the range ``explain`` names); ``also`` lists, when the CVEs' affected ranges are given, the
highest fix of another release line that lies outside every bounded range of every member (a range with no upper bound, such as an old
line an advisory leaves unfixed, is not read as holding a fix of another line); ``unstated`` names the CVEs whose range states no fix,
and ``held_by`` the CVEs whose own data puts ``version`` inside another of their ranges.

Cost: the caller's one ``values()`` read of the matches (``rows_of``) and a pass in memory; the fix's other lines read the page's CVEs'
affected ranges in one query (``affected_of``).
"""
import hashlib
import re
from types import SimpleNamespace

GROUP_SCAN_MAX = 20000  # matches read to build the groups (the Findings list's cap, cveFeed.finding_groups.GROUP_SCAN_MAX)
MEMBERS_SHOWN = 200  # members listed in full on a group; ``member_ids`` always holds every one
SEVERITY_BY_BAND = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'}
SEVERITY_RANK = {name: band for band, name in SEVERITY_BY_BAND.items()}
TRIAGE_KEYS = ('needs_validation', 'likely', 'confirmed')  # the mix a group always states, other classifications counted as they come

BASE_FIELDS = ('id', 'cve_entry_id', 'cve_entry__cve_id', 'matched_product', 'matched_version', 'source', 'template_result', 'ai_verdict',
               'remediation_status', 'created_at', 'updated_at', 'subdomain_id', 'subdomain__name', 'subdomain__target_domain__project_id',
               'triage__classification', 'triage__validation_status', 'triage__first_seen', 'triage__last_seen', 'heat_rank', 'sev')


def _norm(value):
    return re.sub(r'[^a-z0-9]', '', str(value or '').lower())


def product_key(product):
    """``(key, label)``: the product a matched product name is, as the rest of cvENGINE knows it. A server ``match_explain`` knows
    (``NGINX Open Source`` -> ``nginx``), a JavaScript library ``cveFeed.detection`` knows (``jquery`` -> ``jQuery``), else the name's
    letters and digits with the name itself as the label. ``('', '')`` for an empty name."""
    from cveFeed import match_explain
    from cveFeed.detection import _libraries, library_key
    norm = _norm(product)
    if not norm:
        return '', ''
    known = match_explain._PRODUCT_KEYS.get(norm)
    if known:
        return known, match_explain._LABELS.get(known, known)
    lib = library_key(product)
    if lib:
        return f'lib:{lib}', _libraries()[lib][0]
    return norm, str(product).strip()[:80]


def rows_of(qs):
    """The one ``values()`` read the grouping needs of ``qs`` (CVE matches annotated with ``heat_rank`` and ``sev``, as the Findings list's
    sources are, ``with_list_annotations`` for a plain match queryset): the fields above, the range each match was made on
    (``evidence.range``, ``evidence.affected_index``) and whether it has hard evidence (``match_policy.hard_evidence_q``)."""
    from django.db.models import BooleanField, Case, Value, When
    from django.db.models.fields.json import KeyTransform

    from cveFeed.match_policy import hard_evidence_q
    return qs.annotate(own_range=KeyTransform('range', 'evidence'), affected_index=KeyTransform('affected_index', 'evidence'),
                       hard=Case(When(hard_evidence_q(), then=Value(True)), default=Value(False), output_field=BooleanField())) \
        .values(*BASE_FIELDS, 'own_range', 'affected_index', 'hard')


def with_list_annotations(qs):
    """``heat_rank`` (3 fire, 2 smoke, 1 ice: ``threat.match_heat_rank_expr``) and ``sev`` (the CVSS band, 4 critical .. 1 low, an unscored
    CVE low) on a plain CVE match queryset, exactly as the Findings list annotates its CVE source."""
    from django.db.models import Case, IntegerField, Value, When

    from cveFeed.threat import CRITICAL_CVSS, HIGH_CVSS, match_heat_rank_expr
    band = Case(When(cve_entry__cvss__gte=CRITICAL_CVSS, then=Value(4)), When(cve_entry__cvss__gte=HIGH_CVSS, then=Value(3)),
                When(cve_entry__cvss__gte=4.0, then=Value(2)), default=Value(1), output_field=IntegerField())
    return qs.annotate(heat_rank=match_heat_rank_expr(), sev=band)


def is_groupable(row):
    """A match that rests on its version alone, with a product, a version and a host: the only kind a group holds."""
    return (not row.get('hard') and bool(str(row.get('matched_version') or '').strip()) and bool(product_key(row.get('matched_product'))[0])
            and bool(str(row.get('subdomain__name') or '').strip()) and row.get('subdomain__target_domain__project_id') is not None)


def group_key(row, site_of=None):
    """The grouping key of a row, or None (the row stays its own). ``site_of(project id, host name)`` names the site the host serves (the
    Hosts page's host); by default the host name alone."""
    if not is_groupable(row):
        return None
    project, name = row['subdomain__target_domain__project_id'], row['subdomain__name']
    site = (site_of(project, name) if site_of else None) or ('n', name.lower())
    return (project, product_key(row['matched_product'])[0], str(row['matched_version']).strip(), site)


def key_id(key):
    """A short stable id of a key, for the page to tell groups apart (never parsed back)."""
    return 'v' + hashlib.sha1('\x1f'.join(str(part) for part in key).encode()).hexdigest()[:20]


def build(rows, site_of=None):
    """The list items of ``rows`` (dicts, in the caller's order: hottest first in the Findings list), each ``{'rep', 'members', 'key'}``: a
    group's first member is its representative (the row a click opens) and the group sits where that member would. A row that does not
    group is an item of its own (``key`` None)."""
    out, groups = [], {}
    for row in rows:
        key = group_key(row, site_of)
        if key is None:
            out.append({'rep': row, 'members': [row], 'key': None})
            continue
        group = groups.get(key)
        if group is None:
            group = groups[key] = {'rep': row, 'members': [row], 'key': key}
            out.append(group)
        else:
            group['members'].append(row)
    return out


def sort_key(item):
    """The order of a list of groups on its own (the grouped CVE match list): hottest, then most severe, then the most CVEs, then the
    most findings; ties by the smallest member id, so a page never reorders between two requests. Use with ``reverse=False``."""
    members = item['members']
    return (-max(m.get('heat_rank') or 0 for m in members), -max(m.get('sev') or 0 for m in members),
            -len({m.get('cve_entry_id') for m in members}), -len(members), min(m['id'] for m in members))


# --- the fix -----------------------------------------------------------------------------------------------------------------------------

def _parsed(version):
    from cveFeed.correlation import parse_version
    try:
        return parse_version(version, strict=True)
    except Exception:  # noqa: BLE001 - a bound a feed wrote badly is no bound, never a failed list
        return None


def _line(parsed):
    return tuple(parsed[:2]) if parsed is not None else None


def _bounded(ranges):
    """The ranges with an upper bound (``fixed`` or ``last_affected``), in the form ``correlation.range_verdict`` reads."""
    out = []
    for rng in ranges or ():
        upper = {k: v for k, v in (('fixed', rng.get('fixed')), ('lastAffected', rng.get('last_affected'))) if v}
        if upper:
            out.append({**({'introduced': rng['introduced']} if rng.get('introduced') else {}), **upper})
    return out


def _holds(version, ranges):
    """Whether a member's bounded ranges put ``version`` inside one of them (True), else False (outside, or unknown)."""
    from cveFeed.correlation import range_verdict
    parsed = _parsed(version)
    bounded = _bounded(ranges)
    if parsed is None or not bounded:
        return False
    try:
        return range_verdict(parsed, bounded)[0] is True
    except Exception:  # noqa: BLE001
        return False


def member_ranges(row, affected=None):
    """``(own, every)`` of one member as ``match_explain.explain`` reads them (``confirm_guide._ranges_of``): the range it was matched on and,
    when its CVE's ``affected`` list is given, every range the advisory gives for the matched product. ``every`` is ``[own]`` without it."""
    from cveFeed import confirm_guide
    evidence = {'range': row.get('own_range')} if isinstance(row.get('own_range'), dict) else {}
    if isinstance(row.get('affected_index'), int) and not isinstance(row.get('affected_index'), bool):
        evidence['affected_index'] = row['affected_index']
    match = SimpleNamespace(evidence=evidence, cve_entry=SimpleNamespace(affected=affected), matched_product=row.get('matched_product'),
                            matched_version=row.get('matched_version'))
    if affected is None:
        own = confirm_guide._range_of(match)
        return own, [own] if own else []
    try:
        return confirm_guide._ranges_of(match)
    except Exception:  # noqa: BLE001 - help on top of the record
        own = confirm_guide._range_of(match)
        return own, [own] if own else []


def fix_summary(members, affected_of=None):
    """``{version, also, stated, unstated, held_by}``: the fixed-in version of a group, from its members' data only (see the module text).
    ``affected_of`` maps a CVE entry id to its ``affected`` list; without it ``also`` and ``held_by`` stay empty. ``version`` is '' when
    no member's range states a fix."""
    per_cve = {}
    for m in members:
        cve = m.get('cve_entry_id')
        if cve in per_cve:
            continue
        affected = (affected_of or {}).get(cve) if affected_of is not None else None
        per_cve[cve] = (m.get('cve_entry__cve_id') or '', *member_ranges(m, affected))
    fixes = [(own.get('fixed'), _parsed(own.get('fixed'))) for _cve, own, _every in per_cve.values() if own.get('fixed')]
    fixes = [(text, parsed) for text, parsed in fixes if parsed is not None]
    unstated = sorted(cve for cve, own, _every in per_cve.values() if not (own.get('fixed') and _parsed(own.get('fixed')) is not None))
    out = {'version': '', 'also': [], 'stated': len(per_cve) - len(unstated), 'unstated': unstated[:50], 'held_by': []}
    if not fixes:
        return out
    version, top = max(fixes, key=lambda pair: pair[1])
    out['version'] = version
    if affected_of is None:
        return out
    everies = [every for _cve, _own, every in per_cve.values()]
    out['held_by'] = sorted(cve for cve, _own, every in per_cve.values() if _holds(version, every))[:50]
    # the other release lines: a fix every member's data leaves outside all its bounded ranges, the highest of each line
    candidates = {}
    for every in everies:
        for rng in every:
            parsed = _parsed(rng.get('fixed'))
            if parsed is None or _line(parsed) == _line(top):
                continue
            candidates.setdefault(_line(parsed), {})[rng['fixed']] = parsed
    for line in sorted(candidates, reverse=True):
        for text, parsed in sorted(candidates[line].items(), key=lambda pair: pair[1], reverse=True):
            if not any(_holds(text, every) for every in everies):
                out['also'].append(text)
                break
    return out


def affected_of(items):
    """``{cve entry id: affected}`` for the members of ``items`` (groups of the page only): one query."""
    from cveFeed.models import CVEEntry
    ids = {m.get('cve_entry_id') for item in items for m in item['members'] if m.get('cve_entry_id') is not None}
    return dict(CVEEntry.objects.filter(id__in=ids).values_list('id', 'affected')) if ids else {}


# --- what a group says --------------------------------------------------------------------------------------------------------------------

def _tally(values):
    out = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def _member_status(row):
    return 'ruled out' if row.get('ai_verdict') == 'not_affected' else row.get('remediation_status') or 'open'


def fix_text(fix):
    """The fix in words: ``upgrade to 1.31.9 or 1.30.7``, with what the data leaves open; '' when no member states a fix."""
    if not fix or not fix.get('version'):
        return ''
    text = 'upgrade to ' + ' or '.join([fix['version'], *fix.get('also', [])])
    if fix.get('unstated'):
        n = len(fix['unstated'])
        text += f" ({n} of the CVEs state{'s' if n == 1 else ''} no fixed version)"
    if fix.get('held_by'):
        text += f" (the advisory data of {', '.join(fix['held_by'][:3])} also lists {fix['version']} in another affected range: check it)"
    return text


def summary(group, affected=None, iso=None):
    """The ``group`` object of a list item: what the page and an agent read. ``affected``: ``affected_of`` of the page (the fix's other
    release lines need it)."""
    from cveFeed.finding_groups import registrable_domain
    from cveFeed.threat import HEAT_RANK
    iso = iso or (lambda value: value.isoformat() if value else None)
    heat_name = {rank: name for name, rank in HEAT_RANK.items()}
    members = group['members']
    rep = group['rep']
    names = sorted({m['subdomain__name'] for m in members}, key=str.lower)
    cves = sorted({m.get('cve_entry__cve_id') or '' for m in members} - {''})
    fix = fix_summary(members, affected)
    key, label = product_key(rep.get('matched_product'))
    version = str(rep.get('matched_version') or '').strip()
    classes = _tally(m.get('triage__classification') or '' for m in members)
    firsts = [v for v in (m.get('triage__first_seen') or m.get('created_at') for m in members) if v]
    lasts = [v for v in (m.get('triage__last_seen') or m.get('updated_at') for m in members) if v]
    worst_heat = max((m.get('heat_rank') or 0) for m in members)
    worst_sev = max((m.get('sev') or 0) for m in members)
    ordered = sorted(members, key=lambda m: (-(m.get('heat_rank') or 0), -(m.get('sev') or 0), m.get('cve_entry__cve_id') or '',
                                             str(m.get('subdomain__name') or '').lower(), m['id']))
    return {
        'id': key_id(group['key']),
        'by': 'product',
        'product': label,
        'product_key': key,
        'version': version,
        'host_names': names[:50],
        'hosts': len(names),
        'registrable_domain': registrable_domain(rep['subdomain__name']),  # where the Findings page's existing group code reads a site
        'cves': len(cves),
        'cve_ids': cves[:MEMBERS_SHOWN],
        'findings': len(members),
        'heat': heat_name.get(worst_heat, ''),
        'severity': SEVERITY_BY_BAND.get(worst_sev, ''),
        'triage': {**{k: classes.get(k, 0) for k in TRIAGE_KEYS}, 'other': sum(n for k, n in classes.items() if k not in TRIAGE_KEYS)},
        'fixed_in': fix,
        'fix_text': fix_text(fix),
        'version_only': True,  # hard evidence never groups (``is_groupable``)
        'note': f'These rest on the version read ({label} {version}), not on a check of each flaw: none of them is confirmed on the host.',
        'member_ids': [m['id'] for m in ordered],
        'member_status': {str(m['id']): m.get('remediation_status') or 'open' for m in members},
        'ruled_out_ids': [m['id'] for m in members if m.get('ai_verdict') == 'not_affected'],
        'members': [{'kind': 'match', 'id': m['id'], 'cve': m.get('cve_entry__cve_id') or '', 'host': m['subdomain__name'],
                     'heat': heat_name.get(m.get('heat_rank'), ''), 'severity': SEVERITY_BY_BAND.get(m.get('sev'), ''),
                     'status': _member_status(m), 'remediation_status': m.get('remediation_status') or 'open',
                     'classification': m.get('triage__classification') or '', 'validation_status': m.get('triage__validation_status') or 'none',
                     'fixed': member_ranges(m)[0].get('fixed', '')} for m in ordered[:MEMBERS_SHOWN]],
        'members_truncated': len(members) > MEMBERS_SHOWN,
        'heat_counts': _tally(heat_name.get(m.get('heat_rank'), '') for m in members),
        'status_counts': _tally(_member_status(m) for m in members),
        'classification_counts': classes,
        'validation_counts': _tally(m.get('triage__validation_status') or 'none' for m in members),
        'first_seen': iso(min(firsts)) if firsts else None,
        'last_seen': iso(max(lasts)) if lasts else None,
    }


def single(row, iso=None):
    """A match that stands alone in a grouped list of matches (``group_by=product``): the same fields as a group's member, plus its product
    and version, so a reader of the grouped list needs no second shape."""
    from cveFeed.threat import HEAT_RANK
    heat_name = {rank: name for name, rank in HEAT_RANK.items()}
    return {'kind': 'match', 'id': row['id'], 'cve': row.get('cve_entry__cve_id') or '', 'host': row.get('subdomain__name'),
            'product': row.get('matched_product') or '', 'version': row.get('matched_version') or '',
            'heat': heat_name.get(row.get('heat_rank'), ''), 'severity': SEVERITY_BY_BAND.get(row.get('sev'), ''),
            'status': _member_status(row), 'remediation_status': row.get('remediation_status') or 'open',
            'classification': row.get('triage__classification') or '', 'validation_status': row.get('triage__validation_status') or 'none',
            'version_only': not row.get('hard'), 'fixed': member_ranges(row)[0].get('fixed', '')}
