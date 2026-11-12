"""The CVE catalog: search the whole CVE catalog (CVEEntry) by id, part of an id, or a technology, and say how many of the caller's own
hosts each CVE matches.

The catalog is shared by everyone; the host counts and the matching hosts come from CVEMatch, whose default manager is scoped to the
projects the caller may see (tenancy.scope), so nothing here filters by project itself.

A query that looks like a CVE id ("CVE-2024-6387", "2024-6387", "cve-2024", a bare number of 4+ digits) matches ``cve_id``. Anything else
matches the vendor, product and package names of ``affected`` and then the title, case-insensitive substring, so "ssh" finds OpenSSH and
"php" finds PHP. Ranked: the exact id, then ids ending in the fragment, then product hits, then title hits, newest first within each.
Migration 0147 adds trigram indexes over exactly the expressions below so a substring search stays fast on a large catalog.
"""
import re

from django.db.models import BooleanField, Case, Count, F, IntegerField, Q, Value, When
from django.db.models.expressions import RawSQL

from cveFeed.models import CVEEntry, CVEMatch
from cveFeed.threat import classify_threat_tier

PAGE_SIZE = 50
MAX_QUERY = 120
MAX_HOSTS = 200  # matching hosts listed in the detail panel; the row's count is still the full number
SEVERITIES = ('critical', 'high', 'medium', 'low')
_TABLE = '"cveFeed_cveentry"'

# The vendor, product and package names of every affected entry, as one upper-cased JSON text (never the version ranges). The trigram
# index of migration 0147 is built on this exact text: change one and you must change the other (tests/test_cve_explorer.py checks).
PRODUCTS_SQL = ("upper((jsonb_path_query_array(affected, '$[*].vendor') || jsonb_path_query_array(affected, '$[*].product')"
                " || jsonb_path_query_array(affected, '$[*].package'))::text)")
TITLE_SQL = 'upper(title)'

_ID_SHAPES = (
    re.compile(r'^CVE-?\d{0,4}(-\d*)?$'),  # cve, cve-, CVE-2024, CVE-2024-6387
    re.compile(r'^\d{4}-\d*$'),  # 2024-, 2024-6387
    re.compile(r'^\d{4,}$'),  # 6387, 63870 (a shorter number is too vague to be an id)
)
_FULL_ID = re.compile(r'^(?:CVE-)?(\d{4}-\d{4,})$')


def clean_query(raw):
    return ' '.join((raw or '').split())[:MAX_QUERY]


def looks_like_id(q):
    q = (q or '').strip().upper()
    return bool(q) and any(p.match(q) for p in _ID_SHAPES)


def severity_of(cvss):
    """The CVSS v3 band of a score, '' when there is none."""
    if cvss is None:
        return ''
    return 'critical' if cvss >= 9 else 'high' if cvss >= 7 else 'medium' if cvss >= 4 else 'low'


_SEVERITY_Q = {
    'critical': Q(cvss__gte=9),
    'high': Q(cvss__gte=7, cvss__lt=9),
    'medium': Q(cvss__gte=4, cvss__lt=7),
    'low': Q(cvss__lt=4),
}


def _like(q):
    """``%Q%`` for LIKE against an upper-cased column, with the caller's own % and _ taken literally."""
    return '%' + q.upper().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'


def search(q='', severity='', kev=False):
    """CVEEntry rows for the explorer, ranked and ordered (not yet paged). ``severity`` must be '' or one of SEVERITIES."""
    q = clean_query(q)
    qs = CVEEntry.objects.all()
    if severity:
        qs = qs.filter(_SEVERITY_Q[severity])
    if kev:
        qs = qs.filter(kev=True)
    if not q:
        return qs.annotate(rank=Value(0, output_field=IntegerField())).order_by(F('published_at').desc(nulls_last=True), '-pk')
    if looks_like_id(q):
        frag = q.upper()
        full = _FULL_ID.match(frag)
        exact = f'CVE-{full.group(1)}' if full else ''
        qs = qs.filter(cve_id__icontains=frag).annotate(rank=Case(
            When(cve_id__iexact=exact, then=Value(0)), When(cve_id__iendswith=frag, then=Value(1)),
            default=Value(2), output_field=IntegerField()))
    else:
        pattern = _like(q)
        product = RawSQL(f"{PRODUCTS_SQL} LIKE %s", (pattern,), output_field=BooleanField())
        title = RawSQL(f"{TITLE_SQL} LIKE %s", (pattern,), output_field=BooleanField())
        qs = qs.filter(Q(product) | Q(title)).annotate(rank=Case(
            When(Q(product), then=Value(3)), default=Value(4), output_field=IntegerField()))
    return qs.order_by('rank', F('published_at').desc(nulls_last=True), '-pk')


def host_counts(entry_ids):
    """``{cve pk: distinct hosts}`` over the matches the caller may see, leaving out a match the reviewer ruled out."""
    return dict(CVEMatch.objects.filter(cve_entry__in=entry_ids).exclude(ai_verdict='not_affected')
                .order_by().values_list('cve_entry').annotate(n=Count('subdomain', distinct=True)))


def _epss(entry):
    epss = (entry.intel or {}).get('epss') if isinstance(entry.intel, dict) else None
    return epss if isinstance(epss, dict) else {}


def row(entry, hosts=0):
    epss = _epss(entry)
    return {
        'cve_id': entry.cve_id,
        'title': (entry.title or entry.original_description or '')[:200],
        'cvss': entry.cvss,
        'severity': severity_of(entry.cvss),
        'tier': classify_threat_tier(kev=entry.kev, epss_reached=entry.epss_reached, exploit_db=entry.exploit_db, cvss=entry.cvss),
        'kev': bool(entry.kev),
        'epss': bool(entry.epss_reached),
        'epss_score': epss.get('score'),
        'exploit_db': bool(entry.exploit_db),
        'published_at': entry.published_at.isoformat() if entry.published_at else None,
        'hosts': hosts,
    }


def page(q='', severity='', kev=False, number=1):
    qs = search(q, severity, kev)
    count = qs.count()
    start = (number - 1) * PAGE_SIZE
    entries = list(qs[start:start + PAGE_SIZE]) if start < count else []
    counts = host_counts([e.pk for e in entries]) if entries else {}
    return {'query': clean_query(q), 'severity': severity, 'kev': kev, 'page': number, 'page_size': PAGE_SIZE, 'count': count,
            'has_next': start + PAGE_SIZE < count, 'items': [row(e, counts.get(e.pk, 0)) for e in entries]}


def _affected(entry):
    out = []
    for a in entry.affected if isinstance(entry.affected, list) else []:
        if not isinstance(a, dict):
            continue
        ranges = [{k: str(r[k]) for k in ('introduced', 'fixed', 'lastAffected') if r.get(k)}
                  for r in (a.get('ranges') or []) if isinstance(r, dict)]
        out.append({'vendor': str(a.get('vendor') or ''), 'product': str(a.get('product') or ''), 'package': str(a.get('package') or ''),
                    'ranges': [r for r in ranges if r]})
    return out


def _references(entry):
    """``[{url, type}]``: the feed stores a bare URL or ``{url, type}``. Only http(s) links leave, so a page can link them as they are."""
    out = []
    for ref in entry.references if isinstance(entry.references, list) else []:
        url, kind = (ref, '') if isinstance(ref, str) else (ref.get('url'), ref.get('type') or '') if isinstance(ref, dict) else ('', '')
        if isinstance(url, str) and re.match(r'^https?://', url, re.I):
            out.append({'url': url, 'type': str(kind)})
    return out


def detail(cve_id):
    """Everything the detail panel shows, or None for an id the catalog does not have."""
    from cveFeed.threat import match_heat
    entry = CVEEntry.objects.filter(cve_id__iexact=(cve_id or '').strip()).first()
    if entry is None:
        return None
    matches = (CVEMatch.objects.filter(cve_entry=entry).exclude(ai_verdict='not_affected')
               .select_related('cve_entry', 'triage', 'subdomain__target_domain__project').order_by('subdomain__name', 'pk'))
    hosts, seen = [], set()
    for m in matches:
        sub = m.subdomain
        project = sub.target_domain.project if sub.target_domain_id and sub.target_domain.project_id else None
        key = (project.pk if project else None, sub.pk)
        if key in seen:
            continue
        seen.add(key)
        if len(hosts) < MAX_HOSTS:
            hosts.append({'host': sub.name, 'project': project.slug if project else '', 'project_name': project.name if project else '',
                          'product': m.matched_product, 'version': m.matched_version, 'in_range': m.version_in_range,
                          'heat': match_heat(m), 'status': m.remediation_status, 'match_id': m.pk})
    epss = _epss(entry)
    return {**row(entry, len(seen)), 'title': entry.title or '', 'summary': entry.summary or '', 'description': entry.original_description or '',
            'cvss_vector': entry.cvss_vector or '', 'epss_percentile': epss.get('percentile'), 'status': entry.status or '',
            'affected': _affected(entry), 'references': _references(entry), 'host_count': len(seen), 'hosts': hosts}
