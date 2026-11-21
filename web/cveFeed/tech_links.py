"""A host's technology links: where each came from, and the one function that writes them.

``SubdomainTechnology`` (``startScan`` 0028) records, for each technology of a host, ``source`` (which reading linked it), ``cpe`` (the CPE that
reading named) and ``observed_at`` (when it was last read). Every pass that links a technology to a host writes through ``link`` here, with one of
the values of ``SOURCES``, so the API and search can say where a technology came from and correlation can tell a CPE a template stated from one
the server derived from a name:

* a CPE a source *stated* (a technology template's metadata, a panel template's) is written on the link even when the host already had the
  technology from elsewhere;
* a CPE the server *derived* from the name (``derived_cpe``: a template that names products by matcher, such as ``tech-detect``, states none) only
  fills a link that has no CPE or a derived one: it never replaces a stated CPE;
* a reading that names no CPE adds the link where it is missing and never clears a CPE; on a link that has one it records the time and, on a link
  stored before ``source`` existed, the source.

Every reading refreshes ``observed_at`` of the links it confirms. Links stored before ``source`` existed keep it empty until a source reads the
technology again (docs/UPGRADE.md); a link carried onto a later scan's row (``tech_carry``, ``discovery.seed_from_scan``, ``tech_rows``) keeps
the source, CPE and time it had.
"""
import functools
import logging

logger = logging.getLogger(__name__)

# The vocabulary of ``SubdomainTechnology.source``: stable values, each one pass of the pipeline. '' is a link stored before the column existed.
NUCLEI = 'nuclei'  # a nuclei technology template named it (``nuclei_scan.tech_name_from``); ``cpe``: the CPE the template's metadata states
NUCLEI_DERIVED = 'nuclei:derived'  # a template that names products by matcher (``tech-detect``, WAF, favicon) named it; ``cpe`` derived from the name
PANEL = 'vsrc:panel'  # a nuclei panel template named it without a version (``panel_versions``); ``cpe``: the template's
BBOT = 'bbot'  # discovery (bbot's technology events, ``reNgine.tasks``)
PROBE = 'probe'  # a version or identity probe, the virtual host sweep or the subdirectory applications (``probes``)
VERSION_SOURCE = 'vsrc'  # a version source of the catalogue read it (``version_sources``)
ROUTE = 'route'  # the web route check's front-page fingerprint (``route_auth``)
WAF = 'waf'  # the WAF fingerprint (``waf_fingerprint``)
WPSCAN = 'wpscan'  # the WordPress scan (``wpscan_scan``)

SOURCES = {
    NUCLEI: 'nuclei technology template',
    NUCLEI_DERIVED: 'nuclei name matcher (CPE derived from the name)',
    PANEL: 'nuclei panel template',
    BBOT: 'discovery (bbot)',
    PROBE: 'version and identity probes',
    VERSION_SOURCE: 'version source',
    ROUTE: 'web route check fingerprint',
    WAF: 'WAF fingerprint',
    WPSCAN: 'WordPress scan',
}
DERIVED = frozenset({NUCLEI_DERIVED})  # the sources whose CPE the server derived from a name: never outranks a stated one


def is_derived(source):
    """Whether a link of ``source`` carries a CPE the server derived from the technology's name rather than one a template or banner stated."""
    return source in DERIVED


def link(links, source, now=None):
    """Write host technology links ``{(subdomain id, technology id): cpe or ''}`` read by ``source`` (one of ``SOURCES``), at ``now``, by the rules of
    this module. Three statements whatever the size. Returns how many links were new."""
    from django.utils import timezone

    from startScan.models import SubdomainTechnology
    if source not in SOURCES:
        raise ValueError(f'unknown technology link source {source!r}')
    wanted = {(int(s), int(t)): (cpe or '')[:255] for (s, t), cpe in links.items() if s and t}
    if not wanted:
        return 0
    now = now or timezone.now()
    derived = is_derived(source)
    existing = {(r.subdomain_id, r.technology_id): r for r in SubdomainTechnology.objects.filter(
        subdomain_id__in={s for s, _t in wanted}, technology_id__in={t for _s, t in wanted}) if (r.subdomain_id, r.technology_id) in wanted}
    new, changed = [], []
    for (sub_id, tech_id), cpe in wanted.items():
        row = existing.get((sub_id, tech_id))
        if row is None:
            new.append(SubdomainTechnology(subdomain_id=sub_id, technology_id=tech_id, source=source, cpe=cpe, observed_at=now))
            continue
        if cpe and (not derived or not row.cpe or is_derived(row.source)):
            row.source, row.cpe = source, cpe  # a stated CPE wins; a derived one only fills a link without one or replaces a derived one
        elif not row.source:
            row.source = source  # stored before the column existed: the reading that confirms it now
        row.observed_at = now
        changed.append(row)
    if new:
        SubdomainTechnology.objects.bulk_create(new, ignore_conflicts=True)
    if changed:
        SubdomainTechnology.objects.bulk_update(changed, ['source', 'cpe', 'observed_at'], batch_size=500)
    return len(new)


def link_host(sub, techs, source, now=None):
    """Link the Technology rows ``techs`` (``{technology: cpe}``, or an iterable of them) to the host row ``sub`` (``link``), and drop the row's
    prefetched technologies so what reads it next sees them. Returns how many links were new."""
    pairs = techs if isinstance(techs, dict) else {t: '' for t in techs}
    added = link({(sub.pk, t.pk): cpe for t, cpe in pairs.items()}, source, now=now)
    forget(sub)
    return added


def forget(*subs):
    """Drop the prefetched technologies of host rows whose links were written past the related manager."""
    for sub in subs:
        cache = getattr(sub, '_prefetched_objects_cache', None)
        if cache:
            cache.pop('technologies', None)


# ----------------------------------------------------------------------------- a CPE derived from a name

def _cpe_prefix(text):
    """``(part, vendor, product)`` of a CPE 2.3 string, or None."""
    parts = (text or '').strip().lower().split(':')
    if len(parts) < 5 or parts[:2] != ['cpe', '2.3'] or parts[2] not in ('a', 'o', 'h') or not parts[3] or not parts[4] or '*' in parts[3:5]:
        return None
    return parts[2], parts[3], parts[4]


@functools.lru_cache(maxsize=4)
def _alias_cpes(path):
    """``{name token: {(part, vendor, product)}}`` from the product alias data (``data/product_aliases.json``, what correlation reads): the CPEs an
    entry's evidence cites, for each name the entry lists."""
    import json

    from cveFeed import correlation
    with open(path, encoding='utf-8') as fh:
        doc = json.load(fh)
    out = {}
    for entry in doc.get('aliases', ()):
        cpes = {c for c in (_cpe_prefix(e) for e in entry.get('evidence', ()) if isinstance(e, str)) if c}
        if not cpes:
            continue
        for name in entry.get('names', ()):
            out.setdefault(correlation._norm(name), set()).update(cpes)
    return out


_template_cpes = {}  # (id of the two maps) -> (the maps, kept so an id is never reused, {name token: Counter((part, vendor, product))})


def _template_index(tech, panels):
    """``{name token: Counter((part, vendor, product))}`` from the vendor and product the technology and panel templates' own metadata name
    (``nuclei_templates.template_products``), each under its product and under vendor and product together ("atlassian jira")."""
    from collections import Counter

    from cveFeed import correlation, nuclei_templates
    key = (id(tech), id(panels))
    if key not in _template_cpes:
        found = {}
        for products in (tech, panels):
            for meta in products.values():
                vendor, product = meta.get('vendor') or '', meta.get('product') or ''
                if not (nuclei_templates._CLEAN.match(vendor) and nuclei_templates._CLEAN.match(product)):
                    continue
                cpe = (meta.get('part') or 'a', vendor, product)
                tokens = {correlation._norm(f'{vendor} {product}')}
                alone = correlation._norm(product)
                # the product alone, unless it is a word too short or too generic to stand for one vendor's product ("amp" is Google's AMP
                # pages as much as CubeCoders' AMP), and not when the vendor is the product ("php")
                if alone == correlation._norm(vendor) or (len(alone) > correlation._MIN_TOKEN and alone not in correlation.GENERIC_WORDS
                                                          and alone not in correlation.GENERIC_PRODUCT_TOKENS):
                    tokens.add(alone)
                for token in tokens:
                    if len(token) >= correlation._MIN_TOKEN:
                        found.setdefault(token, Counter())[cpe] += 1
        _template_cpes.clear()
        _template_cpes[key] = (tech, panels, found)
    return _template_cpes[key][2]


def _one_vendor(cpes):
    """The CPE of ``cpes`` when they all name one product of one vendor (spellings of a vendor across renames are one: ``nginx`` and ``f5``), the
    most cited first; None when they name more than one."""
    from cveFeed import correlation
    groups = []
    for part, vendor, product in cpes:
        same = correlation.VENDOR_CLASSES.get(correlation._norm(vendor, True), frozenset()) | {correlation._norm(vendor, True)}
        group = next((g for g in groups if g['vendors'] & same and g['product'] == correlation._norm(product, True)), None)
        if group is None:
            groups.append({'vendors': set(same), 'product': correlation._norm(product, True), 'cpes': [(part, vendor, product)]})
        else:
            group['vendors'] |= same
            group['cpes'].append((part, vendor, product))
    return groups[0]['cpes'][0] if len(groups) == 1 else None


def _allowed(token, vendor):
    """Whether a name the alias data restricts to some vendors (``restrict``: "Express" is expressjs's, never Ubiquiti's) may take ``vendor``."""
    from cveFeed import correlation
    vendors, _required = correlation.NAME_VENDORS.get(token, ((), False))
    if not vendors:
        return True
    mine = correlation.VENDOR_CLASSES.get(correlation._norm(vendor, True), frozenset()) | {correlation._norm(vendor, True)}
    return bool(mine & set(vendors))


def derived_cpe(name, tech=None, panels=None):
    """The CPE prefix (``cpe:2.3:a:atlassian:jira``) the server's own name normalisation gives a product a name matcher reported, or '' when it
    knows none or knows more than one vendor's product by that name. The name is read as correlation reads it (``correlation.read_technology``,
    ``_norm``), then looked up in

    1. the product alias data (``data/product_aliases.json``, #726): the CPE an entry's evidence cites for the names it lists ("apachegeneric" is
       ``apache:http_server``);
    2. the vendor and product the technology and panel templates' own metadata name (the template index of the Sentinel library): a name that is a
       template's product ("wordpress") or its vendor and product ("atlassian-jira").

    A name the alias data restricts to some vendors only takes a CPE of theirs; a product two vendors use (``ambiguous_products``) is only taken
    when the name also says the vendor. The CPE says nothing about the version: it names the product, so correlation can match it CPE first."""
    from cveFeed import correlation, nuclei_templates, tech_coverage
    base = correlation.read_technology(name or '')[0]
    token = correlation._norm(base)
    if len(token) < correlation._MIN_TOKEN or tech_coverage.service_kind(base):
        return ''
    got = _one_vendor(sorted(_alias_cpes(correlation.ALIASES_FILE).get(token, ())))
    if got is None:
        tech = nuclei_templates.technology_products() if tech is None else tech
        panels = nuclei_templates.panel_products() if panels is None else panels
        counted = _template_index(tech, panels).get(token)
        if counted:
            ranked = [cpe for cpe, _n in sorted(counted.items(), key=lambda kv: (-kv[1], kv[0]))]
            got = _one_vendor(ranked)
            if got and correlation._norm(got[2], True) in correlation.AMBIGUOUS_PRODUCTS and token == correlation._norm(got[2]):
                got = None  # "the product" alone, when two vendors make one of that name
    if not got or not _allowed(token, got[1]):
        return ''
    return nuclei_templates.cpe_prefix(got[1], got[2], got[0])
