"""Search a project's supplier host cards by technology: "show me every supplier host running PHP or Node.js".

The question is "what do my suppliers run, so I can ask whether they are patched", so this is a plain text match over what each card
shows: the technology names and versions the fingerprinting found, and the raw Server and X-Powered-By banners. A query is one or more terms
separated by commas (any term matches); a term is matched anywhere in ``name version`` (so ``php``, ``php 7``, ``php:7.4``, ``node``,
``nginx 1.1`` all work), case-insensitively. Cards are few (a few hundred at most per project), so the match runs in Python over the project's
cards; nothing here touches the network."""
MAX_TERMS = 8
MAX_TERM = 60


def terms_of(query):
    """The distinct lowercase search terms in ``query`` (comma separated; a ``:`` or ``/`` between a name and its version reads as a space)."""
    out = []
    for part in str(query or '').replace(';', ',').split(','):
        term = ' '.join(part.lower().replace(':', ' ').replace('/', ' ').split())[:MAX_TERM]
        if term and term not in out:
            out.append(term)
    return out[:MAX_TERMS]


def label(tech):
    return f'{tech.get("name", "")} {tech.get("version", "")}'.strip()


def matching(card, terms):
    """The technologies of ``card`` that any of ``terms`` matches, and whether a raw banner matched where no technology did."""
    techs = [t for t in (card.technologies or []) if any(term in label(t).lower().replace(':', ' ') for term in terms)]
    http = card.http or {}
    banner = ' '.join(str(http.get(k) or '') for k in ('server', 'powered_by')).lower()
    return techs, (not techs and any(term in banner for term in terms))


def cards_for(project_id, query='', supplier_id=None, tier=''):
    """``[(card, matched_technologies)]`` of the project: every card when ``query`` is empty, else those a term matches, suppliers by tier then
    name and domains alphabetically."""
    from cveFeed.models import Supplier, SupplierHostCard
    terms = terms_of(query)
    rows = SupplierHostCard.objects.filter(supplier__project_id=project_id).select_related('supplier')
    if supplier_id:
        rows = rows.filter(supplier_id=supplier_id)
    if tier in Supplier.TIERS:
        rows = rows.filter(supplier__tier=tier)
    rank = {t: i for i, t in enumerate(Supplier.TIERS)}
    out = []
    for card in sorted(rows, key=lambda c: (rank.get(c.supplier.tier, 9), c.supplier.name.lower(), c.domain)):
        if not terms:
            out.append((card, []))
            continue
        techs, by_banner = matching(card, terms)
        if techs or by_banner:
            out.append((card, techs))
    return out


def facets(project_id):
    """The technologies seen across the project's suppliers, most widespread first: ``[{'name', 'category', 'suppliers', 'hosts', 'versions'}]``,
    one row per technology name (case-insensitive) with the distinct versions seen. What the search box offers as a click."""
    from cveFeed.models import SupplierHostCard
    seen = {}
    for card in SupplierHostCard.objects.filter(supplier__project_id=project_id).select_related('supplier'):
        for tech in card.technologies or []:
            key = tech['name'].lower()
            row = seen.setdefault(key, {'name': tech['name'], 'category': tech.get('category', ''), 'suppliers': set(), 'hosts': 0, 'versions': set()})
            row['suppliers'].add(card.supplier_id)
            row['hosts'] += 1
            if tech.get('version'):
                row['versions'].add(tech['version'])
    rows = [{'name': r['name'], 'category': r['category'], 'suppliers': len(r['suppliers']), 'hosts': r['hosts'],
             'versions': sorted(r['versions'])[:20]} for r in seen.values()]
    return sorted(rows, key=lambda r: (-r['suppliers'], -r['hosts'], r['name'].lower()))
