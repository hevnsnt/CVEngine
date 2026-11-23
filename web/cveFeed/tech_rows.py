"""One Technology row per product spelling: the name a source writes is folded onto the row that already names the same product and version
in another case ("Caddy" and "caddy", "PHP:8.1.2" and "php:8.1.2"), so a host's inventory and the coverage report count a product once.

Two names are the same when ``tech_coverage.normalise_sighting`` reads them as the same product token (``correlation._norm``: case and
punctuation dropped, a detector's template word or rename applied: "Nginx version:1.18.0" is nginx 1.18.0) at the same version. Only a row
whose name differs in case is reused on write (one indexed lookup); ``merge_duplicates`` folds the rows stored before, the same way.
"""
import logging

logger = logging.getLogger(__name__)


def key(name):
    """``(product token, version)`` a stored technology name reads as, or None for a name too short to compare."""
    from cveFeed import correlation, tech_coverage
    seen = tech_coverage.normalise_sighting(name or '')
    token = correlation._norm(seen['name'])
    return (token, (seen['version'] or '').strip().lower()) if token else None


def technology(name):
    """The Technology row for ``name``: the row of that exact name, else the oldest row whose name is the same in another case and reads as
    the same product and version (``key``), else a new one."""
    from startScan.models import Technology
    name = (name or '')[:500]
    row = Technology.objects.filter(name=name).order_by('id').first()
    if row is not None:
        return row
    wanted = key(name)
    for other in Technology.objects.filter(name__iexact=name).order_by('id')[:5]:
        if wanted is not None and key(other.name) == wanted:
            return other
    return create(name)


def create(name):
    """A new Technology row named exactly ``name``, or the row another writer created meanwhile: the name is unique
    (``uniq_technology_name``), so the loser of the race reads the winner's row instead of failing the scan."""
    from django.db import IntegrityError, transaction

    from startScan.models import Technology
    try:
        with transaction.atomic():
            return Technology.objects.create(name=name)
    except IntegrityError:
        row = Technology.objects.filter(name=name).first()
        if row is None:
            raise
        return row


def merge_duplicates(apply=False):
    """Fold the Technology rows whose names differ only in case and read as the same product and version onto the oldest of them: their host
    links move to it (a host already linked to it keeps one link) and they are deleted. Returns ``{'groups', 'rows', 'hosts': {subdomain ids}}``."""
    from django.db.models.functions import Lower

    from startScan.models import EndPoint, Subdomain, Technology
    groups = {}
    for pk, name, lowered in Technology.objects.annotate(lowered=Lower('name')).order_by('id').values_list('id', 'name', 'lowered'):
        if name:
            groups.setdefault(lowered, []).append((pk, name))
    out = {'groups': 0, 'rows': 0, 'hosts': set()}
    through = Subdomain.technologies.through
    for rows in groups.values():
        if len(rows) < 2:
            continue
        keep_pk, keep_name = rows[0]
        same = [pk for pk, name in rows[1:] if key(name) is not None and key(name) == key(keep_name)]
        if not same:
            continue
        out['groups'] += 1
        out['rows'] += len(same)
        moved = list(through.objects.filter(technology_id__in=same).values_list('subdomain_id', flat=True))
        out['hosts'] |= set(moved)
        if not apply:
            continue
        linked = set(through.objects.filter(technology_id=keep_pk, subdomain_id__in=moved).values_list('subdomain_id', flat=True))
        # a moved link keeps where it came from (its source, the CPE its template named, when it was seen)
        # one with a CPE last, so it wins, and of those one whose CPE a source stated over one the server derived (cveFeed.tech_links)
        from cveFeed import tech_links
        meta = {r.subdomain_id: r for r in sorted(through.objects.filter(technology_id__in=same),
                                                  key=lambda r: (bool(r.cpe), bool(r.cpe) and not tech_links.is_derived(r.source), r.id))}
        through.objects.bulk_create([through(subdomain_id=s, technology_id=keep_pk, source=meta[s].source, cpe=meta[s].cpe, observed_at=meta[s].observed_at)
                                     if s in meta else through(subdomain_id=s, technology_id=keep_pk) for s in set(moved) - linked], ignore_conflicts=True)
        through.objects.filter(technology_id__in=same).delete()
        pages = EndPoint.techs.through  # an endpoint's technologies point at the same rows
        on_pages = set(pages.objects.filter(technology_id__in=same).values_list('endpoint_id', flat=True))
        on_kept = set(pages.objects.filter(technology_id=keep_pk, endpoint_id__in=on_pages).values_list('endpoint_id', flat=True))
        pages.objects.bulk_create([pages(endpoint_id=e, technology_id=keep_pk) for e in on_pages - on_kept], ignore_conflicts=True)
        pages.objects.filter(technology_id__in=same).delete()
        Technology.objects.filter(pk__in=same).delete()
    return out
