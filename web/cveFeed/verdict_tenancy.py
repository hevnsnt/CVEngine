"""Release the findings an earlier version closed with another tenant's stored answer (task 256).

Before 1.3.3 a closing answer reached on one host (an automatic identity closure read from that host's sighting, or an AI answer to what
that host showed) was stored in tables that have no tenant (``MatchVerdict``, ``TriageVerdict``) and handed to any other host, in any
organization, whose finding had the same key: correlation seeded a new CVE match from it as not affected, and triage reused it instead of
asking. The code no longer does either (``correlation._seedable``, ``triage.closure_reusable``), and migration 0139 records the origin of
the closing answers it can prove. This module finds the findings that were already closed that way and puts them back where their own
evidence leaves them, then deletes the shared not_affected rows nothing reads any more. It never touches a finding a validation hit
confirmed, a remediation status, an assignee or a comment.

Run it with ``manage.py release_shared_closures`` (a dry run that only counts) and ``--apply``.
"""
from django.db import transaction
from django.utils import timezone

CHUNK = 1000


def _seeded(mv):
    """The CVE matches correlation seeded from the shared row ``mv``: its key, its verdict and its exact reason and model, and no closing
    classification of their own (the match the row was written from, and any match closed by its own check or answer, has one)."""
    from django.db.models import Exists, OuterRef

    from cveFeed.models import CVEMatch, Triage
    from cveFeed.triage import CLOSING
    key = {'cve_entry_id': mv.cve_entry_id, 'matched_product': mv.matched_product, 'matched_version': mv.matched_version, 'source': mv.source}
    key.update({'version_in_range__isnull': True} if mv.version_in_range is None else {'version_in_range': mv.version_in_range})
    own = Triage.objects.filter(match=OuterRef('pk'), status='triaged', classification__in=CLOSING)
    return (CVEMatch.objects.filter(ai_verdict='not_affected', ai_reason=mv.ai_reason, ai_model=mv.ai_model, **key)
            .exclude(Exists(own)))


def release_shared_closures(apply=False):
    """Count, and with ``apply`` release, what other tenants' answers closed. Returns the counts:

    * ``triage_rows``: Triage rows classified by a stored closing answer they may not reuse (another project or host, or no recorded
      origin): held at needs_validation and detached from the answer, as ``triage._apply`` now does; their CVE match's legacy verdict
      becomes uncertain when it is still the one that answer wrote.
    * ``seeded_matches``: CVE matches correlation started as not affected from a shared row, never closed by their own check: back to
      unjudged, so their own triage and checks decide.
    * ``shared_rows``: the shared not_affected rows deleted after that (nothing has read them since the fix).
    """
    from cveFeed import scoring, triage
    from cveFeed.models import CVEMatch, MatchVerdict, Triage
    counts = {'triage_rows': 0, 'seeded_matches': 0, 'shared_rows': 0}
    touched = set()
    now = timezone.now()
    last = 0
    while True:
        rows = list(Triage.objects.filter(pk__gt=last, status='triaged', classification__in=triage.CLOSING, verdict__isnull=False,
                                          verdict__classification__in=triage.CLOSING).exclude(validation_status='hit')
                    .select_related('verdict', 'match').order_by('pk')[:CHUNK])
        if not rows:
            break
        last = rows[-1].pk
        held = [row for row in rows if not triage.closure_reusable(row.verdict, row, row.kind, row.match)]
        counts['triage_rows'] += len(held)
        if not apply or not held:
            continue
        with transaction.atomic():
            for row in held:
                old_reason = row.reason
                Triage.objects.filter(pk=row.pk).update(verdict=None, classification='needs_validation', reason=triage.HELD_REASON, updated_at=now)
                if row.match_id:
                    changed = CVEMatch.objects.filter(pk=row.match_id, ai_verdict='not_affected', ai_reason=old_reason[:2000]).update(
                        ai_verdict=triage.verdict_for('needs_validation'), ai_reason=triage.HELD_REASON, updated_at=now)
                    if changed:
                        touched.add(row.match_id)
    for mv in MatchVerdict.objects.filter(ai_verdict='not_affected').order_by('pk').iterator(chunk_size=CHUNK):
        seeded = _seeded(mv)
        if not apply:
            counts['seeded_matches'] += seeded.count()
            continue
        ids = list(seeded.values_list('pk', flat=True))
        if ids:
            counts['seeded_matches'] += CVEMatch.objects.filter(pk__in=ids, ai_verdict='not_affected').update(
                ai_verdict='', ai_reason='', ai_model='', updated_at=now)
            touched.update(ids)
    shared = MatchVerdict.objects.filter(ai_verdict='not_affected')
    counts['shared_rows'] = shared.delete()[0] if apply else shared.count()
    if touched:
        ids = sorted(touched)
        for start in range(0, len(ids), CHUNK):
            scoring.rescore_for_matches(CVEMatch.objects.filter(pk__in=ids[start:start + CHUNK]).select_related('subdomain__target_domain'))
        from cveFeed.views import bump_stats_revision
        bump_stats_revision()
    return counts


ONCE_LANE = 'verdict_tenancy_256'


def release_once():
    """The one-time background run of ``release_shared_closures(apply=True)``, from the first correlation after the upgrade: a durable marker
    (BackgroundCursor ``verdict_tenancy_256``) makes every later call a single indexed read. Never fatal: a failure is logged and retried by
    the next correlation. Returns the counts, or None when it already ran (or another worker holds it)."""
    import logging

    from cveFeed.models import BackgroundCursor
    if BackgroundCursor.objects.filter(lane=ONCE_LANE, last_pk__gt=0).exists():
        return None
    try:
        with transaction.atomic():
            cursor, _ = BackgroundCursor.objects.select_for_update(skip_locked=True).get_or_create(lane=ONCE_LANE)
            if cursor.last_pk:
                return None
            counts = release_shared_closures(apply=True)
            cursor.last_pk = 1
            cursor.save(update_fields=['last_pk', 'updated_at'])
    except Exception:  # noqa: BLE001 - a cleanup must never stop correlation
        logging.getLogger(__name__).exception('could not release the findings closed by another tenant\'s verdict')
        return None
    # counts only, in the worker log: an instance-wide activity line would show every tenant how many of all tenants' findings moved
    logging.getLogger(__name__).info('released shared closures once: %s', counts)
    return counts
