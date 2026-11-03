"""Release the findings an earlier version closed with another tenant's stored answer, and take back the text it shared (task 256).

Before 1.3.3 a closing answer reached on one host (an automatic identity closure read from that host's sighting, or an AI answer to what
that host showed) was stored in tables that have no tenant (``MatchVerdict``, ``TriageVerdict``) and handed to any other host, in any
organization, whose finding had the same key: correlation seeded a new CVE match from it as not affected, and triage reused it instead of
asking. Any shared answer also carried the model's words about the host it was reached on onto the other findings. The code no longer does
any of that (``correlation._seedable``, ``triage.closure_reusable``, ``triage.verdict_text``), and migration 0140 records the origin of the
answers it can prove. This module puts the findings already closed that way back where their own evidence leaves them (held for validation
while their own review is asked, ``triage.own_signature``), replaces the shared words on other projects' findings with a fixed sentence, and
deletes the shared not_affected rows nothing reads any more.

It only ever acts across organizations: on an instance with one organization (or none) nothing was shared with another tenant, and it changes
nothing. A finding's own closure is never reopened: an answer reached on its own project and host, an identity or operating-system closure
that its own sighting still supports (``correlation.invalid_identity_reason``), and a closure of the same organization. It never touches a
finding a validation hit confirmed, a remediation status, an assignee or a comment.

Run it with ``manage.py release_shared_closures`` (a dry run that only counts) and ``--apply``. ``release_once`` runs it once, by itself,
from the first correlation after the upgrade.
"""
import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)
CHUNK = 500
COUNTS = ('triage_rows', 'kept_own', 'shared_text', 'seeded_matches', 'shared_rows')


def tenants():
    """``{project id: tenant}``: a project's organization, or the project itself when it has none."""
    from dashboard.models import Project
    return {pk: (('org', org_id) if org_id else ('project', pk)) for pk, org_id in Project.objects.values_list('pk', 'org_id')}


def _seeded(mv):
    """The CVE matches correlation seeded from the shared row ``mv``: its key, its verdict and its exact reason and model, and no closing
    classification of their own (the match the row was written from, and any match closed by its own check or answer, has one)."""
    from django.db.models import Exists, OuterRef

    from cveFeed.models import Triage
    from cveFeed.triage import CLOSING
    own = Triage.objects.filter(match=OuterRef('pk'), status='triaged', classification__in=CLOSING)
    return _same_key(mv).filter(ai_verdict=mv.ai_verdict, ai_reason=mv.ai_reason, ai_model=mv.ai_model).exclude(Exists(own))


def _same_key(mv):
    from cveFeed.models import CVEMatch
    key = {'cve_entry_id': mv.cve_entry_id, 'matched_product': mv.matched_product, 'matched_version': mv.matched_version, 'source': mv.source}
    key.update({'version_in_range__isnull': True} if mv.version_in_range is None else {'version_in_range': mv.version_in_range})
    return CVEMatch.objects.filter(**key)


def _own_identity_closure(row):
    """Whether ``row`` (a CVE match's Triage row holding a deterministic closing answer) is that host's own identity or operating-system
    closure, which its sighting still supports: it is kept, detached from the shared answer."""
    from cveFeed import correlation
    match = row.match
    return bool(match is not None and (row.verdict.model or '').startswith('deterministic') and correlation.invalid_identity_reason(match))


def _decide(row, owner):
    """What happens to one Triage row holding a stored closing answer: 'keep' (its own closure, or one of its own organization), 'own'
    (its own identity closure: kept, detached from the shared answer) or 'release' (held for validation; its own review is asked)."""
    from cveFeed import triage
    verdict = row.verdict
    if triage.closure_reusable(verdict, row, row.kind, row.match):
        return 'keep'
    if verdict.project_id is not None and owner.get(verdict.project_id) == owner.get(row.project_id):
        return 'keep'  # reached in another project of the same organization: not across tenants
    if row.kind == 'cve_match' and _own_identity_closure(row):
        return 'own'
    return 'release'


def _note(per_project, project_id, key, n=1):
    if project_id is not None and n:
        per_project.setdefault(project_id, dict.fromkeys(COUNTS, 0))[key] += n


def release_shared_closures(apply=False):
    """Count, and with ``apply`` change, what other tenants' stored answers did. Each chunk is its own transaction. Returns the counts:

    * ``triage_rows``: Triage rows closed by a stored answer reached in another organization (or of unknown origin): held at needs
      validation, detached from the answer and queued for their own review (``triage.own_signature``); their CVE match's legacy verdict
      becomes uncertain when it is still the one that answer wrote.
    * ``kept_own``: CVE matches whose own sighting still supports the identity or operating-system closure they hold: kept closed, detached.
    * ``shared_text``: Triage rows (and their CVE match) showing the model's words of an answer reached in another project: given the fixed
      ``triage.SHARED_REASON``.
    * ``seeded_matches``: CVE matches correlation started as not affected from a shared row, never closed by their own check: back to
      unjudged, so their own triage decides; matches seeded with a shared row's words get the fixed sentence.
    * ``shared_rows``: the shared not_affected rows deleted after that; the others keep their verdict and get the fixed sentence.

    ``projects`` holds the same counts per project, for one activity line each."""
    from cveFeed import scoring, triage
    from cveFeed.models import CVEMatch, MatchVerdict, Triage
    counts, per_project = dict.fromkeys(COUNTS, 0), {}
    owner = tenants()
    if len(set(owner.values())) <= 1:
        return {**counts, 'projects': per_project}  # one organization: nothing was ever shared with another tenant
    touched = set()
    now = timezone.now()
    base = (Triage.objects.filter(verdict__isnull=False, status='triaged').exclude(validation_status='hit')
            .select_related('verdict', 'match__cve_entry', 'match__subdomain__target_domain'))
    last = 0
    while True:
        rows = list(base.filter(pk__gt=last).order_by('pk')[:CHUNK])
        if not rows:
            break
        last = rows[-1].pk
        release, own, text = [], [], []
        for row in rows:
            if row.match is not None:
                row.match.triage = row  # is_version_only reads the validation status here, not with a query per row
            verdict = row.verdict
            if row.classification in triage.CLOSING and verdict.classification in triage.CLOSING:
                decision = _decide(row, owner)
                if decision == 'release':
                    release.append(row)
                    continue
                if decision == 'own':
                    own.append(row)
                    continue
            if not triage.same_project(verdict, row) and row.reason and row.reason != triage.SHARED_REASON and verdict.reason \
                    and verdict.reason in row.reason:
                text.append(row)
        for key, found in (('triage_rows', release), ('kept_own', own), ('shared_text', text)):
            counts[key] += len(found)
            for row in found:
                _note(per_project, row.project_id, key)
        if not apply or not (release or own or text):
            continue
        with transaction.atomic():
            for row in release:
                Triage.objects.filter(pk=row.pk, verdict_id=row.verdict_id).update(
                    verdict=None, status='pending', classification='needs_validation', reason=triage.HELD_REASON, updated_at=now)
                if row.match_id and CVEMatch.objects.filter(pk=row.match_id, ai_verdict='not_affected', ai_reason=row.reason[:2000]).update(
                        ai_verdict=triage.verdict_for('needs_validation'), ai_reason=triage.HELD_REASON, ai_model='', updated_at=now):
                    touched.add(row.match_id)
            for row in own:
                Triage.objects.filter(pk=row.pk, verdict_id=row.verdict_id).update(verdict=None, updated_at=now)
            for row in text:
                Triage.objects.filter(pk=row.pk, verdict_id=row.verdict_id, reason=row.reason).update(reason=triage.SHARED_REASON, updated_at=now)
                if row.match_id:
                    CVEMatch.objects.filter(pk=row.match_id, ai_reason=row.reason[:2000]).update(ai_reason=triage.SHARED_REASON)
    last = 0
    while True:
        shared = list(MatchVerdict.objects.filter(pk__gt=last).order_by('pk')[:CHUNK])
        if not shared:
            break
        last = shared[-1].pk
        with transaction.atomic():
            for mv in shared:
                if mv.ai_verdict == 'not_affected':
                    seeded = list(_seeded(mv).values_list('pk', 'subdomain__target_domain__project_id'))
                    counts['seeded_matches'] += len(seeded)
                    for _, project_id in seeded:
                        _note(per_project, project_id, 'seeded_matches')
                    if apply and seeded:
                        ids = [pk for pk, _ in seeded]
                        CVEMatch.objects.filter(pk__in=ids, ai_verdict='not_affected').update(ai_verdict='', ai_reason='', ai_model='', updated_at=now)
                        touched.update(ids)
                elif mv.ai_reason != triage.SHARED_REASON:
                    if apply:  # the matches it seeded with its words (not one whose own review holds them), then the row: the verdict stays
                        from django.db.models import Exists, OuterRef
                        own = Triage.objects.filter(match=OuterRef('pk'), reason=mv.ai_reason)
                        _same_key(mv).filter(ai_verdict=mv.ai_verdict, ai_reason=mv.ai_reason).exclude(Exists(own)).update(
                            ai_reason=triage.SHARED_REASON)
                        MatchVerdict.objects.filter(pk=mv.pk).update(ai_reason=triage.SHARED_REASON)
    closing = MatchVerdict.objects.filter(ai_verdict='not_affected')
    counts['shared_rows'] = closing.delete()[0] if apply else closing.count()
    if touched:
        ids = sorted(touched)
        for start in range(0, len(ids), CHUNK):
            scoring.rescore_for_matches(CVEMatch.objects.filter(pk__in=ids[start:start + CHUNK]).select_related('subdomain__target_domain'))
        from cveFeed.views import bump_stats_revision
        bump_stats_revision()
    return {**counts, 'projects': per_project}


ONCE_LANE = 'verdict_tenancy_256'
CLAIMED, DONE = 2, 1  # BackgroundCursor.last_pk: claimed by a worker (with its time in updated_at), or done
CLAIM_TIMEOUT = timedelta(hours=1)  # a claim older than this was a worker that died: the next correlation runs it again (it is idempotent)


def _claim():
    from cveFeed.models import BackgroundCursor
    with transaction.atomic():
        cursor, _ = BackgroundCursor.objects.select_for_update(skip_locked=True).get_or_create(lane=ONCE_LANE)
        if cursor.last_pk == DONE or (cursor.last_pk == CLAIMED and cursor.updated_at > timezone.now() - CLAIM_TIMEOUT):
            return False
        cursor.last_pk = CLAIMED
        cursor.save(update_fields=['last_pk', 'updated_at'])
        return True


def release_once():
    """The one-time background run of ``release_shared_closures(apply=True)``, from the first correlation after the upgrade: a durable marker
    (BackgroundCursor ``verdict_tenancy_256``) makes every later call a single indexed read. The run is claimed first (a short transaction),
    then works in chunks with their own transactions, so it never holds one transaction over the whole instance. Never fatal: a failure is
    logged and the claim lapses, so a later correlation runs it again. Each project with a change gets one activity line with its own counts
    (never instance-wide, which would show every tenant how many of all tenants' findings moved). Returns the counts, or None when it
    already ran (or another worker holds it)."""
    from cveFeed import activity
    from cveFeed.models import BackgroundCursor
    if BackgroundCursor.objects.filter(lane=ONCE_LANE, last_pk=DONE).exists():
        return None
    try:
        if not _claim():
            return None
        counts = release_shared_closures(apply=True)
        per_project = counts.pop('projects')
        BackgroundCursor.objects.filter(lane=ONCE_LANE).update(last_pk=DONE, updated_at=timezone.now())
    except Exception:  # noqa: BLE001 - a cleanup must never stop correlation
        logger.exception('could not release the findings closed by another tenant\'s verdict')
        return None
    for project_id, mine in per_project.items():
        parts = [f'{mine["triage_rows"]} reopened for their own review' if mine['triage_rows'] else '',
                 f'{mine["seeded_matches"]} CVE match(es) set back to unjudged' if mine['seeded_matches'] else '',
                 f'{mine["shared_text"]} note(s) from another organization\'s finding removed' if mine['shared_text'] else '']
        parts = [p for p in parts if p]
        if parts:
            activity.log('confirm', 'Findings judged from another organization\'s answer: ' + '; '.join(parts), project=project_id,
                         decision='released_shared_verdicts', **mine)
    logger.info('released shared closures once: %s', counts)
    return counts
