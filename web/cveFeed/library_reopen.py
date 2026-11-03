"""Once after the upgrade: reopen the library matches an earlier build closed on the page's own files.

Builds before the final review of 1.3.3 (and the squash merge of #384 on develop) closed a technology scan's JavaScript library version
because the host's front page seemed to contradict it: its files stated another version (``named_by_script``, ``contradicted_by_file``),
a file stated nothing (``file_states_nothing``), the page loaded no script of the library (``no_such_script``) or the version was a theme's
``?ver=`` (``cache_buster``); and a validation's script read (#387) closed one whose file stated a fixed version
(``script_read_fixed_version``). Static reading cannot prove a page loads nothing else at run time, so none of these closes any more
(``js_libraries.HostLibraries.judge``): the match is a candidate at the file-name confidence with a note saying what the file states.

``reopen_once`` runs ``reopen_file_closures`` one time, from the first correlation after the upgrade (a durable BackgroundCursor marker, as
``verdict_tenancy.release_once`` does). It reopens only closures the deterministic correlation made with one of those reasons
(``js_libraries.FILE_KINDS``, and the script read's fixed version: ``kind_of``), on a match nobody has worked (remediation status open); never a redirect alias, never a closure a person or
the AI made. The match goes back to unjudged at the file-name confidence and its triage row to pending, so triage judges it again under the
version-only ceiling; nothing is paged (a version-only match is smoke at most). Each project gets one activity line with its own count.
"""
import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

ONCE_LANE = 'library_file_closures_133'
CLAIMED, DONE = 2, 1  # BackgroundCursor.last_pk: claimed by a worker (with its time in updated_at), or done
CLAIM_TIMEOUT = timedelta(hours=1)  # a claim older than this was a worker that died: the next correlation runs it again (it is idempotent)
CHUNK = 500
AUTOMATIC_MODEL = 'deterministic-correlation'  # what correlation.close_invalid_correlation writes; a person's or the AI's closure differs


# the fixed-version closure of a validation's script read (#387), which shares the gap: its alias closure ("...answers a permanent
# redirect...") stays
SCRIPT_READ_FIXED = 'A fresh read of every web base shows the copy of'


def kind_of(reason):
    """The kind of a stored closure this step reopens, or '' for one it leaves (a redirect alias, anything else)."""
    from cveFeed import js_libraries
    from cveFeed.correlation import SCRIPT_READ
    text = str(reason or '')
    if text.startswith(SCRIPT_READ) and SCRIPT_READ_FIXED in text[:len(SCRIPT_READ) + 80]:
        return 'script_read_fixed_version'
    kind = js_libraries.closure_kind(text)
    return kind if kind in js_libraries.FILE_KINDS else ''


def _candidates():
    from django.db.models import Q

    from cveFeed import js_libraries
    from cveFeed.correlation import SCRIPT_READ
    from cveFeed.models import CVEMatch
    return (CVEMatch.objects.filter(Q(ai_reason__startswith=js_libraries.LIBRARY_CLOSED) | Q(ai_reason__startswith=SCRIPT_READ),
                                    ai_verdict='not_affected', ai_model=AUTOMATIC_MODEL, remediation_status='open')
            .select_related('cve_entry', 'subdomain__target_domain').order_by('pk'))


def reopen_file_closures(apply=True):
    """Reopen every automatic library closure of a kind no longer made (``js_libraries.FILE_KINDS``), in chunks of CHUNK, each in its own
    transaction. Idempotent: a reopened match is no longer closed, so a second run finds nothing. With ``apply=False`` it only counts.
    Returns ``{'reopened': n, 'by_kind': {kind: n}, 'projects': {project id: n}}``."""
    from cveFeed import js_libraries, scoring
    from cveFeed.models import CVEMatch, Triage
    reopened, by_kind, projects, last = 0, {}, {}, 0
    now = timezone.now()
    while True:
        batch = list(_candidates().filter(pk__gt=last)[:CHUNK])
        if not batch:
            break
        last = batch[-1].pk
        mine = [m for m in batch if kind_of(m.ai_reason)]
        if not mine:
            continue
        for m in mine:
            kind = kind_of(m.ai_reason)
            by_kind[kind] = by_kind.get(kind, 0) + 1
            project = m.subdomain.target_domain.project_id if m.subdomain and m.subdomain.target_domain_id else None
            projects[project] = projects.get(project, 0) + 1
        reopened += len(mine)
        if not apply:
            continue
        with transaction.atomic():
            for m in mine:
                evidence = m.evidence if isinstance(m.evidence, dict) else {}
                evidence = {**evidence, 'library_reopened_at': now.isoformat(), 'reopened_from': kind_of(m.ai_reason)}
                # a candidate at the file-name confidence (what correlation gives a library version no file closes), unjudged again
                CVEMatch.objects.filter(pk=m.pk, ai_verdict='not_affected').update(
                    ai_verdict='', ai_reason='', ai_model='', confidence=js_libraries.CONFIDENCE['filename'], evidence=evidence, updated_at=now)
            Triage.objects.filter(match_id__in=[m.pk for m in mine], classification='not_applicable').update(
                verdict=None, status='pending', classification='', reason='', updated_at=now)
        scoring.rescore_for_matches(CVEMatch.objects.filter(pk__in=[m.pk for m in mine]).select_related('subdomain__target_domain'))
    return {'reopened': reopened, 'by_kind': by_kind, 'projects': projects}


def _claim():
    from cveFeed.models import BackgroundCursor
    with transaction.atomic():
        cursor, _ = BackgroundCursor.objects.select_for_update(skip_locked=True).get_or_create(lane=ONCE_LANE)
        if cursor.last_pk == DONE or (cursor.last_pk == CLAIMED and cursor.updated_at > timezone.now() - CLAIM_TIMEOUT):
            return False
        cursor.last_pk = CLAIMED
        cursor.save(update_fields=['last_pk', 'updated_at'])
        return True


def reopen_once():
    """The one-time run of ``reopen_file_closures``, from the first correlation after the upgrade: a durable marker (BackgroundCursor
    ``ONCE_LANE``) makes every later call a single indexed read. Never fatal: a failure is logged and the claim lapses, so a later
    correlation runs it again. Logs the count; each project with a reopened match gets one activity line with its own count (never the
    instance-wide total). Returns the counts, or None when it already ran (or another worker holds it)."""
    from cveFeed import activity
    from cveFeed.models import BackgroundCursor
    if BackgroundCursor.objects.filter(lane=ONCE_LANE, last_pk=DONE).exists():
        return None
    try:
        if not _claim():
            return None
        counts = reopen_file_closures(apply=True)
        BackgroundCursor.objects.filter(lane=ONCE_LANE).update(last_pk=DONE, updated_at=timezone.now())
    except Exception:  # noqa: BLE001 - a cleanup must never stop correlation
        logger.exception('could not reopen the library matches closed on the page\'s files')
        return None
    for project_id, count in counts['projects'].items():
        if project_id is not None and count:
            activity.log('confirm', f'{count} JavaScript library CVE match(es) reopened: an earlier build closed them on the page\'s own files, '
                                    'which cannot prove what the page loads at run time; they are candidates again, held below fire',
                         project=project_id, decision='reopened_library_file_closures', reopened=count)
    logger.info('reopened %d library matches closed on the page\'s files: %s', counts['reopened'], counts['by_kind'])
    return counts
