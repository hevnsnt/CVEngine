"""Operator notes on findings and hosts, as the AI reads them.

A note is what a person or an agent observed about one finding (a ``FindingComment``, optionally with an ``observation`` and ``evidence``)
or about a whole host (a ``HostNote``). Notes are data, never instructions: the reviewer and the host review put the newest of them into
their model input inside a fenced, labelled block (``for_review``), capped in number and length, and the model is told to weigh them as
claims, not orders. A note never changes a finding's status by itself: only a review's verdict (through ``reviewer.close_gate``) or an
explicit status change does.

A new note queues a fresh review of what it is about (``queue_rereview``): the finding's triage row (or the open findings of the host) get
``notes_mark``, which is part of the review key (``reviewer.review_key``), so the reviewer's existing due list hands them out again. At most
one such queueing per finding per ``REREVIEW_GAP``: a note written inside that window is still read by the review it queued if that review
has not run yet, and otherwise at the finding's next review.
"""
from django.core.cache import cache

from cveFeed.models import NOTE_OBSERVATIONS, NOTE_SOURCES

REVIEW_NOTES = 10       # the most notes one review reads, newest first (the finding's and its host's together)
REVIEW_NOTE_CHARS = 1000  # the most characters of one note's text, and of its evidence, a review reads
MAX_TEXT = 4000         # the most characters a note's text and its evidence may hold
REREVIEW_GAP = 900      # seconds: a finding is queued for a fresh review by a note at most once in this window
REREVIEW_HOST_CAP = 200  # the most open findings of one host a host note queues
OBSERVATIONS = NOTE_OBSERVATIONS
SOURCES = NOTE_SOURCES


class NoteError(ValueError):
    """A note's fields are not acceptable (the message says which)."""


def clean_fields(text, observation=None, evidence=None, require_text=True):
    """``(text, observation, evidence)`` checked: text not empty (unless ``require_text`` is off), observation one of OBSERVATIONS or empty,
    evidence text of at most MAX_TEXT characters. Raises NoteError."""
    if not isinstance(text, str) or (require_text and not text.strip()):
        raise NoteError('text must not be empty')
    if observation in (None, ''):
        observation = ''
    elif not isinstance(observation, str) or observation not in OBSERVATIONS:
        raise NoteError('observation must be one of ' + ', '.join(OBSERVATIONS))
    if evidence is None:
        evidence = ''
    elif not isinstance(evidence, str):
        raise NoteError('evidence must be text')
    if len(evidence) > MAX_TEXT:
        raise NoteError(f'evidence must be at most {MAX_TEXT} characters')
    return text[:MAX_TEXT], observation, evidence


def via_of(token):
    """The name a note records for the API token it came through ('' without one)."""
    return str(getattr(token, 'name', '') or '')[:100] if token is not None else ''


def _who(source, via):
    # who wrote it as the model is told: the channel only, never a login or a token's name (a token name is free text its owner chose)
    return {'ui': 'a person in the web interface', 'mcp': 'an agent through MCP', 'rest': 'a caller of the REST API'}.get(source, 'unknown')


def _shown(row, on):
    return {'on': on, 'observation': row.observation or 'comment', 'written_by': _who(row.source, row.via),
            'date': row.created_at.date().isoformat() if row.created_at else '',
            'text': (row.text or '')[:REVIEW_NOTE_CHARS], 'evidence': (row.evidence or '')[:REVIEW_NOTE_CHARS]}


def for_review(project_id, finding_kind, finding_ids, host):
    """The newest notes a review of one finding reads: the notes of the finding (``finding_ids``: this copy and its earlier copies) and of its
    host, newest first, at most REVIEW_NOTES, each cut to REVIEW_NOTE_CHARS. ``finding_kind`` is the audit kind (match, vulnerability or
    hygiene); ``host`` the finding's host name ('' for none). Two indexed reads."""
    from cveFeed.models import FindingComment, HostNote
    rows = []
    if finding_ids:
        rows += [(c.created_at, c.pk, _shown(c, 'finding')) for c in
                 FindingComment.objects.filter(project_id=project_id, finding_kind=finding_kind, finding_id__in=list(finding_ids))
                 .order_by('-created_at', '-id')[:REVIEW_NOTES]]
    if host:
        rows += [(n.created_at, n.pk, _shown(n, 'host')) for n in
                 HostNote.objects.filter(project_id=project_id, host=host).order_by('-created_at', '-id')[:REVIEW_NOTES]]
    rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
    return [r[2] for r in rows[:REVIEW_NOTES]]


def host_notes(project_id, host, limit=REVIEW_NOTES):
    """The newest notes of one host as a review reads them."""
    from cveFeed.models import HostNote
    if not host:
        return []
    return [_shown(n, 'host') for n in HostNote.objects.filter(project_id=project_id, host=host).order_by('-created_at', '-id')[:limit]]


def _gate(triage_id):
    return cache.add(f'cvengine:notes:rereview:{triage_id}', 1, REREVIEW_GAP)


def queue_rereview(triage_ids, note_id):
    """Queue these findings' triage rows for a fresh AI review because of note ``note_id``: each row not queued by a note within REREVIEW_GAP
    gets ``notes_mark = note_id``, which changes its review key. Returns the number queued. Nothing else about the finding changes."""
    from cveFeed.models import Triage
    ids = [pk for pk in dict.fromkeys(triage_ids) if pk and _gate(pk)]
    if not ids:
        return 0
    return Triage.objects.filter(pk__in=ids).update(notes_mark=int(note_id))


def queue_finding(kind, finding_id, note_id):
    """``queue_rereview`` for one finding of ``kind`` (match, vulnerability or hygiene): its triage row, when it has one."""
    from cveFeed.models import Triage
    column = {'match': 'match_id', 'hygiene': 'hygiene_id'}.get(kind, 'vulnerability_id')
    return queue_rereview(list(Triage.objects.filter(**{column: finding_id}).values_list('pk', flat=True)[:5]), note_id)


def queue_host(project_id, host, note_id):
    """``queue_rereview`` for the open findings of one host (at most REREVIEW_HOST_CAP)."""
    from cveFeed import reviewer
    from cveFeed.models import Triage
    ids = list(Triage.objects.filter(reviewer.open_q(), project_id=project_id, host=host).exclude(kind='route_auth')
               .order_by('-id').values_list('pk', flat=True)[:REREVIEW_HOST_CAP])
    return queue_rereview(ids, note_id)
