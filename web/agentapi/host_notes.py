"""Operator notes on a whole host (cveFeed.models.HostNote), for MCP (add_host_note, list_host_notes) and REST.

The host is a stored inventory row of the project (``host_review_api._host_row``: a foreign or unknown id is a 404, the same answer either
way). Writing needs write access to the project (no read-only token, no audit role, never ``_all``). A note is read by its host's name, so it
stays with the host when a rescan replaces the row. Every note is written to the audit log (``host.note``) and queues the host's open
findings for a fresh AI review (cveFeed.notes); it never changes a finding's status by itself.
"""
from agentapi.host_review_api import _host_row
from agentapi.services import ApiError, _iso, _user_brief, paginate

HOST_NOTES_SHOWN = 20  # the newest notes get_host_review and export_host carry; list_host_notes pages through all of them


def note_dict(n):
    return {'id': n.id, 'host': n.host, 'host_id': n.subdomain_id, 'text': n.text, 'observation': n.observation or None, 'evidence': n.evidence or '',
            'author': _user_brief(n.author), 'source': n.source, 'via': n.via or None, 'created': _iso(n.created_at)}


def newest(project, host, limit=HOST_NOTES_SHOWN):
    """The newest notes of one host of ``project``, newest first."""
    from cveFeed.models import HostNote
    return [note_dict(n) for n in HostNote.objects.filter(project=project, host=host).select_related('author').order_by('-created_at', '-id')[:limit]]


def for_names(project, names, limit):
    """Every note of the hosts named ``names`` (a host and its aliases) in ``project``, newest first, at most ``limit``: for export_host."""
    from cveFeed.models import HostNote
    return [note_dict(n) for n in HostNote.objects.filter(project=project, host__in=list(names)).select_related('author').order_by('-created_at', '-id')[:limit]]


def list_host_notes(ctx, slug, host_id, params=None):
    """Every note of one stored host, oldest first, a page at a time."""
    from cveFeed.models import HostNote
    project, _sub, host = _host_row(ctx, slug, host_id)
    rows = HostNote.objects.filter(project=project, host=host).select_related('author').order_by('id')
    return paginate(rows, params or {}, note_dict)


def add_host_note(ctx, slug, host_id, text, observation=None, evidence=None, source='rest'):
    """Add one note to a stored host. ``observation`` is one of cveFeed.notes.OBSERVATIONS (optional), ``evidence`` optional text."""
    from cveFeed import notes
    from cveFeed.admin_api import audit
    from cveFeed.models import HostNote
    project, sub, host = _host_row(ctx, slug, host_id, write=True)
    try:
        text, observation, evidence = notes.clean_fields(text, observation, evidence)
    except notes.NoteError as exc:
        raise ApiError(400, str(exc)) from exc
    source = source if source in notes.SOURCES else 'rest'
    note = HostNote.objects.create(project=project, subdomain=sub, host=host, author=ctx.user, text=text, observation=observation,
                                   evidence=evidence, source=source, via=notes.via_of(ctx.token))
    audit(ctx.user, 'host.note', f'{host} in {project.slug}', project.org, project=project.slug, host=host, note_id=note.pk,
          observation=observation, text=text[:200], source=source)
    queued = notes.queue_host(project.pk, host, note.pk)
    return {**note_dict(note), 'reviews_queued': queued}
