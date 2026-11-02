"""The connection log of this server's own scanners (``cveFeed.local_egress``) over the REST API and MCP.

One record per local outbound connection (or planned probe of an external tool) to a logged port (25, 465 and 587 by default): when, the
destination address and port, whether it was sent, paced or skipped, whether the record is exact or estimated, and the source (tool, project,
scan). It belongs to the whole instance, not to a project, so only an App Admin may read it; anyone else gets 403. Read-only.
"""
from datetime import datetime, timezone

from agentapi.services import ApiError

ADMIN_ONLY = 'the egress connection log belongs to the whole instance: only an App Admin may read it'


def _admin(ctx):
    if not (ctx.user.is_authenticated and ctx.user.is_superuser):
        raise ApiError(403, ADMIN_ONLY)


def _time(value, name):
    """Epoch seconds from an ISO 8601 time or a number, or None."""
    if value in (None, ''):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        raise ApiError(400, f'{name} must be an ISO 8601 time or epoch seconds') from None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()


def _filters(args):
    from dashboard.models import Project
    port = args.get('port')
    if port not in (None, ''):
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ApiError(400, 'port must be a number') from None
    else:
        port = None
    project = None
    slug = args.get('project')
    if slug not in (None, ''):
        project = Project.objects.filter(slug=str(slug)).values_list('id', flat=True).first()
        if project is None:
            raise ApiError(404, 'no such project')
    return {'port': port, 'project': project, 'since': _time(args.get('since'), 'since'), 'until': _time(args.get('until'), 'until')}


def _slugs():
    from dashboard.models import Project
    return dict(Project.objects.values_list('id', 'slug'))


def list_connections(ctx, args):
    """A page of the log, newest first. ``args``: port, project (slug), since, until (ISO 8601 or epoch seconds), limit (up to 1000, default
    100) and cursor (the ``next`` of the previous page)."""
    from cveFeed import local_egress
    _admin(ctx)
    try:
        limit = int(args.get('limit') or 100)
    except (TypeError, ValueError):
        raise ApiError(400, 'limit must be a number') from None
    page = local_egress.connection_log(limit=limit, cursor=args.get('cursor') or None, **_filters(args))
    names = _slugs()
    for record in page['records']:
        record['project'] = names.get(record['project'], record['project'])
    page['logged_ports'] = sorted(local_egress.log_ports())
    page['note'] = ('exact: this server opened, or decided not to open, that very connection; estimated: an external tool (nmap, naabu, '
                    'testssl.sh, nuclei) was given the address and the port in its probe plan, and its own packets are not watched')
    return page


def connections_csv(ctx, args):
    """Every matching record as a CSV download (the same filters as ``list_connections``)."""
    from cveFeed import local_egress
    from django.http import HttpResponse
    _admin(ctx)
    text = local_egress.connection_log_csv(project_names=_slugs(), **_filters(args))
    response = HttpResponse(text, content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="cvengine-egress-connections.csv"'
    return response
