"""REST and MCP front of the reports (cveFeed.report_export): ask for one, read its state, download it, and the lists the Reporting page reads."""
from agentapi.services import ApiError


def export_report(ctx, slug, body):
    """Queue a report of a project. ``body``: {host (optional, one exact host name, findings reports only), include_closed (optional boolean), kind
    (findings, the default, or hosts), format (pdf, the default, or csv)}. Returns the report's state with 202, or 200 when the same report is already
    being made."""
    from cveFeed import report_export
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be a JSON object')
    if body.get('org') not in (None, ''):  # the MCP tool takes project or org in one object
        return export_org_report(ctx, body['org'], {k: v for k, v in body.items() if k != 'org'}, slug=slug)
    job, created = report_export.enqueue(ctx, slug, host=body.get('host'), include_closed=body.get('include_closed', False),
                                         kind=body.get('kind') or 'findings', fmt=body.get('format') or 'pdf')
    return report_export.serialize(job), (202 if created else 200)


def export_org_report(ctx, org, body, slug=None):
    """Queue a report of an organization: its projects the caller can read. ``body``: {include_closed, kind, format}, as for a project (no host)."""
    from cveFeed import report_export
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be a JSON object')
    job, created = report_export.enqueue(ctx, slug or None, host=body.get('host'), include_closed=body.get('include_closed', False), org=org,
                                         kind=body.get('kind') or 'findings', fmt=body.get('format') or 'pdf')
    return report_export.serialize(job), (202 if created else 200)


def report_status(ctx, slug, token, org=None):
    from cveFeed import report_export
    return report_export.status(ctx, slug, token, org=org)


def report_download(ctx, slug, token, org=None):
    from cveFeed import report_export
    return report_export.download(ctx, slug, token, org=org)


def list_report_scopes(ctx, params=None):
    """What the Reporting page's picker offers: each organization and project the caller can report on, with what they may do with email reports there."""
    from agentapi import report_scope
    return report_scope.list_scopes(ctx)


def list_my_reports(ctx, params=None):
    """The caller's own reports that have not expired, newest first (at most 20)."""
    from cveFeed import report_export
    return {'results': report_export.recent(ctx)}
