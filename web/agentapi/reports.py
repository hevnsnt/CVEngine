"""REST and MCP front of the PDF reports (cveFeed.report_export): ask for one, read its state, download it."""
from agentapi.services import ApiError


def export_report(ctx, slug, body):
    """Queue a report. ``body``: {host (optional, one exact host name), include_closed (optional boolean)}. Returns the report's state
    with 202, or 200 when the same report is already being made."""
    from cveFeed import report_export
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be a JSON object')
    job, created = report_export.enqueue(ctx, slug, host=body.get('host'), include_closed=body.get('include_closed', False))
    return report_export.serialize(job), (202 if created else 200)


def report_status(ctx, slug, token):
    from cveFeed import report_export
    return report_export.status(ctx, slug, token)


def report_download(ctx, slug, token):
    from cveFeed import report_export
    return report_export.download(ctx, slug, token)
