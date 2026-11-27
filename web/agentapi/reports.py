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


def get_threats(ctx, params):
    """This period's most important vulnerabilities for a project (``project``) or an organization (``org``), as the email reports show them (cveFeed.report_threats):
    Zero Wire briefings first, then CISA KEV additions and new critical CVEs, each with how many of the caller's hosts it reaches. ``days`` (1 to 31, default 7) is the
    period ending now; ``cadence`` weekly or monthly sets it instead. Read access to the scope is all it takes; it reads stored results only."""
    from datetime import timedelta

    from django.utils import timezone

    from agentapi import report_scope
    from cveFeed import report_schedule, report_threats
    scope = report_scope.resolve(ctx, project=params.get('project') or None, org=params.get('org') or None)
    cadence = params.get('cadence')
    if cadence not in (None, '', 'weekly', 'monthly'):
        raise ApiError(400, 'cadence must be weekly or monthly')
    try:
        days = {'weekly': 7, 'monthly': 30}.get(cadence) or int(params.get('days') or 7)
    except (TypeError, ValueError):
        raise ApiError(400, 'days must be a whole number from 1 to 31')
    if not 1 <= days <= 31:
        raise ApiError(400, 'days must be a whole number from 1 to 31')
    end = timezone.now()
    start = end - timedelta(days=days)
    items, note = report_threats.top(scope, start, end)
    return {'scope': {'kind': scope.kind, 'slug': scope.slug, 'name': scope.label}, 'days': days,
            'period': {'start': start.isoformat(), 'end': end.isoformat(), 'label': report_schedule.period_label(start, end, 'UTC')}, 'items': items, 'note': note}


def get_zero_wire(ctx, params=None):
    """Whether the Zero Wire briefings are on, and (for an App Admin) when they were last read and why a read failed."""
    from cveFeed.models import ReportingSettings, ZeroWireBriefing
    from cveFeed import license_safe
    row = ReportingSettings.current()
    out = {'enabled': row.zero_wire_enabled}
    if ctx.user.is_superuser:  # hosted_off: CVENGINE_HOSTED_LICENSE_SAFE keeps it off whatever the switch says
        out.update(hosted_off=license_safe.enabled(), synced_at=row.zero_wire_synced_at.isoformat() if row.zero_wire_synced_at else None, error=row.zero_wire_error, briefings=ZeroWireBriefing.objects.count())
    return out


def set_zero_wire(ctx, body):
    """An App Admin, in the web interface, switches the Zero Wire briefings on or off. A token is refused: it changes what the server fetches."""
    from cveFeed.models import ReportingSettings
    from tenancy import audit
    if ctx.token is not None:
        raise ApiError(403, 'a person switches the Zero Wire briefings on or off, in the web interface (Reporting); a token may not')
    if not ctx.user.is_superuser:
        raise ApiError(403, 'only an App Admin can switch the Zero Wire briefings on or off')
    if not isinstance(body, dict) or not isinstance(body.get('enabled'), bool):
        raise ApiError(400, 'send {"enabled": true} or {"enabled": false}')
    row = ReportingSettings.objects.first() or ReportingSettings()
    changed = row.pk is None or row.zero_wire_enabled != body['enabled']
    row.zero_wire_enabled, row.updated_by = body['enabled'], ctx.user
    row.save()
    if changed:
        audit.record(ctx.user, 'reporting.zero_wire', 'on' if body['enabled'] else 'off', enabled=body['enabled'])
    return get_zero_wire(ctx)
