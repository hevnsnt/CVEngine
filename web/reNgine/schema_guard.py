"""A web process that runs newer code than its database answers 503 (retry later), not 500.

An update replaces the files first (``./web`` is a bind mount into the running containers), builds, and only then migrates, so for
the minutes of the build a web worker that restarts loads the new code against the old schema and every query that names a new column
or table fails. Those requests are not bugs: they are asked again after the migration. Sentinels and other API clients back off on a
503 with ``Retry-After`` and the proxy shows its maintenance page to a browser; a 500 reads as a defect and is counted as one.

A database error only counts as "the schema is behind" when it is an undefined column or table (SQLSTATE 42703, 42P01) AND the database
really has migrations waiting, so a genuine bug that names a column that does not exist is still a 500 once everything is migrated.
"""
import logging
import time

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.utils import OperationalError, ProgrammingError
from django.http import JsonResponse

logger = logging.getLogger(__name__)

UNDEFINED = ('42703', '42P01')  # undefined_column, undefined_table
RETRY_AFTER = 30
CHECK_SECONDS = 5  # how long "migrations are waiting" is remembered, so a burst of failing requests asks the database once
_checked = {'at': 0.0, 'pending': False}
_logged = {'at': 0.0}


def migrations_pending():
    now = time.monotonic()
    if now - _checked['at'] < CHECK_SECONDS:
        return _checked['pending']
    try:
        executor = MigrationExecutor(connection)
        pending = bool(executor.migration_plan(executor.loader.graph.leaf_nodes()))
    except Exception:  # noqa: BLE001 - a database that cannot even say is not "behind", it is down: that stays a 500
        pending = False
    _checked.update(at=now, pending=pending)
    return pending


def behind(exc):
    """True when ``exc`` is a missing column or table in a database that has migrations waiting."""
    if not isinstance(exc, (ProgrammingError, OperationalError)):
        return False
    cause = exc.__cause__
    code = getattr(cause, 'pgcode', None) or getattr(cause, 'sqlstate', None)
    return code in UNDEFINED and migrations_pending()


def unavailable(request=None):
    """The 503 an API client or the proxy understands; logged once a minute, not once per request."""
    now = time.monotonic()
    if now - _logged['at'] > 60:
        _logged['at'] = now
        logger.warning('the database has migrations waiting (an update is in progress?): answering 503 until they are applied')
    response = JsonResponse({'error': 'the server is updating its database; try again shortly'}, status=503)
    response['Retry-After'] = str(RETRY_AFTER)
    return response


class SchemaBehindMiddleware:
    """Answers 503 for an unhandled database error that comes from a schema that is behind the code (see the module text)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        return unavailable(request) if behind(exception) else None
