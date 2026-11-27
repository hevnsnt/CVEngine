"""A database statement cut off by the web service's statement timeout (``CVENGINE_WEB_STATEMENT_TIMEOUT_MS``, review 2 F2).

Postgres answers it with SQLSTATE 57014 (query_canceled). It is not a bug in the caller's request or in the code: the request was too big for the time a
web request may take, so the API answers 503 with a plain message and the MCP answers a tool error, and a caller narrows the request and asks again."""
from contextlib import contextmanager

MESSAGE = 'the database could not answer this request in time: narrow it (fewer terms, a smaller project, a smaller page) and ask again'


def hit(exc):
    """True when ``exc`` (or the error it wraps) is a statement the database cancelled for running too long."""
    seen = 0
    while exc is not None and seen < 6:
        if getattr(exc, 'pgcode', None) == '57014' or type(exc).__name__ == 'QueryCanceled':
            return True
        exc, seen = exc.__cause__ or exc.__context__, seen + 1
    return False


@contextmanager
def bounded(ms):
    """A transaction (a savepoint inside a caller's) in which no statement runs longer than ``ms`` milliseconds. PostgreSQL only.

    ``SET LOCAL`` lasts until the outermost transaction ends, not until a savepoint is released, so inside a caller's transaction (a request that runs in
    one, every TestCase) the limit would outlive this block and cut off the caller's later statements (CI: a 2 second limit left by the status call cut
    off the next route's query). The limit the caller had is put back when the block ends; a block that fails rolls back to its savepoint, and that
    undoes the SET as well."""
    from django.db import connection, transaction
    nested = connection.in_atomic_block
    with transaction.atomic():
        previous = None
        with connection.cursor() as cursor:
            if nested:  # one statement reads the caller's limit and sets this block's
                cursor.execute("SELECT current_setting('statement_timeout'), set_config('statement_timeout', %s, true)", [f'{int(ms)}ms'])
                previous = cursor.fetchone()[0]
            else:
                cursor.execute('SET LOCAL statement_timeout = %s', [ms])
        yield
        if previous is not None and not connection.needs_rollback:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('statement_timeout', %s, true)", [previous])
