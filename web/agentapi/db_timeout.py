"""A database statement cut off by the web service's statement timeout (``CVENGINE_WEB_STATEMENT_TIMEOUT_MS``, review 2 F2).

Postgres answers it with SQLSTATE 57014 (query_canceled). It is not a bug in the caller's request or in the code: the request was too big for the time a
web request may take, so the API answers 503 with a plain message and the MCP answers a tool error, and a caller narrows the request and asks again."""
MESSAGE = 'the database could not answer this request in time: narrow it (fewer terms, a smaller project, a smaller page) and ask again'


def hit(exc):
    """True when ``exc`` (or the error it wraps) is a statement the database cancelled for running too long."""
    seen = 0
    while exc is not None and seen < 6:
        if getattr(exc, 'pgcode', None) == '57014' or type(exc).__name__ == 'QueryCanceled':
            return True
        exc, seen = exc.__cause__ or exc.__context__, seen + 1
    return False
