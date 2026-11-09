"""Where a slow dashboard request spent its time, visible without a profiler.

Every GET of the dashboard's own pages and APIs (``/cve/...`` and ``/api/v1/projects/...``) answers with a ``Server-Timing`` header that the browser
shows in the Network panel's Timing tab::

    Server-Timing: total;dur=1840.2, db;dur=1522.9;desc="38 queries", snap;desc="project snapshots, as of 41 s, 1 missing"

``total`` is the time inside the application (before the proxy and the network), ``db`` the time the database statements took and how many there
were, and each ``note(...)`` a view leaves says where the answer came from (a stored snapshot, how old, or computed in the request). A request that
takes longer than ``SLOW_SECONDS`` also writes one warning line, so a slowdown can be diagnosed from a screenshot of the devtools row and the log::

    slow request GET /cve/api/stats 200 4.21s db=3.10s queries=38 snap=project snapshots, as of 41 s

The line carries the path only (no query string: it can hold search terms), the status, the total, the database time, the statement count and
the notes. The counting wraps the database cursor of the request's own thread, so it costs a clock read per statement and works with DEBUG off.
"""
import logging
import threading
import time

from django.db import connection

logger = logging.getLogger(__name__)
SLOW_SECONDS = 1.0
_local = threading.local()


def note(name, text=''):
    """Leave a note for the Server-Timing header and the slow-request line of the request running in this thread (a no-op outside one)."""
    notes = getattr(_local, 'notes', None)
    if notes is not None:
        notes.append((str(name), str(text)))


def wanted(request):
    path = request.path
    return request.method == 'GET' and (path.startswith('/cve/') or path.startswith('/api/v1/projects/')) and path != '/cve/api/alive'


class ServerTimingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not wanted(request):
            return self.get_response(request)
        stat = {'n': 0, 'seconds': 0.0}

        def count(execute, sql, params, many, context):
            started = time.perf_counter()
            try:
                return execute(sql, params, many, context)
            finally:
                stat['n'] += 1
                stat['seconds'] += time.perf_counter() - started
        _local.notes = []
        started = time.perf_counter()
        try:
            with connection.execute_wrapper(count):
                response = self.get_response(request)
        finally:
            notes, _local.notes = _local.notes, None
        total = time.perf_counter() - started
        parts = [f'total;dur={total * 1000:.1f}', f'db;dur={stat["seconds"] * 1000:.1f};desc="{stat["n"]} queries"']
        for name, text in notes:
            clean = ''.join(c for c in text if c not in '"\\\r\n')[:120]
            parts.append(f'{"".join(c for c in name if c.isalnum() or c in "-_")};desc="{clean}"' if clean else "".join(c for c in name if c.isalnum() or c in "-_"))
        try:
            response['Server-Timing'] = ', '.join(parts)
        except Exception:  # noqa: BLE001 - a response that refuses headers is not worth a failed request
            pass
        if total > SLOW_SECONDS:
            extra = ' '.join(f'{n}={t}' if t else n for n, t in notes)
            logger.warning('slow request %s %s %s %.2fs db=%.2fs queries=%d %s', request.method, request.path, getattr(response, 'status_code', '?'),
                           total, stat['seconds'], stat['n'], extra)
        return response
