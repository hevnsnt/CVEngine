"""Keep the database's table statistics honest.

Postgres plans every query from per-table statistics. They are lost when the database crashes (the kernel killed it for memory on 11/9), and autovacuum's analyze
trigger is a percentage of the table's last known size, so a table the statistics think holds 1,313 rows (``startScan_port`` really held 612,846) almost never
gets analyzed again. Every join across it was planned for a tiny table. ``ANALYZE`` of the whole database took 17 seconds on the VPS and holds no
blocking lock. This runs it when any table with rows has no analysis at all, or none for ``MAX_AGE_DAYS``; one cheap read otherwise.
"""
import logging

from django.core.cache import cache
from django.db import connection

logger = logging.getLogger(__name__)

MAX_AGE_DAYS = 7
CHECK_KEY = 'cvengine:db_stats:checked'
CHECK_SECONDS = 600
RUN_KEY = 'cvengine:db_stats:running'
RUN_SECONDS = 1800

STALE_SQL = """
    SELECT count(*) FROM pg_stat_user_tables
    WHERE (n_live_tup + n_dead_tup) > 0
      AND coalesce(greatest(last_analyze, last_autoanalyze), 'epoch'::timestamptz) < now() - make_interval(days => %s)
"""


def stale_tables():
    """How many tables with rows have never been analyzed, or not for ``MAX_AGE_DAYS``."""
    with connection.cursor() as cursor:
        cursor.execute(STALE_SQL, [MAX_AGE_DAYS])
        return cursor.fetchone()[0]


def analyze_if_needed():
    """True when it ran ``ANALYZE``. Checks at most every ten minutes and runs one at a time. Never raises: this is housekeeping."""
    try:
        if connection.vendor != 'postgresql' or not cache.add(CHECK_KEY, 1, CHECK_SECONDS):
            return False
        stale = stale_tables()
        if not stale or not cache.add(RUN_KEY, 1, RUN_SECONDS):
            return False
        try:
            with connection.cursor() as cursor:
                cursor.execute('ANALYZE')
            logger.info('db_stats: analyzed the database (%s table(s) had no recent statistics)', stale)
        finally:
            cache.delete(RUN_KEY)
        return True
    except Exception:  # noqa: BLE001 - the next tick tries again
        logger.exception('db_stats: could not check or refresh the table statistics')
        return False
