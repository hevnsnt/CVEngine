"""The scans that make up each domain's current inventory (correlation.latest_scan_q), read in one small statement.

latest_scan_q used to embed three subqueries over the finished scans (the newest full scan of each domain, the host-pipeline scans after it, the
domains with a full scan) in every host, match, finding and count statement. The planner could not use those sets to reach the rows (it read every
host through an index in name order and filtered 25,000 of 31,000 away), ran a window over every finished scan and seq scanned the scan table twice
per statement: 52,000 buffers and about 140 ms for the bare id query on a live install, 0.8 to 3.8 s inside real statements.

Now the sets are read once per call of latest_scan_q (``current_scan_sets``: two small partial indexes, startScan 0029, about 35 buffers) and passed
to the statement as array literals (``in_id_array``), so the planner reaches the current rows by the scan index (about 4,000 buffers). The answer is
the same: the sets are read in the same way as before, only earlier, when the filter is built instead of when its statement runs.
"""
from collections import namedtuple

from django.db import connection
from django.db.models import ForeignKey, IntegerField, Lookup, Max

ScanSets = namedtuple('ScanSets', 'latest_full after_full full_domains unfull_domains')
ScanSets.__doc__ = """``latest_full``: the newest successful full scan of each domain that has one. ``after_full``: the successful host-pipeline scans
newer than their domain's newest full scan (every one, for a domain without a full scan). ``full_domains``: the domains with a successful full scan.
``unfull_domains``: every other domain. Frozensets of ids."""


class IdArray(Lookup):
    """``column = ANY('{1,2,3}'::integer[])``: membership in a list of ids passed as ONE array literal. ``__in`` with a list writes one parameter
    per id, and PostgreSQL then parses and plans each as its own constant: with 2,000 scan ids that took 10 to 15 ms of planning per statement, the
    single literal about 6. A NULL column is not a member (the same as ``IN``)."""

    lookup_name = 'in_id_array'
    prepare_rhs = False

    def get_prep_lookup(self):
        return '{%s}' % ','.join(str(int(i)) for i in sorted(self.rhs))

    def as_sql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        return f'{lhs} = ANY(%s::integer[])', (*lhs_params, self.rhs)


ForeignKey.register_lookup(IdArray)
IntegerField.register_lookup(IdArray)


def current_scan_sets():
    """The ids latest_scan_q needs (``ScanSets``), read in one statement. The two scan filters are the ORM's own, so they read the partial indexes
    ``scan_done_full_idx`` and ``scan_done_pipe_idx`` (index only, no window, no seq scan of the scan table), and the definitions match the ones
    latest_scan_q used before: a scan is finished when its status is 2, a full scan when its tasks do not name the host pipeline (NULL tasks count
    as full), and a host-pipeline scan is after the full scan when its id is greater than the newest full scan of its domain."""
    from cveFeed.discovery import HOST_PIPELINE_TASK
    from startScan.models import ScanHistory
    from targetApp.models import Domain

    done = ScanHistory.objects.filter(scan_status=2)
    full_sql, full_params = (done.exclude(tasks__contains=[HOST_PIPELINE_TASK]).order_by().values('domain_id').annotate(last=Max('id'))
                             .values_list('domain_id', 'last').query.sql_with_params())
    pipe_sql, pipe_params = done.filter(tasks__contains=[HOST_PIPELINE_TASK]).order_by().values_list('id', 'domain_id').query.sql_with_params()
    domain_sql, domain_params = Domain.objects.order_by().values_list('id').query.sql_with_params()
    sql = (f'WITH full_last (domain_id, last) AS ({full_sql}), pipeline (id, domain_id) AS ({pipe_sql}) '
           'SELECT (SELECT array_agg(last) FROM full_last), (SELECT array_agg(domain_id) FROM full_last), '
           '(SELECT array_agg(p.id) FROM pipeline p LEFT JOIN full_last f ON f.domain_id = p.domain_id WHERE f.last IS NULL OR p.id > f.last), '
           f'(SELECT array_agg(d.id) FROM ({domain_sql}) d (id) WHERE NOT EXISTS (SELECT 1 FROM full_last f WHERE f.domain_id = d.id))')
    with connection.cursor() as cursor:
        cursor.execute(sql, (*full_params, *pipe_params, *domain_params))
        latest_full, full_domains, after_full, unfull_domains = cursor.fetchone()
    return ScanSets(frozenset(latest_full or ()), frozenset(after_full or ()), frozenset(full_domains or ()), frozenset(unfull_domains or ()))
