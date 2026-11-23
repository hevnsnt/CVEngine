"""The scans that make up each domain's current inventory (correlation.latest_scan_q), read in one small statement.

latest_scan_q used to embed three subqueries over the finished scans (the newest full scan of each domain, the host-pipeline scans after it, the
domains with a full scan) in every host, match, finding and count statement. The planner could not use those sets to reach the rows (it read every
host through an index in name order and filtered 25,000 of 31,000 away), ran a window over every finished scan and seq scanned the scan table twice
per statement: 52,000 buffers and about 140 ms for the bare id query on a live install, 0.8 to 3.8 s inside real statements.

Now the lookup ``__in_current_scans`` reads the sets when its statement is compiled (``current_scan_sets``: one statement over two partial indexes,
startScan 0029, about 35 buffers) and writes them into the statement as array literals, so the planner reaches the current rows by the scan index
(about 4,000 buffers). The sets are read again for every statement, so a queryset evaluated later (a page of a long walk) sees the scans as they are
then, exactly as the subqueries did; every lookup of one statement (its subqueries too) shares one read.
"""
import sys
from collections import namedtuple

from django.core.exceptions import EmptyResultSet
from django.db.models import ForeignKey, Lookup

ScanSets = namedtuple('ScanSets', 'latest_full after_full current full_domains unfull_domains')
ScanSets.__doc__ = """``latest_full``: the newest successful full scan of each domain that has one. ``after_full``: the successful host-pipeline scans
newer than their domain's newest full scan (every one, for a domain without a full scan). ``current``: both. ``full_domains``: the domains with a
successful full scan. ``unfull_domains``: every other domain. Frozensets of ids."""

_MEMO = '_cvengine_current_scan_sets'
_COMPILER_CODES = None


def current_scan_sets(connection):
    """The ids latest_scan_q needs (``ScanSets``), read in one statement. The two scan filters are the ORM's own, so they read the partial indexes
    ``scan_done_full_idx`` and ``scan_done_pipe_idx`` (index only, no window, no seq scan of the scan table), and the definitions are the ones
    latest_scan_q used before: a scan is finished when its status is 2, a full scan when its tasks do not name the host pipeline (NULL tasks count
    as full), and a host-pipeline scan is after the full scan when its id is greater than the newest full scan of its domain."""
    from cveFeed.discovery import HOST_PIPELINE_TASK
    from startScan.models import ScanHistory
    from targetApp.models import Domain

    # ScanHistory.objects is scoped to the request's projects (tenancy.scope) like the subqueries this replaces; an empty scope compiles to nothing.
    done = ScanHistory.objects.filter(scan_status=2)
    full_sql, full_params = _sql(done.exclude(tasks__contains=[HOST_PIPELINE_TASK]).order_by('domain_id', '-id').distinct('domain_id')
                                 .values_list('domain_id', 'id'))  # the newest of each domain
    pipe_sql, pipe_params = _sql(done.filter(tasks__contains=[HOST_PIPELINE_TASK]).order_by().values_list('id', 'domain_id'))
    # Every domain, unscoped: "a domain without a full scan" stands for "not a domain with one", which the previous filter said of any domain.
    domain_sql, domain_params = _sql(Domain._base_manager.order_by().values_list('id'))
    sql = (f'WITH full_last (domain_id, last) AS ({full_sql}), pipeline (id, domain_id) AS ({pipe_sql}) '
           'SELECT (SELECT array_agg(last) FROM full_last), (SELECT array_agg(domain_id) FROM full_last), '
           '(SELECT array_agg(p.id) FROM pipeline p LEFT JOIN full_last f ON f.domain_id = p.domain_id WHERE f.last IS NULL OR p.id > f.last), '
           f'(SELECT array_agg(d.id) FROM ({domain_sql}) d (id) WHERE NOT EXISTS (SELECT 1 FROM full_last f WHERE f.domain_id = d.id))')
    with connection.cursor() as cursor:
        cursor.execute(sql, (*full_params, *pipe_params, *domain_params))
        latest_full, full_domains, after_full, unfull_domains = (frozenset(ids or ()) for ids in cursor.fetchone())
    return ScanSets(latest_full, after_full, latest_full | after_full, full_domains, unfull_domains)


def _sql(queryset):
    try:
        return queryset.query.sql_with_params()
    except EmptyResultSet:  # a scope with no project: no scan is finished in it
        return 'SELECT NULL::integer, NULL::integer WHERE false', ()


def _forget_sets(execute, sql, params, many, context):
    """A statement ran on the connection: drop the shared sets (and the compile frame they hold) at once."""
    setattr(context['connection'], _MEMO, None)
    return execute(sql, params, many, context)


def _outermost_compile():
    """The frame of the outermost SQL compiler running in this thread: the statement being built. A subquery (an ``Exists``, an ``__in`` of a
    queryset) is compiled inside its outer statement's frame, so every lookup of one statement finds the same frame, and the next statement
    another one. None when no compiler is running."""
    global _COMPILER_CODES
    if _COMPILER_CODES is None:
        from django.db.models.sql import compiler as sql_compiler
        classes = (sql_compiler.SQLCompiler, sql_compiler.SQLInsertCompiler, sql_compiler.SQLDeleteCompiler, sql_compiler.SQLUpdateCompiler,
                   sql_compiler.SQLAggregateCompiler)
        _COMPILER_CODES = frozenset(getattr(cls, name).__code__ for cls in classes for name in ('as_sql', 'execute_sql', 'pre_sql_setup')
                                    if name in vars(cls))
    outer, frame = None, sys._getframe(1)
    while frame is not None:
        if frame.f_code in _COMPILER_CODES:
            outer = frame
        frame = frame.f_back
    return outer


def sets_for_statement(connection):
    """The sets for the statement being compiled on ``connection``: read once, then shared by its other lookups (the outer filter and its
    subqueries), and read again for the next statement. Keyed by the outermost compiler frame, so whether sets are shared never depends on timing,
    and by the request's scope (tenancy.scope)."""
    from tenancy import scope

    allowed = scope.current_allowed()
    key = (_outermost_compile(), None if allowed is None else frozenset(allowed))
    memo = getattr(connection, _MEMO, None)
    if key[0] is not None and memo is not None and memo[0][0] is key[0] and memo[0][1] == key[1]:
        return memo[1]
    if _forget_sets not in connection.execute_wrappers:
        connection.execute_wrappers.append(_forget_sets)
    sets = current_scan_sets(connection)
    setattr(connection, _MEMO, (key, sets))
    return sets


class InCurrentScans(Lookup):
    """``column = ANY('{1,2,3}'::integer[])`` with one of the ``ScanSets`` (named by the right-hand side, ``scan_history_id__in_current_scans=
    'current'``), read when the statement is compiled. One array literal: ``__in`` with a list writes one parameter per id, and PostgreSQL plans
    each as its own constant (10 to 15 ms of planning with 2,000 scan ids; about 6 this way). A NULL column is not a member, as with ``IN``."""

    lookup_name = 'in_current_scans'
    prepare_rhs = False

    def get_prep_lookup(self):
        if self.rhs not in ScanSets._fields:
            raise ValueError(f'in_current_scans takes one of {ScanSets._fields}, not {self.rhs!r}')
        return self.rhs

    def as_sql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        ids = getattr(sets_for_statement(connection), self.rhs)
        return f'{lhs} = ANY(%s::integer[])', (*lhs_params, '{%s}' % ','.join(str(int(i)) for i in sorted(ids)))


ForeignKey.register_lookup(InCurrentScans)
