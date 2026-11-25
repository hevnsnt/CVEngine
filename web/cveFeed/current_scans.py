"""The scans that make up each domain's current inventory (correlation.latest_scan_q), read in one small statement.

latest_scan_q used to embed three subqueries over the finished scans (the newest full scan of each domain, the host-pipeline scans after it, the
domains with a full scan) in every host, match, finding and count statement. The planner could not use those sets to reach the rows (it read every
host through an index in name order and filtered 25,000 of 31,000 away), ran a window over every finished scan and seq scanned the scan table twice
per statement: 52,000 buffers and about 140 ms for the bare id query on a live install, 0.8 to 3.8 s inside real statements.

Now the lookup ``__in_current_scans`` reads the sets when its statement is compiled (``current_scan_sets``: one statement over two partial indexes,
startScan 0029, about 35 buffers) and writes them into the statement as array literals, so the planner reaches the current rows by the scan index
(about 4,000 buffers). The sets are read again for every statement, so a queryset evaluated later (a page of a long walk) sees the scans as they are
then, exactly as the subqueries did; every lookup of one statement (its subqueries too) shares one read.

A computation that is itself a snapshot of a moment (``snapshot_cache``: the Overview, the headline counts, the situations ranking) runs inside
``shared_sets``: there every statement shares one read per connection and scope, for the length of the block. The Overview's summary read the sets
fourteen times (about 5 ms each) to answer one poll, and a scan that finishes while it is being worked out changes nothing it says.

Under a tenancy scope (``tenancy.scope``) the sets hold the scope's scans and domains only. The scans always were scoped; the domain list used to be every
domain of the install, so a request limited to one project listed every other project's domain in ``unfull_domains`` (it cannot see their full scans),
about 1,000 ids instead of 31 on a live install, and the planner then expected tens of thousands of host rows where a few hundred were current. For a
domain in the scope the answer is the same either way (it has a full scan in the scope or it has none), so every row of the scope is kept or dropped as
before; only a row of a domain outside the scope can tell the difference, and a scoped caller never reads one (every statement that uses these sets
reads its rows through the scoped managers or filters by the caller's own project ids).
"""
import contextvars
import sys
from collections import namedtuple
from contextlib import contextmanager

from django.core.exceptions import EmptyResultSet
from django.db.models import ForeignKey, Lookup

ScanSets = namedtuple('ScanSets', 'latest_full after_full current full_domains unfull_domains')
ScanSets.__doc__ = """``latest_full``: the newest successful full scan of each domain that has one. ``after_full``: the successful host-pipeline scans
newer than their domain's newest full scan (every one, for a domain without a full scan). ``current``: both. ``full_domains``: the domains with a
successful full scan. ``unfull_domains``: every other domain (of the tenancy scope, when one is active). Frozensets of ids."""

_MEMO = '_cvengine_current_scan_sets'
_COMPILER_CODES = None
_SHARED = contextvars.ContextVar('cvengine_shared_scan_sets', default=None)


@contextmanager
def shared_sets():
    """Within this block the sets are read once per connection and scope (``tenancy.scope``) and reused by every statement, instead of once per
    statement. For a read-only computation of one moment (a snapshot); nested blocks share the outer one."""
    if _SHARED.get() is not None:
        yield
        return
    token = _SHARED.set({})
    try:
        yield
    finally:
        _SHARED.reset(token)


def current_scan_sets(connection):
    """The ids latest_scan_q needs (``ScanSets``), read in one statement. The two scan filters are the ORM's own, so they read the partial indexes
    ``scan_done_full_idx`` and ``scan_done_pipe_idx`` (index only, no window, no seq scan of the scan table), and the definitions are the ones
    latest_scan_q used before: a scan is finished when its status is 2, a full scan when its tasks do not name the host pipeline (NULL tasks count
    as full), and a host-pipeline scan is after the full scan when its id is greater than the newest full scan of its domain."""
    from cveFeed.discovery import HOST_PIPELINE_TASK
    from startScan.models import ScanHistory
    from targetApp.models import Domain
    from tenancy import scope

    # ScanHistory.objects is scoped to the request's projects (tenancy.scope) like the subqueries this replaces; an empty scope compiles to nothing.
    done = ScanHistory.objects.filter(scan_status=2)
    full_sql, full_params = _sql(done.exclude(tasks__contains=[HOST_PIPELINE_TASK]).order_by('domain_id', '-id').distinct('domain_id')
                                 .values_list('domain_id', 'id'))  # the newest of each domain
    pipe_sql, pipe_params = _sql(done.filter(tasks__contains=[HOST_PIPELINE_TASK]).order_by().values_list('id', 'domain_id'))
    # The domains of the same scope as the scans (every domain when nothing scopes the call): "a domain without a full scan" stands for "not a domain
    # with one" for every domain the caller can read. A domain outside the scope is left out instead of being listed as never fully scanned, which it
    # only seemed to be because its scans are out of sight (see the module text).
    domain_sql, domain_params = _sql(scope.scope_queryset(Domain._base_manager.order_by()).values_list('id'), width=1)
    sql = (f'WITH full_last (domain_id, last) AS ({full_sql}), pipeline (id, domain_id) AS ({pipe_sql}) '
           'SELECT (SELECT array_agg(last) FROM full_last), (SELECT array_agg(domain_id) FROM full_last), '
           '(SELECT array_agg(p.id) FROM pipeline p LEFT JOIN full_last f ON f.domain_id = p.domain_id WHERE f.last IS NULL OR p.id > f.last), '
           f'(SELECT array_agg(d.id) FROM ({domain_sql}) d (id) WHERE NOT EXISTS (SELECT 1 FROM full_last f WHERE f.domain_id = d.id))')
    with connection.cursor() as cursor:
        cursor.execute(sql, (*full_params, *pipe_params, *domain_params))
        latest_full, full_domains, after_full, unfull_domains = (frozenset(ids or ()) for ids in cursor.fetchone())
    return ScanSets(latest_full, after_full, latest_full | after_full, full_domains, unfull_domains)


def _sql(queryset, width=2):
    try:
        return queryset.query.sql_with_params()
    except EmptyResultSet:  # a scope with no project: no scan is finished in it, and it holds no domain
        return 'SELECT ' + ', '.join(['NULL::integer'] * width) + ' WHERE false', ()


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
    shared = _SHARED.get()
    if shared is not None:  # inside ``shared_sets``: one read for the block
        block_key = (connection.alias, None if allowed is None else frozenset(allowed))
        if block_key not in shared:
            shared[block_key] = current_scan_sets(connection)
        return shared[block_key]
    key = (_outermost_compile(), None if allowed is None else frozenset(allowed))
    memo = getattr(connection, _MEMO, None)
    if key[0] is not None and memo is not None and memo[0][0] is key[0] and memo[0][1] == key[1]:
        return memo[1]
    if _forget_sets not in connection.execute_wrappers:
        # at the bottom of the list, never at the top: ``connection.execute_wrapper`` blocks (tenancy.snapshot, a test's counter) remove theirs with
        # ``pop()``, which takes the last one. Appended inside such a block, this hook was taken off in its place and the block's own hook stayed on the
        # connection for good: one more on every request of a web thread, each run around every later statement.
        connection.execute_wrappers.insert(0, _forget_sets)
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
