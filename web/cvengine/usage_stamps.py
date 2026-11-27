"""Usage stamps: the writes that only record that something was used or heard from (a token's ``last_used_at``, an agent's ``last_seen``, the
machine numbers a Sentinel reports on every heartbeat). They run on the request path, before the view answers, and under a busy disk each one used to
wait for its commit's WAL flush: an API token stamp averaged 0.7 s and peaked at 123 s on production, on a row no lock holder ever touches.

Two tools, used together by each stamp:

- ``one_writer(kind, pk, stored, ttl)``: one writer at a time per stale value. Every concurrent request of the same token or agent reads the same
  stale stamp, and each used to send its own UPDATE and queue on the row lock behind the others' commits. The first one to take the value it read
  writes; the ones that arrive while it writes skip (their UPDATE would change nothing: the WHERE repeats the staleness test). The hold ends with
  the write, so a later caller that still read the old value only runs an UPDATE that matches no row. Without the cache every caller writes, as
  before.
- ``relaxed_commit()``: the write runs in its own tiny transaction with ``SET LOCAL synchronous_commit TO OFF``, so its commit does not wait for the
  WAL flush. A crash can lose the last few hundred milliseconds of stamps; it can never corrupt the row or the database (PostgreSQL's asynchronous
  commit keeps every committed state consistent). Inside a caller's open transaction it changes nothing: SET LOCAL would relax the caller's whole
  commit, so the write then runs as part of it, exactly as before.

Never use either for a security record: the audit log, a revocation, a lockout or failure counter, a one-time secret read, or anything that decides
access. Those stay fully synchronous.

The counterpart, ``durable_commit()``: the database runs with ``synchronous_commit=off`` server wide (``POSTGRES_SYNCHRONOUS_COMMIT`` in the compose
files, docs/CONFIGURATION.md), so every commit may lose its last few hundred milliseconds on a crash. The few writes that must survive one (an audit
row, a token revocation, an address ban, a validation budget reservation) run with ``SET LOCAL synchronous_commit TO ON``: their commit waits for the
WAL flush, as every commit did before. A flush covers all WAL written before it, so the writes the same request committed earlier become durable too.
"""
from contextlib import contextmanager

from django.core.cache import cache
from django.db import DEFAULT_DB_ALIAS, connections, transaction

KEY = 'cvengine:stamp:{kind}:{pk}:{stored}'


@contextmanager
def one_writer(kind, pk, stored, ttl):
    """Yields whether this caller should write the stamp of row ``pk`` that it read as ``stored``: True for one caller at a time per stored value
    (``cache.add``), held while its write and commit run and released after, so only the callers that arrive during that write skip it. ``ttl``
    bounds the hold if the process dies mid-write. Always True when the cache cannot answer."""
    key = KEY.format(kind=kind, pk=pk, stored=stored.isoformat() if stored is not None else 'none')
    try:
        won = bool(cache.add(key, 1, max(1, int(ttl))))
        held = won
    except Exception:  # noqa: BLE001 - without the cache every caller writes, as it did
        won, held = True, False
    try:
        yield won
    finally:
        if held:
            try:
                cache.delete(key)
            except Exception:  # noqa: BLE001 - the hold then ends with its ttl
                pass


@contextmanager
def relaxed_commit(using=DEFAULT_DB_ALIAS):
    """Run the block in its own transaction whose commit does not wait for the WAL flush. Yields True when it did, False when the block simply ran
    in the caller's open transaction (or on a database that is not PostgreSQL)."""
    conn = connections[using]
    if conn.in_atomic_block or conn.vendor != 'postgresql':
        yield False
        return
    with transaction.atomic(using=using):
        with conn.cursor() as cursor:
            cursor.execute('SET LOCAL synchronous_commit TO OFF')
        yield True


@contextmanager
def durable_commit(using=DEFAULT_DB_ALIAS):
    """Make the commit that holds the block's writes wait for the WAL flush, whatever the server wide ``synchronous_commit``. Outside a transaction
    the block runs in its own; inside a caller's open transaction the setting applies to that transaction (``SET LOCAL`` lasts until its commit),
    so the caller's commit, which carries the block's writes, is the durable one. No savepoint is opened, so a failing write inside a caller's
    transaction behaves exactly as before. Yields True when the setting was made, False on a database that is not PostgreSQL."""
    conn = connections[using]
    if conn.vendor != 'postgresql':
        yield False
        return
    if conn.in_atomic_block:
        with conn.cursor() as cursor:
            cursor.execute('SET LOCAL synchronous_commit TO ON')
        yield True
        return
    with transaction.atomic(using=using):
        with conn.cursor() as cursor:
            cursor.execute('SET LOCAL synchronous_commit TO ON')
        yield True
