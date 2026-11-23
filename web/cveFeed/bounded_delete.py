"""Large deletes in bounded, restartable steps.

Django cascades a delete in Python: ``Project.delete()`` collects every target, scan, host copy, finding, match, endpoint and activity row under
it and deletes them all in one transaction, and for a model with ``post_delete`` receivers (Subdomain, Domain, HostScreenshot) it loads every
full row first. On a big project that is hundreds of thousands of rows in one transaction, statements that can reach the web statement timeout,
and a failure that throws away all the work done.

``drain`` deletes the rows of a queryset ``batch`` at a time, smallest id first, each batch in a transaction of its own. Every batch is the
model's own Django delete on a list of ids, so its cascades, ``SET_NULL`` updates and ``post_delete`` hooks (screenshot files, cache drops) run
exactly as they would in one big delete; only the transactions are smaller. ``drain_below`` drains, children before parents, every model a
delete of some rows cascades to, and leaves those rows (and any model in ``keep``) for the caller's own final delete, which then finds little or
nothing left to collect. Every row drained is one the final delete would have removed (only ``CASCADE`` links are followed), so the rows that
go and the rows that stay are the same; what changes is that a failure part way leaves the work already committed in place, and running the
same delete again finishes it.
"""
import time

from django.db import IntegrityError, models, transaction

BATCH = 2000


def _cascade_children(model):
    """``(child model, field name)`` for every non many-to-many model holding a ``CASCADE`` key to ``model`` (hidden ``related_name='+'`` keys
    included, as Django's collector does). Automatic many-to-many link tables are left out: the collector deletes them with one statement per
    batch of their parent."""
    for rel in model._meta.get_fields(include_hidden=True):
        if not (rel.auto_created and not rel.concrete and (rel.one_to_many or rel.one_to_one)):
            continue
        if rel.on_delete is not models.CASCADE or rel.related_model._meta.auto_created:
            continue
        yield rel.related_model, rel.field.name


def plan(model, keep=(), only=None):
    """``[(child model, lookup to model)]`` for the models a delete of ``model`` rows cascades to, children before parents. ``keep`` models are
    passed through (their own children are listed) but not listed; with ``only`` just those models are listed."""
    paths, queue = {model: ''}, [model]
    while queue:  # breadth first: the shortest chain of CASCADE keys to the root
        parent = queue.pop(0)
        for child, field in _cascade_children(parent):
            if child not in paths:
                paths[child] = f'{field}__{paths[parent]}' if paths[parent] else field
                queue.append(child)
    reached = [m for m in paths if m is not model]
    children = {m: {c for c, _ in _cascade_children(m) if c in paths and c is not m} for m in reached}
    ordered, done = [], set()
    while len(done) < len(reached):
        ready = [m for m in reached if m not in done and children[m] <= done]
        if not ready:  # a cycle of CASCADE keys: start with the model furthest from the root, the collector settles the rest
            ready = [max((m for m in reached if m not in done), key=lambda m: paths[m].count('__'))]
        for m in ready:
            done.add(m)
            ordered.append(m)
    keep = set(keep)
    return [(m, paths[m]) for m in ordered if m not in keep and (only is None or m in only)]


def drain(qs, batch=None, before=None, attempts=1, pause=0.0):
    """Delete every row of ``qs``, ``batch`` rows per transaction, smallest id first. ``before(ids)``, when given, runs first inside each
    batch's transaction and may return a dict of numbers; they are summed over the committed batches. A batch failing with ``IntegrityError``
    (a scan wrote a row for what is being deleted, and the key is checked at commit) is read and tried again, up to ``attempts`` times.
    Returns ``{'rows': deleted rows of qs, **summed}``."""
    model, last, totals, batch = qs.model, None, {'rows': 0}, batch or BATCH
    while True:
        page = qs if last is None else qs.filter(pk__gt=last)
        ids, extra = [], {}
        for attempt in range(max(1, attempts)):
            try:
                with transaction.atomic():
                    ids = list(page.order_by('pk').values_list('pk', flat=True)[:batch])
                    extra = (before(ids) if before and ids else None) or {}
                    if ids:
                        model._base_manager.filter(pk__in=ids).delete()
                break
            except IntegrityError:
                if attempt >= attempts - 1:
                    raise
                time.sleep(pause)
        for key, value in {'rows': len(ids), **extra}.items():
            totals[key] = totals.get(key, 0) + value
        if len(ids) < batch:
            return totals
        last = ids[-1]


def drain_below(model, ids, keep=(), only=None, batch=None, attempts=1, pause=0.0):
    """Drain everything a delete of the ``model`` rows ``ids`` would cascade to (see ``plan``), but not those rows: the caller deletes them
    itself, with whatever it does in the same transaction (an audit row, a cache bump, file names it reads first)."""
    ids = list(ids)
    if not ids:
        return
    for child, path in plan(model, keep, only):
        drain(child._base_manager.filter(**{f'{path}__in': ids}), batch, attempts=attempts, pause=pause)
