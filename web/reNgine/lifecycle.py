"""Explicit state machines: one table per lifecycle field, and one way to change it.

A lifecycle field (a scan's ``scan_status``, a Sentinel task's ``status``, a finding's ``remediation_status``...) used to be changed by
``.update(status=...)`` calls spread over the code, each deciding on its own which states it may leave. A write made from a stale read then
moved a row backwards: a person stopped a scan and the pipeline, finishing a moment later, marked it a success. A :class:`Machine` names
the states, what people call each one, and which moves are allowed, and :meth:`Machine.move` makes a move only from a state allowed to take
it, in one conditional UPDATE, so a late or stale write changes nothing instead of overwriting a newer decision.

    SCAN = Machine('scan', 'scan_status', states={...}, moves={QUEUED: (RUNNING, ...), ...})
    SCAN.move(ScanHistory.objects.filter(pk=scan_id), SUCCESS, stop_scan_date=now)   # 1 when it moved, 0 when the scan had moved on

The tables live in :mod:`reNgine.state_machines` (one file to read every lifecycle), and docs/STATE-MACHINES.md lists each one with the code
that drives it. ``legend()`` is the same table as data, for the REST API, the MCP tools and the UI, so a state is named the same way everywhere.

No Django import at module level: the tables are importable from models, settings and plain tests.
"""
import logging

logger = logging.getLogger(__name__)


class Refused(ValueError):
    """A move the table does not allow, raised by :meth:`Machine.check` for a person's request (the API answers 409 with this text)."""

    def __init__(self, machine, current, target):
        self.machine, self.current, self.target = machine, current, target
        allowed = machine.next_states(current)
        options = ', '.join(machine.key(s) for s in allowed) if allowed else 'nothing (it is final)'
        super().__init__(f'{machine.label} is {machine.key(current)}; it cannot become {machine.key(target)} from there '
                         f'(allowed next: {options})')


class Machine:
    """One lifecycle field.

    ``states``: ``{value: (key, label, meaning)}`` in display order. ``value`` is what the database stores (an int for scans, a word
    elsewhere); ``key`` is the stable name the API and the docs use; ``label`` is what people read; ``meaning`` is one sentence on what it
    says about the thing. ``moves``: ``{from_value: (to_value, ...)}``; a state with no entry, or an empty one, is final. ``initial``: the
    states a row may be created in. A move to the state a row is already in counts as allowed only when it is listed (a finished scan that
    reports finished again refreshes its fields; a stopped one does not)."""

    def __init__(self, name, field, *, label, states, moves, initial, doc=''):
        self.name, self.field, self.label, self.doc = name, field, label, doc
        self.states = dict(states)
        self.moves = {k: tuple(v) for k, v in moves.items()}
        self.initial = tuple(initial)
        unknown = [v for src, dsts in self.moves.items() for v in (src, *dsts) if v not in self.states]
        unknown += [v for v in self.initial if v not in self.states]
        if unknown:
            raise ValueError(f'machine {name}: {sorted(map(str, set(unknown)))} are not states')

    # --- reading the table -------------------------------------------------------------------------------------------------

    def key(self, value):
        """The stable name of ``value`` (``'running'`` for a scan's 1); an unknown value is shown as itself."""
        state = self.states.get(value)
        return state[0] if state else str(value)

    def label_of(self, value):
        state = self.states.get(value)
        return state[1] if state else str(value)

    def next_states(self, value):
        return self.moves.get(value, ())

    def is_final(self, value):
        return value in self.states and not self.next_states(value)

    def allowed(self, current, target):
        return target in self.next_states(current)

    def sources(self, target):
        """Every state a row may be in for a move to ``target``."""
        return tuple(src for src, dsts in self.moves.items() if target in dsts)

    def check(self, current, target):
        """Raise :class:`Refused` unless ``current`` may become ``target`` (for a person's request: answer why, do not guess)."""
        if not self.allowed(current, target):
            raise Refused(self, current, target)

    def legend(self):
        """The table as data, in display order: ``{name, field, label, states: [{value, key, label, meaning, final, next}]}``."""
        return {'name': self.name, 'field': self.field, 'label': self.label, 'doc': self.doc,
                'states': [{'value': v, 'key': k, 'label': lab, 'meaning': meaning, 'initial': v in self.initial, 'final': self.is_final(v),
                            'next': [self.key(n) for n in self.next_states(v)]}
                           for v, (k, lab, meaning) in self.states.items()]}

    # --- changing a row ----------------------------------------------------------------------------------------------------

    def move(self, queryset, target, *, only_from=None, field=None, **also):
        """Move every row of ``queryset`` that is in a state allowed to become ``target`` (narrowed to ``only_from`` when given), setting
        ``also`` with it, in one conditional UPDATE. Returns how many rows moved: 0 means each had already moved on (a person stopped the
        scan, another worker finished it), which is the point, not an error. ``field`` names another column driven by the same table
        (a scan's stage rows store the same codes in ``status``)."""
        sources = set(self.sources(target))
        if only_from is not None:
            sources &= set(only_from)
        if not sources:
            raise ValueError(f'machine {self.name}: nothing may move to {self.key(target)}' + (f' from {only_from}' if only_from is not None else ''))
        column = field or self.field
        moved = queryset.filter(**{f'{column}__in': sources}).update(**{column: target}, **also)
        if not moved:
            logger.debug('%s: no row moved to %s (each had already left %s)', self.name, self.key(target), sorted(map(str, sources)))
        return moved

    def __repr__(self):
        return f'<Machine {self.name}>'


REGISTRY = {}


def register(machine):
    if machine.name in REGISTRY:
        raise ValueError(f'machine {machine.name} is defined twice')
    REGISTRY[machine.name] = machine
    return machine


def legends():
    """Every registered table, for the REST API and the MCP ``describe_states`` tool."""
    from reNgine import state_machines  # noqa: F401 - importing registers them
    return [m.legend() for m in REGISTRY.values()]
