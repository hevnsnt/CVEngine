"""The result contract between cvENGINE and a Sentinel, as data.

``sentinel_contract.json`` is a JSON Schema (2020-12) of what a Sentinel sends back for each task kind. It is the one file both sides
read: the Sentinel repo takes a copy at the version it targets and validates its own results against it, and this repo's tests tie it
to the limits the broker enforces (``sentinel_broker``) and to one fixture per kind. A change a client must follow bumps
``contract_version``. The server stays strict whatever a client sends (``sentinel_broker.clean_result``); the contract is what a
correct client keeps to, so the server never has to clip or drop anything of a good Sentinel's.

The kinds are listed once, in ``kind_since``: ``KINDS`` is that list, and ``SentinelTask.KINDS`` is ``KINDS``. Every other per-kind table (the
cleaners, the dispatch budgets, ``$defs.results`` and ``$defs.targets``) is held to it by ``tests.test_sentinel_contract``.

Frozen fixtures. ``tests/fixtures/sentinel_results/`` holds one good result per kind at the current ``contract_version``. Bumping
``contract_version`` copies the then-current fixtures, unchanged, into ``v<N>/`` (``v1/`` is the first set, and ``waf.json``, which arrived in 2,
joins ``v2/``). A frozen set is never edited again, and the server keeps accepting every one of them down to ``min_supported_contract_version``:
a Sentinel one release behind sends exactly what it sent before, and ``tests.test_sentinel_contract`` runs each frozen set through
``sentinel_broker.clean_result`` and this schema."""
import json
from pathlib import Path

PATH = Path(__file__).with_name('sentinel_contract.json')


def load():
    return json.loads(PATH.read_text())


KINDS = tuple(load()['kind_since'])  # every task kind, in the order the file lists them


def version():
    return load()['contract_version']


def min_supported():
    """The oldest contract version a Sentinel may declare and still be offered work. The server speaks the current contract and this one (the
    previous), so an external Sentinel that is one release behind keeps working while it is updated."""
    return load()['min_supported_contract_version']


def kind_since(kind):
    """The contract version that introduced ``kind``: a Sentinel declaring an older one cannot run it."""
    return load()['kind_since'][kind]


def can_run(reported, kind):
    """Whether a Sentinel that declared contract version ``reported`` (``None``: it never said, which is every client from before the field,
    and is taken to speak version 1) can be handed a ``kind`` task. A kind this file does not know is never offered."""
    reported = 1 if reported is None else reported
    try:
        return reported >= max(min_supported(), kind_since(kind))
    except KeyError:
        return False


def state(reported):
    """``unreported`` (an older client), ``current``, ``previous`` (still supported, one release behind), ``unsupported`` (older than the server
    still speaks), or ``newer`` (it declares a contract this server does not know yet; it is offered what this server can describe)."""
    if reported is None:
        return 'unreported'
    if reported > version():
        return 'newer'
    if reported == version():
        return 'current'
    return 'previous' if reported >= min_supported() else 'unsupported'


def reply():
    """What a Sentinel is told in a register or heartbeat answer, so it can tell for itself whether it is behind."""
    return {'version': version(), 'min_supported': min_supported()}


def result_schema(kind):
    """A self-contained schema for the result of a ``kind`` task (``$defs`` included, so a validator needs nothing else)."""
    doc = load()
    if kind not in doc['$defs']['results']:
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/results/{kind}', '$defs': doc['$defs']}


def target_schema(kind):
    """A self-contained schema for the ``target`` the server hands a Sentinel for a ``kind`` task."""
    doc = load()
    if kind not in doc['$defs']['targets']:
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/targets/{kind}', '$defs': doc['$defs']}
