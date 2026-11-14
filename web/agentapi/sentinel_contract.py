"""The result contract between cvENGINE and a Sentinel, as data.

``sentinel_contract.json`` is a JSON Schema (2020-12) of what a Sentinel sends back for each task kind. Its one source of truth is the
scanner library (``cvengine_scanner.contract``, repo hevnsnt/cvENGINE-sentinel), which this server installs at the commit pinned in
``web/requirements.txt``; this module reads it from the installed library and holds no copy. A contract change lands as a Sentinel pull
request first, then the server bumps that pin (docs/SENTINELS.md, "The result contract"). This repo's tests tie the file to the limits the broker enforces (``sentinel_broker``) and to one fixture per kind. A change a client must follow bumps
``contract_version``. The server stays strict whatever a client sends (``sentinel_broker.clean_result``); the contract is what a
correct client keeps to, so the server never has to clip or drop anything of a good Sentinel's.

The kinds are listed once, in ``kind_since``: ``KINDS`` is that list, and ``SentinelTask.KINDS`` is ``KINDS``. Every other per-kind table (the
cleaners, the dispatch budgets, ``$defs.results`` and ``$defs.targets``) is held to it by ``tests.test_sentinel_contract``. A streamed kind
(``STREAMED``: ``bbot_discovery``, contract version 3) also has ``$defs.partials``: the batches it posts while it runs.

Frozen fixtures. ``tests/fixtures/sentinel_results/`` holds one good result per kind at the current ``contract_version``. Bumping
``contract_version`` copies the then-current fixtures, unchanged, into ``v<N>/`` (``v1/`` is the first set, and ``waf.json``, which arrived in 2,
joins ``v2/``, copied when version 3 added ``bbot_discovery`` and ``secrets_scan``). A frozen set is never edited again, and the server keeps accepting every one of them down to ``min_supported_contract_version``:
a Sentinel one release behind sends exactly what it sent before, and ``tests.test_sentinel_contract`` runs each frozen set through
``sentinel_broker.clean_result`` and this schema."""
from cvengine_scanner import contract as _library

PATH = _library.PATH  # the file inside the installed library (read-only: it is the library's, not this repo's)


_cached = {'stamp': None, 'doc': None}


def load():
    """The contract document. Read and parsed once per version of the file (its size and modification time are checked, a ``stat`` call), not once per call: the
    contract is asked about for every Sentinel's rights (``can_run``, 8 kinds each), every heartbeat and every result, and parsing the 60 KB file each time was
    45% of the Sentinels page and most of a heartbeat. The document is shared: read it, never change it."""
    try:
        info = PATH.stat()
        stamp = (info.st_mtime_ns, info.st_size)
    except OSError:
        return _library.load()
    if _cached['stamp'] != stamp or _cached['doc'] is None:
        _cached['doc'], _cached['stamp'] = _library.load(), stamp
    return _cached['doc']


KINDS = tuple(load()['kind_since'])  # every task kind, in the order the file lists them
STREAMED = tuple(load()['$defs']['partials'])  # the kinds that post partial results while they run (``partial_schema``) before the result that closes them


def version():
    return load()['contract_version']


def min_supported():
    """The oldest contract version a Sentinel may declare and still be offered work. The server speaks the current contract and this one (the
    previous), so an external Sentinel that is one release behind keeps working while it is updated."""
    return load()['min_supported_contract_version']


def kind_since(kind):
    """The contract version that introduced ``kind``: a Sentinel declaring an older one cannot run it."""
    return load()['kind_since'][kind]


def external_since(kind):
    """The contract version from which a Sentinel that is not the built-in scanner may be offered ``kind``, one of the kinds the built-in scanner keeps
    while it is in use (``external_since``, contract 4: ``nuclei_validate`` 4, ``path_probe`` 3; ``agentapi.ai_checks``), or ``None``: never offered
    outside. Read fail closed: an installed library whose contract has no such table (older than 4) offers neither kind outside, as before.
    (The library's own ``contract.external_since`` is not called, so an older installed library cannot fail on it.)"""
    since = (load().get('external_since') or {}).get(kind)
    return since if isinstance(since, int) and not isinstance(since, bool) else None


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


OLDER_NOTE = 'This scanner is older than this server needs, update it'
NOTES = {
    'unsupported': OLDER_NOTE,
    'previous': 'This scanner is one release behind this server: it is offered the kinds it can run. Update it for the newest ones',
    'newer': 'This scanner is newer than this server (fine): it is offered the kinds this server knows',
}


def note(reported):
    """The sentence a page shows for a Sentinel that declared contract version ``reported``, or ``''`` when there is nothing to say (current, or an old
    client the server still serves). A Sentinel older than ``min_supported`` is offered NO work (``can_run`` is false for every kind), and says so. One
    that never reported a version is taken as version 1, so it gets the same sentence when the server no longer speaks 1."""
    found = state(reported)
    if found == 'unreported' and min_supported() > 1:
        return OLDER_NOTE
    return NOTES.get(found, '')


def reply():
    """What a Sentinel is told in a register or heartbeat answer, so it can tell for itself whether it is behind."""
    return {'version': version(), 'min_supported': min_supported()}


def result_schema(kind):
    """A self-contained schema for the result of a ``kind`` task (``$defs`` included, so a validator needs nothing else)."""
    doc = load()
    if kind not in doc['$defs']['results']:
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/results/{kind}', '$defs': doc['$defs']}


def partial_schema(kind):
    """A self-contained schema for one batch of partial results a streamed ``kind`` task posts while it runs (``STREAMED``)."""
    doc = load()
    if kind not in doc['$defs'].get('partials', {}):
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/partials/{kind}', '$defs': doc['$defs']}


def target_schema(kind):
    """A self-contained schema for the ``target`` the server hands a Sentinel for a ``kind`` task."""
    doc = load()
    if kind not in doc['$defs']['targets']:
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/targets/{kind}', '$defs': doc['$defs']}
