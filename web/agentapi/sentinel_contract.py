"""The result contract between cvENGINE and a Sentinel, as data.

``sentinel_contract.json`` is a JSON Schema (2020-12) of what a Sentinel sends back for each task kind. It is the one file both sides
read: the Sentinel repo takes a copy at the version it targets and validates its own results against it, and this repo's tests tie it
to the limits the broker enforces (``sentinel_broker``) and to one fixture per kind. A change a client must follow bumps
``contract_version``. The server stays strict whatever a client sends (``sentinel_broker.clean_result``); the contract is what a
correct client keeps to, so the server never has to clip or drop anything of a good Sentinel's."""
import json
from pathlib import Path

PATH = Path(__file__).with_name('sentinel_contract.json')


def load():
    return json.loads(PATH.read_text())


def version():
    return load()['contract_version']


def result_schema(kind):
    """A self-contained schema for the result of a ``kind`` task (``$defs`` included, so a validator needs nothing else)."""
    doc = load()
    if kind not in doc['$defs']['results']:
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/results/{kind}', '$defs': doc['$defs']}
