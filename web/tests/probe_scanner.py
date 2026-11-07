"""A fake Sentinel's ``http_probe`` answer for tests: each planned probe of a task run by ``probes.run_http_probe`` (the rule the scanner carries a
copy of) over a ``get(url)`` the test supplies instead of a network. The scanner's own requests, redirects and gates are tested in the Sentinel
repository (cvengine_scanner/tests/probes/test_probes.py)."""
from cveFeed import probes


def result(task, get):
    """The contract's ``http_probe`` result for ``task``: one row per planned probe, its observations, or its error when the read raised."""
    rows = []
    for planned in task['target']['probes']:
        try:
            found = probes.run_http_probe(planned['probe'], planned['base'], set(planned['allowed']), get=get, sleep=lambda seconds: None)
        except Exception as exc:  # noqa: BLE001 - a probe that crashed is reported as an error, as the scanner reports one
            rows.append({'id': planned['id'], 'observations': [], 'error': type(exc).__name__})
            continue
        rows.append({'id': planned['id'], 'observations': found})
    return {'outcome': 'done', 'probes': rows, 'touched': [planned['host'] for planned in task['target']['probes']], 'refused': []}
