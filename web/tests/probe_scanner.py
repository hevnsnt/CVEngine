"""A fake Sentinel's ``http_probe`` answer for tests: each planned probe of a task run by the scanner library's own ``run_http_probe`` (the code a
real Sentinel runs, from the pinned ``cvengine-scanner``; this server carries no copy of it) over a ``get(url)`` the test supplies instead of a
network. The scanner's own requests, redirects and gates are tested in the Sentinel repository (cvengine_scanner/tests/probes/test_probes.py)."""
from cvengine_scanner.probes import version_probes


def result(task, get):
    """The contract's ``http_probe`` result for ``task``: one row per planned probe, its observations, or its error when the read raised."""
    rows = []
    for planned in task['target']['probes']:
        try:
            found = version_probes.run_http_probe(planned['probe'], planned['base'], set(planned['allowed']), get=get, sleep=lambda seconds: None)
        except Exception as exc:  # noqa: BLE001 - a probe that crashed is reported as an error, as the scanner reports one
            rows.append({'id': planned['id'], 'observations': [], 'error': type(exc).__name__})
            continue
        rows.append({'id': planned['id'], 'observations': found})
    return {'outcome': 'done', 'probes': rows, 'touched': [planned['host'] for planned in task['target']['probes']], 'refused': []}


def not_found(url):
    """A site that answers every page with an empty 404 (no WordPress, no software to name)."""
    return {'status': 404, 'headers': {}, 'body': '', 'title': '', 'challenge': '', 'server': '', 'powered_by': '', 'content_type': '',
            'final_url': url, 'url': url}


def start(testcase, get=None, kinds=(), responders=None, **options):
    """A started fake Sentinel that serves ``http_probe`` (plus any ``kinds``) for ``testcase``: each probe of a task is run by the scanner library over
    ``get(url)`` (default: ``not_found``), the way a real Sentinel answers it. ``responders`` and ``options`` go to ``FakeScanner`` as they are."""
    from tests.fake_scanner import FakeScanner
    answers = {'http_probe': lambda task: result(task, get or not_found)}
    answers.update(responders or {})
    return FakeScanner(kinds=['http_probe', *kinds], responders=answers, **options).start_for(testcase)


def run_http_probe(probe_id, base, allowed, get, sleep=None):
    """The observations one http probe reads over ``get(url)`` (a page by URL), by the scanner library's own ``run_http_probe``: the code a Sentinel
    runs, which is where the reading lives (this server keeps no copy). The tests that assert what a page makes the probe read use it; the tests of what the
    server does with the reading go through ``start`` and the real dispatcher."""
    return version_probes.run_http_probe(probe_id, base, set(allowed), get=get, sleep=sleep or (lambda seconds: None))
