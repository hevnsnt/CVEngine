"""A fake Sentinel's ``route_probe`` answer for tests: each URL of a task read by ``route_auth.analyse`` (the rule the scanner carries a copy of),
as the contract's row. The scanner's own second look at a path that cannot exist (``catch_all``) and its script reads are the Sentinel's
(cvengine_scanner/tests/probes/test_routes.py); a test that needs those states reports them itself."""
from cveFeed import route_auth as ra


def rows_for(task, site, scripts=None):
    """``(rows, touched)`` for the ``route_probe`` ``task``: ``site(url)`` is the probe answer of one route (a dict as the scanner library's ``probe_url`` returns);
    an ``OSError`` from it is a route reported with its error."""
    rows = []
    for entry in task['target']['hosts']:
        for url in entry['urls']:
            try:
                got = ra.analyse(site(url))
                if scripts is not None and got['evidence'].get('page_scripts'):  # the scanner reads the front page's scripts (``read_scripts``)
                    read_scripts(got, lambda target, **_kw: site(target), 0, **scripts)
            except OSError as exc:
                rows.append({'id': url, 'error': f'{type(exc).__name__}: {exc}'})
                continue
            rows.append({'id': url, 'status': got['status'], 'title': got['title'], 'content_type': got['content_type'], 'state': got['state'],
                         'evidence': {k: v for k, v in got['evidence'].items() if k != 'page_scripts'}, 'sensitive': got['sensitive'],
                         'sensitive_score': got['sensitive_score'], 'bytes': got['bytes'],
                         'credentials': [{'type': t, 'value': v} for t, v in got['credentials']]})
    return rows, [entry['host'] for entry in task['target']['hosts']]


def result(task, site, scripts=None):
    """``scripts``: keyword arguments of ``read_scripts`` (``project``, ``target``, ``reader``) when the scanner reads the front page's scripts too."""
    rows, touched = rows_for(task, site, scripts)
    return {'outcome': 'done', 'routes': rows, 'touched': touched, 'refused': []}


# --- the front page's scripts, read the way the scanner reads them (the server's own copy of this wrapper went with its local route check) ---------

ROOT_READ_BYTES = ra.MAX_READ_BYTES  # a front page is read this far (its footer scripts are the host's too); a page still longer is marked truncated


def read_scripts(result, probe, scan_id, budget=None, project=None, gate=None, reader=None, target=None):
    """What the scanner does with a front page ``result`` (``route_auth.analyse``): read the scripts the page loads through ``js_libraries.read_page``
    over ``probe(url)`` (the library reader's own vetting, budgets and cache) and put the library records and the fingerprints they give into the
    result's evidence, as the Sentinel's route check reports them (cvengine_scanner/probes/routes.py). Used by the scenario tests that replay a live
    site through the library correlation and closure, which stay on the server."""
    import time

    from cveFeed import js_libraries
    from cvengine_scanner import fingerprint
    from reNgine import resources
    evidence = result.get('evidence') or {}
    page = evidence.pop('page_scripts', None) or {}
    entries, page_url = page.get('scripts') or [], page.get('page') or ''
    if not entries:
        return
    budget = budget if budget is not None else {'left': js_libraries.MAX_SCRIPTS_PER_HOST}
    coverage = {}
    records = js_libraries.read_page(entries, page_url, probe, js_libraries.vetter(page_url, project, gate, target), budget,
                                     before_each=lambda: time.sleep(ra.PER_REQUEST_GAP), stop=lambda: resources.abort_requested(scan_id),
                                     reader=reader, project=project, coverage=coverage)
    if isinstance(evidence.get('script_page'), dict):  # how many of the page's scripts were read whole: a script not read may hold anything
        evidence['script_page']['unread'] = max(0, coverage.get('scripts', 0) - coverage.get('read', 0))
    resolved = {r['product'].lower() for r in records.values()}
    hints = {f['name'] for f in evidence.get('fingerprints') or []
             if f.get('source') == 'script:filename' and f['name'].split(':', 1)[0].strip().lower() in resolved}
    kept = [f for f in evidence.get('fingerprints') or [] if f['name'] not in hints]
    found = fingerprint.extend(kept, js_libraries.names_of(records))
    if records:
        evidence['libraries'] = records
    if found:
        evidence['fingerprints'] = found
        evidence['fingerprint_names'] = [f['name'] for f in found]
    else:
        evidence.pop('fingerprints', None)
        evidence.pop('fingerprint_names', None)
