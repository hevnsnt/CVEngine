"""``hygiene.run_hygiene`` against a fake Sentinel that answers the way a test's own helpers say.

The hygiene sweep reads certificates and mail records on a Sentinel (the ``hygiene_check`` kind): this server asks nothing. A test that wants a
sweep to see a particular certificate or mail review passes the same three helpers the old local sweep took:

* ``probe(host, port)`` -> the certificate info (``hygiene.evaluate_cert``'s dict, dates as datetimes) or ``None`` (nothing answered there);
* ``emailer(name)`` -> ``(findings, anything)``, the mail review of a name (``hygiene.Finding`` list);
* ``mx(name, 'MX')`` -> whether a name has mail servers of its own (only the names the server did not insist on are reviewed when they have).

and the fake Sentinel reports those as the task's result.
"""
from cveFeed import hygiene
from tests.fake_scanner import FakeScanner


def _cert_row(host, port, info):
    if not info:
        return {'host': host, 'port': port, 'found': False}
    cert = {k: info.get(k) or '' for k in ('subject', 'issuer', 'signature_algorithm', 'key_description', 'protocol', 'cipher', 'chain_error')}
    cert.update({'sans': list(info.get('sans') or []), 'legacy_tls': bool(info.get('legacy_tls'))})
    for key in ('not_before', 'not_after'):
        value = info.get(key)
        cert[key] = value.isoformat() if value else None
    return {'host': host, 'port': port, 'found': True, 'cert': cert}


def responder(probe=None, emailer=None, mx=None):
    def serve(task):
        target = task['target']
        certs = [_cert_row(t['host'], t['port'], (probe or (lambda h, p: None))(t['host'], t['port'])) for t in target['tls']]
        mail = []
        for entry in target['mail']:
            if not (entry['always'] or (mx or (lambda n, t: False))(entry['name'], 'MX')):
                continue
            findings, _ = (emailer or (lambda name: ([], False)))(entry['name'])
            mail.append({'name': entry['name'], 'has_mx': bool((mx or (lambda n, t: False))(entry['name'], 'MX')) or bool(entry['always']),
                         'findings': [{'check': f.check, 'severity': f.severity, 'title': f.title, 'detail': f.detail, 'host': f.host,
                                       'evidence': f.evidence or {}} for f in findings]})
        return {'outcome': 'done', 'certs': certs, 'mail': mail, 'touched': [t['host'] for t in target['tls']], 'refused': []}
    return serve


def _testcase():
    import inspect
    import unittest
    for frame in inspect.stack()[2:]:
        owner = frame.frame.f_locals.get('self')
        if isinstance(owner, unittest.TestCase):
            return owner
    raise RuntimeError('run_hygiene of tests.hygiene_scanner is called from a test method')


def run_hygiene(domain_id, probe=None, emailer=None, mx=None, **kwargs):
    """``hygiene.run_hygiene(domain_id, **kwargs)`` with a fake Sentinel answering from ``probe``, ``emailer`` and ``mx``. The fake is started once per
    test (a second call in the same test reuses it with the new helpers) and stopped by the test's cleanup."""
    case = _testcase()
    fake = getattr(case, '_hygiene_fake', None)
    if fake is None or fake._stack is None:
        fake = case._hygiene_fake = FakeScanner(kinds=['hygiene_check']).start_for(case)
    fake.responders['hygiene_check'] = responder(probe, emailer, mx)
    return hygiene.run_hygiene(domain_id, **kwargs)
