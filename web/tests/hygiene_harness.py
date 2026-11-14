"""Run ``hygiene.run_hygiene`` the only way it runs now: through a Sentinel (the fake built-in scanner of ``tests.fake_scanner``).

A test that used to inject ``probe``, ``emailer`` and ``mx`` helpers into the sweep passes the same three callables here. They stand in for what the
scanner reads: ``probe(host, port)`` returns the certificate info (or None: nothing speaks TLS there), ``emailer(name)`` returns ``(findings, has_mx)``
for a mail name, ``mx(name, 'MX')`` says whether a discovered host has an MX record of its own (the scanner reviews the target's own name whatever its
records). The answer goes through the real result cleaning (``probe_results.clean_hygiene_check``) and the real stage, so what the test asserts on is
what the server stores from a Sentinel's report. Nothing in the sweep runs on this server (``assert_ran_nowhere_locally``).
"""
import datetime
from unittest import mock

from cvengine_scanner.probes import hygiene as scanner_hygiene

from tests.fake_scanner import FakeScanner

# the mail review a Sentinel makes (the library's, the code the built-in scanner runs): a test that needs the findings of a zone passes this as ``emailer``
email_findings = scanner_hygiene.email_findings


def _iso(value):
    if value is None or isinstance(value, str):
        return value
    return (value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)).isoformat()


def _cert_row(host, port, info):
    if not info:
        return {'host': host, 'port': port, 'found': False}
    cert = {k: info.get(k) or '' for k in ('subject', 'issuer', 'signature_algorithm', 'key_description', 'protocol', 'cipher', 'chain_error')}
    cert.update(sans=list(info.get('sans') or []), not_before=_iso(info.get('not_before')), not_after=_iso(info.get('not_after')),
                legacy_tls=bool(info.get('legacy_tls')))
    return {'host': host, 'port': port, 'found': True, 'cert': cert}


def responder(probe=None, emailer=None, mx=None):
    probe = probe or (lambda host, port: None)
    emailer = emailer or (lambda name: ([], False))
    mx = mx or (lambda name, rtype: False)

    def answer(task):
        target = task['target']
        certs = [_cert_row(t['host'], t['port'], probe(t['host'], t['port'])) for t in target['tls']]
        mail = []
        for item in target['mail']:
            if not item.get('always') and not mx(item['name'], 'MX'):
                continue
            findings, has_mx = emailer(item['name'])
            mail.append({'name': item['name'], 'has_mx': bool(has_mx), 'findings': [
                {'check': f.check, 'severity': f.severity, 'title': f.title, 'detail': f.detail, 'host': f.host, 'evidence': f.evidence or {}} for f in findings]})
        return {'outcome': 'done', 'certs': certs, 'mail': mail, 'touched': [t['host'] for t in target['tls']], 'refused': []}
    return answer


def run_hygiene(domain_id, probe=None, emailer=None, mx=None, hosts=None, now=None):
    """``hygiene.run_hygiene`` for ``domain_id`` with a scanner that answers from ``probe``, ``emailer`` and ``mx``."""
    from cveFeed import hygiene
    patches = (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True))
    for patch in patches:
        patch.start()
    try:
        with FakeScanner(kinds=['hygiene_check'], responders={'hygiene_check': responder(probe, emailer, mx)}):
            return hygiene.run_hygiene(domain_id, hosts=hosts, now=now)
    finally:
        for patch in patches:
            patch.stop()
