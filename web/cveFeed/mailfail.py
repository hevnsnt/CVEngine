"""What is left on the server of the email-security checks adapted from MailFail by Black Hills Information Security
(https://github.com/ACK-J/MailFail).

The reads and the evaluators are a Sentinel's (``hygiene_check``, ``cvengine_scanner.probes.mailfail``); the server stores what it reports
(``cveFeed.hygiene``, ``agentapi.probe_results``). This module keeps the credit line the activity card shows, and the IANA RDAP bootstrap and
the registrable-domain helper that ``domain_ownership`` and ``triage`` use.
"""
import time

CREDIT = 'MailFail by Black Hills Information Security (https://github.com/ACK-J/MailFail)'
HTTP_TIMEOUT = 5


# ----------------------------------------------------------------------------- RDAP

_RDAP = {'at': 0.0, 'services': None}


def _rdap_services(session):
    """IANA's RDAP bootstrap for domains (RFC 9224), cached for a day."""
    if _RDAP['services'] is None or time.time() - _RDAP['at'] > 86400:
        resp = session.get('https://data.iana.org/rdap/dns.json', timeout=HTTP_TIMEOUT, allow_redirects=False)
        resp.raise_for_status()
        _RDAP['services'], _RDAP['at'] = resp.json().get('services', []), time.time()
    return _RDAP['services']


def registrable(name):
    """The registrable domain of a mail-related name. Leading underscore labels (_spf, _dmarc, _report) are not host names,
    so they are dropped first: _spf.example.com -> example.com."""
    from targetApp.target_types import apex_domain
    labels = (name or '').strip().lower().rstrip('.').split('.')
    while labels and labels[0].startswith('_'):
        labels.pop(0)
    return apex_domain('.'.join(labels))
