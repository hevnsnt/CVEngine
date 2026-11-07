"""What stays of the MailFail email-security checks (adapted from MailFail by Black Hills Information Security,
https://github.com/ACK-J/MailFail) on the server: the credit line that goes with the findings, and the registry (RDAP) readers. The checks
themselves read the target's DNS and its MTA-STS policy, so a Sentinel runs them (the ``hygiene_check`` kind, ``cvengine_scanner.probes.mailfail``);
this server evaluates nothing about a domain by asking it.
"""
import time

CREDIT = 'MailFail by Black Hills Information Security (https://github.com/ACK-J/MailFail)'
HTTP_TIMEOUT = 5


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
