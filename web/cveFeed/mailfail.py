"""Email-security checks adapted from MailFail by Black Hills Information Security (https://github.com/ACK-J/MailFail).

MailFail is a browser extension that reviews a domain's mail setup for spoofing and takeover risks. These are its
checks, re-implemented server side for CVEngine's hygiene scan, beside the SPF / DMARC / DKIM / CAA review in
cveFeed.hygiene (which already covers MailFail's missing / multiple / +all / ?all / ptr / p=none / pct / sp / weak-key
rules). Like MailFail they only read DNS, ask public domain registries (RDAP) whether a referenced domain is registered,
and fetch the domain's own MTA-STS policy over HTTPS. Nothing sends mail or opens an SMTP connection.

Two MailFail checks need no code here: dnspython follows a CNAME at _dmarc on its own, and it joins a TXT record's
quoted strings the way RFC 7208 §3.3 says receivers must. The zone-walking (NSEC / NSEC3) and SRV / NS listings are
reconnaissance, not configuration findings, and are left out.

Evaluators are pure functions over fetched records, as in cveFeed.hygiene, so every rule is unit tested.
"""
import base64
import concurrent.futures
import logging
import os
import re
import time

from cveFeed.hygiene import HIGH, INFO, LOW, MEDIUM, Finding, _txt_value, dkim_key_bits, parse_tags

logger = logging.getLogger(__name__)

CREDIT = 'MailFail by Black Hills Information Security (https://github.com/ACK-J/MailFail)'
HTTP_TIMEOUT = 5
MAX_POLICY_BYTES = 64 * 1024
MAX_TAKEOVER_DOMAINS = 15
MAX_REPORT_DOMAINS = 10
MAX_DANE_MX = 5
# More DKIM selectors seen in the wild (on top of hygiene.DKIM_SELECTORS), and the ARC sealing selectors of the large
# mail platforms. Bounded on purpose: MailFail tries ~900 names, which is too many lookups for a server-side sweep.
EXTRA_DKIM_SELECTORS = ('s1024', 's2048', 'key1', 'key2', 'dkim1', 'm1', 'sm', 'sig1', 'smtpapi', 'everlytickey1',
                        'everlytickey2', 'mailjet', 'amazonses', 'turbo-smtp')
ARC_SELECTORS = ('arc', 'arc-20160816', 'arc-20240605', 'arcselector9901', 'arcselector10001')
DIRECT_SEND_MX = ('mail.protection.outlook.com', 'mail.protection.partner.outlook.cn')
DIRECT_SEND_REFERENCE = 'https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/'
# RFC 8624 §3.1: algorithms that MUST NOT be used for signing (ECC-GOST is also deprecated by RFC 9558)
WEAK_DNSSEC_ALGORITHMS = {1: 'RSAMD5', 3: 'DSA', 5: 'RSASHA1', 6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1', 12: 'ECC-GOST'}
RSA_DNSSEC_ALGORITHMS = {1, 5, 7, 8, 10}
CHECKS_PREFIXES = ('mx_', 'mta_sts_', 'smtp_tlsrpt_', 'dane_', 'dnssec_', 'bimi_', 'arc_', 'adsp_', 'mailchannels_')


def _finding(check, severity, title, detail, host, evidence=None, reference=''):
    evidence = {**(evidence or {}), 'credit': CREDIT}
    if reference:
        evidence['reference'] = reference
    return Finding(check, severity, title, detail, host, evidence)


def _values(records):
    return [_txt_value(r) for r in records]


def _first(values, prefix):
    return next((v for v in values if v.lower().startswith(prefix)), '')


def _misplaced(values, prefix):
    """A record that names the version tag somewhere but does not start with it: receivers ignore it."""
    return not _first(values, prefix) and next((v for v in values if prefix in v.lower()), '')


# ----------------------------------------------------------------------------- SPF

def evaluate_spf(domain, txt_records):
    values, findings = _values(txt_records), []
    bad = _misplaced(values, 'v=spf1')
    if bad:
        findings.append(_finding('spf_invalid_prefix', MEDIUM, 'SPF record does not start with v=spf1',
                                 'Receivers only read a TXT record that begins with "v=spf1" (RFC 7208 §4.5), so this one is ignored '
                                 'and the domain has no working SPF.', domain, {'record': bad}))
    spf = _first(values, 'v=spf1').lower()
    if 'include:relay.mailchannels.net' in spf:
        findings.append(_finding('spf_mailchannels', INFO, 'SPF authorises the shared MailChannels relay',
                                 'MailChannels relays mail for many customers. Publish a _mailchannels TXT record (Domain Lockdown) '
                                 'so only your own account can send as this domain.', domain, {'record': spf}))
    return findings


def spf_referenced_domains(txt_records):
    """The domains an SPF record's include: and redirect= terms name (macros left out)."""
    spf = _first(_values(txt_records), 'v=spf1')
    out = []
    for term in spf.split()[1:]:
        t = term.lstrip('+-~?')
        if t.lower().startswith(('include:', 'redirect=')):
            name = re.split('[:=]', t, 1)[1].strip().rstrip('.').lower()
            if name and '%' not in name:
                out.append(name)
    return out


# ----------------------------------------------------------------------------- DMARC

def evaluate_dmarc(domain, records):
    values, findings = _values(records), []
    host = f'_dmarc.{domain}'
    bad = _misplaced(values, 'v=dmarc1')
    if bad:
        findings.append(_finding('dmarc_invalid_prefix', MEDIUM, 'DMARC record does not start with v=DMARC1',
                                 'Receivers only use a record that begins with "v=DMARC1" (RFC 7489 §6.3), so this policy is ignored '
                                 'and the domain can be spoofed.', host, {'record': bad}))
    record = _first(values, 'v=dmarc1')
    if not record:
        return findings
    tags = parse_tags(record)
    for tag, what in (('rua', 'aggregate'), ('ruf', 'failure')):
        targets = [u.strip() for u in tags.get(tag, '').split(',') if u.strip()]
        if any(not u.lower().startswith('mailto:') for u in targets):
            findings.append(_finding(f'dmarc_{tag}_malformed', LOW, f'DMARC {tag}= is not a mailto: address',
                                     f'{what.title()} reports are only sent to mailto: URIs (RFC 7489 §6.2), so none arrive.', host,
                                     {'record': record}))
    fo = [x.strip() for x in tags.get('fo', '').split(':') if x.strip()]
    if '1' in fo and not tags.get('ruf'):
        findings.append(_finding('dmarc_fo_without_ruf', INFO, 'DMARC asks for failure reports (fo=1) but names no ruf= address',
                                 'fo=1 has no effect without a ruf= mailbox, so no failure reports are sent.', host, {'record': record}))
    return findings


def dmarc_report_domains(records):
    """The mail domains of a DMARC record's rua= and ruf= mailto: addresses."""
    record = _first(_values(records), 'v=dmarc1')
    tags = parse_tags(record) if record else {}
    out = []
    for tag in ('rua', 'ruf'):
        for uri in tags.get(tag, '').split(','):
            uri = uri.strip()
            if uri.lower().startswith('mailto:') and '@' in uri:
                name = uri.split('@', 1)[1].split('!', 1)[0].strip().rstrip('.').lower()
                if name and name not in out:
                    out.append(name)
    return out


def evaluate_report_authorization(domain, report_domain, records):
    """RFC 7489 §7.1: a report address outside the domain must publish <domain>._report._dmarc.<report domain>, or receivers
    drop the reports. A wildcard (*._report._dmarc) record answers the same lookup."""
    if _first(_values(records), 'v=dmarc1'):
        return []
    return [_finding('dmarc_report_unauthorized', MEDIUM, f'DMARC reports to {report_domain} are not authorised',
                     f'{report_domain} does not publish {domain}._report._dmarc.{report_domain} (RFC 7489 §7.1), so receivers '
                     'drop the reports and spoofing goes unseen.', f'_dmarc.{domain}', {'report_domain': report_domain})]


# ----------------------------------------------------------------------------- DKIM, ARC, ADSP

def evaluate_dkim(domain, found):
    """Extra checks on the DKIM keys found (``found`` maps selector -> record)."""
    findings = []
    for selector, record in sorted(found.items()):
        tags = parse_tags(record)
        if not tags.get('p', '').replace(' ', ''):
            continue  # revoked
        host = f'{selector}._domainkey.{domain}'
        if 'y' in [x.strip().lower() for x in tags.get('t', '').split(':')]:
            findings.append(_finding('dkim_testing_mode', LOW, f'DKIM key {selector} is in testing mode (t=y)',
                                     'Verifiers may treat mail signed with a testing key as unsigned (RFC 6376 §3.6.1). Remove t=y.',
                                     host, {'selector': selector}))
        hashes = [h.strip().lower() for h in tags.get('h', '').split(':') if h.strip()]
        if hashes and 'sha256' not in hashes:
            findings.append(_finding('dkim_sha1', MEDIUM, f'DKIM key {selector} only allows SHA-1 (h={tags.get("h")})',
                                     'SHA-1 signatures are no longer accepted by verifiers (RFC 8301). Allow sha256.', host,
                                     {'selector': selector}))
        if tags.get('k', 'rsa').strip().lower() == 'rsa' and dkim_key_bits(record) == 0:
            findings.append(_finding('dkim_invalid_key', LOW, f'DKIM key {selector} cannot be parsed',
                                     'The p= value is not a valid RSA public key, so mail signed with this selector fails DKIM.',
                                     host, {'selector': selector}))
    return findings


def evaluate_arc(domain, found):
    findings = []
    for selector, record in sorted(found.items()):
        bits = dkim_key_bits(record)
        host = f'{selector}._domainkey.{domain}'
        if 0 < bits < 1024:
            findings.append(_finding('arc_weak_key', HIGH, f'ARC key {selector} is only {bits} bits',
                                     'Keys under 1024 bits can be factored, so ARC seals can be forged. Rotate to 2048.', host,
                                     {'selector': selector, 'bits': bits}))
        elif bits == 1024:
            findings.append(_finding('arc_short_key', LOW, f'ARC key {selector} is 1024 bits', 'Rotate to 2048 bits.', host,
                                     {'selector': selector, 'bits': bits}))
    return findings


def evaluate_adsp(domain, records):
    values = [v for v in _values(records) if v and 'v=dkim1' not in v.lower() and 'v=spf1' not in v.lower()]
    if not values:
        return []
    return [_finding('adsp_present', INFO, 'Obsolete ADSP record published',
                     'ADSP was declared historic and replaced by DMARC (RFC 7489 Appendix A.5); receivers ignore it. Remove it and '
                     'rely on DMARC.', f'_adsp._domainkey.{domain}', {'record': values[0]})]


# ----------------------------------------------------------------------------- BIMI, MX, MailChannels

def evaluate_bimi(domain, records):
    """Record checks only: the logo and certificate URLs are not fetched (they are whatever the record says)."""
    values = [v for v in _values(records) if v]
    if not values:
        return []
    host, findings = f'default._bimi.{domain}', []
    record = _first(values, 'v=bimi1')
    if not record:
        return [_finding('bimi_invalid', LOW, 'BIMI record does not start with v=BIMI1',
                         'Mailbox providers ignore a BIMI record that does not begin with "v=BIMI1", so no logo is shown.', host,
                         {'record': values[0]})]
    tags = parse_tags(record)
    logo, vmc = tags.get('l', ''), tags.get('a', '')
    if logo and (not logo.lower().startswith('https://') or not logo.lower().split('?', 1)[0].endswith('.svg')):
        findings.append(_finding('bimi_logo_invalid', LOW, 'BIMI logo is not an HTTPS SVG',
                                 'BIMI requires an HTTPS link to an SVG Tiny Portable/Secure logo; raster images and plain HTTP are '
                                 'rejected.', host, {'l': logo}))
    if vmc and not vmc.lower().startswith('https://'):
        findings.append(_finding('bimi_vmc_invalid', LOW, 'BIMI certificate (a=) is not an HTTPS URL',
                                 'The mark certificate must be served over HTTPS.', host, {'a': vmc}))
    return findings


def evaluate_mx(domain, mx_hosts):
    hosts = [h.rstrip('.').lower() for h in mx_hosts]
    m365 = [h for h in hosts if h.endswith(DIRECT_SEND_MX)]
    if not m365:
        return []
    return [_finding('mx_direct_send', MEDIUM, 'Microsoft 365 mail: check that Direct Send is turned off',
                     'Mail is delivered by Microsoft 365. While Direct Send is allowed, anyone on the internet can send mail to '
                     "this domain's users that looks like it came from inside the organization. Turn it off with "
                     'Set-OrganizationConfig -RejectDirectSend $true (Exchange Online). CVEngine reads this from DNS only and '
                     'never sends mail to test it.', domain, {'mx': m365}, reference=DIRECT_SEND_REFERENCE)]


def evaluate_mailchannels(domain, records):
    record = _first(_values(records), 'v=mc1')
    if not record or 'cfid=' not in record.lower():
        return []
    return [_finding('mailchannels_shared_relay', LOW, 'MailChannels Domain Lockdown allows a Cloudflare Workers account',
                     'cfid= authorises a Cloudflare account; on the shared MailChannels relay a Workers account can be enough to '
                     'send as this domain. Prefer auth= with your own MailChannels account id.', f'_mailchannels.{domain}',
                     {'record': record})]


# ----------------------------------------------------------------------------- MTA-STS and TLS reporting

def parse_mta_sts_mode(policy):
    for line in (policy or '').splitlines():
        key, _, value = line.partition(':')
        if key.strip().lower() == 'mode':
            return value.strip().lower()
    return ''


def evaluate_mta_sts(domain, records, policy, has_mx, policy_checked=True):
    """``policy`` is the text of https://mta-sts.<domain>/.well-known/mta-sts.txt, or None when it could not be fetched;
    with ``policy_checked`` False the file was not asked for and only the DNS record is reviewed."""
    values = [v for v in _values(records) if v]
    host = f'_mta-sts.{domain}'
    if not values:
        if not has_mx:
            return []
        return [_finding('mta_sts_missing', INFO, 'No MTA-STS policy',
                         'Without MTA-STS (RFC 8461), mail sent to this domain can be downgraded to plain text by an attacker on the '
                         'path.', host)]
    if not _first(values, 'v=stsv1'):
        return [_finding('mta_sts_invalid', LOW, 'MTA-STS record does not start with v=STSv1',
                         'Senders ignore an MTA-STS record that does not begin with "v=STSv1" (RFC 8461 §3.1).', host,
                         {'record': values[0]})]
    if policy is None:
        if not policy_checked:
            return []
        return [_finding('mta_sts_policy_unreachable', LOW, 'MTA-STS policy file could not be fetched',
                         f'The record exists but https://mta-sts.{domain}/.well-known/mta-sts.txt did not answer with a policy, so '
                         'senders cannot apply it.', host)]
    mode = parse_mta_sts_mode(policy)
    if mode in ('testing', 'none'):
        return [_finding('mta_sts_not_enforced', MEDIUM, f'MTA-STS policy is in mode: {mode}',
                         'In testing mode failures are only reported and mail is still delivered without TLS; mode: none turns '
                         'the policy off. Move to mode: enforce.', host, {'mode': mode})]
    return []


def evaluate_tls_reporting(domain, records, has_mx):
    values = [v for v in _values(records) if v]
    host = f'_smtp._tls.{domain}'
    if not values:
        if not has_mx:
            return []
        return [_finding('smtp_tlsrpt_missing', INFO, 'No SMTP TLS reporting (TLS-RPT) record',
                         'TLS-RPT (RFC 8460) sends reports when senders cannot deliver over TLS, which shows downgrade attacks '
                         'and broken certificates.', host)]
    record = _first(values, 'v=tlsrptv1')
    problems = []
    if not record:
        problems.append('it does not start with v=TLSRPTv1 (RFC 8460 §3)')
    else:
        targets = [u.strip().lower() for u in parse_tags(record).get('rua', '').split(',') if u.strip()]
        if not targets:
            problems.append('it has no rua= address')
        elif any(not u.startswith(('mailto:', 'https://')) for u in targets):
            problems.append('rua= only accepts mailto: and https:// URIs')
    if not problems:
        return []
    return [_finding('smtp_tlsrpt_invalid', LOW, 'TLS-RPT record is not usable', f'Senders ignore it: {"; ".join(problems)}.',
                     host, {'record': values[0]})]


# ----------------------------------------------------------------------------- DANE and DNSSEC

def evaluate_dane(domain, tlsa_by_mx):
    """``tlsa_by_mx`` maps an MX host to its TLSA records at _25._tcp (RFC 7672)."""
    findings = []
    for mx, records in sorted(tlsa_by_mx.items()):
        problems = set()
        for record in records:
            parts = record.split()
            if len(parts) < 4 or not all(p.isdigit() for p in parts[:3]):
                problems.add('a TLSA record cannot be parsed')
                continue
            usage, selector, mtype = (int(p) for p in parts[:3])
            if usage in (0, 1):
                problems.add(f'usage {usage} (PKIX) is not used for SMTP; use 3 (DANE-EE) or 2 (DANE-TA)')
            if usage == 3 and selector == 0:
                problems.add('selector 0 pins the whole certificate, which breaks at every renewal; use selector 1')
            if mtype == 0:
                problems.add('matching type 0 publishes the full data; use 1 (SHA-256)')
            elif mtype == 2:
                problems.add('matching type 2 (SHA-512) is optional for senders; publish 1 (SHA-256)')
        if problems:
            findings.append(_finding('dane_misconfigured', LOW, f'DANE TLSA record for {mx} is misconfigured',
                                     'Senders that check DANE may refuse or not protect delivery: ' + '; '.join(sorted(problems)) + '.',
                                     f'_25._tcp.{mx}', {'records': records}))
    return findings


def rsa_key_bits(key_b64):
    """Modulus size of an RFC 3110 RSA DNSKEY, 0 if it cannot be read."""
    try:
        raw = base64.b64decode(key_b64 + '=' * (-len(key_b64) % 4))
        if raw[0] == 0:
            elen, offset = int.from_bytes(raw[1:3], 'big'), 3
        else:
            elen, offset = raw[0], 1
        return int.from_bytes(raw[offset + elen:], 'big').bit_length()
    except Exception:  # noqa: BLE001
        return 0


def evaluate_dnssec(domain, dnskeys):
    """``dnskeys`` are DNSKEY records as text ("flags protocol algorithm key")."""
    findings, weak_algorithms, short_keys, bad_protocol = [], set(), [], False
    for record in dnskeys:
        parts = record.split()
        if len(parts) < 4 or not all(p.isdigit() for p in parts[:3]):
            continue
        protocol, algorithm = int(parts[1]), int(parts[2])
        if protocol != 3:
            bad_protocol = True
        if algorithm in WEAK_DNSSEC_ALGORITHMS:
            weak_algorithms.add(WEAK_DNSSEC_ALGORITHMS[algorithm])
        if algorithm in RSA_DNSSEC_ALGORITHMS:
            bits = rsa_key_bits(''.join(parts[3:]))
            if 0 < bits < 1024:
                short_keys.append(bits)
    if bad_protocol:
        findings.append(_finding('dnssec_invalid_protocol', LOW, 'DNSKEY with a protocol other than 3',
                                 'The protocol field must be 3 (RFC 4034 §2.1.2); validators treat the key as invalid.', domain))
    if weak_algorithms:
        findings.append(_finding('dnssec_weak_algorithm', MEDIUM, f'DNSSEC signs with a deprecated algorithm ({", ".join(sorted(weak_algorithms))})',
                                 'RFC 8624 §3.1 says these algorithms must not be used for signing; validators increasingly treat the '
                                 'zone as unsigned. Roll over to ECDSAP256SHA256 (13) or ED25519 (15).', domain,
                                 {'algorithms': sorted(weak_algorithms)}))
    if short_keys:
        findings.append(_finding('dnssec_weak_key', HIGH, f'DNSSEC RSA key is only {min(short_keys)} bits',
                                 'RSA keys under 1024 bits can be factored, so DNS answers for this zone can be forged.', domain,
                                 {'bits': sorted(short_keys)}))
    return findings


# ----------------------------------------------------------------------------- domain takeover (RDAP)

_RDAP = {'at': 0.0, 'services': None}


def _rdap_services(session):
    """IANA's RDAP bootstrap for domains (RFC 9224), cached for a day."""
    if _RDAP['services'] is None or time.time() - _RDAP['at'] > 86400:
        resp = session.get('https://data.iana.org/rdap/dns.json', timeout=HTTP_TIMEOUT, allow_redirects=False)
        resp.raise_for_status()
        _RDAP['services'], _RDAP['at'] = resp.json().get('services', []), time.time()
    return _RDAP['services']


def rdap_registered(name, session=None):
    """True or False when the domain's registry answers, None when it cannot tell (no RDAP server, an error, a redirect)."""
    import requests
    session = session or requests
    try:
        tld = name.rsplit('.', 1)[-1].lower()
        base = next((urls[0] for tlds, urls in _rdap_services(session) if tld in [t.lower() for t in tlds] and urls), None)
        if not base or not base.lower().startswith('https://'):
            return None
        resp = session.get(base.rstrip('/') + f'/domain/{name}', timeout=HTTP_TIMEOUT, allow_redirects=False,
                           headers={'Accept': 'application/rdap+json'})
    except Exception:  # noqa: BLE001 - no answer is never a finding
        return None
    if resp.status_code == 200:
        return True
    if resp.status_code == 404:
        return False
    return None


def registrable(name):
    """The registrable domain of a mail-related name. Leading underscore labels (_spf, _dmarc, _report) are not host names,
    so they are dropped first: _spf.example.com -> example.com."""
    from targetApp.target_types import apex_domain
    labels = (name or '').strip().lower().rstrip('.').split('.')
    while labels and labels[0].startswith('_'):
        labels.pop(0)
    return apex_domain('.'.join(labels))


def unregistered_domains(names, domain, has_ns, registered):
    """The registrable domains among ``names`` (other than the target's own) that no registry has: a domain that has name
    servers is registered, so only a name with no NS records is asked about, and only an explicit "not found" counts."""
    own = registrable(domain)
    roots = []
    for name in names:
        root = registrable(name)
        if root and root != own and root not in roots:
            roots.append(root)
    return [root for root in roots[:MAX_TAKEOVER_DOMAINS] if not has_ns(root) and registered(root) is False]


def evaluate_takeover(domain, spf_domains, report_domains):
    findings = []
    for root in spf_domains:
        findings.append(_finding('spf_include_registerable', HIGH, f'SPF includes {root}, which is not registered',
                                 f'Anyone can register {root} and publish an SPF record that authorises their own servers, then send '
                                 'mail that passes SPF as this domain. Remove the include.', domain, {'domain': root}))
    for root in report_domains:
        findings.append(_finding('dmarc_report_domain_registerable', HIGH, f'DMARC reports go to {root}, which is not registered',
                                 f'Anyone can register {root} and receive this domain\'s DMARC reports, which list its mail servers '
                                 'and senders. Point rua=/ruf= at a domain you own.', f'_dmarc.{domain}', {'domain': root}))
    return findings


# ----------------------------------------------------------------------------- network and the review

def fetch_mta_sts_policy(domain):
    """The domain's own MTA-STS policy over verified HTTPS (RFC 8461 requires a valid certificate), connecting only to the
    addresses admitted once by pinned_transport (no rebinding between check and connect), no redirects, at most
    MAX_POLICY_BYTES. None when there is no usable answer."""
    import ssl

    from cveFeed import pinned_transport
    host = f'mta-sts.{domain}'
    try:
        addresses = pinned_transport.resolve(host, 443)
    except (OSError, ValueError):
        return None
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    conn = pinned_transport.HTTPConnection(host, 443, addresses, HTTP_TIMEOUT, context=ctx)
    try:
        conn.request('GET', '/.well-known/mta-sts.txt', headers={'Host': host, 'User-Agent': 'CVEngine'})
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        body = resp.read(MAX_POLICY_BYTES + 1)
        return None if len(body) > MAX_POLICY_BYTES else body.decode('utf-8', 'replace')
    except Exception:  # noqa: BLE001
        return None
    finally:
        conn.close()


def review(domain, has_mx, spf_txt, dmarc_txt, dkim_found, fetch, records, http=False):
    """Every MailFail check for one mail domain. ``fetch`` reads TXT records and ``records`` (name, type) any other type, as
    text; ``http`` allows the two outbound kinds of request (RDAP and the MTA-STS policy), off when DNS is injected."""
    findings = evaluate_spf(domain, spf_txt) + evaluate_dmarc(domain, dmarc_txt) + evaluate_dkim(domain, dkim_found)

    def safe(label, fn):
        try:
            return fn()
        except Exception:  # noqa: BLE001 - one failing check never stops the others
            logger.warning('MailFail check %s failed for %s', label, domain, exc_info=True)
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        arc = dict(zip(ARC_SELECTORS, pool.map(lambda s: fetch(f'{s}._domainkey.{domain}'), ARC_SELECTORS)))
        names = {'adsp': f'_adsp._domainkey.{domain}', 'bimi': f'default._bimi.{domain}', 'sts': f'_mta-sts.{domain}',
                 'rpt': f'_smtp._tls.{domain}', 'mc': f'_mailchannels.{domain}'}
        txt = dict(zip(names, pool.map(fetch, names.values())))
    found_arc = {s: next((r for r in rs if 'p=' in r.lower()), '') for s, rs in arc.items()}
    findings += safe('arc', lambda: evaluate_arc(domain, {s: r for s, r in found_arc.items() if r}))
    findings += safe('adsp', lambda: evaluate_adsp(domain, txt['adsp']))
    findings += safe('bimi', lambda: evaluate_bimi(domain, txt['bimi']))
    findings += safe('mailchannels', lambda: evaluate_mailchannels(domain, txt['mc']))
    findings += safe('tlsrpt', lambda: evaluate_tls_reporting(domain, txt['rpt'], has_mx))
    findings += safe('mta-sts', lambda: evaluate_mta_sts(
        domain, txt['sts'], fetch_mta_sts_policy(domain) if (http and txt['sts']) else None, has_mx, policy_checked=http))
    mx_hosts = [r.split()[-1] for r in records(domain, 'MX') if r.split()]
    findings += safe('mx', lambda: evaluate_mx(domain, mx_hosts))
    findings += safe('dane', lambda: evaluate_dane(domain, {
        mx.rstrip('.'): records(f'_25._tcp.{mx.rstrip(".")}', 'TLSA') for mx in mx_hosts[:MAX_DANE_MX] if mx.rstrip('.')}))
    findings += safe('dnssec', lambda: evaluate_dnssec(domain, records(domain, 'DNSKEY')))
    reports = dmarc_report_domains(dmarc_txt)
    external = [r for r in reports if registrable(r) and registrable(r) != registrable(domain)][:MAX_REPORT_DOMAINS]
    for ext in external:
        findings += safe('report-auth', lambda ext=ext: evaluate_report_authorization(domain, ext, fetch(f'{domain}._report._dmarc.{ext}')))
    if http and os.environ.get('CVENGINE_HYGIENE_RDAP', '1') != '0':
        import requests
        session = requests.Session()
        has_ns = lambda name: bool(records(name, 'NS'))  # noqa: E731
        registered = lambda name: rdap_registered(name, session)  # noqa: E731
        findings += safe('takeover', lambda: evaluate_takeover(
            domain, unregistered_domains(spf_referenced_domains(spf_txt), domain, has_ns, registered),
            unregistered_domains(reports, domain, has_ns, registered)))
    return findings
