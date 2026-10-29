"""Domain and TLS hygiene: certificate validity and expiry, TLS configuration, and SPF / DKIM / DMARC.

Evaluators are pure functions over plain data (records, cert info) so every rule is unit tested; the
network helpers (DNS via dnspython, TLS via ssl) are thin and injectable. Each run upserts findings and
resolves the ones that no longer apply, so the table always reflects the current state.
"""
import base64
import concurrent.futures
import datetime
import functools
import logging
import re
import socket
from cveFeed import legacy_tls, pinned_transport
import ssl
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4
DNS_TIMEOUT = 5
TLS_TIMEOUT = 5
TLS_PORTS = (443, 8443, 9443, 993, 995, 465, 636)
MAX_TLS_TARGETS = 300
TLS_WORKERS = 20
# Mail providers rotate selector names; these cover Google, Microsoft 365, Mailchimp, SendGrid and the usual defaults.
DKIM_SELECTORS = ('default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'smtp',
                  'mandrill', 'mxvault', 'zoho', 'protonmail', 'fm1', 'fm2')
SPF_LOOKUP_LIMIT = 10
SPF_MAX_QUERIES = 50  # records fetched for one domain: the owner of a scanned domain controls how wide its include tree is
SPF_MAX_TERMS = 200  # terms read from one record
EXPIRY_BANDS = ((0, CRITICAL, 'has expired'), (7, HIGH, 'expires within 7 days'),
                (30, MEDIUM, 'expires within 30 days'), (60, LOW, 'expires within 60 days'))


@dataclass
class Finding:
    check: str
    severity: int
    title: str
    detail: str = ''
    host: str = ''
    evidence: dict = field(default_factory=dict)


# ----------------------------------------------------------------------------- SPF

def _txt_value(record):
    return record.strip().strip('"')


def evaluate_spf(domain, txt_records, has_mx, lookup_count=None):
    """SPF review. ``txt_records`` are the domain's TXT strings; ``lookup_count`` the resolved DNS-lookup total."""
    spf = [_txt_value(r) for r in txt_records if _txt_value(r).lower().startswith('v=spf1')]
    if not spf:
        sev, why = (MEDIUM, 'This domain receives mail, so anyone can spoof it.') if has_mx else \
            (LOW, 'The domain does not appear to send mail; publish "v=spf1 -all" so nobody can spoof it.')
        return [Finding('spf_missing', sev, 'No SPF record', why, domain)]
    if len(spf) > 1:
        return [Finding('spf_multiple', HIGH, 'More than one SPF record',
                        'Receivers treat several SPF records as a permanent error, so SPF fails for everyone.', domain,
                        {'records': spf})]
    record, findings = spf[0], []
    terms = record.lower().split()
    all_term = next((t for t in terms if re.fullmatch(r'[+\-~?]?all', t)), None)
    redirect = any(t.startswith('redirect=') for t in terms)
    if all_term in ('+all', 'all'):
        findings.append(Finding('spf_allow_all', CRITICAL, 'SPF allows any server to send as this domain',
                                f'"{record}" ends in +all, which authorises the whole internet.', domain, {'record': record}))
    elif all_term == '?all':
        findings.append(Finding('spf_neutral', MEDIUM, 'SPF ends in ?all (neutral)',
                                'A neutral result gives receivers no reason to reject spoofed mail. Use -all.', domain, {'record': record}))
    elif all_term == '~all':
        findings.append(Finding('spf_softfail', LOW, 'SPF ends in ~all (soft fail)',
                                'Spoofed mail is marked, not rejected. Move to -all once all senders are listed.', domain, {'record': record}))
    elif all_term is None and not redirect:
        findings.append(Finding('spf_no_all', MEDIUM, 'SPF has no "all" mechanism',
                                'Without a closing -all or redirect, unlisted servers are not told to fail.', domain, {'record': record}))
    if 'ptr' in terms or any(t.lstrip('+-~?').startswith('ptr') for t in terms):
        findings.append(Finding('spf_ptr', LOW, 'SPF uses the discouraged ptr mechanism',
                                'ptr is slow and unreliable; list explicit ip4/ip6/include instead.', domain, {'record': record}))
    if lookup_count is not None and lookup_count > SPF_LOOKUP_LIMIT:
        findings.append(Finding('spf_too_many_lookups', MEDIUM, f'SPF needs {lookup_count} DNS lookups (limit {SPF_LOOKUP_LIMIT})',
                                'Over the limit, SPF returns a permanent error and legitimate mail can fail.', domain,
                                {'lookups': lookup_count}))
    return findings


def count_spf_lookups(domain, fetch_txt, depth=0, seen=None):
    """DNS-lookup cost of a domain's SPF record, following include/redirect (a, mx, ptr, exists, include, redirect each cost one)."""
    seen = seen if seen is not None else set()
    if depth > 10 or domain in seen or len(seen) >= SPF_MAX_QUERIES:
        return 0  # past the budget the count is already far over the limit of 10
    seen.add(domain)
    spf = next((_txt_value(r) for r in fetch_txt(domain) if _txt_value(r).lower().startswith('v=spf1')), None)
    if not spf:
        return 0
    total = 0
    for term in spf.split()[1:SPF_MAX_TERMS]:
        t = term.lstrip('+-~?').lower()
        if t.startswith(('include:', 'redirect=')):
            total += 1 + count_spf_lookups(re.split('[:=]', t, 1)[1], fetch_txt, depth + 1, seen)
        elif t.split(':')[0].split('/')[0] in ('a', 'mx', 'ptr', 'exists'):
            total += 1
    return total


# ----------------------------------------------------------------------------- DMARC

def parse_tags(record):
    tags = {}
    for part in _txt_value(record).split(';'):
        if '=' in part:
            k, _, v = part.partition('=')
            tags[k.strip().lower()] = v.strip()
    return tags


def evaluate_dmarc(domain, txt_records, has_mx):
    dmarc = [_txt_value(r) for r in txt_records if _txt_value(r).lower().startswith('v=dmarc1')]
    if not dmarc:
        sev, why = (HIGH, 'Mail for this domain can be spoofed and receivers have no policy to follow.') if has_mx else \
            (LOW, 'Publish "v=DMARC1; p=reject" so the domain cannot be used to send spoofed mail.')
        return [Finding('dmarc_missing', sev, 'No DMARC record', why, domain)]
    if len(dmarc) > 1:
        return [Finding('dmarc_multiple', MEDIUM, 'More than one DMARC record', 'Receivers ignore DMARC when several records exist.',
                        domain, {'records': dmarc})]
    tags, findings = parse_tags(dmarc[0]), []
    policy = tags.get('p', '').lower()
    if policy not in ('none', 'quarantine', 'reject'):
        findings.append(Finding('dmarc_invalid', MEDIUM, 'DMARC record has no valid policy', f'"{dmarc[0]}" is missing p=none|quarantine|reject.',
                                domain, {'record': dmarc[0]}))
        return findings
    if policy == 'none':
        findings.append(Finding('dmarc_none', MEDIUM, 'DMARC policy is p=none (monitoring only)',
                                'Spoofed mail is still delivered. Move to quarantine, then reject, once reports look clean.', domain,
                                {'record': dmarc[0]}))
    elif policy == 'quarantine':
        findings.append(Finding('dmarc_quarantine', INFO, 'DMARC policy is p=quarantine',
                                'Good. p=reject is the strongest setting.', domain, {'record': dmarc[0]}))
    pct = tags.get('pct')
    if pct and pct.isdigit() and int(pct) < 100 and policy != 'none':
        weaker = 'quarantine' if policy == 'reject' else 'none'
        findings.append(Finding('dmarc_partial', LOW, f'DMARC applies to only {pct}% of mail',
                                f'The other {100 - int(pct)}% of failing mail is treated as p={weaker} (RFC 7489 §6.6.4). Raise pct to 100.',
                                domain, {'pct': int(pct)}))
    if not tags.get('rua'):
        findings.append(Finding('dmarc_no_reports', LOW, 'DMARC has no aggregate report address (rua)',
                                'Without reports you cannot see who is sending as this domain.', domain, {'record': dmarc[0]}))
    sp = tags.get('sp', '').lower()
    if sp == 'none' and policy in ('quarantine', 'reject'):
        findings.append(Finding('dmarc_subdomain_weak', MEDIUM, 'DMARC subdomain policy is weaker (sp=none)',
                                'Attackers can spoof subdomains even though the apex is protected.', domain, {'record': dmarc[0]}))
    return findings


def has_dmarc_record(records):
    return any(_txt_value(r).lower().startswith('v=dmarc1') for r in records)


# the findings about the policy a name is held to; the rest (reports, pct, sp) belong to the record, so they are the owner's, not the name's
INHERITED_DMARC_CHECKS = ('dmarc_none', 'dmarc_quarantine', 'dmarc_invalid', 'dmarc_multiple')


def evaluate_inherited_dmarc(domain, apex, records, has_mx):
    """DMARC review of a name that publishes no record of its own: a receiver falls back to the organizational domain's record
    (RFC 7489 section 6.6.3) and applies its ``sp`` tag to subdomains, so the apex's policy is the one the name has. Only what that
    policy says about the name is reported here (the record's own details are the apex's finding)."""
    values = [_txt_value(r) for r in records if _txt_value(r).lower().startswith('v=dmarc1')]
    tags = parse_tags(values[0])
    sp = tags.get('sp', '').lower()
    effective = [f'v=DMARC1; p={sp}; rua={tags.get("rua", "")}'] if len(values) == 1 and sp in ('none', 'quarantine', 'reject') else records
    found = []
    for f in evaluate_dmarc(domain, effective, has_mx):
        if f.check in INHERITED_DMARC_CHECKS:
            f.detail = f'{f.detail} (This name has no DMARC record of its own; it follows the policy of {apex}.)'.strip()
            f.evidence = {**f.evidence, 'inherited_from': apex}
            found.append(f)
    return found


# ----------------------------------------------------------------------------- DKIM

def dkim_key_bits(record):
    """RSA key size in bits from a DKIM TXT record, 0 if revoked/unparseable."""
    p = parse_tags(record).get('p', '').replace(' ', '')
    if not p:
        return 0
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        key = load_der_public_key(base64.b64decode(p + '=' * (-len(p) % 4)))
        return getattr(key, 'key_size', 0)
    except Exception:  # noqa: BLE001
        return 0


def evaluate_dkim(domain, found, has_mx):
    """``found`` maps selector -> TXT record for the selectors that exist."""
    if not found:
        if not has_mx:
            return []
        return [Finding('dkim_not_found', INFO, 'No DKIM key found on common selectors',
                        'Not conclusive: DKIM selectors are arbitrary names. Check your mail provider that outbound mail is signed.',
                        domain, {'tried': list(DKIM_SELECTORS)})]
    findings = []
    found = {s: r for s, r in found.items() if parse_tags(r).get('p', '')}  # revoked selectors do not count as present
    if not found and has_mx:
        return [Finding('dkim_not_found', INFO, 'No DKIM key found on common selectors',
                        'Not conclusive: DKIM selectors are arbitrary names. Check your mail provider that outbound mail is signed.',
                        domain, {'tried': list(DKIM_SELECTORS)})]
    for selector, record in sorted(found.items()):
        bits = dkim_key_bits(record)
        host = f'{selector}._domainkey.{domain}'
        if parse_tags(record).get('p', '') == '':
            continue  # an empty key is a revoked selector (or a wildcard placeholder): nothing to fix
        if 0 < bits < 1024:
            findings.append(Finding('dkim_weak_key', HIGH, f'DKIM key for {selector} is only {bits} bits',
                                    'Keys under 1024 bits can be factored. Rotate to 2048.', host, {'selector': selector, 'bits': bits}))
        elif bits == 1024:
            findings.append(Finding('dkim_short_key', LOW, f'DKIM key for {selector} is 1024 bits', 'Rotate to 2048 bits.', host,
                                    {'selector': selector, 'bits': bits}))
    return findings


def evaluate_caa(domain, caa_records):
    if caa_records:
        return []
    return [Finding('caa_missing', INFO, 'No CAA record', 'A CAA record limits which certificate authorities may issue for this domain.', domain)]


# ----------------------------------------------------------------------------- TLS

def hostname_matches(hostname, names):
    """Certificate name match with single-label wildcards (``*.example.com``)."""
    hostname = hostname.lower().rstrip('.')
    for name in names:
        name = name.lower().rstrip('.')
        if name == hostname:
            return True
        if name.startswith('*.') and hostname.count('.') >= name.count('.') and hostname.split('.', 1)[1:] == [name[2:]]:
            return True
    return False


def evaluate_cert(info, now=None):
    """Findings for one certificate. ``info`` keys: host, port, not_after (datetime), sans, subject, signature_algorithm,
    key_description ('RSA 2048'), protocol, chain_error, legacy_tls."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    host, port = info['host'], info['port']
    where = f'{host}:{port}'
    findings = []
    if info.get('not_after'):
        days = (info['not_after'] - now).days
        for limit, severity, phrase in EXPIRY_BANDS:
            if days < limit or (limit == 0 and info['not_after'] <= now):
                code = 'tls_expired' if limit == 0 else 'tls_expiring'
                title = f'Certificate for {where} {phrase}' if limit else f'Certificate for {where} expired {-days} days ago'
                if limit and days >= 0:
                    title += f' ({days} days left)'
                findings.append(Finding(code, severity, title, f'Valid until {info["not_after"]:%Y-%m-%d}.', where,
                                        {'days_left': days, 'not_after': info['not_after'].isoformat()}))
                break
    names = list(info.get('sans') or [])
    if info.get('subject') and info['subject'] not in names:
        names.append(info['subject'])
    if names and not is_ip(host) and not hostname_matches(host, names):
        findings.append(Finding('tls_hostname_mismatch', HIGH, f'Certificate for {where} does not cover {host}',
                                f'It is valid for: {", ".join(names[:6])}.', where, {'names': names[:20]}))
    err = (info.get('chain_error') or '').lower()
    if err and 'hostname mismatch' not in err and 'ip address mismatch' not in err and 'expired' not in err:
        if 'self-signed' in err or 'self signed' in err:
            findings.append(Finding('tls_self_signed', MEDIUM, f'{where} uses a self-signed certificate',
                                    'Browsers and clients will not trust it.', where, {'error': info['chain_error']}))
        else:
            findings.append(Finding('tls_untrusted_chain', MEDIUM, f'{where} certificate chain is not trusted',
                                    info['chain_error'], where, {'error': info['chain_error']}))
    sig = (info.get('signature_algorithm') or '').lower()
    if 'md5' in sig or 'sha1' in sig:
        findings.append(Finding('tls_weak_signature', HIGH, f'{where} certificate is signed with {info["signature_algorithm"]}',
                                'SHA-1 and MD5 signatures can be forged. Reissue with SHA-256.', where, {'signature': info['signature_algorithm']}))
    key = info.get('key_description') or ''
    m = re.fullmatch(r'RSA (\d+)', key)
    if m and int(m.group(1)) < 2048:
        findings.append(Finding('tls_weak_key', HIGH, f'{where} uses a {m.group(1)}-bit RSA key', 'Use at least 2048 bits.', where, {'key': key}))
    if info.get('protocol') in ('TLSv1', 'TLSv1.1', 'SSLv3') or info.get('legacy_tls'):
        findings.append(Finding('tls_legacy_protocol', MEDIUM, f'{where} still accepts TLS 1.0 / 1.1',
                                'Disable TLS 1.0 and 1.1; keep TLS 1.2 and 1.3.', where, {'protocol': info.get('protocol')}))
    return findings


def _fetch_cert(host, port, timeout=TLS_TIMEOUT, legacy=False, addresses=None, project=None):
    """Connect without verification (so broken certs can still be read), return a plain info dict or None."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    if legacy:  # a modern client cannot read servers that only speak TLS 1.0 / 1.1: legacy_tls is the one module that speaks those
        got = legacy_tls.handshake(host, port, timeout, addresses=addresses, project=project)
        if got is None:
            return None
        der, protocol, cipher = got
    else:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # explicit: legacy_tls is the only place old protocols are spoken
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with pinned_transport.open_socket(addresses if addresses is not None else pinned_transport.resolve(host, port, **_project_kw(project)), timeout, **_project_kw(project)) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
                der, protocol, cipher = tls.getpeercert(binary_form=True), tls.version(), (tls.cipher() or ('',))[0]
        except (OSError, ssl.SSLError, socket.timeout, ValueError):
            return None
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    pub = cert.public_key()
    key = f'RSA {pub.key_size}' if isinstance(pub, rsa.RSAPublicKey) else \
        f'EC {pub.curve.name}' if isinstance(pub, ec.EllipticCurvePublicKey) else type(pub).__name__
    cn = next((a.value for a in cert.subject if a.oid == x509.NameOID.COMMON_NAME), '')
    issuer = next((a.value for a in cert.issuer if a.oid == x509.NameOID.ORGANIZATION_NAME), '') or \
        next((a.value for a in cert.issuer if a.oid == x509.NameOID.COMMON_NAME), '')
    sig = getattr(cert.signature_hash_algorithm, 'name', '')
    return {'host': host, 'port': port, 'subject': cn, 'issuer': issuer, 'sans': sans,
            'not_before': getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc),
            'not_after': getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc),
            'signature_algorithm': f'{sig} ({cert.signature_algorithm_oid._name})' if sig else cert.signature_algorithm_oid._name,
            'key_description': key, 'protocol': protocol, 'cipher': cipher}


def _chain_error(host, port, timeout=TLS_TIMEOUT, addresses=None, project=None):
    """Empty string if the system trust store accepts the certificate for this host, else the reason."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with pinned_transport.open_socket(addresses if addresses is not None else pinned_transport.resolve(host, port, **_project_kw(project)), timeout, **_project_kw(project)) as raw, ctx.wrap_socket(raw, server_hostname=host):
            return ''
    except ssl.SSLCertVerificationError as exc:
        return (exc.verify_message or str(exc))[:300]
    except (OSError, ssl.SSLError, ValueError):
        return ''


def _accepts_legacy_tls(host, port, timeout=TLS_TIMEOUT, addresses=None, project=None):
    """True only if the server actually negotiated TLS 1.0 or 1.1 (a successful handshake alone proves nothing)."""
    return legacy_tls.accepts(host, port, timeout, addresses=addresses, project=project)


CERT_TEXT_LIMITS = {'subject': 500, 'issuer': 500, 'signature_algorithm': 100, 'key_description': 100, 'protocol': 20, 'cipher': 100,
                    'chain_error': 300}
MAX_CERT_SANS = 200
MAX_CERT_SAN_LENGTH = 255


def clip_certificate(info):
    """A copy of a probed certificate whose text fits the TlsCertificate columns and whose name list is bounded. A server can present
    a certificate with a 10 KB subject or 50,000 names; storing it as is would raise and drop the rest of the domain's TLS review."""
    out = dict(info)
    for key, limit in CERT_TEXT_LIMITS.items():
        out[key] = str(out.get(key) or '')[:limit]
    out['sans'] = [str(name)[:MAX_CERT_SAN_LENGTH] for name in (out.get('sans') or [])[:MAX_CERT_SANS]]
    return out


def _project_kw(project):
    """``{'project': id}`` when the target has one that may authorise a tailnet device, else nothing (the probes take it as an option)."""
    return {} if project is None else {'project': project}


def probe_tls(host, port, project=None, addresses=None):
    """Read the certificate and TLS posture of ``host:port``. ``project`` may authorise a tailnet device of its own. ``addresses`` (numeric
    ``(family, sockaddr)`` pairs a caller already vetted, as ``pinned_transport.resolve`` returns them) replaces the lookup, so the third-party
    supplier checks connect only to the addresses they admitted themselves."""
    kw = _project_kw(project)
    if addresses is None:
        try:
            addresses = pinned_transport.resolve(host, port, **kw)
        except (OSError, ValueError):
            return None
    info = _fetch_cert(host, port, addresses=addresses, **kw)
    if info:
        info['chain_error'] = _chain_error(host, port, addresses=addresses, **kw)
        info['legacy_tls'] = _accepts_legacy_tls(host, port, addresses=addresses, **kw)
        return info
    info = _fetch_cert(host, port, legacy=True, addresses=addresses, **kw)  # a modern client cannot read servers that only speak TLS 1.0 / 1.1
    if info:
        info['chain_error'] = 'cannot be verified: the server only speaks TLS 1.0 / 1.1'
        info['legacy_tls'] = True
    return info


# ----------------------------------------------------------------------------- DNS

def _resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = DNS_TIMEOUT
    return r


def fetch_txt(name, resolver=None):
    import dns.exception
    import dns.resolver
    try:
        return [b''.join(rdata.strings).decode('utf-8', 'replace') for rdata in (resolver or _resolver()).resolve(name, 'TXT')]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return []


def has_record(name, rtype, resolver=None):
    import dns.exception
    import dns.resolver
    try:
        return bool(list((resolver or _resolver()).resolve(name, rtype)))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return False


def fetch_records(name, rtype, resolver=None):
    """Any record type as text (MX "10 mx.example.com.", TLSA, DNSKEY, NS), [] when there is none or DNS fails."""
    import dns.exception
    import dns.resolver
    try:
        return [rdata.to_text() for rdata in (resolver or _resolver()).resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return []


def organizational_domain(name):
    from targetApp.target_types import apex_domain
    return apex_domain(name)


def email_findings(domain, fetch=fetch_txt, mx=has_record, records=None):
    """SPF, DMARC, DKIM and CAA review for one domain, plus the checks adapted from MailFail (cveFeed.mailfail), with
    injectable DNS for tests. With injected DNS, other record types default to none and no outbound request is made."""
    from cveFeed import mailfail
    real_dns = fetch is fetch_txt
    records = records or (fetch_records if real_dns else (lambda name, rtype: []))
    has_mx = mx(domain, 'MX')
    txt = fetch(domain)
    findings = evaluate_spf(domain, txt, has_mx, count_spf_lookups(domain, fetch))
    dmarc = fetch(f'_dmarc.{domain}')
    apex = None if has_dmarc_record(dmarc) else organizational_domain(domain)
    parent = fetch(f'_dmarc.{apex}') if apex and apex != domain else []
    if has_dmarc_record(parent):  # no record of its own: the organizational domain's policy applies to this name
        findings += evaluate_inherited_dmarc(domain, apex, parent, has_mx)
    else:
        findings += evaluate_dmarc(domain, dmarc, has_mx)
    selectors = DKIM_SELECTORS + mailfail.EXTRA_DKIM_SELECTORS
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        answers = pool.map(lambda selector: fetch(f'{selector}._domainkey.{domain}'), selectors)
        found = {}
        for selector, rows in zip(selectors, answers):
            for record in rows:
                if 'v=dkim1' in record.lower() or 'p=' in record.lower():
                    found[selector] = record
    findings += evaluate_dkim(domain, found, has_mx)
    findings += evaluate_caa(domain, mx(domain, 'CAA'))
    try:
        findings += mailfail.review(domain, has_mx, txt, dmarc, found, fetch, records, http=real_dns)
    except Exception:  # noqa: BLE001 - the established checks above stand on their own
        logger.exception('MailFail checks failed for %s', domain)
    return findings, has_mx


# ----------------------------------------------------------------------------- runner

def is_ip(value):
    return bool(re.fullmatch(r'[\d.]+|[0-9a-fA-F:]+:[0-9a-fA-F:]*', value or ''))


def tls_targets(domain, hosts=None):
    """(host, port) pairs to probe: port 443 on every known host, plus other TLS ports seen open."""
    from startScan.models import Subdomain, open_ports
    from targetApp.target_types import scannable_hosts
    targets, seen = [], set()
    selected = set(hosts) if hosts is not None else None

    allowed = {}

    def add(host, port):
        if (host, port) not in seen and len(targets) < MAX_TLS_TARGETS:
            seen.add((host, port))
            if host not in allowed:  # a stored name may point somewhere a scanner must not go now
                allowed[host] = bool(scannable_hosts([host], project=domain.project_id))
            if allowed[host]:
                targets.append((host, port))
    if selected is None or domain.name in selected:
        add(domain.name, 443)
    for sub in Subdomain.objects.filter(target_domain=domain).prefetch_related('ip_addresses__ports'):
        if selected is not None and sub.name not in selected:
            continue
        add(sub.name, 443)
        for ip in sub.ip_addresses.all():
            for port in open_ports(ip):
                if port.number in TLS_PORTS and port.number != 443:
                    add(sub.name, port.number)
    return targets


def email_domains(domain, mx=has_record):
    """The target itself, plus discovered hosts that have their own MX record."""
    from startScan.models import Subdomain
    names = [] if is_ip(domain.name) else [domain.name]
    extra = [s.name for s in Subdomain.objects.filter(target_domain=domain).exclude(name=domain.name)[:100]
             if not is_ip(s.name) and mx(s.name, 'MX')]
    return names + extra


def store_findings(domain, found, hosts=None, owns=lambda check: True):
    """Upsert ``found`` (Finding objects) as the HygieneFinding rows of ``domain``, and resolve the open rows whose check this run
    owns (``owns(check_name)``) that it did not find again (limited to ``hosts`` when given). Returns the rows resolved. The
    Tailscale checks (cveFeed.tailscale_checks) and the UDP exposure checks (cveFeed.udp_scan) store through here too, and the TLS and email sweep leaves their rows alone."""
    from django.utils import timezone

    from cveFeed.models import HygieneFinding
    keep = set()
    for f in found:
        keep.add((f.host or domain.name, f.check))
        defaults = {'severity': f.severity, 'title': f.title[:300], 'detail': f.detail, 'evidence': f.evidence,
                    'status': 'open', 'resolved_at': None}
        before = HygieneFinding.objects.filter(domain=domain, host=f.host or domain.name, check_name=f.check).first()
        if before and before.status == 'resolved' and before.remediation_status == 'fixed':
            # it was fixed, the sweep saw it gone, and now it is back: a regression must reappear in the actionable view
            defaults.update(remediation_status='open', remediation_updated_at=timezone.now(), remediation_by=None,
                            remediation_note=(before.remediation_note + '\n' if before.remediation_note else '')
                            + 'Reopened: the check found this again after it was marked fixed.')
        HygieneFinding.objects.update_or_create(
            domain=domain, host=f.host or domain.name, check_name=f.check, defaults=defaults)
    stale = [x for x in HygieneFinding.objects.filter(domain=domain, status='open')
             if owns(x.check_name) and (hosts is None or x.host in hosts or (x.check_name.startswith('tls_') and x.host.rpartition(':')[0] in hosts))
             and (x.host, x.check_name) not in keep]  # a certificate finding's host is 'name:port', a host-only run is given the names
    for x in stale:
        x.status, x.resolved_at = 'resolved', timezone.now()
        x.save(update_fields=['status', 'resolved_at'])
    if domain.project_id:  # hygiene issues count toward the host score: a new or resolved one moves it now, not at the daily pass
        from cveFeed import scoring
        touched = sorted({h.lower() for h, _ in keep} | {x.host.lower() for x in stale})
        for i in range(0, len(touched), scoring.CHUNK):
            scoring.rescore_quietly(domain.project_id, touched[i:i + scoring.CHUNK])
    return stale


def run_hygiene(domain_id, probe=probe_tls, emailer=email_findings, mx=has_record, now=None, hosts=None):
    """Check one target's certificates, TLS configuration and email authentication; upsert and resolve findings."""
    from cveFeed import activity, changes
    from cveFeed.models import TlsCertificate
    from targetApp.models import Domain
    domain = Domain.objects.get(pk=domain_id)
    project = domain.project_id
    if probe is probe_tls:  # the project may authorise the tailnet devices of its own
        probe = functools.partial(probe_tls, project=project)
    running = activity.log('hygiene', f'Checking TLS and email authentication for {domain.name}', project=project, status='running')
    found = []

    targets = tls_targets(domain, hosts=hosts)
    probed = 0
    cert_changes = 0
    existing = {(c.host, c.port): c for c in TlsCertificate.objects.filter(domain=domain)}  # one query; bounded by MAX_TLS_TARGETS
    with concurrent.futures.ThreadPoolExecutor(max_workers=TLS_WORKERS) as pool:
        for info in pool.map(lambda t: probe(*t), targets):
            if not info:
                continue
            probed += 1
            info = clip_certificate(info)  # the certificate is the scanned server's own text: fit it to the columns
            prev = existing.get((info['host'], info['port']))
            TlsCertificate.objects.update_or_create(
                domain=domain, host=info['host'], port=info['port'],
                defaults={**{k: info.get(k) or '' for k in ('subject', 'issuer', 'signature_algorithm', 'key_description', 'protocol',
                                                            'cipher', 'chain_error')},
                          'sans': info.get('sans') or [], 'not_before': info.get('not_before'), 'not_after': info.get('not_after'),
                          'legacy_tls': bool(info.get('legacy_tls'))})
            if changes.record_cert_change(domain, info['host'], info['port'], before=prev, after=info, project_id=project):
                cert_changes += 1
            found += evaluate_cert(info, now=now)
    mail_hosts = email_domains(domain, mx) if hosts is None else ([domain.name] if domain.name in hosts and not is_ip(domain.name) else [])
    if mail_hosts:  # the email review includes the checks adapted from MailFail: credit it where people watch the work
        from cveFeed.mailfail import CREDIT
        shown = ', '.join(mail_hosts[:3]) + (f' and {len(mail_hosts) - 3} more' if len(mail_hosts) > 3 else '')
        credited = activity.log('hygiene', f'Running MailFail email-security checks on {shown} '
                                '(MailFail by Black Hills Information Security)', project=project, status='running', credit=CREDIT)
    mail_found = []
    for name in mail_hosts:
        findings, _ = emailer(name)
        mail_found += findings
    found += mail_found
    if mail_hosts:
        issues = len([f for f in mail_found if f.severity >= LOW and (f.evidence or {}).get('credit') == CREDIT])
        activity.settle(credited, 'done', message=(
            f'MailFail checks (Black Hills Information Security) on {shown}: {issues} issue{"s" if issues != 1 else ""}'),
            credit=CREDIT, mail_domains=len(mail_hosts), issues=issues)

    stale = store_findings(domain, found, hosts=hosts, owns=lambda check: not check.startswith(('ts_', 'tlsa_', 'bkt_', 'udp_')))  # the tailnet, testssl.sh, cloud storage and UDP checks keep their own
    try:  # the medium and worse findings are triaged (impact and a fix); never fatal to the check
        from cveFeed import triage
        triage.triage_hygiene(domain_id)
    except Exception:  # noqa: BLE001
        logger.exception('could not triage the hygiene findings of %s', domain.name)
    worst = max((f.severity for f in found if f.severity >= LOW), default=-1)
    counts = {'tls_hosts': probed, 'mail_domains': len(mail_hosts), 'findings': len([f for f in found if f.severity >= LOW]),
              'resolved': len(stale), 'cert_changes': cert_changes}
    activity.settle(running, 'done', message=(
        f'Hygiene check of {domain.name}: {probed} certificate{"s" if probed != 1 else ""}, '
        f'{counts["findings"]} issue{"s" if counts["findings"] != 1 else ""}'
        + (f' (worst: {["info", "low", "medium", "high", "critical"][worst]})' if worst >= 0 else '')), **counts)
    from cveFeed import ledger
    if hosts is None:
        ledger.record('hygiene', [domain.name], project)  # a host-only probe is not whole-target coverage
    return counts
