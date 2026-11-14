"""Domain and TLS hygiene: certificate validity and expiry, TLS configuration, SPF / DKIM / DMARC, and cleartext services (cveFeed.cleartext).

Evaluators are pure functions over plain data (records, cert info) so every rule is unit tested; the
reads of the host (certificates, TLS, DNS) are a Sentinel's (the ``hygiene_check`` kind, ``cvengine_scanner.probes``): this module judges what comes back. Each run upserts findings and
resolves the ones that no longer apply, so the table always reflects the current state.
"""
import base64
import datetime
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4
TLS_PORTS = (443, 8443, 9443, 993, 995, 465, 636)
MAX_TLS_TARGETS = 300
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


def dmarc_policy(records, subdomain=False):
    """The policy a receiver applies from a DMARC record set (``sp`` for a subdomain when it is valid, else ``p``), '' when there is no
    single valid record or it covers less than all mail (pct below 100)."""
    values = [_txt_value(r) for r in records if _txt_value(r).lower().startswith('v=dmarc1')]
    if len(values) != 1:
        return ''
    tags = parse_tags(values[0])
    policy, sp = tags.get('p', '').lower(), tags.get('sp', '').lower()
    if subdomain and sp in ('none', 'quarantine', 'reject'):
        policy = sp
    pct = tags.get('pct', '100')
    if policy not in ('none', 'quarantine', 'reject') or (pct.isdigit() and int(pct) < 100):
        return ''
    return policy


def evaluate_inherited_dmarc(domain, apex, records, has_mx):
    """DMARC review of a name that publishes no record of its own: a receiver falls back to the organizational domain's record
    (RFC 7489 section 6.6.3) and applies its ``sp`` tag to subdomains, so the apex's policy is the one the name has. When that policy is
    weak the cause is the apex's record, so the finding is the apex's (host ``apex``, the same check the apex's own review raises),
    listing the names it covers in ``evidence['covers']``: one row for the parent, not one per subdomain. An enforcing policy is no
    finding for the name."""
    values = [_txt_value(r) for r in records if _txt_value(r).lower().startswith('v=dmarc1')]
    own = evaluate_dmarc(apex, records, has_mx)
    if len(values) != 1:
        wanted = {'dmarc_multiple'}
    else:
        tags = parse_tags(values[0])
        policy, sp = tags.get('p', '').lower(), tags.get('sp', '').lower()
        effective = sp if sp in ('none', 'quarantine', 'reject') else policy
        if policy not in ('none', 'quarantine', 'reject'):
            wanted = {'dmarc_invalid'}
        elif effective == 'none':
            wanted = {'dmarc_none'} if policy == 'none' else {'dmarc_subdomain_weak'}
        else:
            wanted = set()
    found = []
    for f in own:
        if f.check in wanted:
            f.host = apex
            f.evidence = {**f.evidence, 'inherited_from': apex, 'covers': [domain]}
            found.append(f)
    return found


def merge_findings(found):
    """One finding per (host, check): the subdomains that inherit a parent's DMARC policy each report the parent's finding, and the
    parent may report it itself. The worst severity stands and ``evidence['covers']`` lists every name it was raised for."""
    merged, order = {}, []
    for f in found:
        key = (f.host, f.check)
        if key not in merged:
            merged[key] = f
            order.append(key)
            continue
        kept = merged[key]
        covers = sorted(dict.fromkeys([*(kept.evidence or {}).get('covers', []), *(f.evidence or {}).get('covers', [])]))  # sorted: the names shown do not depend on the order the sweep finished them in
        if f.severity > kept.severity or ('inherited_from' in (kept.evidence or {}) and 'inherited_from' not in (f.evidence or {})):
            merged[key] = kept = f
        if covers:
            kept.evidence = {**(kept.evidence or {}), 'covers': covers[:200]}
    out = []
    for key in order:
        f = merged[key]
        covers = sorted((f.evidence or {}).get('covers') or [])
        if covers:
            shown = ', '.join(covers[:5]) + (f' and {len(covers) - 5} more' if len(covers) > 5 else '')
            note = f' Names with no DMARC record of their own follow this policy: {shown}.'
            f.detail = (f.detail.split(' Names with no DMARC record')[0] + note).strip()
        out.append(f)
    return out


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
                                        {'days_left': days, 'not_after': info['not_after'].isoformat(),
                                         **({'issuer': str(info['issuer'])[:200]} if info.get('issuer') else {})}))
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
                                'Disable TLS 1.0 and 1.1; keep TLS 1.2 and 1.3.', where, legacy_evidence(info)))
    return findings


def legacy_evidence(info):
    """The evidence of a legacy-protocol finding: the TLS 1.0 / 1.1 handshake that completed (the version the server chose and the cipher),
    not the modern handshake the certificate was read over. ``protocol`` is the legacy version; ``modern_protocol`` the one a current client
    got, when it got one."""
    legacy = info.get('legacy_handshake') if isinstance(info.get('legacy_handshake'), dict) else {}
    protocol, cipher = legacy.get('protocol') or '', legacy.get('cipher') or ''
    if not protocol and info.get('protocol') in ('TLSv1', 'TLSv1.1', 'SSLv3'):  # the certificate itself was read over the old protocol
        protocol, cipher = info.get('protocol'), info.get('cipher') or ''
    evidence = {'protocol': protocol or 'TLSv1.0 / 1.1', 'cipher': cipher,
                'handshake': (f'{protocol} handshake completed' + (f' with {cipher}' if cipher else '')) if protocol else
                             'a TLS 1.0 / 1.1 handshake completed'}
    if info.get('protocol') and info.get('protocol') != protocol:
        evidence['modern_protocol'] = info.get('protocol')
    return evidence


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


# ----------------------------------------------------------------------------- DNS


# A DNS finding that says a record is missing opens only when two resolvers agree it is, or when the next run sees the same thing: a
# one-off timeout or SERVFAIL is not a missing record. By default only the system resolver is asked, so a missing record needs two
# consecutive observations, and no client name leaves for a third party. CVENGINE_HYGIENE_CONFIRM_RESOLVERS (comma-separated resolver
# addresses, e.g. "1.1.1.1,8.8.8.8") opts in to confirming in one run: those resolvers are then sent the names whose record seems missing.
CONFIRM_RESOLVERS = ()
CONFIRM_TIMEOUT = 3
ABSENCE_CHECKS = ('spf_missing', 'dmarc_missing')


def confirm_resolvers():
    """The extra resolvers asked to confirm an absence: none unless CVENGINE_HYGIENE_CONFIRM_RESOLVERS lists some."""
    import os
    raw = os.environ.get('CVENGINE_HYGIENE_CONFIRM_RESOLVERS')
    return CONFIRM_RESOLVERS if raw is None else tuple(x.strip() for x in raw.split(',') if x.strip())


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
        if (selected is not None and sub.name not in selected) or not domain.includes_host(sub.name):  # =example.com: no name under it
            continue
        add(sub.name, 443)
        for ip in sub.ip_addresses.all():
            for port in open_ports(ip):
                if port.number in TLS_PORTS and port.number != 443:
                    add(sub.name, port.number)
    return targets


def mail_candidates(domain):
    """``(own, extra)``: the target's own name (none for an address) and up to 100 of its discovered hosts that may have mail of their own, before
    any DNS says so (``email_domains`` keeps the ones with an MX record that are not a CNAME)."""
    from startScan.models import Subdomain
    own = [] if is_ip(domain.name) else [domain.name]
    extra = [s.name for s in Subdomain.objects.filter(target_domain=domain).exclude(name=domain.name)[:100]
             if not is_ip(s.name) and domain.includes_host(s.name)]
    return own, extra


def email_domains(domain, mx, cname=None):
    """The target itself, plus discovered hosts that have their own MX record. A name that is a CNAME has none of its own: a CNAME cannot
    sit beside an MX, so the MX a lookup returns for it is its target's (www.example.com, a CNAME to example.com, answers with example.com's
    MX). Its mail is its target's, reviewed under that name, and it is left out. ``mx(name, 'MX')`` and ``cname(name)`` say whether a name has an
    MX record and whether it is a CNAME: the answers of a Sentinel's DNS reads (this server looks nothing up); ``cname`` defaults to never."""
    cname = cname or (lambda name: False)
    own, extra = mail_candidates(domain)
    return own + [name for name in extra if mx(name, 'MX') and not cname(name)]


PENDING = 'pending'  # HygieneFinding.status of a DNS absence seen once and not agreed by two resolvers: evidence, not an open finding


def store_findings(domain, found, hosts=None, owns=lambda check: True, live_cnames=False, across_targets=False, unanswered=None):
    """Upsert ``found`` (Finding objects) as the HygieneFinding rows of ``domain``, and resolve the open rows whose check this run
    owns (``owns(check_name)``) that it did not find again (limited to ``hosts`` when given). Returns the rows resolved. The
    Tailscale checks (cveFeed.tailscale_checks) and the UDP exposure checks (cveFeed.udp_scan) store through here too, and the TLS and email sweep leaves their rows alone.

    Every finding is rated for its endpoint first (``hygiene_rating.rate``: vendor-managed names, the vendor's own endpoints, an
    expected private CA, BREACH without a session, managed certificates, dev hosts); ``live_cnames`` lets that look up a CNAME that
    discovery did not store. A DNS absence that only one resolver saw (``evidence['dns_confirmed'] is False``) is stored as ``pending``,
    which no list, count or heat reads, and opens when the next run sees it again.

    ``across_targets`` (the TLS and email sweep, ``run_hygiene``): a finding another target of the same project already filed for the same host
    and check is that row, updated, not a second one. The other callers place their rows under a target of their own choosing (the tailnet's
    anchor) and keep filing them there.

    ``unanswered(host, check)``: whether this run could not check that host for that check (a scanner did not report it): an open row it names is
    left as it is, never resolved for want of an answer."""
    from django.utils import timezone

    from cveFeed import hygiene_rating
    from cveFeed.finding_lifecycle import FOLDED
    from cveFeed.models import HygieneFinding
    try:
        found = hygiene_rating.rate(domain, merge_findings(list(found)), live=live_cnames)
    except Exception:  # noqa: BLE001 - an unrated finding is better than a lost one
        logger.exception('could not rate the hygiene findings of %s', domain.name)
    keep = set()
    # The same host and check filed under another target of this project (a host covered by its apex's target and by a target of its own):
    # that row is this finding too, so it is updated instead of filed twice (cveFeed.finding_lifecycle). One query for the whole run.
    elsewhere = {}
    if across_targets and domain.project_id and found:
        for row in (HygieneFinding.objects.filter(domain__project_id=domain.project_id, host__in={f.host or domain.name for f in found},
                                                  check_name__in={f.check for f in found})
                    .exclude(domain=domain).order_by('id')):
            if not (row.status == 'resolved' and (row.remediation_note or '').startswith(FOLDED)):
                elsewhere.setdefault((row.host, row.check_name), row)
    for f in found:
        keep.add((f.host or domain.name, f.check))
        before = HygieneFinding.objects.filter(domain=domain, host=f.host or domain.name, check_name=f.check).first()
        if before is not None and before.status == 'resolved' and (before.remediation_note or '').startswith(FOLDED):
            before = None  # the engine folded this copy into another row: it stays closed, and that row is the finding
            folded_own = True
        else:
            folded_own = False
        target = before or elsewhere.get((f.host or domain.name, f.check))
        status = 'open'
        if (f.evidence or {}).get('dns_confirmed') is False:
            if target is not None and target.status == PENDING:
                f.evidence = {**f.evidence, 'confirmed_by': 'seen again on the next run'}
            elif not (target is not None and target.status == 'open'):
                status = PENDING  # one resolver, once: kept with its evidence, opened only if the next run sees it too
        defaults = {'severity': f.severity, 'title': f.title[:300], 'detail': f.detail, 'evidence': f.evidence,
                    'status': status, 'resolved_at': None}
        if status == 'open' and target is not None and target.status in ('resolved', PENDING) and target.remediation_status == 'fixed':
            # it was fixed, the sweep saw it gone, and now it is back (a DNS absence after a second look): a regression must reappear
            # in the actionable view
            defaults.update(remediation_status='open', remediation_updated_at=timezone.now(), remediation_by=None,
                            remediation_note=(target.remediation_note + '\n' if target.remediation_note else '')
                            + 'Reopened: the check found this again after it was marked fixed.')
        if target is not None and target.domain_id != domain.id:
            HygieneFinding.objects.filter(pk=target.pk).update(**defaults, last_seen=timezone.now())
        elif not folded_own:
            HygieneFinding.objects.update_or_create(
                domain=domain, host=f.host or domain.name, check_name=f.check, defaults=defaults)
    stale = [x for x in HygieneFinding.objects.filter(domain=domain, status__in=('open', PENDING))
             if owns(x.check_name) and (hosts is None or x.host in hosts or (x.check_name.startswith('tls_') and x.host.rpartition(':')[0] in hosts))
             and (x.host, x.check_name) not in keep and not (unanswered and unanswered(x.host, x.check_name))]  # a certificate finding's host is 'name:port', a host-only run is given the names
    for x in stale:
        x.status, x.resolved_at = 'resolved', timezone.now()
        x.save(update_fields=['status', 'resolved_at'])
    if domain.project_id:  # hygiene issues count toward the host score: a new or resolved one moves it now, not at the daily pass
        from cveFeed import scoring
        touched = sorted({h.lower() for h, _ in keep} | {x.host.lower() for x in stale})
        for i in range(0, len(touched), scoring.CHUNK):
            scoring.rescore_quietly(domain.project_id, touched[i:i + scoring.CHUNK])
    return stale


def _norm(name):
    return str(name or '').strip().lower().rstrip('.')


def _cert_info(host, port, cert):
    """A cleaned ``hygiene_check`` certificate row (``probe_results._certificate``) as the evaluators read it: the dates as datetimes."""
    info = {**cert, 'host': host, 'port': port}
    for key in ('not_before', 'not_after'):
        info[key] = datetime.datetime.fromisoformat(cert[key]) if cert.get(key) else None
    return info


def _remote_review(domain, targets, hosts):
    """``(review, waiting)``: what a Sentinel's ``hygiene_check`` answered for the TLS endpoints ``targets`` and the mail names of ``domain`` (``hosts``
    limits the run to those names), or ``(None, True)`` when no scanner can take the work (the kind never runs on this server): nothing is recorded and
    the target stays due.

    ``review['infos']`` maps ``(host, port)`` to the certificate read, ``review['unknown_tls']`` holds the ``host:port`` of every endpoint the scanner
    did not answer for (not reported, refused by the policy or failed: never read as "nothing there"), ``review['mail']`` maps each reviewed name to
    ``(findings, has_mx)``, ``review['mail_hosts']`` lists them in order and ``review['unknown_mail']`` the names that had to be reviewed and were not."""
    from agentapi import probe_dispatch
    from reNgine.resources import ScannerUnavailable
    own, extra = mail_candidates(domain)
    if hosts is not None:
        own, extra = ([domain.name] if domain.name in hosts and not is_ip(domain.name) else []), []
    mail = [(name, True) for name in own] + [(name, False) for name in extra]
    try:
        result = probe_dispatch.try_hygiene(domain, targets, mail)
    except ScannerUnavailable as exc:
        logger.info('hygiene check of %s waits for a scanner: %s', domain.name, exc)
        return None, True
    rows = {(_norm(c['host']), c['port']): c for c in result.get('certs') or []}
    review = {'infos': {}, 'unknown_tls': set(), 'mail': {}, 'mail_hosts': [], 'unknown_mail': set()}
    for host, port in targets:
        row = rows.get((_norm(host), port))
        if row is None or row.get('error'):
            review['unknown_tls'].add(f'{host}:{port}')
        elif row.get('found'):
            review['infos'][(host, port)] = _cert_info(host, port, row['cert'])
    reviews = {_norm(m['name']): m for m in result.get('mail') or []}
    # a name whose lookup failed on the scanner (a resolver timeout is not "no MX record"): its open findings stay open, whether or not it is an own name
    lookup_failed = {_norm(n) for n in result.get('unknown_names') or [] if isinstance(n, str)}
    for name, always in mail:
        row = reviews.get(_norm(name))
        if _norm(name) in lookup_failed or (row is not None and row.get('error')):
            review['unknown_mail'].add(name)
        elif row is not None:
            review['mail_hosts'].append(name)
            review['mail'][name] = ([Finding(f['check'], f['severity'], f['title'], f['detail'], f['host'], f['evidence']) for f in row['findings']],
                                    row['has_mx'])
        elif always:
            review['unknown_mail'].add(name)
    return review, False


def run_hygiene(domain_id, now=None, hosts=None):
    """Check one target's certificates, TLS configuration and email authentication; upsert and resolve findings.

    The endpoints and mail names go to a Sentinel as one ``hygiene_check`` task (``agentapi.probe_dispatch.try_hygiene``); this server never reads a
    certificate or a record itself. It evaluates and stores what comes back. An endpoint or a mail domain the scanner did not answer for is unknown: its
    open findings stay open. With no scanner able to take the work (the kind is in ``sentinel_dispatch.NEVER_LOCAL``) nothing is recorded and the target
    stays due."""
    from cveFeed import activity, changes
    from cveFeed.models import TlsCertificate
    from targetApp.models import Domain
    domain = Domain.objects.get(pk=domain_id)
    project = domain.project_id
    running = activity.log('hygiene', f'Checking TLS and email authentication for {domain.name}', project=project, status='running')
    found = []

    targets = tls_targets(domain, hosts=hosts)
    review, waiting = _remote_review(domain, targets, hosts)
    if waiting:
        activity.settle(running, 'done', message=f'Hygiene check of {domain.name}: waiting for a scanner, the target stays due', skipped=True)
        return {'tls_hosts': 0, 'mail_domains': 0, 'findings': 0, 'resolved': 0, 'cert_changes': 0, 'cleartext': 0,
                'skipped': 'waiting for a scanner: the target stays due'}
    probed = 0
    cert_changes = 0
    existing = {(c.host, c.port): c for c in TlsCertificate.objects.filter(domain=domain)}  # one query; bounded by MAX_TLS_TARGETS
    for info in review['infos'].values():
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
    mail_hosts, emailer = review['mail_hosts'], (lambda name: review['mail'][name])
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

    cleartext_found, cleartext_ok = [], True  # Telnet, FTP, rlogin and a plain-HTTP login, from the ports and routes already stored: no probe
    try:
        from cveFeed import cleartext
        cleartext_found = cleartext.findings_for(domain, hosts=hosts)
    except Exception:  # noqa: BLE001 - the rest of the review stands on its own, and an open finding is not resolved for want of an answer
        cleartext_ok = False
        logger.exception('cleartext service check failed for %s', domain.name)
    found += cleartext_found
    flood_found, flood_ok = [], True  # a host that answers on an unusually large number of ports: one info note, from the stored ports
    try:
        from cveFeed import port_flood
        flood_found = port_flood.findings_for(domain, hosts=hosts)
    except Exception:  # noqa: BLE001 - an open note is not resolved for want of an answer
        flood_ok = False
        logger.exception('port flood check failed for %s', domain.name)
    found += flood_found

    unanswered = None
    if review['unknown_tls'] or review['unknown_mail']:
        def unanswered(host, check):  # a certificate finding's host is 'name:port'; a mail finding's is the name or a record name under it
            if check.startswith('tls_'):
                return host in review['unknown_tls']
            return any(host == name or host.endswith('.' + name) for name in review['unknown_mail'])
    stale = store_findings(domain, found, hosts=hosts, owns=lambda check: not check.startswith(('ts_', 'tlsa_', 'bkt_', 'udp_', 'src_'))  # the tailnet, the TLS audit, cloud storage, UDP and secrets-scan checks keep their own
                           and (cleartext_ok or not check.startswith('cleartext_')) and (flood_ok or not check.startswith('portflood_')), live_cnames=True, across_targets=True, unanswered=unanswered)
    if project:  # a redirect alias's copy of what its target host has is folded into the target's row (cveFeed.finding_lifecycle)
        from cveFeed import finding_lifecycle
        names = {finding_lifecycle.host_name(f.host or domain.name) for f in found} | {host for host, _port in targets}
        finding_lifecycle.fold_aliases_quietly(project, names)
    try:  # the medium and worse findings are triaged (impact and a fix); never fatal to the check
        from cveFeed import triage
        triage.triage_hygiene(domain_id)
    except Exception:  # noqa: BLE001
        logger.exception('could not triage the hygiene findings of %s', domain.name)
    worst = max((f.severity for f in found if f.severity >= LOW), default=-1)
    counts = {'tls_hosts': probed, 'mail_domains': len(mail_hosts), 'findings': len([f for f in found if f.severity >= LOW]),
              'resolved': len(stale), 'cert_changes': cert_changes, 'cleartext': len(cleartext_found)}
    activity.settle(running, 'done', message=(
        f'Hygiene check of {domain.name}: {probed} certificate{"s" if probed != 1 else ""}, '
        f'{counts["findings"]} issue{"s" if counts["findings"] != 1 else ""}'
        + (f' (worst: {["info", "low", "medium", "high", "critical"][worst]})' if worst >= 0 else '')), **counts)
    from cveFeed import ledger
    if hosts is None:
        ledger.record('hygiene', [domain.name], project)  # a host-only probe is not whole-target coverage
    return counts
