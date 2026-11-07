"""The server's reading of the probe kinds' results (contract version 3): ``http_probe``, ``dns_resolve``, ``alive_check``, ``bucket_check``, ``identity_check``, ``hygiene_check``, ``dangling_dns_check``, ``supplier_check``, ``vhost_probe``, ``subdir_probe`` and ``route_probe``.

Every result is untrusted. ``clean_*`` keep only the contract's shape, clip every string and cap every list (the bounds are the contract's and
``cveFeed.models.ProbeObservation``'s columns); ``bind`` then drops what the task did not ask about (a probe id it did not plan, a name it did
not name), so a Sentinel can only ever answer for its own task's hosts. ``agentapi.sentinel_broker.clean_result`` calls both."""
import json
import re

from agentapi.services import ApiError

MAX_PROBES = 300
MAX_OBSERVATIONS = 40
MAX_EVIDENCE_BYTES = 16 * 1024
MAX_HOSTS = 2000
MAX_NAMES = 500
MAX_ADDRESSES_PER_NAME = 32
KINDS = ('version', 'identity', 'edge', 'wordpress', 'wp-upgrade-dir')
OUTCOMES = ('found', 'hidden', 'absent', 'challenged', 'edge')


def _text(value, limit):
    from agentapi.sentinel_broker import _text as clip
    return clip(value, limit)


def _host(value):
    text = _text(value, 260).strip().lower().rstrip('.')
    return text if text and not any(c.isspace() for c in text) else ''


def _evidence(value):
    """A JSON object of at most MAX_EVIDENCE_BYTES, or ``{}``: what the probe read (signals, a library record) is shown and read as data only."""
    if not isinstance(value, dict):
        return {}
    try:
        text = json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return {}
    return value if len(text.encode('utf-8')) <= MAX_EVIDENCE_BYTES else {}


def _observation(item):
    if not isinstance(item, dict) or item.get('kind') not in KINDS or item.get('outcome') not in OUTCOMES:
        return None
    confidence = item.get('confidence')
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or confidence != confidence:
        return None
    port = item.get('port', 0)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        port = 0
    return {'kind': item['kind'], 'product': _text(item.get('product'), 120), 'version': _text(item.get('version'), 100),
            'variant': _text(item.get('variant'), 60), 'outcome': item['outcome'], 'confidence': max(0.0, min(1.0, float(confidence))),
            'source': _text(item.get('source'), 48), 'port': port, 'url': _text(item.get('url'), 500), 'evidence': _evidence(item.get('evidence'))}


def _hosts(values):
    if not isinstance(values, list):
        return []
    out = []
    for value in values[:MAX_HOSTS]:
        host = _host(value)
        if host and host not in out:
            out.append(host)
    return out


def clean_http_probe(body):
    probes = body.get('probes')
    if not isinstance(probes, list) or len(probes) > MAX_PROBES:
        raise ApiError(400, 'an http_probe result lists its probes (at most %d)' % MAX_PROBES)
    out = []
    for item in probes:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'] or not isinstance(item.get('observations'), list):
            continue
        row = {'id': _text(item['id'], 200),
               'observations': [o for o in map(_observation, item['observations'][:MAX_OBSERVATIONS]) if o is not None]}
        if item.get('error'):
            row['error'] = _text(item['error'], 200)
        out.append(row)
    return {'probes': out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


def clean_dns_resolve(body):
    from agentapi.sentinel_broker import _address
    resolved, errors = body.get('resolved'), body.get('errors')
    if not isinstance(resolved, dict) or not isinstance(errors, dict) or len(resolved) > MAX_NAMES or len(errors) > MAX_NAMES:
        raise ApiError(400, 'a dns_resolve result lists what resolved and what could not be answered (at most %d names each)' % MAX_NAMES)
    out = {}
    for name, addresses in resolved.items():
        name = _host(name)
        if not name or not isinstance(addresses, list):
            continue
        clean = []
        for address in addresses[:MAX_ADDRESSES_PER_NAME]:
            ip = _address(address) if isinstance(address, str) else None
            if ip and ip not in clean:
                clean.append(ip)
        if clean:
            out[name] = clean
    failed = {name: _text(why, 120) for name, why in ((_host(k), v) for k, v in errors.items()) if name and name not in out}
    refused = [n for n in _hosts(body.get('refused'))[:MAX_NAMES]]
    return {'resolved': out, 'errors': failed, 'refused': refused}


MAX_CHECKS = 600


def clean_alive_check(body):
    checks = body.get('checks')
    if not isinstance(checks, list) or len(checks) > MAX_CHECKS:
        raise ApiError(400, 'an alive_check result lists its checks (at most %d)' % MAX_CHECKS)
    out = []
    for item in checks:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'] or not isinstance(item.get('alive'), bool):
            continue
        row = {'id': _text(item['id'], 200), 'alive': item['alive']}
        if item.get('error'):
            row['error'] = _text(item['error'], 200)
        out.append(row)
    return {'checks': out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


MAX_IDENTITY_DNS = 200
MAX_IDENTITY_CERTS = 50
MAX_IDENTITY_RECORDS = 50
MAX_IDENTITY_NAMES = 100
IDENTITY_DNS_STATES = ('ok', 'none', 'unknown')
IDENTITY_DNS_TYPES = ('A', 'CNAME', 'NS', 'MX', 'PTR')


def clean_identity_check(body):
    """The DNS answers and certificate names of an ``identity_check`` result, clipped. A row that is not well formed is dropped: it reads as no
    answer (unknown), never as ``none``. Only ``status == 'ok'`` rows carry records or names; ``none`` carries nothing."""
    dns, certs = body.get('dns'), body.get('certs')
    if not isinstance(dns, list) or not isinstance(certs, list) or len(dns) > MAX_IDENTITY_DNS or len(certs) > MAX_IDENTITY_CERTS:
        raise ApiError(400, 'an identity_check result lists its DNS answers (at most %d) and certificates (at most %d)' % (MAX_IDENTITY_DNS, MAX_IDENTITY_CERTS))
    dns_out = []
    for item in dns:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'] or item.get('status') not in IDENTITY_DNS_STATES:
            continue
        records = item.get('records') if isinstance(item.get('records'), list) and item['status'] == 'ok' else []
        row = {'id': _text(item['id'], 200), 'status': item['status'], 'records': [_text(r, 260) for r in records[:MAX_IDENTITY_RECORDS] if isinstance(r, str)]}
        if item['status'] == 'ok' and isinstance(item.get('canonical'), str):
            row['canonical'] = _host(item['canonical'])
        if item.get('error'):
            row['error'] = _text(item['error'], 200)
        dns_out.append(row)
    cert_out = []
    for item in certs:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'] or item.get('status') not in ('ok', 'unknown'):
            continue
        found = item.get('names') if isinstance(item.get('names'), list) and item['status'] == 'ok' else []
        row = {'id': _text(item['id'], 200), 'status': item['status'], 'names': [_text(n, 260) for n in found[:MAX_IDENTITY_NAMES] if isinstance(n, str)]}
        if item.get('error'):
            row['error'] = _text(item['error'], 200)
        cert_out.append(row)
    return {'dns': dns_out, 'certs': cert_out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


MAX_BUCKETS = 100
BUCKET_STATES = ('public', 'private', 'missing', 'unknown')


def _verdict(raw):
    """A bucket verdict clipped to the contract, or None. The object names stay raw here: ``bucket_scan`` redacts them before storing or showing."""
    if not isinstance(raw, dict) or raw.get('state') not in BUCKET_STATES:
        return None
    objects = raw.get('objects') if isinstance(raw.get('objects'), list) else []
    object_read = raw.get('object_read')
    def number(value, top):
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= top else 0
    return {'state': raw['state'], 'objects': [_text(o, 1024) for o in objects[:20] if isinstance(o, str)], 'truncated': raw.get('truncated') is True,
            'region': _text(raw.get('region'), 40), 'object_read': object_read if isinstance(object_read, bool) else None,
            'status': number(raw.get('status'), 999), 'code': _text(raw.get('code'), 64), 'request_count': number(raw.get('request_count'), 20)}


def clean_bucket_check(body):
    buckets = body.get('buckets')
    if not isinstance(buckets, list) or len(buckets) > MAX_BUCKETS:
        raise ApiError(400, 'a bucket_check result lists its buckets (at most %d)' % MAX_BUCKETS)
    out = []
    for item in buckets:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
            continue
        verdict = _verdict(item.get('verdict'))
        if verdict is not None:
            out.append({'id': _text(item['id'], 300), 'verdict': verdict})
    return {'buckets': out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


MAX_CERTS = 300
MAX_MAIL = 101
MAX_MAIL_FINDINGS = 200
# The check families the email review raises (``hygiene.evaluate_*``, ``mailfail``). A Sentinel can report only these: a finding named like another
# stage's (tls_*, ts_*, bkt_*, udp_*, src_*, cleartext_*) is dropped, so it can neither file nor resolve a row that belongs to that stage.
MAIL_CHECK_PREFIXES = ('spf_', 'dmarc_', 'dkim_', 'caa_', 'mx_', 'mta_sts_', 'smtp_tlsrpt_', 'dane_', 'dnssec_', 'bimi_', 'arc_', 'adsp_', 'mailchannels_')
_CHECK_NAME = re.compile(r'[a-z0-9_]{1,64}')
_HOST_NAME = re.compile(r'[A-Za-z0-9_.\-]{1,300}')


def _timestamp(value):
    """An ISO 8601 timestamp as the same text with a zone (a certificate's date), or None when it does not read as one."""
    import datetime
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        stamp = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return (stamp if stamp.tzinfo else stamp.replace(tzinfo=datetime.timezone.utc)).isoformat()


def _certificate(raw):
    """A certificate clipped to the columns it is stored in (``hygiene.clip_certificate`` limits), or None when it has no readable expiry."""
    if not isinstance(raw, dict):
        return None
    after = _timestamp(raw.get('not_after'))
    if after is None:
        return None
    legacy = raw.get('legacy_handshake') if isinstance(raw.get('legacy_handshake'), dict) else {}
    sans = raw.get('sans') if isinstance(raw.get('sans'), list) else []
    out = {'subject': _text(raw.get('subject'), 500), 'issuer': _text(raw.get('issuer'), 500), 'sans': [_text(s, 255) for s in sans[:200] if isinstance(s, str)],
           'not_before': _timestamp(raw.get('not_before')), 'not_after': after, 'signature_algorithm': _text(raw.get('signature_algorithm'), 100),
           'key_description': _text(raw.get('key_description'), 100), 'protocol': _text(raw.get('protocol'), 20), 'cipher': _text(raw.get('cipher'), 100),
           'chain_error': _text(raw.get('chain_error'), 300), 'legacy_tls': raw.get('legacy_tls') is True}
    if legacy:
        out['legacy_handshake'] = {'protocol': _text(legacy.get('protocol'), 20), 'cipher': _text(legacy.get('cipher'), 100)}
    return out


def _finding(raw):
    """One mail finding clipped to the HygieneFinding columns, or None: an unknown check family, a severity out of range or a host that is no name."""
    if not isinstance(raw, dict):
        return None
    check, severity, host = raw.get('check'), raw.get('severity'), raw.get('host')
    if not isinstance(check, str) or not _CHECK_NAME.fullmatch(check) or not check.startswith(MAIL_CHECK_PREFIXES):
        return None
    if isinstance(severity, bool) or not isinstance(severity, int) or not 0 <= severity <= 4:
        return None
    if not isinstance(host, str) or not _HOST_NAME.fullmatch(host):
        return None
    return {'check': check, 'severity': severity, 'title': _text(raw.get('title'), 300), 'detail': _text(raw.get('detail'), 2000), 'host': host,
            'evidence': _evidence(raw.get('evidence'))}


def clean_hygiene_check(body):
    certs, mail = body.get('certs'), body.get('mail')
    if not isinstance(certs, list) or len(certs) > MAX_CERTS or not isinstance(mail, list) or len(mail) > MAX_MAIL:
        raise ApiError(400, 'a hygiene_check result lists its certs (at most %d) and mail reviews (at most %d)' % (MAX_CERTS, MAX_MAIL))
    out_certs, out_mail = [], []
    for item in certs:
        if not isinstance(item, dict) or not isinstance(item.get('host'), str) or not item['host'] or isinstance(item.get('port'), bool) \
                or not isinstance(item.get('port'), int) or not 0 < item['port'] < 65536:
            continue
        row = {'host': _text(item['host'], 260), 'port': item['port'], 'found': False}
        if item.get('found') is True:
            cert = _certificate(item.get('cert'))
            if cert is None:
                row['error'] = 'the certificate could not be read'  # a TLS service answered but what came back is unusable: unknown
            else:
                row.update(found=True, cert=cert)
        elif isinstance(item.get('error'), str) and item['error']:
            row['error'] = _text(item['error'], 200)  # not asked or not probed: unknown, never "nothing there"
        out_certs.append(row)
    for item in mail:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not item['name'] or not isinstance(item.get('findings'), list):
            continue
        findings = [f for f in (_finding(x) for x in item['findings'][:MAX_MAIL_FINDINGS]) if f is not None]
        out_mail.append({'name': _text(item['name'], 253), 'has_mx': item.get('has_mx') is True, 'findings': findings})
    return {'certs': out_certs, 'mail': out_mail, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


MAX_RATINGS = 50


def clean_dangling_dns_check(body):
    ratings = body.get('ratings')
    if not isinstance(ratings, list) or len(ratings) > MAX_RATINGS:
        raise ApiError(400, 'a dangling_dns_check result lists its ratings (at most %d)' % MAX_RATINGS)
    out = []
    for item in ratings:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'] or item.get('state') not in ('rated', 'unknown'):
            continue
        row = {'id': _text(item['id'], 200), 'state': item['state']}
        if item['state'] == 'rated':
            severity = item.get('severity')
            row.update(severity=severity if isinstance(severity, int) and not isinstance(severity, bool) and 1 <= severity <= 3 else None,
                       drop=item.get('drop') is True, note=_text(item.get('note'), 2000), zone=_text(item.get('zone'), 260))
        out.append(row)
    return {'ratings': out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


MAX_SUPPLIER_DOMAINS = 25
MAX_POSTURES = 200
SUPPLIER_CATEGORIES = ('tls', 'email', 'web', 'exposed')  # decided on the Sentinel; the fifth category, cve, is matched here against the catalog
SUPPLIER_RESOLVABLE = SUPPLIER_CATEGORIES + ('cve',)
CARD_STATES = ('ok', 'unreachable', 'no_address', 'blocked', 'challenged')
CHECK_NAME_RE = re.compile(r'^[A-Za-z0-9_@.:\-]{1,60}$')


def _int(value, low, high, default=0):
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else default


def _opt_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and -1 <= value <= 10 ** 9 else None


def _strings(values, count, limit):
    return [_text(v, limit) for v in values[:count] if isinstance(v, str)] if isinstance(values, list) else []


def _supplier_posture(item):
    """One finding of a supplier name, or None. The text to ask the supplier is never taken from the result: ``supplier_checks.ask_for`` writes it."""
    if not isinstance(item, dict) or item.get('category') not in SUPPLIER_CATEGORIES:
        return None
    check, severity = item.get('check'), item.get('severity')
    if not isinstance(check, str) or not CHECK_NAME_RE.match(check) or isinstance(severity, bool) or not isinstance(severity, int) or not 0 <= severity <= 4:
        return None
    return {'check': check, 'severity': severity, 'title': _text(item.get('title'), 300), 'detail': _text(item.get('detail'), 4000),
            'category': item['category'], 'evidence': _evidence(item.get('evidence'))}


def _supplier_card(raw):
    """The host card sections of one name, each reduced to the keys and types the card stores. Anything else is dropped."""
    import ipaddress
    raw = raw if isinstance(raw, dict) else {}
    state = raw.get('state') if raw.get('state') in CARD_STATES else 'unreachable'
    addresses = []
    for value in (raw.get('addresses') if isinstance(raw.get('addresses'), list) else [])[:6]:
        try:
            addresses.append(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            continue
    ev = raw.get('evidence') if isinstance(raw.get('evidence'), dict) else {}
    evidence = {}
    if ev.get('address') in ('ok', 'none', 'blocked', 'unknown'):
        evidence['address'] = ev['address']
    if ev.get('dns') in ('ok', 'nxdomain', 'unknown'):
        evidence['dns'] = ev['dns']
    for key, limit in (('note', 300), ('challenged', 60)):
        if isinstance(ev.get(key), str):
            evidence[key] = _text(ev[key], limit)
    card = {'state': state, 'addresses': addresses, 'evidence': evidence}
    tls = raw.get('tls')
    if isinstance(tls, dict):
        def stamp(value):
            return _text(value, 40) if isinstance(value, str) and value else None
        card['tls'] = {'subject': _text(tls.get('subject'), 500), 'issuer': _text(tls.get('issuer'), 500), 'sans': _strings(tls.get('sans'), 50, 255),
                       'not_before': stamp(tls.get('not_before')), 'not_after': stamp(tls.get('not_after')), 'days_left': _opt_int(tls.get('days_left')),
                       'key': _text(tls.get('key'), 100), 'signature': _text(tls.get('signature'), 100), 'protocol': _text(tls.get('protocol'), 20),
                       'cipher': _text(tls.get('cipher'), 100), 'chain_error': _text(tls.get('chain_error'), 300), 'legacy_tls': tls.get('legacy_tls') is True}
    mail = raw.get('mail')
    if isinstance(mail, dict):
        card['mail'] = {'handles_mail': mail.get('handles_mail') is True, 'mx': mail.get('mx') is True}
    page = raw.get('http')
    if isinstance(page, dict):
        section = {'https_status': _opt_int(page.get('https_status')), 'http_status': _opt_int(page.get('http_status'))}
        if isinstance(page.get('headers'), dict):  # a front page that answered: its response as read
            headers = page['headers']
            section.update({'url': _text(page.get('url'), 300), 'status': _opt_int(page.get('status')), 'title': _text(page.get('title'), 200),
                            'content_type': _text(page.get('content_type'), 100), 'server': _text(page.get('server'), 200),
                            'powered_by': _text(page.get('powered_by'), 200), 'location': _text(page.get('location'), 300),
                            'cookies': _strings(page.get('cookies'), 20, 100), 'bytes': _opt_int(page.get('bytes')),
                            'headers': {_text(k, 100).lower(): _text(v, 200) for k, v in list(headers.items())[:60] if isinstance(k, str) and isinstance(v, str)}})
        card['http'] = section
    elif 'http' in raw:
        card['http'] = None
    return card


def _supplier_row(item):
    if not isinstance(item, dict):
        return None
    domain = _host(item.get('domain'))
    if not domain or len(domain) > 253:
        return None
    postures = [p for p in (_supplier_posture(x) for x in (item.get('postures') if isinstance(item.get('postures'), list) else [])[:MAX_POSTURES]) if p]
    resolvable = {}
    if isinstance(item.get('resolvable'), dict):
        for category, prefixes in list(item['resolvable'].items())[:8]:
            if category in SUPPLIER_RESOLVABLE and isinstance(prefixes, list):
                resolvable[category] = sorted({_text(x, 60) for x in prefixes[:40] if isinstance(x, str)})
    summary = {}
    if isinstance(item.get('summary'), dict):
        for key, value in list(item['summary'].items())[:8]:
            if isinstance(key, str) and (value is None or isinstance(value, (bool, int)) or isinstance(value, str)):
                summary[_text(key, 40)] = _text(value, 200) if isinstance(value, str) else value
    fingerprints = [{'name': _text(f.get('name'), 120), 'source': _text(f.get('source'), 40)}
                    for f in (item.get('fingerprints') if isinstance(item.get('fingerprints'), list) else [])[:20] if isinstance(f, dict) and isinstance(f.get('name'), str)]
    return {'domain': domain, 'postures': postures, 'resolvable': resolvable, 'summary': summary, 'card': _supplier_card(item.get('card')),
            'fingerprints': fingerprints, 'edges': _strings(item.get('edges'), 10, 60), 'distro': _text(item.get('distro'), 60),
            'answered': item.get('answered') is True, 'stopped': item.get('stopped') is True, 'partial': item.get('partial') is True,
            'requests': _int(item.get('requests'), 0, 5000)}


def clean_supplier_check(body):
    domains = body.get('domains')
    if not isinstance(domains, list) or len(domains) > MAX_SUPPLIER_DOMAINS:
        raise ApiError(400, 'a supplier_check result lists its domains (at most %d)' % MAX_SUPPLIER_DOMAINS)
    out = [row for row in (_supplier_row(item) for item in domains) if row is not None]
    return {'domains': out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


STATES = ('answered', 'no_answer', 'challenged', 'busy')
MAX_VHOST_ADDRESSES = 10
MAX_VHOST_NAMES = 200
MAX_PAGE_BODY = 64 * 1024
MAX_SUBDIR_HOSTS = 10
MAX_SUBDIR_PATHS = 200
SUBDIR_SOURCES = ('curated', 'crawled', 'archive', 'robots', 'sitemap')


def _count(value, top=10 ** 9):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= top else 0


def _fingerprint(raw):
    """The five facts two answers are compared by (``vhost_scan.fingerprint_of``), clipped, or None."""
    if not isinstance(raw, dict) or not isinstance(raw.get('status'), int) or isinstance(raw.get('status'), bool):
        return None
    return {'status': _count(raw['status'], 999), 'title': ' '.join(_text(raw.get('title'), 200).split()), 'length': _count(raw.get('length')),
            'location': _text(raw.get('location'), 200), 'server': _text(raw.get('server'), 60)}


def _page(raw):
    """What a distinct application's own page states: the response a version is read from. Clipped, never executed."""
    if not isinstance(raw, dict):
        return None
    headers = raw.get('headers') if isinstance(raw.get('headers'), dict) else {}
    return {'status': _count(raw.get('status'), 999), 'title': _text(raw.get('title'), 300), 'server': _text(raw.get('server'), 200),
            'content_type': _text(raw.get('content_type'), 100), 'powered_by': _text(raw.get('powered_by'), 200), 'url': _text(raw.get('url'), 500),
            'body': _text(raw.get('body'), MAX_PAGE_BODY),
            'headers': {_text(k, 100).lower(): _text(v, 200) for k, v in list(headers.items())[:60] if isinstance(k, str) and isinstance(v, str)}}


def _answer(raw):
    """``{'state', 'fingerprint'?, 'challenge'?}`` of one request's answer, or None. An answer with no fingerprint is no answer at all."""
    if not isinstance(raw, dict) or raw.get('state') not in STATES:
        return None
    out = {'state': raw['state']}
    if raw['state'] == 'answered':
        fingerprint = _fingerprint(raw.get('fingerprint'))
        if fingerprint is None:
            return None
        out['fingerprint'] = fingerprint
    elif raw['state'] == 'challenged':
        out['challenge'] = _text(raw.get('challenge'), 60) or 'an edge'
        fingerprint = _fingerprint(raw.get('fingerprint'))
        if fingerprint is not None:
            out['fingerprint'] = fingerprint
    return out


def clean_vhost_probe(body):
    addresses = body.get('addresses')
    if not isinstance(addresses, list) or len(addresses) > MAX_VHOST_ADDRESSES:
        raise ApiError(400, 'a vhost_probe result lists its addresses (at most %d)' % MAX_VHOST_ADDRESSES)
    out = []
    for item in addresses:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
            continue
        default = _answer(item.get('default'))
        names = item.get('names') if isinstance(item.get('names'), list) else []
        if default is None:
            continue
        rows = []
        for entry in names[:MAX_VHOST_NAMES]:
            answer = _answer(entry) if isinstance(entry, dict) else None
            if answer is None or not isinstance(entry.get('name'), str) or not _host(entry['name']):
                continue
            row = {'name': _host(entry['name']), **answer}
            if 'own' in entry:
                row['own'] = _fingerprint(entry.get('own'))
            page = _page(entry.get('page')) if answer['state'] == 'answered' else None
            if page is not None:
                row['page'] = page
            rows.append(row)
        out.append({'id': _text(item['id'], 300), 'default': default, 'names': rows})
    return {'addresses': out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


def _found(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get('product'), str) or not raw['product'].strip():
        return None
    confidence = raw.get('confidence')
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or confidence != confidence:
        return None
    return {'product': _text(raw['product'], 120), 'confidence': max(0.0, min(1.0, float(confidence))), 'source': _text(raw.get('source'), 48),
            'version': _text(raw.get('version'), 100), 'indicated': _text(raw.get('indicated'), 500)}


def clean_subdir_probe(body):
    hosts = body.get('hosts')
    if not isinstance(hosts, list) or len(hosts) > MAX_SUBDIR_HOSTS:
        raise ApiError(400, 'a subdir_probe result lists its hosts (at most %d)' % MAX_SUBDIR_HOSTS)
    out = []
    for item in hosts:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'] or item.get('state') not in ('done', 'challenged', 'busy'):
            continue
        challenge = item.get('challenge') if isinstance(item.get('challenge'), dict) else {}
        probed = [_text(p, 500) for p in (item.get('probed') if isinstance(item.get('probed'), list) else [])[:MAX_SUBDIR_PATHS] if isinstance(p, str)]
        answers = []
        for a in (item.get('answers') if isinstance(item.get('answers'), list) else [])[:MAX_SUBDIR_PATHS]:
            fingerprint = _fingerprint(a.get('fingerprint')) if isinstance(a, dict) else None
            if fingerprint is None or not isinstance(a.get('path'), str) or not a['path']:
                continue
            answers.append({'path': _text(a['path'], 500), 'source': a.get('source') if a.get('source') in SUBDIR_SOURCES else 'curated',
                            'fingerprint': fingerprint, 'found': _found(a.get('found'))})
        row = {'id': _text(item['id'], 300), 'state': item['state'], 'requests': _count(item.get('requests'), 150),
               'baseline': _fingerprint(item.get('baseline')), 'probed': probed, 'answers': answers}
        if item['state'] == 'challenged':
            row['challenge'] = {'edge': _text(challenge.get('edge'), 60) or 'an edge', 'status': _count(challenge.get('status'), 999),
                                'path': _text(challenge.get('path'), 500)}
        out.append(row)
    return {'hosts': out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


MAX_ROUTES = 500  # 25 hosts of at most 20 routes
ROUTE_STATES = ('open', 'login', 'sso', 'session_required', 'redirect', 'not_found', 'error', 'catch_all')
MAX_ROUTE_EVIDENCE_BYTES = 128 * 1024
MAX_ROUTE_CREDENTIALS = 20
# the evidence a route check keeps (``cveFeed.route_auth.classify``, ``_read_scripts`` and ``_against_missing_page``): key -> the type it must have.
# Anything else (the page's scripts to read, an invented key) is dropped, a key of the wrong type too.
_ROUTE_EVIDENCE = {'markers': list, 'bytes': int, 'cookies': list, 'server': str, 'powered_by': str, 'headers': dict, 'fingerprints': list,
                   'fingerprint_names': list, 'script_page': dict, 'script_urls': list, 'libraries': dict, 'provider': str, 'redirect_to': str,
                   'www_authenticate': str, 'reason': str, 'catch_all': dict}


def _json_size(value):
    try:
        return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8'))
    except (TypeError, ValueError):
        return None


def _route_evidence(raw):
    """The evidence of one route clipped to the keys and types the route check keeps, or None when it is not JSON or too large (the route is then
    unanswered: a truncated reading would be read as what the page says)."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key, kind in _ROUTE_EVIDENCE.items():
        value = raw.get(key)
        if value is None or isinstance(value, bool) or not isinstance(value, kind):
            continue
        if kind is str:
            value = _text(value, 2000 if key == 'redirect_to' else 100)
        elif key in ('markers', 'cookies', 'fingerprint_names', 'script_urls'):
            value = [_text(v, 2000 if key == 'script_urls' else 120) for v in value[:40 if key != 'cookies' else 60] if isinstance(v, str)]
        elif key == 'fingerprints':
            value = [{'name': _text(v['name'], 120), 'source': _text(v.get('source'), 48)} for v in value[:40]
                     if isinstance(v, dict) and isinstance(v.get('name'), str)]
        out[key] = value
    out.setdefault('provider', '')
    out.setdefault('redirect_to', '')
    size = _json_size(out)
    return out if size is not None and size <= MAX_ROUTE_EVIDENCE_BYTES else None


def _route_sensitive(raw):
    """``{type: {'count', 'sample'}}`` for the kinds ``cveFeed.sensitive`` knows, counts bounded and samples clipped. The score is the server's own."""
    from cveFeed import sensitive
    out = {}
    if not isinstance(raw, dict):
        return out
    for name, row in raw.items():
        if name in sensitive.PATTERNS and isinstance(row, dict):
            count = row.get('count')
            if isinstance(count, int) and not isinstance(count, bool) and 0 < count <= sensitive.MAX_PER_TYPE:
                out[name] = {'count': count, 'sample': _text(row.get('sample'), 200)}
    return out


def _route_credentials(raw):
    from cveFeed import sensitive
    out = []
    for item in raw[:MAX_ROUTE_CREDENTIALS] if isinstance(raw, list) else ():
        if isinstance(item, dict) and item.get('type') in sensitive.CREDENTIAL_TYPES and isinstance(item.get('value'), str) and 0 < len(item['value']) <= 8192:
            out.append({'type': item['type'], 'value': item['value']})
    return out


def _state_fits(state, status):
    """Whether ``state`` is one the status can have: a page that is not there is a 404 or 410, an open page or a login page answered 2xx or 405.
    The other states (a redirect, a session requirement, single sign-on) can come from several statuses, a meta refresh included."""
    if state == 'not_found':
        return status in (404, 410)
    if state in ('open', 'login'):
        return 200 <= status < 300 or status == 405
    return True


def _route(item):
    """One route's reading, or None. A route reported with an error carries no state."""
    if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
        return None
    row = {'id': _text(item['id'], 2000)}
    if item.get('error'):
        row['error'] = _text(item['error'], 200)
        return row
    status = item.get('status')
    status = status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 999 else None
    state = item.get('state')
    if state not in ROUTE_STATES or not _state_fits(state, status or 0):
        return {**row, 'error': 'the scanner reported a state this route cannot have'}
    evidence = _route_evidence(item.get('evidence'))
    if evidence is None:
        return {**row, 'error': 'the scanner reported more evidence than a route may carry'}
    from cveFeed import sensitive
    found = _route_sensitive(item.get('sensitive'))
    size = item.get('bytes')
    return {**row, 'status': status, 'state': state, 'title': _text(item.get('title'), 300), 'content_type': _text(item.get('content_type'), 100),
            'evidence': evidence, 'sensitive': found, 'sensitive_score': sensitive.sensitive_score(found),
            'bytes': size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else 0,
            'credentials': _route_credentials(item.get('credentials'))}


def clean_route_probe(body):
    routes = body.get('routes')
    if not isinstance(routes, list) or len(routes) > MAX_ROUTES:
        raise ApiError(400, 'a route_probe result lists its routes (at most %d)' % MAX_ROUTES)
    out = [r for r in map(_route, routes) if r is not None]
    return {'routes': out, 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}


def bind(kind, result, task):
    """``result`` cut down to what ``task`` asked about: a probe id the task did not plan, or a name it did not name, is dropped and counted."""
    target = task.target if isinstance(task.target, dict) else {}
    if kind == 'vhost_probe':
        asked = {a.get('id'): {n.get('name') for n in a.get('names') or [] if isinstance(n, dict)} for a in target.get('addresses') or [] if isinstance(a, dict)}
        kept, dropped = [], 0
        for a in result['addresses']:
            if a['id'] not in asked:
                dropped += 1
                continue
            names = [n for n in a['names'] if n['name'] in asked[a['id']]]
            dropped += len(a['names']) - len(names)
            kept.append({**a, 'names': names})
        result = {**result, 'addresses': kept}
    elif kind == 'subdir_probe':
        asked = {h.get('id') for h in target.get('hosts') or [] if isinstance(h, dict)}
        kept = [h for h in result['hosts'] if h['id'] in asked]
        dropped = len(result['hosts']) - len(kept)
        result = {**result, 'hosts': kept}
    elif kind == 'hygiene_check':  # only the endpoints and names the task asked about (names compared as the Sentinel writes them: lower case, no final dot)
        def norm(name):
            return str(name or '').strip().lower().rstrip('.')
        tls = {(norm(p.get('host')), p.get('port')) for p in target.get('tls') or [] if isinstance(p, dict)}
        names = {norm(p.get('name')) for p in target.get('mail') or [] if isinstance(p, dict)}
        certs = [c for c in result['certs'] if (norm(c['host']), c['port']) in tls]
        mail = [m for m in result['mail'] if norm(m['name']) in names]
        dropped = len(result['certs']) - len(certs) + len(result['mail']) - len(mail)
        result = {**result, 'certs': certs, 'mail': mail}
    elif kind == 'dangling_dns_check':
        asked = {c.get('id') for c in target.get('checks') or [] if isinstance(c, dict)}
        ratings = [r for r in result['ratings'] if r['id'] in asked]
        dropped = len(result['ratings']) - len(ratings)
        result = {**result, 'ratings': ratings}
    elif kind in ('http_probe', 'alive_check', 'bucket_check', 'route_probe'):
        key = {'http_probe': 'probes', 'alive_check': 'checks', 'bucket_check': 'buckets', 'route_probe': 'routes'}[kind]
        if kind == 'route_probe':  # the routes a task asked about are the urls of its hosts
            asked = {u for h in target.get('hosts') or [] if isinstance(h, dict) for u in h.get('urls') or [] if isinstance(u, str)}
        else:
            asked = {p.get('id') for p in target.get(key) or [] if isinstance(p, dict)}
        kept = [p for p in result[key] if p['id'] in asked]
        dropped = len(result[key]) - len(kept)
        result = {**result, key: kept}
    elif kind == 'identity_check':  # only the questions and endpoints the task asked, once each
        out = {}
        dropped = 0
        for key in ('dns', 'certs'):
            asked = {p.get('id') for p in target.get(key) or [] if isinstance(p, dict)}
            seen, kept = set(), []
            for row in result[key]:
                if row['id'] in asked and row['id'] not in seen:
                    seen.add(row['id'])
                    kept.append(row)
            dropped += len(result[key]) - len(kept)
            out[key] = kept
        result = {**result, **out}
    elif kind == 'supplier_check':  # only the names the task listed, once each
        asked = {str(n).strip().lower().rstrip('.') for n in target.get('domains') or [] if isinstance(n, str)}
        kept, seen = [], set()
        for row in result['domains']:
            if row['domain'] in asked and row['domain'] not in seen:
                seen.add(row['domain'])
                kept.append(row)
        dropped = len(result['domains']) - len(kept)
        result = {**result, 'domains': kept}
    else:
        asked = {str(n).strip().lower().rstrip('.') for n in target.get('names') or [] if isinstance(n, str)}
        resolved = {n: a for n, a in result['resolved'].items() if n in asked}
        errors = {n: e for n, e in result['errors'].items() if n in asked}
        dropped = len(result['resolved']) - len(resolved) + len(result['errors']) - len(errors)
        result = {**result, 'resolved': resolved, 'errors': errors, 'refused': [n for n in result['refused'] if n in asked]}
    return {**result, 'dropped': dropped} if dropped else result
