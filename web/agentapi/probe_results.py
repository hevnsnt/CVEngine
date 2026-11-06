"""The server's reading of the probe kinds' results (contract version 3): ``http_probe``, ``dns_resolve``, ``alive_check``, ``bucket_check``, ``hygiene_check`` and ``dangling_dns_check``.

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


def bind(kind, result, task):
    """``result`` cut down to what ``task`` asked about: a probe id the task did not plan, or a name it did not name, is dropped and counted."""
    target = task.target if isinstance(task.target, dict) else {}
    if kind == 'hygiene_check':  # only the endpoints and names the task asked about (names compared as the Sentinel writes them: lower case, no final dot)
        def norm(name):
            return str(name or '').strip().lower().rstrip('.')
        tls = {(norm(p.get('host')), p.get('port')) for p in target.get('tls') or [] if isinstance(p, dict)}
        names = {norm(p.get('name')) for p in target.get('mail') or [] if isinstance(p, dict)}
        certs = [c for c in result['certs'] if (norm(c['host']), c['port']) in tls]
        mail = [m for m in result['mail'] if norm(m['name']) in names]
        dropped = len(result['certs']) - len(certs) + len(result['mail']) - len(mail)
        result = {**result, 'certs': certs, 'mail': mail}
        return {**result, 'dropped': dropped} if dropped else result
    if kind == 'dangling_dns_check':
        asked = {c.get('id') for c in target.get('checks') or [] if isinstance(c, dict)}
        ratings = [r for r in result['ratings'] if r['id'] in asked]
        dropped = len(result['ratings']) - len(ratings)
        result = {**result, 'ratings': ratings}
        return {**result, 'dropped': dropped} if dropped else result
    if kind in ('http_probe', 'alive_check', 'bucket_check'):
        key = {'http_probe': 'probes', 'alive_check': 'checks', 'bucket_check': 'buckets'}[kind]
        asked = {p.get('id') for p in target.get(key) or [] if isinstance(p, dict)}
        kept = [p for p in result[key] if p['id'] in asked]
        dropped = len(result[key]) - len(kept)
        result = {**result, key: kept}
    else:
        asked = {str(n).strip().lower().rstrip('.') for n in target.get('names') or [] if isinstance(n, str)}
        resolved = {n: a for n, a in result['resolved'].items() if n in asked}
        errors = {n: e for n, e in result['errors'].items() if n in asked}
        dropped = len(result['resolved']) - len(resolved) + len(result['errors']) - len(errors)
        result = {**result, 'resolved': resolved, 'errors': errors, 'refused': [n for n in result['refused'] if n in asked]}
    return {**result, 'dropped': dropped} if dropped else result
