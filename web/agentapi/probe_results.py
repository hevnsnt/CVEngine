"""The server's reading of the probe kinds' results (contract version 3): ``http_probe``, ``dns_resolve``, ``alive_check``, ``bucket_check`` and ``supplier_check``.

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


def bind(kind, result, task):
    """``result`` cut down to what ``task`` asked about: a probe id the task did not plan, or a name it did not name, is dropped and counted."""
    target = task.target if isinstance(task.target, dict) else {}
    if kind in ('http_probe', 'alive_check', 'bucket_check'):
        key = {'http_probe': 'probes', 'alive_check': 'checks', 'bucket_check': 'buckets'}[kind]
        asked = {p.get('id') for p in target.get(key) or [] if isinstance(p, dict)}
        kept = [p for p in result[key] if p['id'] in asked]
        dropped = len(result[key]) - len(kept)
        result = {**result, key: kept}
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
