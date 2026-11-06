"""The server's reading of the probe kinds' results (contract version 3): ``http_probe``, ``dns_resolve``, ``alive_check``, ``bucket_check``, ``vhost_probe`` and ``subdir_probe``.

Every result is untrusted. ``clean_*`` keep only the contract's shape, clip every string and cap every list (the bounds are the contract's and
``cveFeed.models.ProbeObservation``'s columns); ``bind`` then drops what the task did not ask about (a probe id it did not plan, a name it did
not name), so a Sentinel can only ever answer for its own task's hosts. ``agentapi.sentinel_broker.clean_result`` calls both."""
import json

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
    elif kind in ('http_probe', 'alive_check', 'bucket_check'):
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
