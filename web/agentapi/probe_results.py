"""The server's reading of the probe kinds' results (contract version 3): ``http_probe`` and ``dns_resolve``.

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


def bind(kind, result, task):
    """``result`` cut down to what ``task`` asked about: a probe id the task did not plan, or a name it did not name, is dropped and counted."""
    target = task.target if isinstance(task.target, dict) else {}
    if kind == 'http_probe':
        asked = {p.get('id') for p in target.get('probes') or [] if isinstance(p, dict)}
        kept = [p for p in result['probes'] if p['id'] in asked]
        dropped = len(result['probes']) - len(kept)
        result = {**result, 'probes': kept}
    else:
        asked = {str(n).strip().lower().rstrip('.') for n in target.get('names') or [] if isinstance(n, str)}
        resolved = {n: a for n, a in result['resolved'].items() if n in asked}
        errors = {n: e for n, e in result['errors'].items() if n in asked}
        dropped = len(result['resolved']) - len(resolved) + len(result['errors']) - len(errors)
        result = {**result, 'resolved': resolved, 'errors': errors, 'refused': [n for n in result['refused'] if n in asked]}
    return {**result, 'dropped': dropped} if dropped else result
