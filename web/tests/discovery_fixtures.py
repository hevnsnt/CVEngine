"""Test helpers for the discovery results the server stores: what a Sentinel's batch carries, built without a scanner."""
from reNgine.discovery_events import BbotResult, is_informational, short_title

SEVERITIES = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


def fold_findings(events, result=None):
    """A ``BbotResult`` whose ``findings`` hold what each FINDING / VULNERABILITY event of ``events`` says, in the shape a Sentinel batch gives
    (name, informational, severity, host, url, description, module). Other event types are ignored."""
    result = BbotResult() if result is None else result
    for event in events:
        payload = event.get('data') if event.get('data') is not None else event.get('data_json')
        if event.get('type') not in ('FINDING', 'VULNERABILITY') or not isinstance(payload, dict):
            continue
        host = event.get('host')
        severity = SEVERITIES.get(str(payload.get('severity', 'INFO')).upper(), 0)
        description = str(payload.get('description') or payload.get('name') or event['type'].title())
        stated = str(payload.get('severity') or '').upper() in SEVERITIES
        name = short_title(description)
        result.findings.append({
            'name': name, 'informational': is_informational(name, description, severity, stated), 'severity': severity,
            'host': (payload.get('host') or host or '').lower(), 'url': payload.get('url') or '', 'description': description,
            'module': event.get('module') or ''})
    return result


# --- a Sentinel's discovery batches, built from plain event dicts ---------------------------------------------------------------------------------

INTERESTING = ('DNS_NAME', 'IP_ADDRESS', 'OPEN_TCP_PORT', 'URL', 'TECHNOLOGY', 'WAF', 'FINDING', 'VULNERABILITY')


def _status_of(tags):
    for tag in tags or []:
        if isinstance(tag, str) and tag.startswith('status-') and tag[7:].isdigit():
            return int(tag[7:])
    return 0


def event_batch(events, seq=1):
    """One Sentinel batch (the shape ``cveFeed.discovery.batch_result`` reads) for ``events``, plain scanner events of the kinds the tests use
    (DNS_NAME, IP_ADDRESS, OPEN_TCP_PORT, URL, TECHNOLOGY, HTTP_RESPONSE, FINDING). Built here so a test can say what a scanner found."""
    batch = {'seq': seq, 'subdomains': [], 'ips': [], 'ports': [], 'urls': [], 'technologies': [], 'resolutions': [], 'edges': [], 'findings': [],
             'http': [], 'events': [], 'screenshots': []}
    hosts = {}
    for event in events:
        etype, host = event.get('type'), event.get('host')
        payload = event.get('data') if event.get('data') is not None else event.get('data_json')
        if host and event.get('id'):
            hosts[event['id']] = host
        parent_host = hosts.get(event.get('parent')) or ''
        label = None
        if etype == 'DNS_NAME' and isinstance(payload, str):
            name = payload.lower()
            batch['subdomains'].append(name)
            for ip in event.get('resolved_hosts') or []:
                if ':' not in ip:
                    batch['ips'].append(ip)
                    batch['resolutions'].append({'name': name, 'ip': ip})
            label = payload
        elif etype == 'OPEN_TCP_PORT' and isinstance(payload, str) and ':' in payload:
            h, _, port = payload.rpartition(':')
            batch['ports'].append({'host': h.strip('[]'), 'port': int(port)})
            label = payload
        elif etype == 'URL' and isinstance(payload, str):
            batch['urls'].append({'url': payload, 'status': _status_of(event.get('tags'))})
            label = payload
        elif etype == 'TECHNOLOGY' and isinstance(payload, dict):
            batch['technologies'].append({'host': payload.get('host') or host, 'technology': payload.get('technology')})
            label = f"{payload.get('technology', '?')} on {payload.get('host') or host or '?'}"
        elif etype == 'HTTP_RESPONSE' and isinstance(payload, dict):
            batch['http'].append({'host': payload.get('host') or host, 'url': payload.get('url'), 'port': payload.get('port') or 443,
                                  'status': payload.get('status_code') or 0, 'title': payload.get('title') or '', 'webserver': '',
                                  'content_type': '', 'location': ''})
        elif etype in ('FINDING', 'VULNERABILITY'):
            batch['findings'] += fold_findings([event]).findings
            label = str((payload or {}).get('description') or 'finding')[:200] if isinstance(payload, dict) else None
        if host and parent_host and host.lower() != parent_host.lower():
            batch['edges'].append({'parent': parent_host.lower(), 'child': host.lower()})
        if label is not None and etype in INTERESTING:
            batch['events'].append({'type': etype, 'label': label, 'host': host or '', 'parent_host': parent_host, 'module': event.get('module') or ''})
    return batch


def sentinel_discovery(events=(), batches=None, mode=None, problems=(), hard_failures=(), error=None, incomplete='', seen=None, after_batch=None):
    """A ``mock.patch`` (use it as a ``with`` item) of the Sentinel stream dispatch, so ``cveFeed.discovery.run_discovery`` is driven by what a scanner
    would report: ``events`` as one batch, or ``batches`` (a list of event lists, one batch each). ``problems`` / ``hard_failures`` are
    ``(module, reason)`` pairs of the final result; ``mode`` the mode it reports; ``error`` an exception raised after the batches (a stage that
    broke); ``incomplete`` a reason the run stopped part way (the result is then ``None``). ``seen`` (a dict) receives the dispatched ``target`` and
    keyword arguments; ``after_batch(n)`` runs after each batch is stored."""
    from unittest import mock
    chunks = [list(events)] if batches is None else [list(b) for b in batches]

    def dispatch(project, kind, target, scan, on_partial, **kwargs):
        if seen is not None:
            seen.update(kind=kind, target=target, **kwargs)
        for number, chunk in enumerate(chunks, 1):
            on_partial(event_batch(chunk, number))
            if after_batch:
                after_batch(number)
        if error is not None:
            raise error
        if incomplete:
            return {'result': None, 'consumed': len(chunks), 'error': incomplete}
        web = {'URL': 0, 'HTTP_RESPONSE': 0}
        for chunk in chunks:
            for event in chunk:
                if event.get('type') in web:
                    web[event['type']] += 1
        result = {'outcome': 'done', 'partials': len(chunks), 'mode': mode or target.get('mode') or 'standard', 'web_events': web,
                  'problems': [{'module': m, 'reason': r} for m, r in problems],
                  'hard_failures': [{'module': m, 'reason': r} for m, r in hard_failures]}
        return {'result': result, 'consumed': len(chunks)}
    return mock.patch('agentapi.sentinel_stream.dispatch_stream', side_effect=dispatch)
