"""The reviewer's work. Each builds one prompt from the server's data (untrusted parts fenced), makes one model call, checks or bounds the
answer and sends it back. The server decides what happens next; nothing here changes anything by itself.

* ``review_one`` and ``run_ops``: the reviewer's own two jobs, with their fixed prompts (``prompts``).
* ``run_job``: one of the pipeline's AI jobs (triage, validation planning, template drafting, ...). The server sends the job's fixed system
  prompt, its parts in order (text cvENGINE wrote itself, and data that came from a scanned host, a scanner or a feed, which is fenced here
  with ``guard.fence``), the schema and request options, and for the RDP reading one bounded image. The answer goes back as text: the server
  validates it with the same validators it used when it called the model itself."""
import json
import logging
import time

from cvengine_reviewer import guard, llm, profiles, prompts

logger = logging.getLogger(__name__)

REVIEW_MAX_TOKENS = profiles.STAGE_ANSWER_CAPS['finding_review']   # the ANSWER room: the model's thinking is kept room apart (``measured_call``)
OPS_MAX_TOKENS = profiles.STAGE_ANSWER_CAPS['operations_check']
NOTE_LIMIT = 1200


def measured_call(server, stage, provider, system, user, schema, max_tokens, effort='medium'):
    """``llm.call`` for one of the container's own two jobs, and a report of each request to the server (stage, outcome, stop reason, counts,
    never text) so the usage page names the job and counts its refusals. ``max_tokens`` is the ANSWER room: the limit sent is that plus the
    model's thinking reserve for ``effort`` (``profiles.thinking_reserve``), so thinking cannot take the answer's room. A reply cut off at
    the limit is asked ONCE more with a larger one (``profiles.retry_total``); the first request is then reported as ``truncated_retried``
    (recovered, not a failure) and a second cut-off is the failure. The report is best effort: a server that does not take it never changes
    the answer."""
    reserve = profiles.thinking_reserve(provider.get('provider'), provider.get('model') or '', effort)
    limit = profiles.reply_total(max_tokens, reserve)
    attempt = 0
    while True:
        started, report = time.monotonic(), {'stage': stage, 'provider': provider.get('provider'), 'model': provider.get('model')}
        retry = 0
        try:
            text, usage, model = llm.call(provider, system, user, schema, limit, effort)
        except llm.ModelError as exc:
            retry = profiles.retry_total(max_tokens, reserve, limit) if exc.category == 'truncated' and not attempt else 0
            report.update(status='failed', category='truncated_retried' if retry else exc.category, stop_reason=getattr(exc, 'stop_reason', None) or ('max_tokens' if exc.category == 'truncated' else None))
            if not retry:
                raise
        else:
            report.update(status='succeeded', model=model, input_tokens=usage.get('input_tokens'), output_tokens=usage.get('output_tokens'),
                          cache_read_tokens=usage.get('cache_read_tokens'), cache_write_tokens=usage.get('cache_write_tokens'))
            return text, usage, model
        finally:
            report['duration_ms'] = int((time.monotonic() - started) * 1000)
            try:
                server.usage(report)
            except Exception as exc:  # noqa: BLE001 - accounting must never change an answer
                logger.info('%s: the call was not reported to the server (%s)', stage, type(exc).__name__)
        logger.info('%s: reply cut off at %s tokens; asking once more with %s', stage, limit, retry)
        limit, attempt = retry, attempt + 1


def review_message(packet):
    trusted = json.dumps({'kind': packet.get('kind'), **(packet.get('trusted') or {})}, ensure_ascii=False, sort_keys=True, default=str)
    fenced, _ = guard.fence('UNTRUSTED', packet.get('untrusted') or {})
    return (f'TRUSTED (computed by cvENGINE):\n{trusted}\n\n{fenced}\n\n'
            'Judge this finding by the rules and answer with the JSON object.')


def review_one(server, provider, packet):
    """Review one packet and send the verdict. Returns the server's answer, or None when the model failed (the packet's lease runs out
    and the server hands it out again later)."""
    try:
        text, usage, model = measured_call(server, 'finding_review', provider, prompts.REVIEW_SYSTEM, review_message(packet), prompts.REVIEW_SCHEMA,
                                           REVIEW_MAX_TOKENS, effort='medium')
        answer = guard.parse_reply(text, prompts.REVIEW_SCHEMA)
    except llm.ModelError as exc:
        logger.warning('review of %s: model call failed (%s)', packet.get('ref'), exc.category)
        raise
    except guard.ReplyError as exc:
        logger.warning('review of %s: unusable answer (%s)', packet.get('ref'), exc)
        return None
    body = {'review_key': packet.get('review_key'), 'verdict': answer['verdict'], 'confidence': answer['confidence'],
            'reason_code': answer['reason_code'], 'note': guard.scrub(answer['note'], NOTE_LIMIT), 'model': str(model)[:100],
            'usage': usage}
    return server.verdict(packet.get('ref'), body)


def ops_message(snapshot):
    checks = []
    for check in (snapshot.get('checks') or [])[:20]:
        checks.append({'code': check.get('code'), 'state': check.get('state'), 'title': check.get('title'),
                       'actions_offered': check.get('actions') or [], 'description': check.get('detail'), 'facts': check.get('facts')})
    fenced, _ = guard.fence('CHECKS', checks)
    fleet = snapshot.get('fleet') if isinstance(snapshot.get('fleet'), dict) else {}
    counts = {key: fleet[key] for key in ('live_sentinels', 'live_remote', 'builtin_scanner', 'builtin_live', 'slots')
              if isinstance(fleet.get(key), (int, bool))}  # the server's own numbers, whitelisted: nothing else is passed through unfenced
    return f'The server\'s own count of its Sentinels: {json.dumps(counts, sort_keys=True)}\n\n{fenced}\n\nDiagnose every check that is not ok and choose actions, then answer with the JSON object.'


def run_ops(server, provider, release=None):
    """One operations pass: read the checks, ask the model, send the report. Returns the server's answer."""
    snapshot = server.ops_snapshot(release)
    if all((c.get('state') == 'ok') for c in snapshot.get('checks') or []):
        return server.ops_report({'alerts': [], 'actions': [], 'model': '', 'templates_release': release})
    text, _usage, model = measured_call(server, 'operations_check', provider, prompts.OPS_SYSTEM, ops_message(snapshot), prompts.OPS_SCHEMA,
                                        OPS_MAX_TOKENS, effort='low')
    try:
        answer = guard.parse_reply(text, prompts.OPS_SCHEMA)
    except guard.ReplyError as exc:
        logger.warning('operations: unusable answer (%s)', exc)
        answer = {'alerts': [], 'actions': []}
    alerts = [{'code': a['code'], 'severity': a['severity'], 'diagnosis': guard.scrub(a['diagnosis'], NOTE_LIMIT)} for a in answer['alerts']
              if not guard.is_filler(guard.scrub(a['diagnosis'], NOTE_LIMIT))]  # a diagnosis that is filler ("Placeholder") is not sent: the alert shows no reviewer line
    return server.ops_report({'alerts': alerts, 'actions': answer['actions'], 'model': str(model)[:100], 'templates_release': release})


JOB_REPLY_LIMIT = 200_000  # characters of one pipeline answer sent back (the server refuses more)
IMAGE_LIMIT = 6_000_000    # base64 characters of the one image a job may carry
MEDIA_TYPES = ('image/png', 'image/jpeg', 'image/webp', 'image/gif')


class JobError(ValueError):
    """A job the server sent that this container will not run (malformed)."""


def job_message(job):
    """The user message of a pipeline job: its parts in order, text as the server wrote it and data fenced with a fresh nonce each."""
    parts = job.get('parts')
    if not isinstance(parts, list) or not parts or len(parts) > 20:
        raise JobError('a job has from 1 to 20 parts')
    out = []
    for part in parts:
        if not isinstance(part, dict):
            raise JobError('a part is an object')
        if 'fence' in part:
            out.append(guard.fence(str(part['fence']), part.get('data'))[0])
        elif isinstance(part.get('text'), str):
            out.append(part['text'])
        else:
            raise JobError('a part is text or fenced data')
    return '\n'.join(out)


def job_image(job):
    image = job.get('image')
    if image is None:
        return None
    if not isinstance(image, dict) or image.get('media_type') not in MEDIA_TYPES or not isinstance(image.get('data'), str) \
            or not 0 < len(image['data']) <= IMAGE_LIMIT:
        raise JobError('the image is not one this container takes')
    return {'media_type': image['media_type'], 'data': image['data']}


def run_job(server, provider, job):
    """Run one pipeline job and send the answer (or the failure, by category) back. Returns ``(server's answer, failure category)``: the
    category is '' when the model answered, for the caller's back-off."""
    ref, lease = job.get('id'), job.get('lease')
    try:
        system = job.get('system')
        if not isinstance(system, str) or not system.strip():
            raise JobError('a job carries its system prompt')
        schema = job.get('schema') if isinstance(job.get('schema'), dict) else None
        options = job.get('options') if isinstance(job.get('options'), dict) else {}
        text, calls, model = llm.complete(provider, system, job_message(job), schema, options, job_image(job))
    except JobError as exc:
        logger.warning('job %s: not run (%s)', ref, exc)
        return server.job_result(ref, {'lease': lease, 'error': 'malformed_job', 'calls': []}), ''
    except llm.ModelError as exc:
        logger.warning('job %s (%s): model call failed (%s)', ref, job.get('kind'), exc.category)
        body = {'lease': lease, 'error': exc.category, 'calls': getattr(exc, 'calls', [])[:8], 'provider': provider.get('provider'),
                'model': str(provider.get('model') or '')[:200]}
        for key in ('http_status', 'stop_reason'):
            if getattr(exc, key, None) is not None:
                body[key] = getattr(exc, key)
        return server.job_result(ref, body), exc.category
    body = {'lease': lease, 'text': text[:JOB_REPLY_LIMIT], 'calls': calls[:8], 'provider': provider.get('provider'),
            'model': str(model)[:200]}
    return server.job_result(ref, body), ''
