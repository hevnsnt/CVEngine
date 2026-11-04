"""The two jobs. Each builds one prompt from the server's data (untrusted parts fenced), makes one model call, checks the answer and sends
it back. The server decides what happens next; nothing here changes anything by itself."""
import json
import logging

from cvengine_reviewer import guard, llm, prompts

logger = logging.getLogger(__name__)

REVIEW_MAX_TOKENS = 4000   # thinking included; a verdict and an 800-character note need far less
OPS_MAX_TOKENS = 4000
NOTE_LIMIT = 1200


def review_message(packet):
    trusted = json.dumps({'kind': packet.get('kind'), **(packet.get('trusted') or {})}, ensure_ascii=False, sort_keys=True, default=str)
    fenced, _ = guard.fence('UNTRUSTED', packet.get('untrusted') or {})
    return (f'TRUSTED (computed by cvENGINE):\n{trusted}\n\n{fenced}\n\n'
            'Judge this finding by the rules and answer with the JSON object.')


def review_one(server, provider, packet):
    """Review one packet and send the verdict. Returns the server's answer, or None when the model failed (the packet's lease runs out
    and the server hands it out again later)."""
    try:
        text, usage, model = llm.call(provider, prompts.REVIEW_SYSTEM, review_message(packet), prompts.REVIEW_SCHEMA, REVIEW_MAX_TOKENS,
                                      effort='medium')
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
    return f'{fenced}\n\nDiagnose every check that is not ok and choose actions, then answer with the JSON object.'


def run_ops(server, provider, release=None):
    """One operations pass: read the checks, ask the model, send the report. Returns the server's answer."""
    snapshot = server.ops_snapshot(release)
    if all((c.get('state') == 'ok') for c in snapshot.get('checks') or []):
        return server.ops_report({'alerts': [], 'actions': [], 'model': '', 'templates_release': release})
    text, _usage, model = llm.call(provider, prompts.OPS_SYSTEM, ops_message(snapshot), prompts.OPS_SCHEMA, OPS_MAX_TOKENS, effort='low')
    try:
        answer = guard.parse_reply(text, prompts.OPS_SCHEMA)
    except guard.ReplyError as exc:
        logger.warning('operations: unusable answer (%s)', exc)
        answer = {'alerts': [], 'actions': []}
    alerts = [{'code': a['code'], 'severity': a['severity'], 'diagnosis': guard.scrub(a['diagnosis'], NOTE_LIMIT)} for a in answer['alerts']]
    return server.ops_report({'alerts': alerts, 'actions': answer['actions'], 'model': str(model)[:100], 'templates_release': release})
