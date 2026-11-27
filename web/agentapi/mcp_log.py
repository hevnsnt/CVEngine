"""The MCP call log: one ``cveFeed.McpCall`` row per tool call an AI agent (or a signed-in browser) makes on ``/mcp/``, for the MCP page's History.

What is kept: who (the user, the API key's name, the registered agent holding it), which tool, whether it writes, the project it named, the
arguments with secrets masked (``secret_redaction``, as for AI prompts) and every string clipped, whether it worked (with the error a caller saw)
and how long it took. Never the result: a result is the data itself, and the log must not become a second copy of it.

Left out: the heartbeats (``agent_heartbeat``, ``sentinel_heartbeat``), which an agent sends every minute and which change nothing, and a long poll
for work that came back with none (``get_next_task``, ``get_next_sentinel_task``), which a waiting agent repeats all day. A poll that hands out a
task, and any call that fails, is kept: one cut off by the database statement timeout as ``TIMEOUT_ERROR`` and one that crashed as
``INTERNAL_ERROR`` (the traceback stays in the server log).

Recording never fails a call: a database error here is logged and the agent still gets its answer."""
import json
import logging

logger = logging.getLogger(__name__)

ROUTINE = frozenset(('agent_heartbeat', 'sentinel_heartbeat'))
POLLS = frozenset(('get_next_task', 'get_next_sentinel_task'))
STRING_CHARS = 200  # each argument string is cut to this
ARGUMENT_CHARS = 2000  # the whole argument record, as JSON
PROJECT_KEYS = ('slug', 'project', 'project_slug')
# the error kept for a call that never answered normally: the History's Timed out filter matches the first one's prefix
TIMEOUT_ERROR = 'timeout: the database statement ran past the web limit (CVENGINE_WEB_STATEMENT_TIMEOUT_MS)'
INTERNAL_ERROR = 'internal error'


def worth_keeping(tool, ok, result):
    if tool in ROUTINE:
        return False
    if tool in POLLS and ok and isinstance(result, dict) and not result.get('task'):
        return False
    return True


def _clip(value, depth=0):
    if isinstance(value, str):
        return value if len(value) <= STRING_CHARS else value[:STRING_CHARS] + '…'
    if isinstance(value, dict) and depth < 4:
        return {str(k)[:60]: _clip(v, depth + 1) for k, v in list(value.items())[:30]}
    if isinstance(value, (list, tuple)) and depth < 4:
        out = [_clip(v, depth + 1) for v in value[:20]]
        return out + [f'… {len(value) - 20} more'] if len(value) > 20 else out
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:STRING_CHARS]


def summarise(arguments):
    """The arguments as the log keeps them: secrets masked, strings clipped, at most ``ARGUMENT_CHARS`` of JSON (beyond that, the names only)."""
    from cveFeed.ai_jobs import _redact
    if not isinstance(arguments, dict):
        return {}
    kept = _redact(_clip(arguments))
    if len(json.dumps(kept, default=str)) > ARGUMENT_CHARS:
        return {'_too_long': True, 'names': sorted(str(k)[:60] for k in arguments)[:30]}
    return kept


def record(ctx, tool, arguments, *, ok, error='', duration_ms=0, result=None, writes=False):
    if not worth_keeping(tool, ok, result):
        return
    try:
        from cveFeed.models import McpCall
        from tenancy.audit import describe_token
        user = getattr(ctx, 'user', None)
        token = getattr(ctx, 'token', None)
        who = describe_token(token) if token is not None else {}
        args = arguments if isinstance(arguments, dict) else {}
        project = next((str(args[k])[:100] for k in PROJECT_KEYS if isinstance(args.get(k), str) and args.get(k)), '')
        McpCall.objects.create(
            user=user if getattr(user, 'pk', None) else None, username=str(getattr(user, 'username', '') or '')[:150],
            token=token if getattr(token, 'pk', None) else None, token_name=who.get('name', ''), agent_name=str(who.get('agent_name') or '')[:100],
            tool=str(tool)[:64], writes=bool(writes), project=project, arguments=summarise(args), ok=bool(ok),
            error=str(error or '')[:300], duration_ms=max(0, min(int(duration_ms), 2_000_000_000)))
    except Exception:  # noqa: BLE001 - the log is for people; the agent's call has already been answered
        logger.warning('mcp log: the call to %s could not be recorded', tool, exc_info=True)


def visible_to(user):
    """The calls ``user`` may read: an App Admin every call, anyone else the calls made as them (their own keys and their own browser)."""
    from cveFeed.models import McpCall
    rows = McpCall.objects.all()
    return rows if getattr(user, 'is_superuser', False) else rows.filter(user=user)
