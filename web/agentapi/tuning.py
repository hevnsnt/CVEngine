"""Auto-tuning over the REST API and MCP (cveFeed.autotune): the instance's mode, the decisions the tuner made or recommends, and the
person's actions on them (apply a recommendation, revert the last change of a setting, hand a pinned setting back to the tuner).

Auto-tuning belongs to the whole instance, not to a project, so every route and tool here is for an App Admin: anyone else gets 403 (the same
rule as the settings it tunes, which only an App Admin may read or change). A read-only token may read; changing anything needs a token that
can write. Every change is audited by cveFeed.autotune (``autotune.mode``, ``autotune.apply``, ``autotune.revert``, ``autotune.release``)."""
from agentapi.services import ApiError, require_write_token

ADMIN_ONLY = 'auto-tuning belongs to the whole instance: only an App Admin may read or change it'


def _admin(ctx):
    if not (ctx.user.is_authenticated and ctx.user.is_superuser):
        raise ApiError(403, ADMIN_ONLY)


def _call(fn, *args):
    from cveFeed.autotune import TuningError
    try:
        return fn(*args)
    except TuningError as exc:
        raise ApiError(exc.status, exc.message)
    except PermissionError as exc:
        raise ApiError(403, str(exc))


def _person_only(ctx, what):
    """FB-3: applying a recommendation, handing a pinned setting back and reverting a change are a person's decisions. An agent (any API token or MCP call) that applied
    its own recommendation made it a person's change (no 30-minute check, no automatic revert, and a pin in Suggest mode); one that released or reverted undid what a
    person chose. An agent changes a setting with ``change_setting``, which goes through the engine and its rules. (An agent may not even revert its own change: the
    decision does not record which token made it, and taking back a lowered cap would raise that cap.)"""
    if ctx.token is not None:
        raise ApiError(403, f'{what} is a person\'s decision: an agent cannot do it. Use change_setting to ask for a change (it goes through the auto-tuning rules and the agent policy a person set); a person applies, releases or reverts in Settings, Auto-tuning')


def _int(value, name, default):
    if value in (None, ''):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        raise ApiError(400, f'{name} must be an integer')


def get_status(ctx):
    from cveFeed import autotune
    _admin(ctx)
    return autotune.status()


def list_decisions(ctx, params):
    from cveFeed import autotune
    _admin(ctx)
    params = params or {}
    return _call(autotune.list_decisions, params.get('setting') or None, _int(params.get('limit'), 'limit', 50), _int(params.get('offset'), 'offset', 0),
                 params.get('outcome') or None, params.get('source') or None)


def get_maintainer_report(ctx):
    from cveFeed import maintainer_report
    _admin(ctx)
    return maintainer_report.report()


def set_mode(ctx, body):
    from cveFeed import autotune
    _admin(ctx)
    require_write_token(ctx)
    if isinstance(body, dict) and 'agent_policy' in body and ctx.token is not None:
        raise ApiError(403, 'what agents may do to the throughput settings is a person\'s decision: change it in Settings, Auto-tuning')
    if not isinstance(body, dict) or not body or set(body) - {'mode', 'advisor', 'agent_policy'}:
        raise ApiError(400, 'send {"mode": "off" | "suggest" | "auto"} and/or {"advisor": true | false}')
    if ctx.token is not None:  # a token (an agent, or a person's key) may only lower autonomy
        why = autotune.raises_autonomy(body.get('mode'), body.get('advisor'))
        if why:
            raise ApiError(403, why)
    return _call(autotune.set_mode, ctx.user, body.get('mode'), body.get('advisor'), body.get('agent_policy'))


def apply_decision(ctx, decision_id):
    from cveFeed import autotune
    _admin(ctx)
    require_write_token(ctx)
    _person_only(ctx, 'applying a recommendation')
    return _call(autotune.apply_decision, ctx.user, _int(decision_id, 'decision_id', None))


def revert_decision(ctx, decision_id):
    from cveFeed import autotune
    _admin(ctx)
    require_write_token(ctx)
    _person_only(ctx, 'reverting a decision')
    return _call(autotune.revert, ctx.user, _int(decision_id, 'decision_id', None))


def release(ctx, setting):
    from cveFeed import autotune
    _admin(ctx)
    require_write_token(ctx)
    _person_only(ctx, 'handing a pinned setting back to auto-tuning')
    if not isinstance(setting, str) or not setting:
        raise ApiError(400, 'setting is required (a key from get_tuning_status managed[].setting)')
    return _call(autotune.release, ctx.user, setting)
