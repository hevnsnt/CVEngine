"""Auto-tuning of the throughput settings of Settings, configMaxxing: the numbers that say how much this instance does at once and how eagerly it
starts work (scanner kinds at once, hosts assessed at once, hosts per assessment batch, discovery scans kept running, chunks of one stage at
once, the hours between rescans and between Sentinel refreshes) are moved from what this instance measured, instead of being guessed once.

**Modes** (one for the instance, ``AutoTuneSettings``): ``auto`` (the default: the tuner applies bounded changes itself), ``suggest`` (it works
out the same changes and shows each with its reason and an Apply button; nothing changes) and ``off`` (nothing is measured or changed: hand
tuning). ``CVENGINE_AUTOTUNE=0`` in the environment forces ``off`` whatever is saved (the kill switch). Leaving Auto drops the tuned numbers at
once: every setting goes back to what a person saved, else the environment, else the default.

**Pins.** A number a person saves for a setting pins it: the saved value always wins and the tuner never moves it. An environment variable set
to anything other than the built-in default pins its setting too (``env_pin`` of each registry; a value equal to the default is not a pin, since
the compose files pass ``DISCOVERY_CONCURRENCY=${DISCOVERY_CONCURRENCY:-8}`` and the like to every container). "Let auto-tune manage this"
removes the saved value and hands the same number to the tuner, so nothing jumps (the hand-over is a row in the history and counts as a change). Only settings whose registry entry says ``auto_tunable=True``
are ever tuned (``cveFeed.scan_concurrency.FIELDS``, ``cveFeed.tunables.TUNABLES``); AI spend caps and anything that guards safety say False.

**Precedence** for a tunable setting: saved by a person > environment when not the default > tuned (mode Auto) > environment > default. The tuned numbers are a row in the
database (the truth), published to Redis (``reNgine.resources.AUTO_VALUES_KEY``) on every change and every 30 seconds, and read by the workers
the same way as the saved values, so a change takes effect within seconds with no restart (the discovery pool is resized live, as for a save).

**The run** (``run``, the ``autotune`` beat task every ten minutes on cve_feed_queue, one at a time): take a measurement
(``cveFeed.autotune_signals``), then for each tunable setting that is not pinned ask the controller (``cveFeed.autotune_policy``) and, every few
hours when an AI provider is set up and the advisor is on, the AI advisor; apply (Auto) or record as a recommendation (Suggest). Nothing changes
while scanning is paused or an update is being applied. Every change is a ``TuningDecision`` (kept ``RETENTION_DAYS``), an audit entry and an
activity line, and the last change of a setting can be reverted with one click.

**Verify** (``verify_pending``, the start of every run in Auto): an applied change stores what it expected to improve (``expected``) and the
measurements before it (``baseline``); ``VERIFY_SETTLE_SECONDS`` later, once three measurements came after it, the same measurements are judged
(``autotune_policy.verdict``: helped, no effect, regressed, or unknown) and the outcome stored on the decision. A calm change that regressed is
reverted by the tuner itself (a decision with ``action='revert'``, ``phase='verify'``) and the setting is held for a day. Only one calm change is
unverified at a time; a forced back-off, a cap and an emergency back-off never wait. When the watchdog pauses the starting of work for memory
(AM-8) the tuner takes the memory trouble from the measurements before the pause and backs off once, instead of holding with the evidence unread.
"""
import json
import logging
import os
import socket
import time
from collections import namedtuple
from datetime import datetime, timedelta, timezone as dt_timezone

from reNgine import ai_prompts, resources

logger = logging.getLogger(__name__)

MODES = ('off', 'suggest', 'auto')
DEFAULT_MODE = 'auto'
AGENT_POLICIES = ('off', 'suggest', 'auto')   # what an agent may do to a throughput setting (``agent_change``)
DEFAULT_AGENT_POLICY = 'suggest'
KILL_ENV = 'CVENGINE_AUTOTUNE'
VALUES_KEY = resources.AUTO_VALUES_KEY
LAST_RUN_KEY = 'cvengine:autotune:last'
SAMPLES_KEY = 'cvengine:autotune:samples'
BOOT_KEY = 'cvengine:autotune:boot'
ADVISOR_KEY = 'cvengine:autotune:advisor'
ADVICE_KEY = 'cvengine:autotune:advice'  # the advisor's answer, waiting for the next round to judge it against the range then in force
ADVICE_FRESH = 1800             # seconds an answer stays usable: the numbers it was given are older after that
SAMPLES_KEPT = 300              # fifty hours of ten-minute measurements
RETENTION_DAYS = 90
REVERT_HOLD_HOURS = 24          # after a person reverts a change, the tuner does not raise that setting for this long
ADVISOR_STAGE = 'autotune_advisor'
ADVISOR_SEED = 20261101
ADVISOR_SYSTEM = ai_prompts.compose('autotune_advisor',
    'The auto-tuner\'s policy is to aim high first: run as much as this machine sensibly carries, then '
    'back off quickly on evidence of trouble, then probe upward slowly. You get measured numbers from the last hours and, for each setting it may '
    'change now, the number in effect, the target sized for this machine, and the lowest and highest number you may choose. Be ambitious: choose '
    'the highest allowed number unless the measurements show trouble (memory kills or little memory free, timeouts, the database near its '
    'connection limit, a worker not answering, Sentinel waits that ran locally); then choose a lower allowed number. Never name a setting you '
    'were not given. Reply with ONLY {"recommendations": [{"setting": "<name>", "value": <whole number>, "reason": "<one short sentence citing the '
    'numbers>"}]}.')

Managed = namedtuple('Managed', 'key registry label setting env_name')


# --- the registry of tunable settings ----------------------------------------------------------------------------------

def _env_int(name):
    try:
        return int(float(os.environ[name]))
    except (KeyError, ValueError):
        return None


DISCOVERY_PIN_BELOW = 4  # scripts/update-deploy.sh warn_discovery_pin says the same at the same number


def _scan():
    from cveFeed import scan_concurrency
    return scan_concurrency


def managed():
    """Every setting that opts in to auto-tuning, from both registries, with its auto-tuning range (``cveFeed.autotune_policy.Setting``). For a
    scanner kind, HEAVY_TUNE_MIN_<KIND> / HEAVY_TUNE_MAX_<KIND> in the environment narrow or widen the range (never outside what the page
    allows)."""
    from cveFeed import scan_concurrency, tunables
    from cveFeed.autotune_policy import Setting
    out = []
    for f in scan_concurrency.FIELDS:
        if not f.auto_tunable:
            continue
        low, high = f.auto_min, f.auto_max
        if f.group == 'heavy':
            kind = f.key.split('.', 1)[1]
            suffix = kind.upper().replace('-', '_')
            env_low, env_high = _env_int('HEAVY_TUNE_MIN_' + suffix), _env_int('HEAVY_TUNE_MAX_' + suffix)
            low = max(f.low, min(f.high, env_low)) if env_low else low
            high = max(f.low, min(f.high, env_high)) if env_high else high
            high = max(low, high)
            what = f'heavy:{kind}'
        else:
            what = {'discovery_concurrency': 'discovery', 'assess_batch': 'batch', 'work_depth': 'depth', 'assess_share_percent': 'assess_share',
                    'lane.cve_feed': 'lane:cve_feed', 'lane.classic': 'lane:classic'}[f.key]
        optimistic = max(low, min(high, f.auto_optimistic))
        out.append(Managed(f.key, 'scan_concurrency', f.label, Setting(f.key, what, f.label, low, high, f.auto_step, 'more', optimistic,
                                                                               f.default), f.env))
    kinds = {'stage_parallel': 'stage', 'work_min_gap_hours': 'work_gap', 'sentinel_refresh_gap_hours': 'refresh_gap'}
    for t in tunables.TUNABLES:
        if t.auto_tunable:
            out.append(Managed(t.key, 'tunables', t.label, Setting(t.key, kinds[t.key], t.label, t.auto_min, t.auto_max, t.auto_step, t.auto_sense,
                                                                    t.auto_optimistic, t.default), t.env))
    return out


def by_key():
    return {m.key: m for m in managed()}


def _registry(name):
    from cveFeed import scan_concurrency, tunables
    return scan_concurrency if name == 'scan_concurrency' else tunables


def _saved_rows():
    """{registry: (values, meta, row)} straight from the database."""
    from cveFeed import scan_concurrency, tunables
    out = {}
    for name, module in (('scan_concurrency', scan_concurrency), ('tunables', tunables)):
        row = module.saved_row()
        out[name] = ({k: v for k, v in (row.values or {}).items() if k in module.BY_KEY}, row.meta or {}, row)
    return out


def pin_of(m, rows):
    """Who pins a setting, or None: ``(text, 'saved')`` for a value a person saved on the page, ``(text, 'environment')`` for an environment
    variable that is set and differs from the built-in default (``env_pin`` of its registry: a value equal to the default cannot be told from the
    compose files' own fallback). Neither is ever moved by the tuner."""
    saved, meta, row = rows[m.registry]
    if m.key in saved:
        by = (meta.get(m.key) or {}).get('by') or (row.updated_by.username if row.updated_by_id else 'an administrator')
        return by, 'saved'
    module = _registry(m.registry)
    field = module.BY_KEY[m.key]
    env = module.env_value(field)
    if module.env_pin(field, env):
        return f'the environment ({m.env_name}={_number_text(env)})', 'environment'
    return None


def _number_text(number):
    """24.0 as 24, 0.5 as 0.5, 3 as 3."""
    return f'{number:g}' if isinstance(number, float) else str(number)


# --- mode and the published copy ----------------------------------------------------------------------------------------

def killed():
    return resources.autotune_killed()


def settings_row():
    from cveFeed.models import AutoTuneSettings
    return AutoTuneSettings.current()


def agent_policy(row=None):
    row = row or settings_row()
    return row.agent_policy if row.agent_policy in AGENT_POLICIES else DEFAULT_AGENT_POLICY


def effective_mode(row=None):
    if killed():
        return 'off'
    row = row or settings_row()
    return row.mode if row.mode in MODES else DEFAULT_MODE


def _clean_values(values):
    keys = by_key()
    return {k: v for k, v in (values or {}).items() if k in keys and isinstance(v, int) and not isinstance(v, bool)}


def applied_values(row=None):
    """The tuned numbers that apply now, from the database: the row's numbers in mode Auto, none otherwise. An emergency back-off taken while
    the database did not answer and not recorded yet (``pending_emergency``) lowers its keys, so no reader puts the old numbers back."""
    row = row or settings_row()
    if effective_mode(row) != 'auto':
        return {}
    values = _clean_values(row.values)
    for key, number in pending_emergency().items():
        if key in values and number < values[key]:
            values[key] = number
    return values


def publish(row=None):
    """Put the tuned numbers that apply now where the workers read them. A copy is never replaced by an older one (the row's last change is its
    version), so the 30 second tick that read the row just before a change cannot undo the change's own publish. Returns whether Redis took it."""
    try:
        row = row or settings_row()
        values, version = applied_values(row), row.updated_at.timestamp() if row.updated_at else 0.0
        client = resources.redis_client()
        if client is None:
            return False
        import redis
        payload = json.dumps({'mode': effective_mode(row), 'values': values, 't': time.time(), 'v': version})
        for _ in range(3):
            with client.pipeline() as pipe:
                try:
                    pipe.watch(VALUES_KEY)
                    raw = pipe.get(VALUES_KEY)
                    try:
                        current = json.loads(raw).get('v') if raw else None
                    except (ValueError, AttributeError):
                        current = None
                    if isinstance(current, (int, float)) and current > version:
                        return True
                    pipe.multi()
                    pipe.set(VALUES_KEY, payload)
                    pipe.execute()
                    return True
                except redis.WatchError:
                    continue
        return False
    except Exception:  # noqa: BLE001
        logger.warning('auto-tune: could not publish the tuned values; the 30 second tick tries again')
        return False
    finally:
        resources.invalidate_auto()


def recover(publish_again=True):
    """The tuned values from the database (what ``reNgine.resources.auto_values`` falls back to when Redis lost its copy)."""
    row = settings_row()
    values = applied_values(row)
    if publish_again:
        publish(row)
    return values


def reconcile():
    """The 30 second tick (``report_resources``): publish again, so a flushed Redis heals. Never raises."""
    try:
        return publish()
    except Exception:  # noqa: BLE001
        return False


# --- small helpers ---------------------------------------------------------------------------------------------------------

def _redis():
    return resources.redis_client()


def _now():
    from django.utils import timezone
    return timezone.now()


def _iso(value):
    return value.isoformat() if value else None


def _need_admin(user):
    if not (getattr(user, 'is_authenticated', False) and getattr(user, 'is_superuser', False)):
        raise PermissionError('only an App Admin may change auto-tuning')


class TuningError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _baseline(m, saved_values=None):
    """The number a setting would have with nothing saved and nothing tuned (environment, else default), as a whole number."""
    got = _registry(m.registry).resolve(m.key, {}, {})
    return int(round(got['value']))


def _effective(m, saved, tuned):
    return int(round(_registry(m.registry).resolve(m.key, saved, tuned)['value']))


def _cooldowns():
    from cveFeed import tunables
    return (tunables.value('autotune_cooldown_minutes') * 60, tunables.value('autotune_raise_cooldown_minutes') * 60,
            tunables.value('autotune_window_hours') * 3600)


def _activity(message, **detail):
    try:
        from cveFeed import activity
        activity.log('run_check', message[:500], status='done', **detail)
    except Exception:  # noqa: BLE001
        logger.debug('auto-tune: activity line not written', exc_info=False)


def _audit(actor, action, target, **detail):
    from tenancy import audit
    audit.record(actor, action, target, **detail)


def _after_change(keys):
    """A tuned or released discovery pool or worker lane is resized live, like a save."""
    from cveFeed import scan_concurrency
    if 'discovery_concurrency' in keys or any(k in scan_concurrency.LANE_KEYS for k in keys):
        scan_concurrency.request_apply()


# --- applying, recommending, reverting ---------------------------------------------------------------------------------------

def _record(**fields):
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.create(**fields)


def apply_tuned(m, old, new, *, mode, source, reason, signals, pressure=False, actor=None, action=None, phase='', only_lower=False,
                verify=None, only_if=None, hold_until=None):
    """Set a tuned number (mode Auto) and record it. Returns the decision, or None when, checked again under the row's lock, the mode is no
    longer Auto (a person chose Off or Suggest while this run was working, or the kill switch is set) or the setting was pinned meanwhile:
    nothing is written then. ``only_lower``: write only when ``new`` is below the tuned number the row holds now. ``only_if``: write only when
    the tuned number the row holds now is exactly this (a verification revert undoes its own change, never a later one). ``verify``: ``{'expected':
    metric, 'baseline': measurements before, 'at': now}``: the decision is judged ``VERIFY_SETTLE_SECONDS`` after ``at``. ``hold_until``: a datetime
    before which the tuner does not raise this setting (written in the same transaction)."""
    from django.db import transaction

    from cveFeed.models import AutoTuneSettings
    with transaction.atomic():
        row = AutoTuneSettings.objects.select_for_update().get(pk=settings_row().pk)
        if effective_mode(row) != 'auto' or pin_of(m, _saved_rows()) is not None:
            return None
        values = dict(row.values or {})
        before = values.get(m.key)
        if only_lower and not (isinstance(before, int) and new < before):
            return None
        if only_if is not None and before != only_if:
            return None
        values[m.key] = new
        row.values = values
        if hold_until is not None:
            row.meta = {**(row.meta or {}), m.key: {**((row.meta or {}).get(m.key) or {}), 'hold_until': hold_until.isoformat()}}
        row.save()
        extra = {}
        if verify:
            from cveFeed import autotune_policy as policy
            extra = {'expected': verify['expected'], 'baseline': verify['baseline'],
                     'verify_at': verify['at'] + timedelta(seconds=policy.VERIFY_SETTLE_SECONDS)}
        decision = _record(setting=m.key, old_value=old, new_value=new, mode=mode, source=source,
                           action=action or ('raise' if new > old else 'lower'),
                           layer='auto', old_layer_value=before, applied=True, pressure=pressure, phase=phase, reason=reason[:300], signals=signals,
                           actor=actor, **extra)
    publish(row)
    who = {'controller': 'Auto-tuning', 'ai': 'Auto-tuning (AI advisor)', 'agent': 'An agent'}.get(source, f'{getattr(actor, "username", "A person")}')
    _activity(f'{who}: {m.label} {old} -> {new}. {reason}', setting=m.key, decision_id=decision.pk)
    _audit(actor, 'autotune.change', m.key, before=old, after=new, source=source, reason=reason[:300], decision_id=decision.pk, env=m.env_name)
    _after_change([m.key])
    return decision


def recommend(m, old, new, *, mode, source, reason, signals, pressure=False, phase=''):
    """Record a recommendation (mode Suggest). A recommendation of the same number for the same setting that is still open is kept as it is; a
    different one replaces it. Returns the decision, or None when an equal one is open."""
    from cveFeed.models import TuningDecision
    open_ = TuningDecision.objects.filter(setting=m.key, applied=False, resolution='').order_by('-created_at')
    same = open_.filter(old_value=old, new_value=new).first()
    if same is not None:
        return None
    open_.update(resolution='superseded', resolved_at=_now(), resolved_by='auto-tune')
    return _record(setting=m.key, old_value=old, new_value=new, mode=mode, source=source,
                   action='raise' if new > old else 'lower', applied=False, pressure=pressure, phase=phase,
                   reason=reason[:300], signals=signals)


def _retire_suggestions(key, now_dt):
    """In Suggest mode, a recommendation the controller no longer makes (for an hour) is marked replaced, so the page does not offer it."""
    from cveFeed.models import TuningDecision
    TuningDecision.objects.filter(setting=key, applied=False, resolution='', created_at__lt=now_dt - timedelta(hours=1)).update(
        resolution='superseded', resolved_at=now_dt, resolved_by='auto-tune')


def _latest_applied(key):
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.filter(setting=key, applied=True).exclude(resolution='reverted').order_by('-created_at', '-pk').first()


def _decision(decision_id):
    from cveFeed.models import TuningDecision
    try:
        number = int(decision_id)
    except (TypeError, ValueError, OverflowError):
        raise TuningError(404, 'no such tuning decision')
    if not 0 < number < 2 ** 63:  # a bigint primary key: anything else would be a database error, not an answer
        raise TuningError(404, 'no such tuning decision')
    try:
        return TuningDecision.objects.get(pk=number)
    except TuningDecision.DoesNotExist:
        raise TuningError(404, 'no such tuning decision')


def apply_decision(user, decision_id):
    """A person applies a recommendation. In mode Auto (and for a setting no person pinned) it becomes the tuned number; otherwise it is saved
    as that person's value, which pins the setting. Refused when the setting changed since the recommendation was made."""
    _need_admin(user)
    decision = _decision(decision_id)
    if decision.applied or decision.resolution:
        raise TuningError(409, 'this recommendation was already applied or replaced')
    m = by_key().get(decision.setting)
    if m is None:
        raise TuningError(409, 'this setting is no longer auto-tuned')
    rows = _saved_rows()
    saved, _meta, _row = rows[m.registry]
    row = settings_row()
    tuned = applied_values(row)
    current = _effective(m, saved, tuned)
    if current != decision.old_value:
        raise TuningError(409, f'{m.label} is {current} now, not {decision.old_value}: wait for a new recommendation')
    reason = f'applied by {user.username}: {decision.reason}'
    if effective_mode(row) == 'auto' and m.key not in saved:
        done = apply_tuned(m, current, decision.new_value, mode='auto', source='person', reason=reason, signals=decision.signals,
                           actor=user, action='apply')
    else:
        _registry(m.registry).update({m.key: decision.new_value}, user)
        done = _record(setting=m.key, old_value=current, new_value=decision.new_value, mode=effective_mode(row), source='person', action='apply',
                       layer='saved', old_layer_value=saved.get(m.key), applied=True, reason=reason[:300], signals=decision.signals, actor=user)
        _activity(f'{user.username} applied the auto-tuning recommendation: {m.label} {current} -> {decision.new_value}', setting=m.key,
                  decision_id=done.pk)
    type(decision).objects.filter(pk=decision.pk).update(resolution='applied', resolved_at=_now(), resolved_by=user.username)
    _audit(user, 'autotune.apply', m.key, decision_id=decision.pk, before=current, after=decision.new_value)
    return serialize(done)


def revert(user, decision_id):
    """A person takes back the last applied change of one setting: the layer it went to (the tuned numbers, or the saved value) gets back
    exactly what it held before. The tuner then does not raise that setting for REVERT_HOLD_HOURS. Only the newest applied change of a
    setting can be reverted."""
    from django.db import transaction

    from cveFeed.models import AutoTuneSettings
    _need_admin(user)
    decision = _decision(decision_id)
    if not decision.applied or decision.resolution == 'reverted' or decision.action == 'revert':
        raise TuningError(409, 'only an applied change can be reverted')
    if decision.action == 'release':
        raise TuningError(409, 'handing a setting to auto-tuning cannot be reverted: save a value for it to pin it again')
    latest = _latest_applied(decision.setting)
    if latest is None or latest.pk != decision.pk:
        raise TuningError(409, 'a later change of this setting exists: revert that one first')
    m = by_key().get(decision.setting)
    if m is None:
        raise TuningError(409, 'this setting is no longer auto-tuned')
    rows = _saved_rows()
    saved = rows[m.registry][0]
    if decision.layer == 'auto':
        if effective_mode() != 'auto':
            raise TuningError(409, 'auto-tuning is not in Auto mode, so its numbers do not apply now')
        if m.key in saved:
            raise TuningError(409, f'{m.label} is pinned by a saved value now; reset it or change it there')
        with transaction.atomic():
            row = AutoTuneSettings.objects.select_for_update().get(pk=settings_row().pk)
            values, meta = dict(row.values or {}), dict(row.meta or {})
            current = values.get(m.key)
            if decision.old_layer_value is None:
                values.pop(m.key, None)
            else:
                values[m.key] = decision.old_layer_value
            meta[m.key] = {**(meta.get(m.key) or {}), 'hold_until': (_now() + timedelta(hours=REVERT_HOLD_HOURS)).isoformat()}
            row.values, row.meta = values, meta
            row.save()
        publish(row)
        _after_change([m.key])
        old_number, new_number, layer_before = current, decision.old_value, current
    else:
        layer_before = saved.get(m.key)
        _registry(m.registry).update({m.key: decision.old_layer_value}, user)
        old_number, new_number = decision.new_value, decision.old_value
    done = _record(setting=m.key, old_value=old_number, new_value=new_number, mode=effective_mode(), source='person', action='revert',
                   layer=decision.layer, old_layer_value=layer_before, applied=True,
                   reason=f'{user.username} reverted the change of {decision.created_at.isoformat(timespec="minutes")}', signals={}, actor=user)
    type(decision).objects.filter(pk=decision.pk).update(resolution='reverted', resolved_at=_now(), resolved_by=user.username)
    _activity(f'{user.username} reverted an auto-tuning change: {m.label} back to {decision.old_value}', setting=m.key, decision_id=done.pk)
    _audit(user, 'autotune.revert', m.key, decision_id=decision.pk, before=decision.new_value, after=decision.old_value)
    return serialize(done)


def release(user, key):
    """"Let auto-tune manage this": the saved value of a pinned setting is removed and the same number becomes the tuned one, so nothing jumps;
    the tuner may move it once the change cooldowns have passed (a release counts as a change, so there is no immediate jump), in mode Auto.
    It is a row in the history, like any change."""
    from django.db import transaction

    from cveFeed.models import AutoTuneSettings
    _need_admin(user)
    m = by_key().get(key)
    if m is None:
        raise TuningError(400, 'this setting is not auto-tuned')
    if effective_mode() != 'auto':
        raise TuningError(409, 'auto-tuning is not in Auto mode: turn it on first (or reset the saved value to go back to the environment or the default)')
    saved = _saved_rows()[m.registry][0]
    if key not in saved:
        raise TuningError(409, f'{m.label} is not pinned')
    number = int(saved[key])
    with transaction.atomic():
        row = AutoTuneSettings.objects.select_for_update().get(pk=settings_row().pk)
        if effective_mode(row) != 'auto':  # checked again under the lock: a person may have chosen Off or Suggest meanwhile
            raise TuningError(409, 'auto-tuning is not in Auto mode: turn it on first (or reset the saved value to go back to the environment or the default)')
        values = dict(row.values or {})
        before = values.get(key)
        values[key] = number  # the same number, so nothing jumps; the tuner moves it from the next run
        row.values = values
        row.save()
        _registry(m.registry).update({key: None}, user)
    publish(row)
    done = _record(setting=key, old_value=number, new_value=number, mode=effective_mode(row), source='person', action='release', layer='auto',
                   old_layer_value=before, applied=True, reason=f'{user.username} let auto-tune manage this setting',
                   signals={}, actor=user)
    _activity(f'{user.username} let auto-tuning manage {m.label} (from {number})', setting=key, decision_id=done.pk)
    _audit(user, 'autotune.release', key, value=number)
    _after_change([key])
    return serialize(done)


MODE_RANK = {'off': 0, 'suggest': 1, 'auto': 2}


def raises_autonomy(mode=None, advisor=None):
    """What a change would raise that only a person may raise (an agent may only lower autonomy): the mode (off, suggest, auto, in that order) and the AI advisor
    (switching it on spends provider calls). The agent policy has its own refusal. Returns a sentence naming the first, or None."""
    row = settings_row()
    if mode is not None and MODE_RANK.get(mode, 0) > MODE_RANK.get(row.mode, 2):
        return f'raising auto-tuning from {row.mode} to {mode} is a person\'s decision; an agent may only lower it (auto, then suggest, then off)'
    if advisor is True and not row.advisor:
        return 'switching the AI advisor on spends AI provider calls: a person does that, an agent may switch it off'
    return None


AGENT_POLICY_TEXT = {'off': 'not change throughput settings', 'suggest': 'only recommend throughput changes, which a person applies',
                     'auto': 'change throughput settings inside the safe ranges, each checked after 30 minutes'}


def set_mode(user, mode=None, advisor=None, policy=None):
    """App Admin only: the instance's mode (off, suggest, auto) and whether the AI advisor may be asked. Leaving Auto drops the tuned numbers at
    once (every setting goes back to its saved value, environment or default); coming back starts from there."""
    from django.db import transaction

    from cveFeed.models import AutoTuneSettings
    _need_admin(user)
    if mode is None and advisor is None and policy is None:
        raise TuningError(400, 'send mode (off, suggest or auto), advisor (true or false) and/or agent_policy (off, suggest or auto)')
    if policy is not None and policy not in AGENT_POLICIES:
        raise TuningError(400, f'agent_policy must be one of {", ".join(AGENT_POLICIES)}')
    if mode is not None and mode not in MODES:
        raise TuningError(400, f'mode must be one of {", ".join(MODES)}')
    if advisor is not None and not isinstance(advisor, bool):
        raise TuningError(400, 'advisor must be true or false')
    with transaction.atomic():
        row = AutoTuneSettings.objects.select_for_update().get(pk=settings_row().pk)
        before = {'mode': row.mode, 'advisor': row.advisor}
        policy_before = agent_policy(row)
        dropped = []
        if mode is not None and mode != row.mode:
            if row.mode == 'auto':
                dropped = sorted(row.values or {})
                row.values, row.meta = {}, {}
            row.mode = mode
        if advisor is not None:
            row.advisor = advisor
        if policy is not None:
            row.agent_policy = policy
        row.changed_by, row.changed_at = user, _now()
        row.save()
    publish(row)
    after = {'mode': row.mode, 'advisor': row.advisor}
    policy_after = agent_policy(row)
    if after != before or policy_after != policy_before:
        extra = {'agent_policy': {'before': policy_before, 'after': policy_after}} if policy_after != policy_before else {}
        _audit(user, 'autotune.mode', 'auto-tuning', before=before, after=after, dropped=dropped, **extra)
        _activity(f'{user.username} set auto-tuning to {row.mode}' + (' with the AI advisor' if row.advisor else ' without the AI advisor')
                  + (f'; {len(dropped)} tuned setting(s) went back to their saved, environment or default values' if dropped else '')
                  + (f'; agents may now {AGENT_POLICY_TEXT[policy_after]}' if policy_after != policy_before else ''))
    _after_change(dropped)
    return status()


def reset(user):
    """The configMaxxing "reset all": auto-tuning back to its defaults (mode Auto, the advisor on, no tuned numbers). Returns what was cleared."""
    from cveFeed.models import AutoTuneSettings
    _need_admin(user)
    row = settings_row()
    cleared = sorted(row.values or {})
    changed = row.mode != DEFAULT_MODE or not row.advisor or cleared
    AutoTuneSettings.objects.filter(pk=row.pk).update(mode=DEFAULT_MODE, advisor=True, values={}, meta={}, changed_by=user, changed_at=_now(),
                                                      updated_at=_now())
    publish()
    if changed:
        _audit(user, 'autotune.reset', 'auto-tuning', before={'mode': row.mode, 'advisor': row.advisor}, cleared=cleared)
    _after_change(cleared)
    return cleared


# --- the run -------------------------------------------------------------------------------------------------------------

def _process_started():
    """When this process started, in seconds since the epoch (from /proc where there is one)."""
    try:
        with open('/proc/self/stat') as f:
            ticks = int(f.read().rsplit(')', 1)[1].split()[19])
        with open('/proc/stat') as f:
            boot = next(int(line.split()[1]) for line in f if line.startswith('btime'))
        return boot + ticks / os.sysconf('SC_CLK_TCK')
    except Exception:  # noqa: BLE001
        return _IMPORTED


_IMPORTED = time.time()


def boot_marker(now):
    """{'id', 'at'}: the newest start of a process that runs the tuner (a restart, or the restart an update ends with). Kept in Redis so that
    two worker processes taking turns do not reset each other's warm-up: only a process that started later than the one recorded replaces it."""
    started = _process_started()
    mine = {'id': f'{socket.gethostname()}:{os.getpid()}:{int(started)}', 'at': started}
    client = _redis()
    if client is None:
        return mine
    try:
        known = json.loads(client.get(BOOT_KEY) or 'null')
        if not isinstance(known, dict) or known.get('id') != mine['id'] and float(known.get('at', 0)) < started:
            client.set(BOOT_KEY, json.dumps(mine), ex=30 * 86400)
            return mine
        return known
    except Exception:  # noqa: BLE001
        return mine


_local_samples = []


def store_sample(sample):
    """Keep a measurement (newest first in Redis, SAMPLES_KEPT of them) and return every kept one, oldest first."""
    client = _redis()
    if client is None:
        _local_samples.append(sample)
        del _local_samples[:-SAMPLES_KEPT]
        return list(_local_samples)
    try:
        client.lpush(SAMPLES_KEY, json.dumps(sample))
        client.ltrim(SAMPLES_KEY, 0, SAMPLES_KEPT - 1)
        client.expire(SAMPLES_KEY, 3 * 86400)
        out = []
        for raw in client.lrange(SAMPLES_KEY, 0, SAMPLES_KEPT - 1):
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue
        return list(reversed(out))
    except Exception:  # noqa: BLE001
        return [sample]


def _history(key, now_dt):
    """This setting's applied changes in the last two days, as the policy reads them, and a revert's hold (seconds since the epoch)."""
    from cveFeed.models import TuningDecision
    rows = (TuningDecision.objects.filter(setting=key, applied=True, created_at__gte=now_dt - timedelta(days=2))
            .values('created_at', 'old_value', 'new_value', 'pressure', 'action', 'phase'))
    m = by_key()[key]
    from cveFeed.autotune_policy import direction_of
    return [{'at': r['created_at'].timestamp(), 'direction': direction_of(m.setting, r['old_value'] or 0, r['new_value'] or 0),
             'pressure': r['pressure'], 'phase': r['phase'], 'old': r['old_value'], 'new': r['new_value']}
            for r in rows if r['old_value'] is not None and r['new_value'] is not None]


def _hold_until(row, key):
    raw = ((row.meta or {}).get(key) or {}).get('hold_until')
    try:
        return datetime.fromisoformat(raw).timestamp() if raw else None
    except ValueError:
        return None


def remember(summary):
    client = _redis()
    try:
        if client is not None:
            client.set(LAST_RUN_KEY, json.dumps(summary, default=str), ex=7 * 86400)
    except Exception:  # noqa: BLE001
        pass
    _last_local.update(summary=summary)


_last_local = {'summary': None}


def last_run():
    client = _redis()
    try:
        raw = client.get(LAST_RUN_KEY) if client is not None else None
        return json.loads(raw) if raw else _last_local['summary']
    except Exception:  # noqa: BLE001
        return _last_local['summary']


def purge(now_dt):
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.filter(created_at__lt=now_dt - timedelta(days=RETENTION_DAYS)).delete()[0]


def advisor_calls_today():
    """Questions asked of the AI advisor since UTC midnight, failed ones included (the provider bills them)."""
    from cveFeed.models import AIUsage
    midnight = datetime.now(dt_timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return AIUsage.objects.filter(stage=ADVISOR_STAGE, started_at__gte=midnight).count()


def advisor_state(row=None):
    """{'enabled', 'provider', 'used_today', 'cap', 'last_at', 'last_error'}: whether the AI advisor may be asked and what it has used."""
    from cveFeed import tunables
    row = row or settings_row()
    out = {'enabled': bool(row.advisor), 'provider': False, 'used_today': None, 'cap': tunables.value('autotune_ai_max_per_day'),
           'interval_hours': tunables.value('autotune_ai_interval_hours'), 'last_at': None, 'last_error': None}
    try:
        from dashboard.models import AIProviderSettings
        out['provider'] = AIProviderSettings.objects.filter(enabled=True).exists()
        out['used_today'] = advisor_calls_today()
    except Exception:  # noqa: BLE001
        pass
    try:
        client = _redis()
        record = json.loads(client.get(ADVISOR_KEY) or 'null') if client is not None else None
        if isinstance(record, dict):
            out['last_at'], out['last_error'] = record.get('at'), record.get('error')
    except Exception:  # noqa: BLE001
        pass
    return out


def _advisor_due(state, now):
    if not (state['enabled'] and state['provider']):
        return False
    if state['used_today'] is None or state['used_today'] >= state['cap']:
        return False
    last = state.get('last_at')
    return not last or now - float(last) >= state['interval_hours'] * 3600


def _set_record(record):
    try:
        client = _redis()
        if client is not None:
            client.set(ADVISOR_KEY, json.dumps(record), ex=7 * 86400)
    except Exception:  # noqa: BLE001
        pass


def ask_advisor(offered, summary, now):
    """Queue one question for the AI advisor (cveFeed.ai_jobs; the AI reviewer container asks it): the window's numbers and the settings it
    may advise on, no host, no finding, no free text from a scanned host. Its answer is kept for the next round (``job_answer``), which judges
    it against the range in force then. Returns an error, or ''."""
    from cveFeed import ai_jobs
    from cveFeed import autotune_policy as policy
    record = {'at': now, 'error': None}
    try:
        if not ai_jobs.ai_on():
            record['error'] = 'no AI provider'
            return record['error']
        public = {key: {'value': o['value'], 'starting_value': o['baseline'], 'target_for_this_machine': o['target'],
                        'you_may_choose_from': o['range'][0], 'you_may_choose_to': o['range'][1], 'step': o['setting'].step,
                        'higher_number_means': 'more work at once' if o['setting'].sense == 'more' else 'a longer wait between runs',
                        'controller': o['controller']} for key, o in offered.items()}
        ai_jobs.enqueue('autotune_advice', ADVISOR_STAGE, system=ADVISOR_SYSTEM,
                        parts=[{'text': 'The settings you may change now and the measurements of the last hours:'},
                               {'fence': 'NUMBERS', 'data': {'settings': public, 'measurements': summary}}],
                        schema=policy.ADVICE_SCHEMA, options={'temperature': 0, 'seed': ADVISOR_SEED, 'max_tokens': 2000},
                        dedupe='autotune_advice', priority=6)
        return ''
    except Exception as exc:  # noqa: BLE001 - the controller tunes alone when the advisor cannot be asked
        record['error'] = str(type(exc).__name__)[:60]
        return record['error']
    finally:
        _set_record(record)


def job_answer(job, text):
    """The advisor answered: kept for the next round, which validates it (``autotune_policy.validate_advice``) against what it offers then."""
    from reNgine.ai_providers import clean_text
    client = _redis()
    if client is not None:
        client.set(ADVICE_KEY, json.dumps({'reply': clean_text(text, 20000), 'at': _now().timestamp()}), ex=ADVICE_FRESH)
    return None


def job_failure(job, category, detail):
    _set_record({'at': _now().timestamp(), 'error': str(category)[:60]})


def take_advice(now):
    """The advisor's answer waiting for this round (and no longer after it), or None."""
    try:
        client = _redis()
        raw = client.get(ADVICE_KEY) if client is not None else None
        if not raw:
            return None
        client.delete(ADVICE_KEY)
        data = json.loads(raw)
        return data['reply'] if now - float(data.get('at', 0)) <= ADVICE_FRESH else None
    except Exception:  # noqa: BLE001
        return None


def _verification(m, value, new, samples, now_dt, watch_backlog=False):
    """What ``apply_tuned`` stores for a change of ``m`` from ``value`` to ``new``: the measurement it expects to improve and the measurements before
    it (the last ``VERIFY_BEFORE_SAMPLES``, the newest taken at the change: ``t`` says when)."""
    from cveFeed import autotune_policy as policy
    if not samples:
        return None
    direction = policy.direction_of(m.setting, value, new)
    before = policy.measure(m.setting, samples[-policy.VERIFY_BEFORE_SAMPLES:], direction)
    before['t'] = float(samples[-1].get('t', now_dt.timestamp()))
    before['direction'] = direction
    if watch_backlog and direction == 'less':  # a lowering that is judged only by "no trouble" can starve scanning unseen: the backlog it serves is watched too
        before['backlog'] = policy.measure(m.setting, samples[-policy.VERIFY_BEFORE_SAMPLES:], 'more')
    return {'expected': before['metric'], 'baseline': before, 'at': now_dt}


def calm_change_unverified():
    """Whether a calm change (anything that is not a forced back-off, a cap, an emergency or a verification revert) is waiting to be judged: while one
    is, no other calm change is made (``autotune_policy.is_calm``)."""
    from cveFeed import autotune_policy as policy
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.filter(applied=True, layer='auto', outcome='', verify_at__isnull=False, pressure=False).exclude(
        phase__in=policy.NO_ACTION_PHASES).exclude(action='revert').exists()


def verify_pending(now_dt, samples):
    """Judge every applied change whose settling time has passed (``autotune_policy.verify_due``, ``verdict``), store the outcome on the decision and
    take back a calm change that regressed. ``samples``: the measurements since the restart without the paused ones, oldest first. Returns one dict per
    judged change, ``{'id', 'setting', 'outcome', 'detail', 'reverted'}``. A change that cannot be judged (its setting is no longer tuned, or too few
    measurements came ``VERIFY_GIVE_UP_SECONDS`` after the settling time) gets the outcome ``unknown`` and no longer holds another change back."""
    from cveFeed import autotune_policy as policy
    from cveFeed.models import TuningDecision
    now, keys, judged = now_dt.timestamp(), by_key(), []
    pending = (TuningDecision.objects.filter(applied=True, layer='auto', outcome='', verify_at__isnull=False).exclude(action='revert')
               .order_by('created_at', 'pk')[:50])
    for d in pending:
        base = dict(d.baseline or {})
        since = float(base.get('t') or d.created_at.timestamp())
        after = [s for s in samples if float(s.get('t', 0)) > since][:2 * policy.VERIFY_SAMPLES]
        due = policy.verify_due(now, d.verify_at.timestamp(), len(after))
        if due == 'wait':
            continue
        m = keys.get(d.setting)
        direction = base.get('direction') or ('more' if (d.new_value or 0) > (d.old_value or 0) else 'less')
        if m is None:
            outcome, detail = 'unknown', 'the setting is no longer auto-tuned, so the change was not judged'
        elif due == 'give_up':
            outcome, detail = 'unknown', f'only {len(after)} measurement(s) came after the change, so it was not judged'
        elif _lane_unconfirmed(m, d):
            outcome, detail = 'unknown', 'the lane still reports another size than the one set, so the change did not take effect and was not judged'
        else:
            after_m = policy.measure(m.setting, after, direction)
            outcome, detail = policy.verdict(base, after_m)
            base['after'] = after_m
            if isinstance(base.get('backlog'), dict) and outcome != 'regressed':  # an AI lowering: the backlog must not have grown beyond the verdict's tolerance
                after_b = policy.measure(m.setting, after, 'more')
                base['backlog_after'] = after_b
                worse = policy.verdict(base['backlog'], after_b)
                if worse.outcome == 'regressed':
                    outcome, detail = 'regressed', f'the backlog got worse after the lowering: {worse.detail}'
        TuningDecision.objects.filter(pk=d.pk).update(outcome=outcome, outcome_detail=detail[:300], verified_at=now_dt, baseline=base)
        reverted = False
        if m is not None and policy.revert_wanted(outcome, d.phase, d.pressure):
            reverted = _auto_revert(m, d, detail, now_dt)
        judged.append({'id': d.pk, 'setting': d.setting, 'outcome': outcome, 'detail': detail, 'reverted': reverted})
    return judged


def _lane_unconfirmed(m, d):
    """FC-4e: a worker lane's decision is recorded as applied when the number is written; the lane takes it with the next resize round. Judged after thirty minutes the lane
    must report the new size: when it still reports another one the change did not happen, and what it did to memory says nothing about it."""
    from cveFeed import scan_concurrency
    if m.key not in scan_concurrency.LANE_KEYS:
        return False
    seen = scan_concurrency.running_lane(m.key)
    return bool(seen and any(c != d.new_value for c in seen['ceilings']))


def _auto_revert(m, d, detail, now_dt):
    """Undo one change that made things worse: the number goes back to what it was, as a decision of its own (``action='revert'``, ``phase='verify'``,
    ``pressure``: the level it left is remembered as trouble, ``autotune_policy.decide``), the setting is held for ``VERIFY_COOLDOWN_SECONDS`` and
    the judged decision is marked reverted. Only when ``d`` is still the newest applied change of the setting and the tuned number is still the one
    it wrote (a person, or a later change, is never overwritten). Returns whether it was reverted."""
    from cveFeed import autotune_policy as policy
    from cveFeed.models import TuningDecision
    latest = _latest_applied(d.setting)
    if latest is None or latest.pk != d.pk:
        return False
    done = apply_tuned(m, d.new_value, d.old_value, mode='auto', source='controller', pressure=True, action='revert', phase='verify',
                       reason=f'verification of the change of {d.created_at.isoformat(timespec="minutes")}: {detail}; put {d.new_value} back to {d.old_value}',
                       signals={'verified_decision': d.pk}, only_if=d.new_value,
                       hold_until=now_dt + timedelta(seconds=policy.VERIFY_COOLDOWN_SECONDS))
    if done is None:
        return False
    TuningDecision.objects.filter(pk=d.pk).update(resolution='reverted', resolved_at=now_dt, resolved_by='auto-tune')
    TuningDecision.objects.filter(pk=done.pk).update(outcome='reverted', outcome_detail=f'undid decision {d.pk}: {detail}'[:300], verified_at=now_dt)
    return True


# --- agents act through the engine (AM-3) -------------------------------------------------------------------------------------

def recent_samples(now_dt):
    """The stored measurements of the last window without the paused ones, oldest first, read without storing anything (the run stores them)."""
    client, kept = _redis(), []
    if client is None:
        kept = list(_local_samples)
    else:
        try:
            for raw in client.lrange(SAMPLES_KEY, 0, SAMPLES_KEPT - 1):
                try:
                    kept.append(json.loads(raw))
                except ValueError:
                    continue
            kept.reverse()
        except Exception:  # noqa: BLE001
            kept = []
    since = now_dt.timestamp() - _cooldowns()[2]
    return [s for s in kept if float(s.get('t', 0)) >= since and not (s.get('paused') or s.get('updating'))]


def _agent_result(m, raw, status, value, text, **extra):
    return {'setting': m.key, 'label': m.label, 'requested': raw, 'status': status, 'value': value, 'text': text, **extra}


def _agent_limit(m, current, number, samples, history, now_dt):
    """What the controller would let this setting do, for a number that asks for more work than ``current``: ``(highest number allowed, why it is
    not higher)``. The controller's own ceiling (the target for this machine, the level that caused trouble in the last day) and a scanner kind's
    memory budget, so that the next round does not simply lower the number again."""
    from cveFeed import autotune_policy as policy
    setting, now = m.setting, now_dt.timestamp()
    if setting.sense == 'gap':  # a wait between runs: more work is a SHORTER wait, so the ceiling for more work starts at the shortest the range allows
        limit, why = setting.low, f'the shortest wait auto-tuning allows is {setting.low}'
    else:
        limit, why = setting.high, f'the auto-tuning maximum is {setting.high}'
    if samples:
        facts = policy.steady_facts(samples)
        target, reason, known = policy.size_for(setting, facts, current=current)
        if known and policy._beyond(setting, limit, target):
            limit, why = target, f'the target for this machine is {target} ({reason or "sized"})'
        if setting.kind.startswith('heavy:'):
            cap = policy.memory_cap(setting.kind.split(':', 1)[1], samples[-1])
            if cap is not None and setting.sense == 'more' and max(setting.low, cap) < limit:
                limit, why = max(setting.low, cap), f'the memory budget holds {cap} at their real peak'
    held, text = policy.remembered_ceiling(setting, limit, history, now=now)
    if text:
        limit, why = held, text
    return limit, why


def _agent_one(m, raw, user, row, who, mode, policy_name, samples, now_dt, source='agent', reason_text=None, signals_extra=None):
    """One key of an agent's write. Returns the result dict (``status``: applied, suggested, refused or unchanged); nothing is raised for a refusal."""
    from cveFeed import autotune_policy as policy
    setting = m.setting
    if raw is None or isinstance(raw, bool) or not isinstance(raw, int):
        return _agent_result(m, raw, 'refused', None, f'{m.label}: send a whole number. An agent cannot reset a setting to its default; a person does that in Settings.')
    pin = pin_of(m, _saved_rows())
    if pin is not None:
        return _agent_result(m, raw, 'refused', None, f'{m.label} is pinned by {pin[0]}: only a person may change a pinned number or hand it back to auto-tuning.')
    number, clamp = raw, ''
    if not setting.low <= raw <= setting.high:
        number = max(setting.low, min(setting.high, raw))
        clamp = f'clamped to {number}, the safe range is {setting.low} to {setting.high}'
    tuned = applied_values(row)
    current = _effective(m, {}, tuned)
    now = now_dt.timestamp()
    history = _history(m.key, now_dt)
    direction = policy.direction_of(setting, current, number)
    held = ''
    if direction == 'more':
        limit, why = _agent_limit(m, current, number, samples, history, now_dt)
        if policy._beyond(setting, number, limit):
            number, held = limit, f'held at {limit}: {why}'
        if not policy._beyond(setting, number, current):
            return _agent_result(m, raw, 'refused', current, f'{m.label} stays {current}: {why}, so it is not raised.')
        trouble = policy.trouble(setting, samples) if samples else None
        if trouble:
            return _agent_result(m, raw, 'refused', current, f'{m.label} stays {current}: {trouble} right now, so it is not raised.')
    elif direction == 'hold':
        return _agent_result(m, raw, 'unchanged', current, f'{m.label} is already {current}; nothing changed.' + (f' ({clamp})' if clamp else ''))
    notes = '; '.join(x for x in (clamp, held) if x)
    reason = (reason_text or f'an agent ({who}) asked for {raw}') + (f'; {notes}' if notes else '')
    used = {'agent': who, 'requested': raw, 'summary': signals_summary(samples[-6:]) if samples else {}} if source == 'agent' else {
        'requested': raw, 'summary': signals_summary(samples[-6:]) if samples else {}, **(signals_extra or {})}
    if policy_name == 'suggest' or mode == 'suggest':
        why_text = 'the agent policy is Suggest' if policy_name == 'suggest' else 'auto-tuning is in Suggest mode'
        decision = recommend(m, current, number, mode=mode, source=source, reason=reason, signals=used)
        text = (f'Recorded as a recommendation, {m.label} {current} -> {number} ({why_text}): a person applies it with one click '
                f'(apply_tuning_suggestion).' + (f' {notes}.' if notes else ''))
        return _agent_result(m, raw, 'suggested', current, text, decision_id=decision.pk if decision else None)
    if direction == 'more':
        hold = _hold_until(row, m.key)
        if hold and now < hold:
            return _agent_result(m, raw, 'refused', current, f'{m.label} stays {current}: its last change was taken back, so it is not raised for a day.')
        recent = max((h['at'] for h in history), default=None)
        wait = _cooldowns()[1]
        if recent is not None and now - recent < wait:
            return _agent_result(m, raw, 'refused', current, f'{m.label} stays {current}: it changed {int((now - recent) // 60)} minutes ago, a raise waits {int(wait // 60)}.')
        if calm_change_unverified():
            return _agent_result(m, raw, 'refused', current, f'{m.label} stays {current}: an earlier change is still being verified (one calm change at a time). Ask again in half an hour.')
    decision = apply_tuned(m, current, number, mode='auto', source=source, reason=reason, signals=used, actor=user if source == 'agent' else None,
                           verify=_verification(m, current, number, samples, now_dt, watch_backlog=source == 'ai'))
    if decision is None:
        return _agent_result(m, raw, 'refused', current, f'{m.label} stays {current}: auto-tuning changed mode or the setting was pinned meanwhile.')
    text = (f'Applied: {m.label} {current} -> {number}' + (f' ({notes})' if notes else '') + '. It is checked after 30 minutes and undone if it made things worse.')
    return _agent_result(m, raw, 'applied', number, text, decision_id=decision.pk, clamped=bool(clamp or held))


# --- the health-check AI's proposals (cveFeed.reviewer ``apply_ops_report``, ``snapshot``) --------------------------------------------------
# The operations job may propose at most MAX_AI_PROPOSALS numbers in a report, for settings the server offered in the snapshot it read, through the same
# gates as an agent's request (``_agent_one``) and a decision of ``source='ai'``. It never gets a cost-bearing number, a switch, the scan policy, a
# credential, an update, the allowlist, the mode or the agent policy: only ``managed()`` can be offered, and anything else is dropped.
MAX_AI_PROPOSALS = 2           # per report
MAX_AI_CHANGES_PER_DAY = 6     # AI decisions that were applied or recommended in 24 hours: a confused model cannot thrash the settings
AI_HOLD_HOURS = 24             # after a change of the AI was taken back, no proposal for that setting from it for this long
AI_GATE_TEXT = {'policy': 'a person set the agent policy to Off, and the health-check AI is an agent: it may not change throughput settings',
                'advisor': 'the AI advisor switch is off (it covers the health-check AI\'s proposals too)', 'off': 'auto-tuning is off'}


def ai_gate(row=None):
    """Why the health-check AI's proposals are not taken, or '' when they may be: auto-tuning off (the mode, or the kill switch), the AI advisor
    switch off, or the agent policy Off. The health-check AI is an AI agent: its proposals obey the agent policy (a person's setting, ``Suggest`` until
    a person says otherwise) as well as the mode, and the more careful of the two wins: a proposal is applied only when the policy AND the mode are Auto,
    otherwise it is recorded as a recommendation a person applies (``_agent_one``)."""
    row = row or settings_row()
    if effective_mode(row) == 'off':
        return AI_GATE_TEXT['off'] + (f' ({KILL_ENV}=0)' if killed() else '')
    if not row.advisor:
        return AI_GATE_TEXT['advisor']
    if agent_policy(row) == 'off':
        return AI_GATE_TEXT['policy']
    return ''


def ai_changes_today(now_dt):
    """How many decisions of the AI (applied, or recommended in Suggest mode) the last 24 hours hold; a refused or held proposal is not one."""
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.filter(source='ai', action__in=('raise', 'lower'), created_at__gte=now_dt - timedelta(hours=24)).exclude(
        resolution__in=('refused', 'held')).count()


def _ai_held(key, now_dt):
    """Whether a change the AI made to ``key`` was taken back (by the verification or by a person) in the last ``AI_HOLD_HOURS``."""
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.filter(setting=key, source='ai', resolution='reverted', resolved_at__gte=now_dt - timedelta(hours=AI_HOLD_HOURS)).exists()


# The alerts whose resource a setting uses: a lowering of the AI needs trouble for that setting, or one of these alerts open (and cited). ``None``: every setting.
ALERT_RESOURCES = {'memory': None, 'workers_down': ('discovery', 'batch', 'depth', 'stage'), 'scan_errors': ('heavy:',), 'sentinel_errors': ('stage',),
                   'sentinel_waiting': ('stage',), 'queue_starvation': ('assess_share',)}


def _alert_covers(code, setting):
    if code not in ALERT_RESOURCES:
        return False
    kinds = ALERT_RESOURCES[code]
    return kinds is None or any(setting.kind.startswith(k) for k in kinds)


def _lowering_block(m, samples, history, now_dt, unverified, cited, open_codes):
    """Why the AI may not lower (or lengthen) ``m`` now, or '': it needs trouble for the setting, or an open alert about its resource (the one it cites, when it cites
    one), and then the lowering cooldown and the one-calm-change-at-a-time gate apply; with trouble showing neither does (a back-off under trouble is never held up)."""
    from cveFeed import autotune_policy as policy
    if samples and policy.trouble(m.setting, samples):
        return ''
    covering = {c for c in open_codes if _alert_covers(c, m.setting)}
    if cited is not None:
        covering &= {cited}
    if not covering:
        return 'no trouble shows for it and no open alert is about its resource'
    if history and now_dt.timestamp() - max(h['at'] for h in history) < _cooldowns()[0]:
        return 'it changed recently, a lowering waits'
    if unverified:
        return 'an earlier change is still being verified'
    return ''


def ai_offer(now_dt=None):
    """What the health-check AI may propose NOW. Returns ``{'gate': why it may not, or '', 'left_today': proposals still allowed today, 'offered': {key: {'setting',
    'label', 'value', 'range': (lowest, highest), 'higher': text}}, 'not_offered': {key: why}}``. For each setting that is not pinned and not held from the AI: the
    auto-tuning range, but a number that asks for more work stops at the controller's own ceiling (the target for this machine, the level that caused trouble,
    a scanner kind's memory budget) and at the current number while a raise is not allowed (trouble for the setting, a hold, the raise cooldown, another calm
    change not yet verified); a lower number is always allowed. A setting with no number left to choose is listed in ``not_offered`` with the reason."""
    from cveFeed import autotune_policy as policy
    now_dt = now_dt or _now()
    row = settings_row()
    out = {'gate': ai_gate(row), 'left_today': max(0, MAX_AI_CHANGES_PER_DAY - ai_changes_today(now_dt)), 'offered': {}, 'not_offered': {}}
    if out['gate']:
        return out
    if not out['left_today']:
        out['gate'] = f'the AI has made {MAX_AI_CHANGES_PER_DAY} changes in the last 24 hours, which is the most it may'
        return out
    samples, rows, tuned = recent_samples(now_dt), _saved_rows(), applied_values(row)
    unverified, now = calm_change_unverified(), now_dt.timestamp()
    from cveFeed.models import AdminAlert
    open_codes = set(AdminAlert.objects.filter(resolved_at__isnull=True).values_list('code', flat=True))
    for m in managed():
        setting = m.setting
        pin = pin_of(m, rows)
        if pin is not None:
            out['not_offered'][m.key] = f'pinned by {pin[0]}'
            continue
        current = _effective(m, {}, tuned)
        if current == 0 and setting.kind in ('depth', 'refresh_gap'):
            out['not_offered'][m.key] = 'turned off (0) by its environment value'
            continue
        if _ai_held(m.key, now_dt):
            out['not_offered'][m.key] = f'a change of the AI was taken back in the last {AI_HOLD_HOURS} hours'
            continue
        history = _history(m.key, now_dt)
        lower_block = _lowering_block(m, samples, history, now_dt, unverified, None, open_codes)
        one_down = policy.towards(setting, current, 'less')  # one step to less work, as the advisor may go: never to the floor in one report
        if setting.sense == 'more':
            limit, why = _agent_limit(m, current, current, samples, history, now_dt)
            blocker = ''
            if samples and policy.trouble(setting, samples):
                blocker = 'trouble shows for it right now'
            elif (_hold_until(row, m.key) or 0) > now:
                blocker = 'its last change was taken back, so it is not raised for a day'
            elif history and now - max(h['at'] for h in history) < _cooldowns()[1]:
                blocker = 'it changed recently, a raise waits'
            elif unverified:
                blocker = 'an earlier change is still being verified'
            up = current if blocker or not policy._beyond(setting, limit, current) else limit  # the most work it may be asked for
            lowest, highest = (current if lower_block else one_down), max(up, current)
        else:  # a wait between runs: the AI may only lengthen it (less work), one step; shortening it is the controller's call
            lowest, highest, why, blocker = current, (current if lower_block else one_down), '', 'for this setting the AI may only lengthen the wait'
        if lowest == highest:
            out['not_offered'][m.key] = f'no change is allowed: {lower_block or "it is at the end of its range"}; a raise: {blocker or why}'[:160]
            continue
        out['offered'][m.key] = {'setting': setting, 'label': m.label, 'value': current, 'range': (lowest, highest),
                                 'higher': 'more work at once' if setting.sense == 'more' else 'a longer wait between runs',
                                 'raise_stops': blocker or why, 'lowering_stops': lower_block}
    try:  # a worker lane at or below its floor is not managed at all (no room to lower it): say so, so the model and the History know it was left alone on purpose
        from cveFeed import scan_concurrency
        for key, floor in getattr(scan_concurrency, 'LANE_FLOORS', {}).items():
            if key not in by_key():
                out['not_offered'][key] = f'the lane is set at or below its floor of {floor}: auto-tuning never lowers it'
    except Exception:  # noqa: BLE001
        pass
    return out


def ai_apply(proposals, offer, now_dt=None):
    """Judge and apply the health-check AI's proposals. ``proposals``: ``[{'setting', 'value', 'reason', 'alert'}]`` (the report's own, at most
    ``MAX_AI_PROPOSALS`` are read), ``offer``: ``ai_offer()`` read now. ``validate_advice`` keeps what the offered ranges allow; each kept number goes
    through the gates of an agent's request (mode Auto applies it with ``verify=``, Suggest records a recommendation) and a refusal is recorded as a
    decision of its own (``resolution='refused'``), so the History shows it. Returns one dict per proposal: ``{'setting', 'status', 'text'}``, ``status`` one of
    applied, suggested, refused, unchanged."""
    from cveFeed import autotune_policy as policy
    now_dt = now_dt or _now()
    results, items = [], []
    for raw in (proposals if isinstance(proposals, list) else [])[:MAX_AI_PROPOSALS]:
        if isinstance(raw, dict) and isinstance(raw.get('setting'), str):
            items.append({'setting': raw['setting'], 'value': raw.get('value'), 'reason': raw.get('reason'), 'alert': raw.get('alert')})
        else:
            results.append({'setting': '', 'status': 'refused', 'text': 'a proposal that was not {setting, value, reason} was ignored'})
    if len(proposals if isinstance(proposals, list) else []) > MAX_AI_PROPOSALS:
        results.append({'setting': '', 'status': 'refused', 'text': f'only the first {MAX_AI_PROPOSALS} proposals of a report are read'})
    if not items:
        return results
    if offer['gate']:
        return results + [{'setting': i['setting'][:64], 'status': 'refused', 'text': f'ignored: {offer["gate"]}'} for i in items]
    from reNgine.ai_providers import clean_text
    offered = {k: {'setting': o['setting'], 'value': o['value'], 'range': o['range']} for k, o in offer['offered'].items()}
    keys, row, mode, samples = by_key(), settings_row(), effective_mode(), recent_samples(now_dt)
    seen = set()
    for item in items:
        key = item['setting']
        if key in seen:
            results.append({'setting': key[:64], 'status': 'refused', 'text': f'{key[:64]} was named twice: only the first is read'})
            continue
        seen.add(key)
        if key not in offered:  # an unknown setting, a setting this report was not offered, or one that no number is left for: dropped, never recorded as a change
            why = offer['not_offered'].get(key)
            results.append({'setting': key[:64], 'status': 'refused',
                            'text': f'{key[:64]} was not offered to the AI' + (f': {why}' if why else ' (it is not a setting the AI may change)')})
            continue
        accepted, refused, error = policy.validate_advice(json.dumps({'recommendations': [{k: item[k] for k in ('setting', 'value', 'reason')}]}), offered, clean=clean_text)
        m, current = keys[key], offered[key]['value']
        if key not in accepted:
            why = refused[0][1] if refused else (error or 'refused')
            results.append({'setting': key, 'status': 'refused', 'text': _ai_record_refused(m, current, item, why, now_dt)})
            continue
        if ai_changes_today(now_dt) >= MAX_AI_CHANGES_PER_DAY:
            results.append({'setting': key, 'status': 'refused', 'text': _ai_record_refused(m, current, item, f'the AI already made {MAX_AI_CHANGES_PER_DAY} changes in 24 hours', now_dt)})
            continue
        alert = item['alert'] if isinstance(item['alert'], str) and len(item['alert']) <= 40 else None
        if _ai_held(key, now_dt):  # judged again now: a change of the AI taken back after the offer was read still holds the setting
            results.append({'setting': key, 'status': 'refused', 'text': _ai_record_refused(m, current, item, f'a change of the AI was taken back in the last {AI_HOLD_HOURS} hours', now_dt)})
            continue
        if policy.direction_of(m.setting, current, accepted[key]['value']) == 'less':  # judged again now, with the alert the AI cited
            from cveFeed.models import AdminAlert
            block = _lowering_block(m, samples, _history(key, now_dt), now_dt, calm_change_unverified(), alert,
                                    set(AdminAlert.objects.filter(resolved_at__isnull=True).values_list('code', flat=True)))
            if block:
                results.append({'setting': key, 'status': 'refused', 'text': _ai_record_refused(m, current, item, block, now_dt)})
                continue
        extra = {'alerts': [alert]} if alert else {}
        result = _agent_one(m, accepted[key]['value'], None, row, 'AI', mode, agent_policy(row), samples, now_dt, source='ai', reason_text=accepted[key]['reason'], signals_extra=extra)
        if result['status'] == 'refused':
            result['text'] = _ai_record_refused(m, current, item, result['text'], now_dt)
        results.append({'setting': key, 'status': result['status'], 'text': result['text'], 'decision_id': result.get('decision_id')})
        if result['status'] == 'applied':
            row = settings_row()
    return results


def _ai_record_refused(m, current, item, why, now_dt, resolution='refused'):
    """A proposal that was not taken, as a decision of its own so the History says so (``resolution`` refused or held; the reason is in ``outcome_detail``).
    Returns the sentence for the reply."""
    value = item.get('value')
    number = value if isinstance(value, int) and not isinstance(value, bool) else None
    try:
        from reNgine.ai_providers import clean_text
        reason = clean_text(item.get('reason') or '', 200) or 'AI proposal'
        alert = item.get('alert') if isinstance(item.get('alert'), str) and len(item['alert']) <= 40 else None
        direction = 'raise' if number is not None and current is not None and number > current else 'lower'
        _record(setting=m.key, old_value=current, new_value=number, mode=effective_mode(), source='ai', action=direction, applied=False, reason=reason,
                signals={'alerts': [alert]} if alert else {}, resolution=resolution, resolved_at=now_dt, resolved_by='auto-tune', outcome_detail=str(why)[:300])
    except Exception:  # noqa: BLE001 - the History line is a convenience: the refusal itself stands
        logger.debug('auto-tune: a refused proposal could not be recorded', exc_info=False)
    return f'{m.label}: not changed ({str(why)[:200]})'


def ai_hold_all(proposals, why, now_dt=None):
    """Record every proposal of a report as held (the text the model read was flagged, ``cveFeed.reviewer``): nothing is applied. Returns the results."""
    now_dt = now_dt or _now()
    keys, out = by_key(), []
    for raw in (proposals if isinstance(proposals, list) else [])[:MAX_AI_PROPOSALS]:
        key = raw.get('setting') if isinstance(raw, dict) else None
        if not isinstance(key, str) or key not in keys:
            out.append({'setting': str(key)[:64] if key else '', 'status': 'refused', 'text': 'ignored: not a setting the AI may change'})
            continue
        m = keys[key]
        current = _effective(m, {}, applied_values())
        out.append({'setting': key, 'status': 'held', 'text': _ai_record_refused(m, current, raw, why, now_dt, resolution='held')})
    return out


def agent_change(user, values, who='an agent'):
    """AM-3. An agent's write to throughput settings (the keys ``managed`` lists) is not a saved value and not a pin: it is a decision of the engine,
    ``source='agent'``. What happens depends on the agent policy a person set (``off``, ``suggest``, ``auto``) and on the mode:

    * ``off`` (the policy), or auto-tuning off (the mode or the kill switch): refused, nothing is recorded;
    * ``suggest`` (the policy, or the mode): recorded as a recommendation a person applies with one click (``apply_decision``);
    * ``auto``: the number is clamped to the auto-tuning range and to what the controller itself would allow now (the target for this machine, the
      level that caused trouble in the last day, a scanner kind's memory budget), refused while trouble shows for the setting, while another calm
      change is unverified, after a revert's hold and inside the raise cooldown (a LOWER number is never held back by those), and applied through
      ``apply_tuned`` with ``verify=``: judged after 30 minutes and taken back if it made things worse.

    A pinned setting (a person's saved value, an environment pin) is refused: an agent never moves or removes a person's pin.
    ``values``: ``{key: whole number}`` for keys of ``managed()``. Returns ``{key: result}``, each ``{'setting', 'label', 'requested', 'status',
    'value', 'text'}`` (plus ``decision_id`` and ``clamped`` where they apply); ``status``: ``applied``, ``suggested``, ``refused`` or ``unchanged``."""
    _need_admin(user)
    row = settings_row()
    policy_name, mode, keys, now_dt = agent_policy(row), effective_mode(row), by_key(), _now()
    out = {}
    for key, raw in values.items():
        m = keys[key]
        if policy_name == 'off':
            out[key] = _agent_result(m, raw, 'refused', None, f'{m.label} was not changed: a person set the agent policy to Off, so agents may not change throughput settings.')
        elif mode == 'off':
            out[key] = _agent_result(m, raw, 'refused', None, f'{m.label} was not changed: auto-tuning is off'
                                     + (f' ({KILL_ENV}=0)' if killed() else '') + ', so a person changes this setting in Settings.')
    pending = {k: v for k, v in values.items() if k not in out}
    if pending:
        samples = recent_samples(now_dt)
        for key, raw in pending.items():
            out[key] = _agent_one(keys[key], raw, user, row, who, mode, policy_name, samples, now_dt)
            if out[key]['status'] == 'applied':
                row = settings_row()  # the tuned numbers changed: the next key reads them
    return out


# --- a kind that fails every time on a Sentinel is paused there for a while -------------------------------------------------------------

PAUSE_WINDOW_HOURS = 2     # the failures counted are those of this long
PAUSE_FAILURES = 3         # a Sentinel that failed a kind this many times and finished none in the window has the kind paused
PAUSE_HOURS = (2, 4, 6)    # the first pause, the second within a day, the third and later (``sentinel_policy.PAUSE_MAX_HOURS`` holds the last)


KIND_ALERT = 'kind_failing'


def _kind_alert(stuck):
    """One notice while a kind fails every time on a Sentinel and could not be paused because no other live Sentinel could take it (FC-3); resolved by the first round that finds none."""
    from cveFeed.models import AdminAlert
    now = _now()
    open_ = AdminAlert.objects.filter(code=KIND_ALERT, resolved_at__isnull=True).first()
    if not stuck:
        if open_ is not None:
            AdminAlert.objects.filter(pk=open_.pk).update(resolved_at=now)
        return
    detail = '; '.join(stuck[:5])
    title = 'A task kind fails every time on a Sentinel'
    if open_ is None:
        AdminAlert.objects.create(code=KIND_ALERT, severity='warning', title=title, detail=detail + '. Auto-tuning did not pause it, because that would leave the work nowhere to go. Look at that Sentinel, or bring another one online.')
    else:
        AdminAlert.objects.filter(pk=open_.pk).update(detail=detail + '. Auto-tuning did not pause it, because that would leave the work nowhere to go. Look at that Sentinel, or bring another one online.', last_seen=now)


def pause_failing_kinds(mode, now_dt):
    """The knob for ``Sentinel kind pause``: a task kind that failed ``PAUSE_FAILURES`` times on one Sentinel and finished none there in the last
    ``PAUSE_WINDOW_HOURS`` (counted from the end of that Sentinel's last pause of the kind, so a pause is never repeated on the failures that caused it) is paused
    on that Sentinel for 2 hours, 4 on the second pause within a day, then 6: ``sentinel_policy.pause`` records an expiry, so the pause always ends by itself, and
    refuses when two other kinds are paused already or when this is the last Sentinel that can run the kind. Only in mode Auto (in Suggest nothing is paused: a
    pause is not a number a person can apply with a click). Each pause is a ``TuningDecision`` (setting ``sentinel_pause:<kind>``, ``phase='pause'``, the new
    value is the hours) and an audit entry. It is not verified afterwards: it expires on its own, which is the bound. Returns the pauses made."""
    from agentapi import sentinel_policy
    from agentapi.models import Agent, SentinelTask
    if mode != 'auto':
        return []
    made, stuck = [], []
    for agent in Agent.objects.filter(kind='scanner', status='active'):
        stored = ((agent.managed_settings or {}).get('pauses') or {}).get('value') or {}
        active = sentinel_policy.active_pauses(agent, now_dt)
        for kind in SentinelTask.KINDS:
            if kind in active:
                continue
            ended = sentinel_policy._until(stored.get(kind) or {}) if isinstance(stored.get(kind), dict) else None
            since = max(now_dt - timedelta(hours=PAUSE_WINDOW_HOURS), ended) if ended else now_dt - timedelta(hours=PAUSE_WINDOW_HOURS)
            rows = SentinelTask.objects.filter(agent=agent, kind=kind, finished_at__gte=since, status__in=('done', 'failed'))
            if rows.filter(status='done').exists() or rows.filter(status='failed').count() < PAUSE_FAILURES:
                continue
            from cveFeed.models import TuningDecision
            earlier = TuningDecision.objects.filter(setting=f'sentinel_pause:{kind}', signals__agent_id=agent.pk, created_at__gte=now_dt - timedelta(days=1)).count()
            hours = PAUSE_HOURS[min(earlier, len(PAUSE_HOURS) - 1)]
            reason = f'{kind} failed {rows.filter(status="failed").count()} times in a row on {agent.name} and finished none'
            try:
                until = sentinel_policy.pause(agent, kind, hours, reason, by='auto-tuning', now=now_dt)
            except sentinel_policy.PauseRefused as exc:
                logger.info('auto-tune: %s not paused on %s: %s', kind, agent.name, exc)
                if 'last one' in str(exc):  # FC-3: no other live Sentinel can take the work: nothing is paused, and a person is told
                    stuck.append(f'{sentinel_policy.label(kind)} fails every time on {agent.name} and no other live Sentinel can take it')
                continue
            decision = _record(setting=f'sentinel_pause:{kind}', old_value=None, new_value=hours, mode=mode, source='controller', action='pause', layer='',
                               applied=True, pressure=True, phase='pause', reason=f'{reason}; paused until {until.isoformat(timespec="minutes")}',
                               signals={'sentinel': agent.name, 'agent_id': agent.pk, 'kind': kind, 'until': until.isoformat()})
            _audit(None, 'autotune.pause', f'{agent.name}:{kind}', hours=hours, until=until.isoformat(), reason=reason, decision_id=decision.pk)
            _activity(f'Auto-tuning paused {sentinel_policy.label(kind)} on {agent.name} for {hours} hours: {reason}', setting=decision.setting, decision_id=decision.pk)
            made.append({'sentinel': agent.name, 'kind': kind, 'hours': hours, 'until': until.isoformat(), 'id': decision.pk})
    _kind_alert(stuck)
    return made


def _watchdog_memory_pause(now):
    """When the watchdog's pause for memory pressure began (seconds since the epoch), or None when scanning is not paused by it for memory (a
    person's pause, an update's and a disk pause are not memory evidence)."""
    from cveFeed.models import ScanControl
    from cveFeed.watchdog import PAUSE_REASON
    row = ScanControl.objects.filter(pk=1, paused=True, paused_by_update=True).first()
    if row is None or not str(row.reason).startswith(PAUSE_REASON + 'memory'):
        return None
    return row.changed_at.timestamp() if row.changed_at else now


def back_off_for_pause(mode, row, samples, now_dt, boot_at, since, summary):
    """AM-8. The watchdog paused the starting of work because host memory is over 90 percent. Holding until it lets go (and ignoring every sample
    taken meanwhile) would start the same work again afterwards. Instead, once per pause, each setting that holds memory takes ONE back-off from the
    measurements before the pause (``autotune_policy.trouble`` with ``pause``): the level is remembered as trouble for a day like any back-off, so the
    probes do not bring it straight back. Returns the changes made."""
    from cveFeed import autotune_policy as policy
    now, rows, made = now_dt.timestamp(), _saved_rows(), []
    tuned = _clean_values(row.values) if mode == 'auto' else {}
    cooldown, probe_cooldown, _window = _cooldowns()
    for m in managed():
        if pin_of(m, rows) is not None:
            continue
        value = _effective(m, {}, tuned)
        if value == 0 and m.setting.kind in ('depth', 'refresh_gap'):
            continue
        past = _history(m.key, now_dt)
        if any(h['phase'] == 'back_off' and h['at'] >= since for h in past):
            continue  # already backed off in this pause
        plan = policy.decide(m.setting, value, _baseline(m), samples, past, now=now, boot_at=boot_at, target=m.setting.high, cooldown=cooldown,
                             probe_cooldown=probe_cooldown, pause='the watchdog paused the starting of work: host memory is over 90 percent')
        if plan['phase'] != 'back_off':
            continue
        used = {'summary': signals_summary(samples[-6:]), 'controller': plan['reason'], 'watchdog_memory_pause': True, 'alerts': open_alert_codes()}
        if mode == 'auto':
            decision = apply_tuned(m, value, plan['new'], mode=mode, source='controller', reason=plan['reason'], signals=used, pressure=True,
                                   phase='back_off', verify=_verification(m, value, plan['new'], samples, now_dt))
        else:
            decision = recommend(m, value, plan['new'], mode=mode, source='controller', reason=plan['reason'], signals=used, pressure=True,
                                 phase='back_off')
        if decision is not None:
            made.append({'setting': m.key, 'from': value, 'to': plan['new'], 'source': 'controller', 'applied': mode == 'auto', 'id': decision.pk})
    return made


# The open alerts a throughput change can answer (cveFeed.reviewer ``OPS_CODES``): a decision made while one of these is open carries its code in
# ``signals['alerts']``, which is how the alert strip links to the decision (``reviewer.open_alerts``) and the maintainer report names it.
ALERT_CODES = ('memory', 'queue_starvation', 'sentinel_waiting', 'sentinels_idle', 'scan_errors', 'workers_down')


def open_alert_codes():
    """The codes of the open admin alerts a change of these settings may answer, sorted; empty when none is open or the alerts cannot be read."""
    try:
        from cveFeed.models import AdminAlert
        return sorted(set(AdminAlert.objects.filter(resolved_at__isnull=True, code__in=ALERT_CODES).values_list('code', flat=True)))
    except Exception:  # noqa: BLE001 - the record is a convenience: a change is never held back for want of it
        return []


def signals_summary(samples):
    from cveFeed import autotune_signals as signals
    return signals.summarise(samples)


def run(now_dt=None):
    """One auto-tuning round (the ``autotune`` beat task, every ten minutes). Returns the round's summary, which ``status`` shows."""
    from cveFeed import autotune_policy as policy
    from cveFeed import autotune_signals as signals
    from cveFeed import ledger
    now_dt = now_dt or _now()
    now = now_dt.timestamp()
    if not ledger.sweep_claim('autotune', 300):
        return {'skipped': 'another round is running'}
    from django.db import InterfaceError, OperationalError
    try:
        row = settings_row()
    except (OperationalError, InterfaceError):
        return emergency_backoff(now)  # the database does not answer (out of connections, or down): back off from Redis alone
    try:
        purge(now_dt)
    except Exception:  # noqa: BLE001
        logger.debug('auto-tune: old decisions could not be purged', exc_info=False)
    mode = effective_mode(row)
    record_emergency(now_dt)
    row = settings_row()
    publish(row)
    summary = {'at': now_dt.isoformat(), 'mode': mode, 'killed': killed(), 'settings': {}, 'changes': [], 'advisor': None, 'held': None}
    if mode == 'off':
        summary['held'] = f'auto-tuning is off ({KILL_ENV}=0)' if killed() else 'auto-tuning is off'
        remember(summary)
        return summary
    boot = boot_marker(now)
    sample = signals.collect(now, boot['id'])
    cooldown, probe_cooldown, window = _cooldowns()
    kept = [s for s in store_sample(sample) if float(s.get('t', 0)) >= float(boot['at']) - 1]
    samples = [s for s in kept if not (s.get('paused') or s.get('updating'))]
    if sample.get('paused') or sample.get('updating'):
        summary['held'] = 'scanning is paused or an update is being applied: nothing changes'
        since = _watchdog_memory_pause(now) if samples and sample.get('paused') and not sample.get('updating') else None
        if since is not None:  # AM-8: the watchdog's memory pause is evidence, not a reason to look away
            summary['changes'] = back_off_for_pause(mode, row, samples, now_dt, float(boot['at']), since, summary)
            if summary['changes']:
                summary['held'] = 'the watchdog paused the starting of work for memory: backed off once, from the measurements before the pause'
        remember(summary)
        return summary
    in_window = [s for s in samples if s['t'] >= now - window]
    if mode == 'auto':
        summary['verified'] = verify_pending(now_dt, samples)
        row = settings_row()  # a revert just wrote the tuned numbers
        try:
            summary['paused_kinds'] = pause_failing_kinds(mode, now_dt)
        except Exception:  # noqa: BLE001 - a pause that could not be made never stops the round
            logger.warning('auto-tune: the failing-kind check could not run', exc_info=True)
    rows = _saved_rows()
    tuned = _clean_values(row.values) if mode == 'auto' else {}
    facts = policy.steady_facts(samples) if samples else {}  # a Sentinel that missed one heartbeat still counts for sizing
    summary['facts'] = {k: facts.get(k) for k in ('cores', 'memory_budget_mb', 'memory_total_mb', 'db_max', 'sentinel_live', 'sentinel_slots',
                                                  'hosts', 'targets', 'disk_free_percent')}
    summary['sized_for'] = policy.sized_for_text(facts)
    plans, offered = {}, {}
    ready = policy.facts_ready(facts)
    for m in managed():
        info = {'label': m.label}
        pin = pin_of(m, rows)
        if pin is not None:
            by, where = pin
            info.update(state='pinned', pinned_by=by, pinned_from=where, value=_effective(m, rows[m.registry][0], tuned),
                        why_not_raised=f'pinned by {by}')
            summary['settings'][m.key] = info
            continue
        baseline = _baseline(m)
        value = _effective(m, {}, tuned)
        if value == 0 and m.setting.kind in ('depth', 'refresh_gap'):
            info.update(state='off', value=value, why_not_raised='turned off (0) by its environment value')
            summary['settings'][m.key] = info
            continue
        target, target_reason, target_known = policy.size_for(m.setting, facts, current=value)
        hard_cap = policy.memory_cap(m.setting.kind.split(':', 1)[1], samples[-1]) if m.setting.kind.startswith('heavy:') and samples else None
        plan = policy.decide(m.setting, value, baseline, samples, _history(m.key, now_dt), now=now, boot_at=float(boot['at']),
                             target=target, target_reason=target_reason, cooldown=cooldown, probe_cooldown=probe_cooldown,
                             hold_until=_hold_until(row, m.key), hard_cap=hard_cap, target_known=target_known, ready=ready)
        plans[m.key] = (m, value, baseline, plan)
        info.update(state='managed', value=value, starting_value=baseline, target=target, target_reason=target_reason, ceiling=plan['ceiling'],
                    why_not_raised=plan['why_not_raised'] if plan['direction'] != 'more' else '', controller=plan['reason'])
        summary['settings'][m.key] = info
        if plan['ai_range'] and plan['ai_range'][0] != plan['ai_range'][1]:  # the advisor is asked only about a setting the controller lets move
            offered[m.key] = {'setting': m.setting, 'value': value, 'baseline': baseline, 'range': plan['ai_range'], 'target': plan['ceiling'],
                              'controller': plan['reason'] or 'hold'}
    advice = {}
    state = advisor_state(row)
    reply = take_advice(now) if offered else None
    if reply is not None:  # the answer to the question an earlier round queued
        from reNgine.ai_providers import clean_text
        accepted, refused, error = policy.validate_advice(reply, offered, clean=clean_text)
        advice = accepted
        _set_record({'at': state.get('last_at') or now, 'error': error or None})
        summary['advisor'] = {'answered': True, 'accepted': len(accepted), 'refused': [f'{k}: {why}' for k, why in refused][:20],
                              'error': error or None}
    elif offered and _advisor_due(state, now):
        error = ask_advisor(offered, signals.summarise(in_window), now)
        summary['advisor'] = {'asked': True, 'queued': not error, 'error': error or None}
    compact = signals.summarise(in_window[-6:])
    gate_closed = mode == 'auto' and calm_change_unverified()
    for key, (m, value, baseline, plan) in plans.items():
        source, new, reason, pressured, phase = 'controller', plan['new'], plan['reason'], plan['pressure'], plan['phase']
        if not pressured and key in advice:
            source, new, reason = 'ai', advice[key]['value'], advice[key]['reason']
            phase = phase if new == plan['new'] else ''
            if new == value:
                summary['settings'][key]['advisor'] = f'held: {reason}'
                continue
        if new is None or new == value:
            if mode == 'suggest':
                _retire_suggestions(key, now_dt)
            continue
        signals_used = {'summary': compact, 'controller': plan['reason'], 'alerts': open_alert_codes()}
        if mode == 'auto' and gate_closed and policy.is_calm(phase, pressured):
            summary['settings'][key]['why_not_raised'] = 'waiting: an earlier change is still being verified (one calm change at a time)'
            continue
        if mode == 'auto':
            decision = apply_tuned(m, value, new, mode=mode, source=source, reason=reason, signals=signals_used, pressure=pressured, phase=phase,
                                   verify=_verification(m, value, new, samples, now_dt))
        else:
            decision = recommend(m, value, new, mode=mode, source=source, reason=reason, signals=signals_used, pressure=pressured, phase=phase)
        if decision is None and mode == 'auto':
            summary['settings'][key]['why_not_raised'] = 'not applied: the mode changed or the setting was pinned during this run'
        if decision is not None:
            gate_closed = gate_closed or (mode == 'auto' and policy.blocks_calm(phase, pressured))
            summary['changes'].append({'setting': key, 'from': value, 'to': new, 'source': source, 'applied': mode == 'auto', 'id': decision.pk})
            summary['settings'][key]['value'] = new if mode == 'auto' else value
    remember(summary)
    return summary


EMERGENCY_KEY = 'cvengine:autotune:emergency'
DB_DOWN_KEY = 'cvengine:autotune:db-down'
EMERGENCY_KEYS = ('discovery_concurrency', 'work_depth')  # the settings whose tasks each hold a database connection
DB_DOWN_RUNS_APART = 25 * 60  # two failed runs (every ten minutes) no further apart than this are "in a row"


def _json_get(client, key, empty):
    try:
        value = json.loads(client.get(key) or 'null')
    except Exception:  # noqa: BLE001
        return empty
    return value if isinstance(value, type(empty)) else empty


def pending_emergency(client=None):
    """{key: new number} of the emergency back-offs not recorded in the database yet (``EMERGENCY_KEY``). Never raises."""
    try:
        client = client or _redis()
        if client is None:
            return {}
        values = _json_get(client, EMERGENCY_KEY, {}).get('values') or {}
        return {k: v[1] for k, v in values.items() if isinstance(v, list) and len(v) == 2 and isinstance(v[1], int)}
    except Exception:  # noqa: BLE001
        return {}


def emergency_backoff(now):
    """The fallback when the database does not answer (out of connections, or down): nothing can be read or written there, so this works from
    Redis alone, and only when the database failed this run AND the one before (``DB_DOWN_KEY``; a plain Postgres restart of a few seconds is not
    an emergency). Then the discovery pool and the conductor (whose tasks each hold a database connection) take ONE back-off step
    (``autotune_policy.backoff``) and hold for ``BACKOFF_HOLD`` before another, like any back-off.

    The source of truth while the database is away is ``EMERGENCY_KEY`` in Redis: ``{'values': {key: [number before the emergency, number
    now]}, 'at': time of the last step}``. Every reader of the tuned numbers honours it: ``applied_values`` (the database row, so the 30 second
    tick's publish and ``scan_concurrency.apply_discovery``'s resize, and a starting container) lowers a pending key to its emergency number, and
    the published Redis copy carries it too. The discovery workers are resized directly with celery's ``autoscale``. The first run that reaches the
    database again writes the numbers into the row and the history (phase ``emergency``, ``record_emergency``) and clears the key. A setting
    that is pinned, or not tuned, is not touched (``_tuned_applies``: the pins as the workers see them without the database, so the discovery
    workers are never resized below a number a person saved or the environment pins); nothing happens in Off or Suggest, or with the kill
    switch."""
    from cveFeed import autotune_policy as policy
    summary = {'at': datetime.fromtimestamp(now, dt_timezone.utc).isoformat(), 'mode': None, 'settings': {}, 'changes': [], 'advisor': None,
               'held': 'the database does not answer: emergency back-off from Redis only'}
    client = _redis()
    if client is None or killed():
        summary['held'] = 'the database does not answer, and there is no Redis copy to back off from'
        remember(summary)
        return summary
    down = _json_get(client, DB_DOWN_KEY, {})
    in_a_row = bool(down) and now - float(down.get('last', 0)) <= DB_DOWN_RUNS_APART
    client.set(DB_DOWN_KEY, json.dumps({'first': down.get('first', now) if in_a_row else now, 'last': now}), ex=86400)
    if not in_a_row:
        summary['held'] = 'the database did not answer; an emergency back-off follows if it still does not at the next run'
        remember(summary)
        return summary
    pending = _json_get(client, EMERGENCY_KEY, {})
    if pending.get('at') and now - float(pending['at']) < policy.BACKOFF_HOLD:
        summary['held'] = (f'the database does not answer; emergency back-off {int((now - float(pending["at"])) // 60)} min ago, holding '
                           f'{policy.BACKOFF_HOLD // 60} min')
        remember(summary)
        return summary
    copy = _json_get(client, VALUES_KEY, {})
    summary['mode'] = copy.get('mode')
    values = dict(copy.get('values') or {})
    if copy.get('mode') != 'auto':
        remember(summary)
        return summary
    keys, changed = by_key(), {}
    saved = resources.saved_values()
    for key in EMERGENCY_KEYS:
        if isinstance(values.get(key), int) and key in keys:
            if not _tuned_applies(keys[key], saved, values[key]):
                summary['settings'][key] = {'label': keys[key].label, 'state': 'pinned',
                                            'why_not_raised': 'pinned: the emergency back-off leaves it alone'}
                continue
            new = policy.backoff(keys[key].setting, values[key])
            if new < values[key]:
                changed[key] = [values[key], new]
                values[key] = new
    if changed:
        version = max(float(copy.get('v') or 0), time.time()) + 1  # newer than the row, so an old copy never replaces this one
        recorded = dict(pending.get('values') or {})
        for key, (old, new) in changed.items():
            recorded[key] = [(recorded.get(key) or [old])[0], new]
        client.set(EMERGENCY_KEY, json.dumps({'values': recorded, 'at': now}), ex=7 * 86400)
        client.set(VALUES_KEY, json.dumps({**copy, 'values': values, 't': time.time(), 'v': version, 'emergency': True}))
        resources.invalidate_auto()
        if 'discovery_concurrency' in changed:
            _resize_discovery_directly(changed['discovery_concurrency'][1])
        summary['changes'] = [{'setting': k, 'from': o, 'to': n, 'source': 'controller', 'applied': True, 'emergency': True}
                              for k, (o, n) in changed.items()]
    remember(summary)
    return summary


def _tuned_applies(m, saved, number):
    """Whether the tuned ``number`` is what applies for a setting, judged without the database: not when a person saved a value for it (the
    published copy of the saved values, ``saved``, which the workers read too) or the environment pins it (``env_pin``)."""
    return _registry(m.registry).resolve(m.key, saved, {m.key: number})['source'] == 'auto'


def _resize_discovery_directly(ceiling):
    """Resize every discovery worker that answers, without the database (``scan_concurrency.apply_discovery`` reads it)."""
    try:
        from cveFeed import scan_concurrency
        from reNgine.celery import app
        names = list(scan_concurrency.discovery_workers(app))
        if names:
            app.control.broadcast('autoscale', arguments={'max': ceiling}, destination=names, reply=False)
    except Exception:  # noqa: BLE001
        logger.warning('auto-tune: the discovery workers could not be resized during the emergency back-off')


def record_emergency(now_dt):
    """The database answers: forget the failed run (``DB_DOWN_KEY``) and write what ``emergency_backoff`` did into the tuned numbers and the
    history (phase ``emergency``, not counted as trouble at that level, so the policy may restore it quickly: ``autotune_policy.decide``). A
    number is only ever lowered here; a setting whose number is already at or below it (a person changed the mode meanwhile, or it was pinned)
    is left alone. Never raises."""
    client = _redis()
    if client is None:
        return
    try:
        client.delete(DB_DOWN_KEY)
        pending = _json_get(client, EMERGENCY_KEY, {}).get('values') or {}
    except Exception:  # noqa: BLE001
        return
    if not pending:
        return
    keys = by_key()
    for key, pair in pending.items():
        m = keys.get(key)
        if m is None or not isinstance(pair, list) or len(pair) != 2:
            continue
        old, new = pair
        try:
            apply_tuned(m, old, new, mode='auto', source='controller', pressure=False, phase='emergency', signals={'emergency': True},
                        reason='the database did not answer (out of connections or down) in two runs in a row: emergency back-off from Redis',
                        only_lower=True)
        except Exception:  # noqa: BLE001
            logger.warning('auto-tune: the emergency back-off of %s could not be recorded', key)
    client.delete(EMERGENCY_KEY)


# --- what the page, the API and the system status show ---------------------------------------------------------------------

def serialize(d):
    marks = d.signals if isinstance(d.signals, dict) else {}
    return {'id': d.pk, 'at': _iso(d.created_at), 'setting': d.setting, 'label': getattr(by_key().get(d.setting), 'label', None) or (f"{(d.signals or {}).get('kind')} on {(d.signals or {}).get('sentinel')}" if d.action == 'pause' else d.setting),
            'old_value': d.old_value, 'new_value': d.new_value, 'mode': d.mode, 'source': d.source, 'action': d.action, 'layer': d.layer,
            'applied': d.applied, 'pressure': d.pressure, 'phase': d.phase or None, 'reason': d.reason, 'actor': d.actor.username if d.actor_id else None,
            'resolution': d.resolution or None, 'resolved_at': _iso(d.resolved_at), 'resolved_by': d.resolved_by or None,
            'expected': d.expected or None, 'baseline': d.baseline or None, 'verify_at': _iso(d.verify_at), 'verified_at': _iso(d.verified_at),
            'outcome': d.outcome or None, 'outcome_detail': d.outcome_detail or None,
            'alerts': [c for c in (marks.get('alerts') if isinstance(marks.get('alerts'), list) else []) if isinstance(c, str)][:10],
            'undoes': marks.get('verified_decision') if isinstance(marks.get('verified_decision'), int) else None}


OUTCOMES = ('helped', 'no_effect', 'regressed', 'unknown', 'reverted', 'pending')  # ``pending``: applied, to be judged, not judged yet


def list_decisions(setting=None, limit=50, offset=0, outcome=None, source=None):
    """Decisions newest first. ``outcome``: one of ``OUTCOMES`` (``pending`` is a change still waiting to be judged); ``source``: who made them
    (controller, ai, person, agent). A value that is not an outcome is a ``TuningError`` (400), never an empty list."""
    from cveFeed.models import TuningDecision
    qs = TuningDecision.objects.select_related('actor').order_by('-created_at', '-pk')
    if setting:
        qs = qs.filter(setting=str(setting)[:64])
    if outcome:
        if outcome not in OUTCOMES:
            raise TuningError(400, f'outcome must be one of {", ".join(OUTCOMES)}')
        qs = qs.filter(applied=True, outcome='', verify_at__isnull=False) if outcome == 'pending' else qs.filter(outcome=outcome)
    if source:
        qs = qs.filter(source=str(source)[:12])
    limit = max(1, min(200, int(limit)))
    offset = max(0, int(offset))
    rows = list(qs[offset:offset + limit + 1])
    latest = {}
    out = []
    for d in rows[:limit]:
        item = serialize(d)
        if d.applied and d.resolution != 'reverted' and d.action not in ('revert', 'release', 'pause'):
            if d.setting not in latest:
                newest = _latest_applied(d.setting)
                latest[d.setting] = newest.pk if newest else None
            item['can_revert'] = latest[d.setting] == d.pk
        else:
            item['can_revert'] = False
        item['can_apply'] = not d.applied and not d.resolution and d.action in ('raise', 'lower')
        out.append(item)
    return {'results': out, 'has_more': len(rows) > limit}


def discovery_pin():
    """The one pin that costs a whole instance its throughput, or None. On 1.4 a host assessment holds a discovery slot while it waits for a
    Sentinel, so ``DISCOVERY_CONCURRENCY`` below ``DISCOVERY_PIN_BELOW`` in the environment (a leftover from 1.3, when that pool only ran discovery)
    lets one host be assessed at a time while the Sentinels idle, and it pins the value: the tuner may not move it. Returns ``{'value', 'env',
    'text'}`` for the page, the status and the Settings screen, or None when the number is not set by the environment or is not low."""
    for m in managed():
        if m.key != 'discovery_concurrency':
            continue
        pin = pin_of(m, _saved_rows())
        if pin is None or pin[1] != 'environment':
            return None
        value = _effective(m, _saved_rows()[m.registry][0], {})
        if value >= DISCOVERY_PIN_BELOW:
            return None
        env = f'{m.env_name}={value}'
        return {'value': value, 'env': env,
                'text': f'Hosts assessed at once is held at {value} by {env} in the environment (.env), so only {value} host{"" if value == 1 else "s"} '
                        f'{"is" if value == 1 else "are"} assessed at a time and the tuner may not raise it. Remove the line, or set it to {DISCOVERY_PIN_BELOW} or more, '
                        'then restart the stack.'}
    return None


def status():
    """Everything the page, the API, MCP and the system status say about auto-tuning."""
    row = settings_row()
    mode = effective_mode(row)
    last = last_run() or {}
    from cveFeed.models import TuningDecision
    recent = [serialize(d) for d in TuningDecision.objects.select_related('actor').order_by('-created_at', '-pk')[:10]]
    pinned = []
    rows = _saved_rows()
    for m in managed():
        pin = pin_of(m, rows)
        if pin is not None:
            pinned.append({'setting': m.key, 'label': m.label, 'value': _effective(m, rows[m.registry][0], {}), 'by': pin[0], 'from': pin[1]})
    return {
        'mode': row.mode, 'effective_mode': mode, 'killed': killed(), 'kill_switch': KILL_ENV, 'advisor': advisor_state(row),
        'agent_policy': agent_policy(row),
        'changed_by': row.changed_by.username if row.changed_by_id else None, 'changed_at': _iso(row.changed_at),
        'tuned': applied_values(row), 'pinned': pinned, 'discovery_pin': discovery_pin(),
        'managed': [{'setting': m.key, 'label': m.label, 'min': m.setting.low, 'max': m.setting.high, 'step': m.setting.step,
                     'higher_means': 'more work at once' if m.setting.sense == 'more' else 'a longer wait between runs'} for m in managed()],
        'last_run': last or None, 'sized_for': last.get('sized_for'), 'facts': last.get('facts'), 'recent_decisions': recent,
        'run_every_minutes': 10, 'retention_days': RETENTION_DAYS,
    }


def annotate(fields):
    """Add ``autotune`` to each field of a configMaxxing card (pinned, tuned and from what, an open recommendation, why it was not raised) and
    return the mode in one small dictionary."""
    from cveFeed.models import TuningDecision
    row = settings_row()
    mode = effective_mode(row)
    keys = by_key()
    run = last_run() or {}
    last = run.get('settings') or {}
    wanted = [f['key'] for f in fields if f['key'] in keys]
    newest, suggestion = {}, {}
    for d in TuningDecision.objects.filter(setting__in=wanted).order_by('-created_at', '-pk')[:500]:
        if d.applied and d.action != 'release' and d.setting not in newest and d.resolution != 'reverted':
            newest[d.setting] = d
        if not d.applied and not d.resolution and d.setting not in suggestion:
            suggestion[d.setting] = d
    for f in fields:
        m = keys.get(f['key'])
        if m is None:
            f['autotune'] = {'managed': False}
            floor = _scan().LANE_FLOORS.get(f['key'])
            if floor is not None:  # FC-1: say why a worker lane is left alone
                f['autotune']['why_not_managed'] = (f'this lane is set to {f.get("value")}, which is at or below its floor of {floor}: it also runs tasks that must not be starved '
                                                    'by one long task, so auto-tuning never lowers it')
            continue
        env_pinned = f.get('source') == 'environment' and _registry(m.registry).env_pin(_registry(m.registry).BY_KEY[m.key])
        item = {'managed': True, 'pinned': f.get('source') == 'admin' or env_pinned,
                'pinned_by': f.get('set_by') if f.get('source') == 'admin' else None,
                'pinned_env': f'{f.get("env_name")}={_number_text(f.get("env_value"))}' if env_pinned else None,
                'tuned': f.get('source') == 'auto', 'min': m.setting.low, 'max': m.setting.high, 'step': m.setting.step,
                'why_not_raised': (last.get(f['key']) or {}).get('why_not_raised') or None,
                'target': (last.get(f['key']) or {}).get('target'), 'target_reason': (last.get(f['key']) or {}).get('target_reason'),
                'sized_for': run.get('sized_for')}
        d = newest.get(f['key'])
        if d is not None and item['tuned']:
            item.update(was=d.old_value, reason=d.reason, at=_iso(d.created_at), decision_id=d.pk, source=d.source)
        s = suggestion.get(f['key'])
        if s is not None:
            item['suggestion'] = {'id': s.pk, 'value': s.new_value, 'from': s.old_value, 'reason': s.reason, 'at': _iso(s.created_at), 'source': s.source}
        f['autotune'] = item
    return {'mode': row.mode, 'effective_mode': mode, 'killed': killed(), 'sized_for': run.get('sized_for')}
