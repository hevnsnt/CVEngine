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
"""
import json
import logging
import os
import socket
import time
from collections import namedtuple
from datetime import datetime, timedelta, timezone as dt_timezone

from reNgine import resources

logger = logging.getLogger(__name__)

MODES = ('off', 'suggest', 'auto')
DEFAULT_MODE = 'auto'
KILL_ENV = 'CVENGINE_AUTOTUNE'
VALUES_KEY = resources.AUTO_VALUES_KEY
LAST_RUN_KEY = 'cvengine:autotune:last'
SAMPLES_KEY = 'cvengine:autotune:samples'
BOOT_KEY = 'cvengine:autotune:boot'
ADVISOR_KEY = 'cvengine:autotune:advisor'
SAMPLES_KEPT = 300              # fifty hours of ten-minute measurements
RETENTION_DAYS = 90
REVERT_HOLD_HOURS = 24          # after a person reverts a change, the tuner does not raise that setting for this long
ADVISOR_STAGE = 'autotune_advisor'
ADVISOR_SEED = 20261101
ADVISOR_SYSTEM = (
    'You advise the auto-tuner of a vulnerability scanner. Its policy is to aim high first: run as much as this machine sensibly carries, then '
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
            what = {'discovery_concurrency': 'discovery', 'assess_batch': 'batch', 'work_depth': 'depth'}[f.key]
        optimistic = max(low, min(high, f.auto_optimistic))
        out.append(Managed(f.key, 'scan_concurrency', f.label, Setting(f.key, what, f.label, low, high, f.auto_step, 'more', optimistic), f.env))
    kinds = {'stage_parallel': 'stage', 'work_min_gap_hours': 'work_gap', 'sentinel_refresh_gap_hours': 'refresh_gap'}
    for t in tunables.TUNABLES:
        if t.auto_tunable:
            out.append(Managed(t.key, 'tunables', t.label, Setting(t.key, kinds[t.key], t.label, t.auto_min, t.auto_max, t.auto_step, t.auto_sense,
                                                                    t.auto_optimistic), t.env))
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


def effective_mode(row=None):
    if killed():
        return 'off'
    row = row or settings_row()
    return row.mode if row.mode in MODES else DEFAULT_MODE


def _clean_values(values):
    keys = by_key()
    return {k: v for k, v in (values or {}).items() if k in keys and isinstance(v, int) and not isinstance(v, bool)}


def applied_values(row=None):
    """The tuned numbers that apply now, from the database: the row's numbers in mode Auto, none otherwise."""
    row = row or settings_row()
    return _clean_values(row.values) if effective_mode(row) == 'auto' else {}


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
    """A tuned or released discovery pool is resized live, like a save."""
    if 'discovery_concurrency' in keys:
        from cveFeed import scan_concurrency
        scan_concurrency.request_apply()


# --- applying, recommending, reverting ---------------------------------------------------------------------------------------

def _record(**fields):
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.create(**fields)


def apply_tuned(m, old, new, *, mode, source, reason, signals, pressure=False, actor=None, action=None, phase=''):
    """Set a tuned number (mode Auto) and record it. Returns the decision, or None when, checked again under the row's lock, the mode is no
    longer Auto (a person chose Off or Suggest while this run was working, or the kill switch is set) or the setting was pinned meanwhile:
    nothing is written then."""
    from django.db import transaction

    from cveFeed.models import AutoTuneSettings
    with transaction.atomic():
        row = AutoTuneSettings.objects.select_for_update().get(pk=settings_row().pk)
        if effective_mode(row) != 'auto' or pin_of(m, _saved_rows()) is not None:
            return None
        values = dict(row.values or {})
        before = values.get(m.key)
        values[m.key] = new
        row.values = values
        row.save()
        decision = _record(setting=m.key, old_value=old, new_value=new, mode=mode, source=source,
                           action=action or ('raise' if new > old else 'lower'),
                           layer='auto', old_layer_value=before, applied=True, pressure=pressure, phase=phase, reason=reason[:300], signals=signals,
                           actor=actor)
    publish(row)
    who = {'controller': 'Auto-tuning', 'ai': 'Auto-tuning (AI advisor)'}.get(source, f'{getattr(actor, "username", "A person")}')
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


def set_mode(user, mode=None, advisor=None):
    """App Admin only: the instance's mode (off, suggest, auto) and whether the AI advisor may be asked. Leaving Auto drops the tuned numbers at
    once (every setting goes back to its saved value, environment or default); coming back starts from there."""
    from django.db import transaction

    from cveFeed.models import AutoTuneSettings
    _need_admin(user)
    if mode is None and advisor is None:
        raise TuningError(400, 'send mode (off, suggest or auto) and/or advisor (true or false)')
    if mode is not None and mode not in MODES:
        raise TuningError(400, f'mode must be one of {", ".join(MODES)}')
    if advisor is not None and not isinstance(advisor, bool):
        raise TuningError(400, 'advisor must be true or false')
    with transaction.atomic():
        row = AutoTuneSettings.objects.select_for_update().get(pk=settings_row().pk)
        before = {'mode': row.mode, 'advisor': row.advisor}
        dropped = []
        if mode is not None and mode != row.mode:
            if row.mode == 'auto':
                dropped = sorted(row.values or {})
                row.values, row.meta = {}, {}
            row.mode = mode
        if advisor is not None:
            row.advisor = advisor
        row.changed_by, row.changed_at = user, _now()
        row.save()
    publish(row)
    after = {'mode': row.mode, 'advisor': row.advisor}
    if after != before:
        _audit(user, 'autotune.mode', 'auto-tuning', before=before, after=after, dropped=dropped)
        _activity(f'{user.username} set auto-tuning to {row.mode}' + (' with the AI advisor' if row.advisor else ' without the AI advisor')
                  + (f'; {len(dropped)} tuned setting(s) went back to their saved, environment or default values' if dropped else ''))
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


def ask_advisor(offered, summary, now):
    """One question to the AI advisor: the window's numbers and the settings it may advise on, no host, no finding, no free text from a scanned
    host. Returns (accepted, refused, error) from ``autotune_policy.validate_advice``."""
    from cveFeed import autotune_policy as policy
    from reNgine.ai_providers import clean_text, request_options, usage_stage
    from reNgine.ai_settings import get_configured_provider
    client = _redis()
    record = {'at': now, 'error': None}
    try:
        provider = get_configured_provider()
        if provider is None:
            record['error'] = 'no AI provider'
            return {}, [], record['error']
        public = {key: {'value': o['value'], 'starting_value': o['baseline'], 'target_for_this_machine': o['target'],
                        'you_may_choose_from': o['range'][0], 'you_may_choose_to': o['range'][1], 'step': o['setting'].step,
                        'higher_number_means': 'more work at once' if o['setting'].sense == 'more' else 'a longer wait between runs',
                        'controller': o['controller']} for key, o in offered.items()}
        payload = json.dumps({'settings': public, 'measurements': summary}, sort_keys=True, separators=(',', ':'), default=str)
        with usage_stage(ADVISOR_STAGE), request_options(temperature=0, seed=ADVISOR_SEED, schema=policy.ADVICE_SCHEMA, max_tokens=2000):
            reply = provider.complete(ADVISOR_SYSTEM, payload)
        accepted, refused, error = policy.validate_advice(reply, offered, clean=clean_text)
        record['error'] = error or None
        return accepted, refused, error
    except Exception as exc:  # noqa: BLE001 - the controller tunes alone when the advisor cannot answer
        record['error'] = str(getattr(exc, 'category', '') or type(exc).__name__)[:60]
        return {}, [], record['error']
    finally:
        try:
            if client is not None:
                client.set(ADVISOR_KEY, json.dumps(record), ex=7 * 86400)
        except Exception:  # noqa: BLE001
            pass


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
    if sample.get('paused') or sample.get('updating'):
        summary['held'] = 'scanning is paused or an update is being applied: nothing changes'
        remember(summary)
        return summary
    samples = [s for s in kept if not (s.get('paused') or s.get('updating'))]
    in_window = [s for s in samples if s['t'] >= now - window]
    rows = _saved_rows()
    tuned = _clean_values(row.values) if mode == 'auto' else {}
    facts = policy.facts_of(samples[-1]) if samples else {}
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
    if offered and _advisor_due(state, now):
        accepted, refused, error = ask_advisor(offered, signals.summarise(in_window), now)
        advice = accepted
        summary['advisor'] = {'asked': True, 'accepted': len(accepted), 'refused': [f'{k}: {why}' for k, why in refused][:20], 'error': error or None}
    compact = signals.summarise(in_window[-6:])
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
        signals_used = {'summary': compact, 'controller': plan['reason']}
        if mode == 'auto':
            decision = apply_tuned(m, value, new, mode=mode, source=source, reason=reason, signals=signals_used, pressure=pressured, phase=phase)
        else:
            decision = recommend(m, value, new, mode=mode, source=source, reason=reason, signals=signals_used, pressure=pressured, phase=phase)
        if decision is None and mode == 'auto':
            summary['settings'][key]['why_not_raised'] = 'not applied: the mode changed or the setting was pinned during this run'
        if decision is not None:
            summary['changes'].append({'setting': key, 'from': value, 'to': new, 'source': source, 'applied': mode == 'auto', 'id': decision.pk})
            summary['settings'][key]['value'] = new if mode == 'auto' else value
    remember(summary)
    return summary


EMERGENCY_KEY = 'cvengine:autotune:emergency'
EMERGENCY_KEYS = ('discovery_concurrency', 'work_depth')  # the settings whose tasks each hold a database connection


def emergency_backoff(now):
    """The fallback path when the database does not answer (out of connections, or down): nothing can be read or recorded there, so this works
    from Redis alone. The published tuned numbers of the discovery pool and the conductor (the settings whose tasks hold a database
    connection each) are backed off (``autotune_policy.backoff``) and published again with a newer version, so the 30 second tick cannot put
    the old numbers back while the database is away; the discovery workers are resized directly with celery's ``autoscale`` remote control; and
    the change is kept in Redis (``EMERGENCY_KEY``) to be recorded as a back-off in the history by the first run that reaches the database
    again (``record_emergency``). A setting that is pinned, or not tuned, is not touched; nothing happens in Off or Suggest, or with the kill
    switch, as the published copy says."""
    from cveFeed import autotune_policy as policy
    summary = {'at': datetime.fromtimestamp(now, dt_timezone.utc).isoformat(), 'mode': None, 'settings': {}, 'changes': [], 'advisor': None,
               'held': 'the database does not answer: emergency back-off from Redis only'}
    client = _redis()
    if client is None or killed():
        summary['held'] = 'the database does not answer, and there is no Redis copy to back off from'
        remember(summary)
        return summary
    try:
        copy = json.loads(client.get(VALUES_KEY) or '{}')
    except ValueError:
        copy = {}
    summary['mode'] = copy.get('mode')
    values = dict(copy.get('values') or {})
    if copy.get('mode') != 'auto':
        remember(summary)
        return summary
    keys, changed = by_key(), {}
    for key in EMERGENCY_KEYS:
        if isinstance(values.get(key), int) and key in keys:
            new = policy.backoff(keys[key].setting, values[key])
            if new < values[key]:
                changed[key] = [values[key], new]
                values[key] = new
    if changed:
        version = float(copy.get('v') or 0) + 1  # newer than the database row, so the tick's publish of the old row is skipped
        client.set(VALUES_KEY, json.dumps({**copy, 'values': values, 't': time.time(), 'v': version, 'emergency': True}))
        resources.invalidate_auto()
        try:
            pending = json.loads(client.get(EMERGENCY_KEY) or '{}')
        except ValueError:
            pending = {}
        for key, (old, new) in changed.items():
            pending[key] = [pending.get(key, [old])[0], new]
        client.set(EMERGENCY_KEY, json.dumps(pending), ex=7 * 86400)
        if 'discovery_concurrency' in changed:
            _resize_discovery_directly(changed['discovery_concurrency'][1])
        summary['changes'] = [{'setting': k, 'from': o, 'to': n, 'source': 'controller', 'applied': True, 'emergency': True}
                              for k, (o, n) in changed.items()]
    remember(summary)
    return summary


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
    """Record what ``emergency_backoff`` did while the database was away, as back-offs in the history (and in the tuned numbers), once it
    answers again. Never raises."""
    client = _redis()
    try:
        pending = json.loads(client.get(EMERGENCY_KEY) or '{}') if client is not None else {}
    except Exception:  # noqa: BLE001
        return
    if not pending:
        return
    keys = by_key()
    for key, (old, new) in pending.items():
        m = keys.get(key)
        if m is None:
            continue
        try:
            apply_tuned(m, old, new, mode='auto', source='controller', pressure=True, phase='back_off', signals={},
                        reason='the database did not answer (out of connections or down): emergency back-off from Redis')
        except Exception:  # noqa: BLE001
            logger.warning('auto-tune: the emergency back-off of %s could not be recorded', key)
    client.delete(EMERGENCY_KEY)


# --- what the page, the API and the system status show ---------------------------------------------------------------------

def serialize(d):
    return {'id': d.pk, 'at': _iso(d.created_at), 'setting': d.setting, 'label': getattr(by_key().get(d.setting), 'label', d.setting),
            'old_value': d.old_value, 'new_value': d.new_value, 'mode': d.mode, 'source': d.source, 'action': d.action, 'layer': d.layer,
            'applied': d.applied, 'pressure': d.pressure, 'phase': d.phase or None, 'reason': d.reason, 'actor': d.actor.username if d.actor_id else None,
            'resolution': d.resolution or None, 'resolved_at': _iso(d.resolved_at), 'resolved_by': d.resolved_by or None}


def list_decisions(setting=None, limit=50, offset=0):
    from cveFeed.models import TuningDecision
    qs = TuningDecision.objects.select_related('actor').order_by('-created_at', '-pk')
    if setting:
        qs = qs.filter(setting=str(setting)[:64])
    limit = max(1, min(200, int(limit)))
    offset = max(0, int(offset))
    rows = list(qs[offset:offset + limit + 1])
    latest = {}
    out = []
    for d in rows[:limit]:
        item = serialize(d)
        if d.applied and d.resolution != 'reverted' and d.action not in ('revert', 'release'):
            if d.setting not in latest:
                newest = _latest_applied(d.setting)
                latest[d.setting] = newest.pk if newest else None
            item['can_revert'] = latest[d.setting] == d.pk
        else:
            item['can_revert'] = False
        item['can_apply'] = not d.applied and not d.resolution and d.action in ('raise', 'lower')
        out.append(item)
    return {'results': out, 'has_more': len(rows) > limit}


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
        'changed_by': row.changed_by.username if row.changed_by_id else None, 'changed_at': _iso(row.changed_at),
        'tuned': applied_values(row), 'pinned': pinned,
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
