"""The AI money budget: a monthly and an optional daily limit in US dollars that stops paid AI work when it is spent.

Spend is the AI usage ledger (``AIUsage``, one row per provider call the reviewer container made, whatever its outcome) priced at the rates
entered on the AI usage page (``AIPriceRate``), with cache reads and cache writes included. A model with no rate is counted at the most
expensive rate entered for any model, and with no rate entered at all at ``CEILING``, so an unpriced model can only stop the work early, never
late. Self-hosted servers (Ollama, vLLM, LM Studio) bill nobody and are not counted.

The limits come from Settings > AI model (``AIProviderSettings.monthly_budget_usd`` and ``daily_budget_usd``), else from the environment
(``CVENGINE_AI_MONTHLY_BUDGET_USD``, ``CVENGINE_AI_DAILY_BUDGET_USD``), else there is none. The page wins over the environment, like the other
layered AI settings. The month and the day are UTC calendar periods.

When a limit is reached the AI job queue hands out nothing (``ai_jobs.serving`` says why and ``next_jobs`` returns no job), and the finding
reviewer and the operations check stop (``reviewer.enabled``). Queued jobs stay queued and are handed out once the next UTC day or month
begins. The spend is one grouped query, kept in this process for ``CACHE_SECONDS`` and read again at once when the day changes.
"""
import os
import threading
import time
from datetime import datetime, timedelta, timezone as dt_timezone
from decimal import Decimal, InvalidOperation

from django.db.models import Q, Sum
from django.utils import timezone

MONTHLY_ENV = 'CVENGINE_AI_MONTHLY_BUDGET_USD'
DAILY_ENV = 'CVENGINE_AI_DAILY_BUDGET_USD'
LIMIT_MAX = Decimal('1000000')
WARN_SHARE = Decimal('0.8')
CACHE_SECONDS = 60
_MILLION = Decimal(1_000_000)
# USD per million tokens used for a model when no rate at all is entered: a top-tier model's list price, so the budget stops early, not late.
CEILING = {'input': Decimal('15'), 'output': Decimal('75'), 'cache_read': Decimal('1.5'), 'cache_write': Decimal('18.75')}

_lock = threading.Lock()
_cache = {}  # 'spend' -> (expires monotonic, (month start, day start), spend dict)


def clear_cache():
    with _lock:
        _cache.clear()


# ------------------------------------------------------------------------------------------------------------------------- limits

def clean_limit(value):
    """A dollar limit from a page or the environment: a Decimal from 0 to LIMIT_MAX (2 places), or None when unset or not a number."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip().lstrip('$').replace(',', '')
    if not text:
        return None
    try:
        amount = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    if not amount.is_finite() or amount < 0 or amount > LIMIT_MAX:
        return None
    return amount.quantize(Decimal('0.01'))


def limits(row=None):
    """``{'monthly': (Decimal or None, source), 'daily': (...)}``; source is 'setting', 'env' or 'none'."""
    if row is None:
        from dashboard.models import AIProviderSettings
        row = AIProviderSettings.objects.first()
    out = {}
    for name, env in (('monthly', MONTHLY_ENV), ('daily', DAILY_ENV)):
        saved = clean_limit(getattr(row, f'{name}_budget_usd', None)) if row is not None else None
        if saved is not None:
            out[name] = (saved, 'setting')
            continue
        value = clean_limit(os.environ.get(env, ''))
        out[name] = (value, 'env') if value is not None else (None, 'none')
    return out


# -------------------------------------------------------------------------------------------------------------------------- spend

def period_starts(now):
    now = now.astimezone(dt_timezone.utc)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return day.replace(day=1), day


def _rate_dict(rate):
    return {'input': rate.input_per_million_usd, 'output': rate.output_per_million_usd,
            'cache_read': rate.cache_read_per_million_usd, 'cache_write': rate.cache_write_per_million_usd}


def fallback_rate(rates):
    """The rate of a model with no rate: each part the highest entered for any model (a missing cache rate counts as that model's input rate,
    and a cache write at 1.25 times it), else CEILING."""
    if not rates:
        return dict(CEILING)
    full = [complete_rate(r) for r in rates]
    return {part: max(r[part] for r in full) for part in CEILING}


def complete_rate(rate):
    """A rate with every part set: a cache read with no rate costs the input rate, a cache write 1.25 times it (never less than charged)."""
    out = dict(rate)
    if out.get('cache_read') is None:
        out['cache_read'] = out['input']
    if out.get('cache_write') is None:
        out['cache_write'] = out['input'] * Decimal('1.25')
    return out


def price(provider, totals, rate):
    """USD of ``totals`` (input, output, cache_read, cache_write token sums) at ``rate``. Anthropic's input count leaves the cached tokens out;
    an OpenAI style count includes them, so they are taken off before the input rate applies."""
    read, wrote, given = totals.get('cache_read') or 0, totals.get('cache_write') or 0, totals.get('input') or 0
    ordinary = given if provider == 'anthropic' else max(0, given - read)
    return (Decimal(ordinary) * rate['input'] + Decimal(totals.get('output') or 0) * rate['output']
            + Decimal(read) * rate['cache_read'] + Decimal(wrote) * rate['cache_write']) / _MILLION


def _billed_providers():
    from cvengine.ai_profiles import PROFILES
    return [name for name, profile in PROFILES.items() if not profile.needs_url]


def compute_spend(now):
    """``{'month': Decimal, 'day': Decimal, 'fallback_calls': int, 'fallback_models': [names]}`` since the start of the UTC month and day. One
    grouped query over the ledger, plus the price table."""
    from cveFeed.models import AIPriceRate, AIUsage
    month, day = period_starts(now)
    rates = {(r.provider, r.model): complete_rate(_rate_dict(r)) for r in AIPriceRate.objects.all()}
    fallback = fallback_rate(list(rates.values()))
    today = Q(started_at__gte=day)
    grouped = (AIUsage.objects.filter(started_at__gte=month, provider__in=_billed_providers())
               .values('provider', 'model', 'actual_model')
               .annotate(input=Sum('input_tokens'), output=Sum('output_tokens'), cache_read=Sum('cache_read_tokens'),
                         cache_write=Sum('cache_write_tokens'), d_input=Sum('input_tokens', filter=today),
                         d_output=Sum('output_tokens', filter=today), d_cache_read=Sum('cache_read_tokens', filter=today),
                         d_cache_write=Sum('cache_write_tokens', filter=today)).order_by())
    out = {'month': Decimal(0), 'day': Decimal(0), 'fallback_models': []}
    for g in grouped:
        model = g['actual_model'] or g['model']
        rate = rates.get((g['provider'], model))
        if rate is None:
            rate = fallback
            if any(g[k] for k in ('input', 'output', 'cache_read', 'cache_write')):
                out['fallback_models'].append(model or 'unnamed model')
        out['month'] += price(g['provider'], g, rate)
        out['day'] += price(g['provider'], {k: g[f'd_{k}'] for k in ('input', 'output', 'cache_read', 'cache_write')}, rate)
    out['fallback_models'] = sorted(set(out['fallback_models']))
    out['no_rates'] = not rates
    return out


def spend(now=None):
    """``compute_spend`` kept for CACHE_SECONDS in this process; a new UTC day or month reads it again at once."""
    now = now or timezone.now()
    periods = period_starts(now)
    with _lock:
        hit = _cache.get('spend')
        if hit and hit[0] > time.monotonic() and hit[1] == periods:
            return hit[2]
    value = compute_spend(now)
    with _lock:
        _cache['spend'] = (time.monotonic() + CACHE_SECONDS, periods, value)
    return value


# -------------------------------------------------------------------------------------------------------------------------- state

def _usd(amount):
    return f'${Decimal(amount).quantize(Decimal("0.01")):,}'


def _next_month(month_start):
    return (month_start + timedelta(days=32)).replace(day=1)


def state(now=None, row=None):
    """What the pages and the queue need: the limits and their sources, the spend, ``reached`` ('month', 'day' or ''), ``warn`` (80 percent
    or more of a limit, not yet reached), ``resumes`` (ISO date, UTC), and one plain ``message`` ('' when there is nothing to say)."""
    now = now or timezone.now()
    lim = limits(row)
    monthly, daily = lim['monthly'][0], lim['daily'][0]
    out = {'monthly_usd': str(monthly) if monthly is not None else None, 'monthly_source': lim['monthly'][1],
           'daily_usd': str(daily) if daily is not None else None, 'daily_source': lim['daily'][1],
           'month_spent_usd': None, 'day_spent_usd': None, 'reached': '', 'warn': '', 'resumes': None, 'message': '',
           'fallback_models': [], 'no_rates': False}
    if monthly is None and daily is None:
        return out
    spent = spend(now)
    month_start, day_start = period_starts(now)
    out.update(month_spent_usd=str(spent['month'].quantize(Decimal('0.01'))), day_spent_usd=str(spent['day'].quantize(Decimal('0.01'))),
               fallback_models=spent['fallback_models'], no_rates=spent['no_rates'])
    if monthly is not None and spent['month'] >= monthly:
        resume = _next_month(month_start)
        out.update(reached='month', resumes=resume.date().isoformat(),
                   message=f'AI budget reached: {_usd(spent["month"])} of {_usd(monthly)} this month, resumes {resume:%Y-%m-%d} (UTC).')
    elif daily is not None and spent['day'] >= daily:
        resume = day_start + timedelta(days=1)
        out.update(reached='day', resumes=resume.date().isoformat(),
                   message=f'AI budget reached: {_usd(spent["day"])} of {_usd(daily)} today, resumes {resume:%Y-%m-%d} 00:00 UTC.')
    elif monthly is not None and monthly > 0 and spent['month'] >= monthly * WARN_SHARE:
        out.update(warn='month', message=f'AI spend is at {int(spent["month"] * 100 / monthly)} percent of the monthly budget: '
                                         f'{_usd(spent["month"])} of {_usd(monthly)} this month.')
    elif daily is not None and daily > 0 and spent['day'] >= daily * WARN_SHARE:
        out.update(warn='day', message=f'AI spend is at {int(spent["day"] * 100 / daily)} percent of the daily budget: '
                                       f'{_usd(spent["day"])} of {_usd(daily)} today.')
    if out['message'] and spent['fallback_models']:
        out['message'] += (' Some models have no price on the AI usage page and are counted at the highest rate'
                           if not spent['no_rates'] else ' No price is entered on the AI usage page, so every call is counted at a top-tier rate') + '.'
    return out


def blocked(now=None, row=None):
    """``(True, message)`` while a budget is spent, else ``(False, '')``. Never raises: a budget that cannot be read stops the paid work."""
    try:
        current = state(now, row)
    except Exception:  # noqa: BLE001 - fail closed: an error must not let spending run on unseen
        import logging
        logging.getLogger(__name__).exception('AI budget: the spend could not be read; AI work is held')
        try:
            lim = limits(row)
        except Exception:  # noqa: BLE001
            return True, 'the AI budget could not be checked, so AI work is held'
        if lim['monthly'][0] is None and lim['daily'][0] is None:
            return False, ''
        return True, 'the AI budget could not be checked, so AI work is held'
    if current['reached']:
        return True, current['message']
    return False, ''
