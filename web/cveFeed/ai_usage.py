"""Read-only AI attempt accounting and operator supplied price estimates."""
from datetime import timedelta
from decimal import Decimal

from django.db.models import Avg, Count, Q, Sum
from django.db.models.functions import TruncDate
from django.utils import timezone


def _iso(value):
    return value.isoformat() if value else None


def _estimate(row, rate):
    if not rate or row['input_sum'] is None or row['output_sum'] is None:
        return None
    cached = row['cache_read_sum'] or 0
    written = row['cache_write_sum'] or 0
    if cached and rate.cache_read_per_million_usd is None:
        return None
    if written and rate.cache_write_per_million_usd is None:
        return None
    # OpenAI's prompt_tokens includes cached tokens; Anthropic's input_tokens does not.
    ordinary = row['input_sum'] if row['provider'] == 'anthropic' else max(0, row['input_sum'] - cached)
    amount = (Decimal(ordinary) * rate.input_per_million_usd
              + Decimal(row['output_sum']) * rate.output_per_million_usd
              + Decimal(cached) * (rate.cache_read_per_million_usd or 0)
              + Decimal(written) * (rate.cache_write_per_million_usd or 0)) / Decimal(1_000_000)
    return str(amount.quantize(Decimal('0.000001')))


def snapshot(days=7):
    from dashboard.models import AIProviderSettings
    from cveFeed.models import AIPriceRate, AIUsage

    now = timezone.now()
    cutoff = now - timedelta(days=days)
    cfg = AIProviderSettings.objects.first()
    qs = AIUsage.objects.filter(started_at__gte=cutoff)
    aggregate = qs.aggregate(attempts=Count('id'), successes=Count('id', filter=Q(status='succeeded')),
                             errors=Count('id', filter=Q(status='failed')), avg_latency_ms=Avg('duration_ms'))
    rates = {(r.provider, r.model): r for r in AIPriceRate.objects.all()}
    models = []
    known_cost = Decimal(0)
    unknown_cost_attempts = 0
    priced_attempts = 0
    grouped = qs.values('provider', 'model', 'actual_model').annotate(
        attempts=Count('id'), successes=Count('id', filter=Q(status='succeeded')),
        errors=Count('id', filter=Q(status='failed')),
        input_sum=Sum('input_tokens', filter=Q(output_tokens__isnull=False)),
        output_sum=Sum('output_tokens', filter=Q(input_tokens__isnull=False)),
        cache_read_sum=Sum('cache_read_tokens', filter=Q(input_tokens__isnull=False, output_tokens__isnull=False)),
        cache_write_sum=Sum('cache_write_tokens', filter=Q(input_tokens__isnull=False, output_tokens__isnull=False)),
        missing_tokens=Count('id', filter=Q(input_tokens__isnull=True) | Q(output_tokens__isnull=True)),
        avg_latency_ms=Avg('duration_ms')).order_by('-attempts')[:100]
    for group in grouped:
        billed_model = group['actual_model'] or group['model']
        rate = rates.get((group['provider'], billed_model))
        cost = _estimate(group, rate)
        complete_attempts = group['attempts'] - group['missing_tokens']
        if cost is None:
            unknown_cost_attempts += group['attempts']
        else:
            known_cost += Decimal(cost)
            priced_attempts += complete_attempts
            unknown_cost_attempts += group['missing_tokens']
        models.append({**group, 'billed_model': billed_model, 'estimated_usd': cost,
                       'rate_source': rate.source_url if rate else None, 'rate_as_of': _iso(rate.as_of) if rate else None})
    # If >100 model groups exist, totals still include them; their cost remains unknown.
    accounted = sum(group['attempts'] for group in models)
    unknown_cost_attempts += max(0, aggregate['attempts'] - accounted)
    daily = list(qs.annotate(day=TruncDate('started_at')).values('day').annotate(
        attempts=Count('id'), errors=Count('id', filter=Q(status='failed'))).order_by('day'))
    stages = list(qs.values('stage').annotate(attempts=Count('id'), errors=Count('id', filter=Q(status='failed')))
                  .order_by('-attempts')[:30])
    recent = [{'at': _iso(r.started_at), 'provider': r.provider, 'model': r.model,
               'actual_model': r.actual_model, 'stage': r.stage, 'status': r.status,
               'error_category': r.error_category, 'input_tokens': r.input_tokens,
               'output_tokens': r.output_tokens, 'cache_read_tokens': r.cache_read_tokens,
               'cache_write_tokens': r.cache_write_tokens, 'duration_ms': r.duration_ms}
              for r in qs.order_by('-started_at', '-id')[:50]]
    current = AIUsage.objects.filter(provider=cfg.provider) if cfg else AIUsage.objects.none()
    if cfg and cfg.model:
        current = current.filter(Q(model=cfg.model) | Q(actual_model=cfg.model))
    last_success = current.filter(status='succeeded').order_by('-started_at', '-id').first()
    last_error = current.filter(status='failed').order_by('-started_at').first()
    verified = bool(cfg and cfg.verified_at and cfg.verified_provider == cfg.provider and
                    (not cfg.model or cfg.verified_model == cfg.model))
    recent_cutoff = now - timedelta(hours=24)
    health = ('disabled' if not cfg or not cfg.enabled else
              'recent_error' if last_error and last_error.started_at >= recent_cutoff and
              (not last_success or last_error.started_at > last_success.started_at) else
              'responding' if last_success and last_success.started_at >= recent_cutoff else
              'last_verified_over_24h_ago' if verified and cfg.verified_at < recent_cutoff else
              'verified_at_setup' if verified else 'no_recent_activity')
    return {'connected': bool(cfg and cfg.enabled), 'provider': cfg.provider if cfg else None,
            'configured_model': cfg.model or None if cfg else None,
            'verified_model': cfg.verified_model or None if verified else None,
            'verified_at': _iso(cfg.verified_at) if verified else None, 'health': health,
            'observed_model': (last_success.actual_model or last_success.model) if last_success else None,
            'last_success': _iso(last_success.started_at) if last_success else None,
            'last_error': {'at': _iso(last_error.started_at), 'category': last_error.error_category} if last_error else None,
            'period_days': days, 'attempts': aggregate['attempts'], 'successes': aggregate['successes'],
            'errors': aggregate['errors'], 'avg_latency_ms': aggregate['avg_latency_ms'],
            'transport_retries': 0,
            'known_estimated_usd': str(known_cost.quantize(Decimal('0.000001'))) if priced_attempts else None,
            'priced_attempts': priced_attempts,
            'unknown_cost_attempts': unknown_cost_attempts, 'models': models,
            'daily': [{'day': _iso(d['day']), 'attempts': d['attempts'], 'errors': d['errors']} for d in daily],
            'stages': stages, 'recent': recent,
            'rates': [{'provider': r.provider, 'model': r.model, 'input_per_million_usd': str(r.input_per_million_usd),
                       'output_per_million_usd': str(r.output_per_million_usd), 'cache_read_per_million_usd':
                       str(r.cache_read_per_million_usd) if r.cache_read_per_million_usd is not None else None,
                       'cache_write_per_million_usd': str(r.cache_write_per_million_usd) if r.cache_write_per_million_usd is not None else None,
                       'source_url': r.source_url, 'as_of': _iso(r.as_of)} for r in rates.values()],
            'coverage_note': 'Attempts before this usage ledger was installed are unavailable. Provider transport has no automatic retries; task retries are separate attempts. Provider token counts may be absent; estimates use operator supplied rates, not provider invoices.'}


def set_rate(data):
    from datetime import date
    from urllib.parse import urlsplit
    import re
    from cveFeed.models import AIPriceRate
    from dashboard.models import AIProviderSettings
    from cveFeed.settings_api import SettingsError

    provider = str(data.get('provider') or '')
    model = str(data.get('model') or '').strip()
    if provider not in dict(AIProviderSettings.PROVIDER_CHOICES) or not re.fullmatch(r'[A-Za-z0-9._:/-]{1,200}', model):
        raise SettingsError(400, 'choose an exact provider and model')
    def amount(key, optional=False):
        value = data.get(key)
        if optional and value in ('', None):
            return None
        try:
            result = Decimal(str(value))
        except Exception as exc:
            raise SettingsError(400, f'{key} must be a USD amount per million tokens') from exc
        if not result.is_finite() or result < 0 or result > 100000:
            raise SettingsError(400, f'{key} must be between 0 and 100000')
        return result.quantize(Decimal('0.000001'))
    source = str(data.get('source_url') or '').strip()
    try:
        url = urlsplit(source)
    except ValueError as exc:
        raise SettingsError(400, 'provide a public HTTPS pricing source URL') from exc
    if len(source) > 500 or url.scheme != 'https' or not url.hostname or url.username or url.password:
        raise SettingsError(400, 'provide a public HTTPS pricing source URL')
    try:
        as_of = date.fromisoformat(str(data.get('as_of') or ''))
    except ValueError as exc:
        raise SettingsError(400, 'as_of must be a YYYY-MM-DD date') from exc
    if as_of > date.today() or as_of.year < 2000:
        raise SettingsError(400, 'as_of must be a past or current pricing date')
    row, _ = AIPriceRate.objects.update_or_create(provider=provider, model=model, defaults={
        'input_per_million_usd': amount('input_per_million_usd'),
        'output_per_million_usd': amount('output_per_million_usd'),
        'cache_read_per_million_usd': amount('cache_read_per_million_usd', optional=True),
        'cache_write_per_million_usd': amount('cache_write_per_million_usd', optional=True),
        'source_url': source, 'as_of': as_of})
    return {'provider': row.provider, 'model': row.model, 'updated': _iso(row.updated_at)}
