"""Test helper: play the AI reviewer container for the pipeline's AI jobs (cveFeed.ai_jobs).

The stages no longer call a model: they queue a job, and the container answers it. ``serve(fake)`` takes the queued jobs the way the
container does (``ai_jobs.next_jobs``), builds each prompt with the container's own code (``cvengine_reviewer.jobs.job_message``, so the
fences are the real ones), asks ``fake.complete(system, user)`` for the answer, posts it (``ai_jobs.submit``) and continues the stage
(``ai_jobs.apply``) at once instead of in a Celery task. An ``AIProviderError`` the fake raises is posted as the failure category the
container would send. ``fake`` is anything with ``complete``: a ``mock.Mock`` works, and its ``name`` and ``model`` name the provider.
"""
import os
import sys

REVIEWER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'reviewer'))


def container():
    """The reviewer container's ``jobs`` module, imported from reviewer/ (it needs no third-party library to build a prompt)."""
    if REVIEWER_DIR not in sys.path:
        sys.path.insert(0, REVIEWER_DIR)
    from cvengine_reviewer import jobs
    return jobs


def configure(provider='anthropic', model='m', **fields):
    """An enabled AI provider, so the stages queue their questions."""
    from dashboard.models import AIProviderSettings
    defaults = {'api_key': 'sk-ant-test-key'} if provider in ('anthropic', 'openai', 'openrouter') else {'base_url': 'http://192.0.2.10:8000/v1'}
    values = {'enabled': True, 'provider': provider, 'model': model, **defaults, **fields}
    row = AIProviderSettings.objects.first()  # the single settings row: its other settings (budgets) are kept
    if row is None:
        return AIProviderSettings.objects.create(**values)
    for key, value in values.items():
        setattr(row, key, value)
    row.save()
    return row


def ensure_configured(fake):
    """``configure`` with the fake's provider name, unless an enabled provider is already there."""
    from dashboard.models import AIProviderSettings
    from reNgine.ai_profiles import PROFILES
    if not AIProviderSettings.objects.filter(enabled=True).exists():
        name = getattr(fake, 'name', 'anthropic')
        configure(name if name in PROFILES else 'anthropic')


def answer(job, fake):
    """The body the container would post for one handed-out job."""
    from cveFeed import ai_jobs
    from reNgine.ai_providers import AIProviderError
    from reNgine.ai_profiles import PROFILES
    name = getattr(fake, 'name', 'anthropic')
    name = name if name in PROFILES else 'anthropic'
    model = getattr(fake, 'model', 'm')
    model = model if isinstance(model, str) else 'm'
    base = {'lease': job['lease'], 'provider': name, 'model': model}
    try:
        text = fake.complete(job['system'], container().job_message(job))
    except AIProviderError as exc:
        category = exc.category if exc.category in ai_jobs.CATEGORIES else 'provider_error'
        return {**base, 'error': category, 'calls': [{'status': 'failed', 'category': category}],
                **({'http_status': exc.http_status} if exc.http_status else {})}
    return {**base, 'text': text, 'calls': [{'status': 'succeeded', 'input_tokens': 10, 'output_tokens': 5}]}


def serve(fake, rounds=200):
    """Answer every queued job with ``fake`` (a stage's retry is a new round). Returns how many answers were posted."""
    from cveFeed import ai_jobs
    posted = 0
    for _ in range(rounds):
        batch = ai_jobs.next_jobs(ai_jobs.BATCH_MAX)
        if not batch:
            break
        for job in batch:
            ai_jobs.submit(job['id'], answer(job, fake))
            ai_jobs.apply(job['id'])
            posted += 1
    return posted


def triage_prompt(kind, payload, host_context=None):
    """The user message a triage job's model reads, as the container builds it from the job's parts."""
    from reNgine.ai_providers import triage_parts
    return container().job_message({'parts': triage_parts(kind, payload, host_context)})


def _fake(provider):
    return provider is not None and provider is not False


def run_triage(pairs, provider=False, **kw):
    """``triage.run_triage`` as it was called before the queue: ``provider`` a fake answers the questions it queues; None means no AI."""
    from cveFeed import triage
    if _fake(provider):
        ensure_configured(provider)
    stats = triage.run_triage(pairs, provider=None if provider is None else False, **kw)
    if _fake(provider):
        serve(provider)
    return stats


def sweep(project_id=None, provider=False, **kw):
    """``triage.sweep`` with a fake answering, like ``run_triage``."""
    from cveFeed import triage
    if _fake(provider):
        ensure_configured(provider)
    stats = triage.sweep(project_id, provider=None if provider is None else False, **kw)
    if _fake(provider):
        serve(provider)
    return stats


def asking(fn, fake, *args, **kwargs):
    """Call a stage function that queues AI jobs (``fn(*args, **kwargs)``), then answer them with ``fake``. Returns what ``fn`` returned."""
    if _fake(fake):
        ensure_configured(fake)
    out = fn(*args, **kwargs)
    if _fake(fake):
        serve(fake)
    return out
