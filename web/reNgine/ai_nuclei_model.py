"""The model that chooses Nuclei tags and templates (stages ``nuclei_tag_selection`` and ``nuclei_targeting``).

Some models refuse this job (they answer with the stop reason ``refusal`` or with nothing) and a small, fast model of the haiku class answers
it. So it has its own setting, ``AIProviderSettings.nuclei_model``, chosen on Settings > AI model, "Nuclei targeting and tag selection":

* an owner's choice (a model of the provider's list) is used as it is;
* empty is the default: the cheapest model of the provider whose id contains ``haiku`` and that the provider lists as available, resolved from
  the provider's model list when it is read (never a name written in code or stored by a migration); when the list has none, or cannot be read,
  the model of "Everything else" (``AIProviderSettings.model``, never changed by this).

``plan(provider)`` gives the model a request uses and the one it is retried on when it is refused or answers nothing: the haiku default, only
when the request ran on a different model. At most one retry (cveFeed.nuclei_templates._ask).
"""
import logging
import time

logger = logging.getLogger(__name__)

HAIKU = 'haiku'
LIST_TTL = 600   # seconds a provider's resolved haiku is kept (its model list changes a few times a year)
FAIL_TTL = 60    # a list that could not be read is not asked for again for this long
_picked = {}     # (provider, base_url) -> (expires, model id or None)


def _clock():
    return time.time()


def pick_haiku(models):
    """Pure: the cheapest haiku of ``[{'id', 'created', 'price'}]`` (what a provider lists), or None. Ranked by the price per million input
    tokens when the provider reports one (Anthropic's list has none), then an undated alias before a dated snapshot, then the newest."""
    from reNgine.ai_providers import _DATED
    pool = [m for m in models or [] if isinstance(m, dict) and isinstance(m.get('id'), str) and HAIKU in m['id'].lower()]
    if not pool:
        return None

    def rank(m):
        price = m.get('price')
        price = price if isinstance(price, (int, float)) and not isinstance(price, bool) else float('inf')
        return (price, 1 if _DATED.search(m['id']) else 0, -(m.get('created') or 0), m['id'])
    return min(pool, key=rank)['id']


def _key(name, base_url):
    return (str(name), str(base_url or '').strip().rstrip('/').lower())


def remember(name, base_url, raw_models):
    """Keep the haiku of a list that was just read (the Settings page reads one), and return it."""
    choice = pick_haiku(raw_models)
    _picked[_key(name, base_url)] = (_clock() + LIST_TTL, choice)
    return choice


def haiku_default(provider, fetch=True):
    """The default haiku of this provider object's own list: a model id, or None (none listed, or the list cannot be read). ``fetch`` False
    only reports what is known."""
    key = _key(provider.name, provider.base_url)
    hit = _picked.get(key)
    if hit and hit[0] > _clock():
        return hit[1]
    if not fetch:
        return None
    from reNgine.ai_providers import AIProviderError
    try:
        choice = pick_haiku(provider.list_models())
        ttl = LIST_TTL
    except (AIProviderError, AttributeError, KeyError, TypeError, ValueError):
        choice, ttl = None, FAIL_TTL
    _picked[key] = (_clock() + ttl, choice)
    return choice


def configured():
    """What the owner chose ('' for the default)."""
    from dashboard.models import AIProviderSettings
    row = AIProviderSettings.objects.first()
    return (row.nuclei_model or '').strip() if row else ''


def _sibling(provider, model):
    from reNgine.ai_providers import get_provider
    return get_provider(provider.name, model=model, api_key=provider.api_key, base_url=provider.base_url, runtime=provider.runtime)


def plan(provider):
    """``(provider for the request, provider for its one retry or None)``. A provider that is not one of ours (a test double) is used as it
    is. Never raises: a failure here leaves the request on the provider it was given."""
    from reNgine.ai_providers import AIProvider
    if not isinstance(provider, AIProvider):
        return provider, None
    try:
        base_model = provider.model
        haiku = haiku_default(provider)
        chosen = configured() or haiku or base_model
        main = provider if chosen == base_model else _sibling(provider, chosen)
        retry = None
        if haiku and haiku != chosen:
            retry = provider if haiku == base_model else _sibling(provider, haiku)
        return main, retry
    except Exception:  # noqa: BLE001 - choosing a model must never hold a scan up
        logger.warning('the nuclei model could not be resolved; using the default model', exc_info=False)
        return provider, None


def in_force(provider, fetch=False):
    """For the settings page: ``{'model', 'default', 'source'}``; source is 'chosen', 'haiku' or 'everything_else'."""
    from reNgine.ai_providers import AIProviderError
    named = configured()
    try:
        haiku = haiku_default(provider, fetch=fetch)
    except Exception:  # noqa: BLE001
        haiku = None
    try:
        base_model = provider.model if provider is not None else ''
    except AIProviderError:
        base_model = ''
    if named:
        return {'model': named, 'default': haiku or base_model or '', 'source': 'chosen'}
    return {'model': haiku or base_model or '', 'default': haiku or base_model or '', 'source': 'haiku' if haiku else 'everything_else'}
