"""One model call: a fixed system prompt, one user message, one JSON answer. No tools are ever offered to the model, so nothing it writes
can make a request, read a file or run a command; it can only answer.

Anthropic is called through its SDK, with the answer constrained to the schema (``output_config.format``) and the system prompt cached.
OpenAI-compatible servers (OpenAI, OpenRouter, vLLM, LM Studio) and Ollama are called with the standard library, asking for the same
schema where the server supports it. Every answer is checked again by ``guard.parse_reply``.

The provider key is used only as the provider's auth header. It is never put into a prompt, a log line or an error message.
"""
import json
import logging
import urllib.error
import urllib.request

from cvengine_reviewer import guard

logger = logging.getLogger(__name__)

DEFAULT_BASES = {'openai': 'https://api.openai.com/v1', 'openrouter': 'https://openrouter.ai/api/v1',
                 'lmstudio': 'http://host.docker.internal:1234/v1', 'vllm': 'http://host.docker.internal:8000/v1',
                 'ollama': 'http://host.docker.internal:11434'}
# Claude models that take server-side refusal fallbacks on the Claude API (``fallbacks: "default"``): a declined review is re-run on the
# fallback model instead of being lost. Haiku has none.
FALLBACK_MODELS = ('claude-sonnet-5-5', 'claude-opus-5-5', 'claude-opus-5', 'claude-fable-5-1')
MAX_REPLY_BYTES = 200_000


class ModelError(RuntimeError):
    """The call failed; ``category`` says how (auth, refused, truncated, http, network, shape)."""

    def __init__(self, message, category):
        super().__init__(message)
        self.category = category


def call(provider, system, user, schema, max_tokens, effort='medium'):
    """``(reply text, usage {input_tokens, output_tokens}, model)`` for one call to ``provider`` (the job's block of the server's
    configuration: provider, base_url, api_key, model, timeout)."""
    name = provider.get('provider')
    if name == 'anthropic':
        return _anthropic(provider, system, user, schema, max_tokens, effort)
    if name == 'ollama':
        return _ollama(provider, system, user, schema, max_tokens)
    return _openai_compatible(provider, system, user, schema, max_tokens)


def _anthropic(provider, system, user, schema, max_tokens, effort):
    import anthropic
    model = provider.get('model') or ''
    client = anthropic.Anthropic(api_key=provider.get('api_key') or None, base_url=provider.get('base_url') or None,
                                 timeout=float(provider.get('timeout') or 120), max_retries=2)
    output_config = {'format': {'type': 'json_schema', 'schema': guard.for_provider(schema)}}
    if model.startswith('claude-'):
        output_config['effort'] = effort
    extra = {}
    if model in FALLBACK_MODELS and not provider.get('base_url'):
        extra = {'extra_headers': {'anthropic-beta': 'server-side-fallback-2026-07-01'}, 'extra_body': {'fallbacks': 'default'}}
    try:
        message = client.messages.create(
            model=model, max_tokens=max_tokens,
            system=[{'type': 'text', 'text': system, 'cache_control': {'type': 'ephemeral'}}],
            messages=[{'role': 'user', 'content': user}], output_config=output_config, **extra)
    except anthropic.AuthenticationError as exc:
        raise ModelError('the provider refused the API key', 'auth') from exc
    except anthropic.PermissionDeniedError as exc:
        raise ModelError('the API key may not use this model', 'auth') from exc
    except anthropic.NotFoundError as exc:
        raise ModelError(f'the provider does not know the model {model!r}', 'model') from exc
    except anthropic.RateLimitError as exc:
        raise ModelError('rate limited by the provider', 'rate_limit') from exc
    except anthropic.APIStatusError as exc:
        raise ModelError(f'the provider answered HTTP {exc.status_code}', 'http') from exc
    except anthropic.APIConnectionError as exc:
        raise ModelError('could not reach the provider', 'network') from exc
    if message.stop_reason == 'refusal':
        raise ModelError('the model declined to answer', 'refused')
    if message.stop_reason == 'max_tokens':
        raise ModelError('the answer was cut off at the reply limit', 'truncated')
    text = ''.join(block.text for block in message.content if getattr(block, 'type', '') == 'text')
    usage = {'input_tokens': int(getattr(message.usage, 'input_tokens', 0) or 0),
             'output_tokens': int(getattr(message.usage, 'output_tokens', 0) or 0)}
    return text, usage, message.model or model


def _post(url, headers, body, timeout):
    request = urllib.request.Request(url, data=json.dumps(body).encode(), method='POST',
                                     headers={'Content-Type': 'application/json', **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - the URL is the provider the admin configured
            raw = response.read(MAX_REPLY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        category = 'auth' if exc.code in (401, 403) else 'rate_limit' if exc.code == 429 else 'http'
        raise ModelError(f'the provider answered HTTP {exc.code}', category) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ModelError(f'could not reach the provider ({type(exc).__name__})', 'network') from None
    if len(raw) > MAX_REPLY_BYTES:
        raise ModelError('the provider sent an oversized reply', 'shape')
    try:
        return json.loads(raw)
    except ValueError:
        raise ModelError('the provider sent something that is not JSON', 'shape') from None


def _openai_compatible(provider, system, user, schema, max_tokens):
    name = provider.get('provider') or 'openai'
    base = (provider.get('base_url') or DEFAULT_BASES.get(name, DEFAULT_BASES['openai'])).rstrip('/')
    if base.endswith('/chat/completions'):
        base = base[:-len('/chat/completions')]
    headers = {'Authorization': f"Bearer {provider['api_key']}"} if provider.get('api_key') else {}
    body = {'model': provider.get('model') or '', 'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
            'response_format': {'type': 'json_schema', 'json_schema': {'name': 'answer', 'strict': True, 'schema': guard.for_provider(schema)}}}
    body['max_completion_tokens' if name == 'openai' else 'max_tokens'] = max_tokens
    timeout = float(provider.get('timeout') or 120)
    try:
        data = _post(f'{base}/chat/completions', headers, body, timeout)
    except ModelError as exc:
        if exc.category != 'http':
            raise
        body['response_format'] = {'type': 'json_object'}  # a server without schema support: ask for JSON, parse_reply checks the shape
        data = _post(f'{base}/chat/completions', headers, body, timeout)
    try:
        choice = data['choices'][0]
        text = choice['message']['content']
    except (KeyError, IndexError, TypeError):
        raise ModelError('unexpected reply shape', 'shape') from None
    if choice.get('finish_reason') == 'length':
        raise ModelError('the answer was cut off at the reply limit', 'truncated')
    usage = data.get('usage') or {}
    return text or '', {'input_tokens': int(usage.get('prompt_tokens') or 0), 'output_tokens': int(usage.get('completion_tokens') or 0)}, \
        str(data.get('model') or provider.get('model') or '')


def _ollama(provider, system, user, schema, max_tokens):
    base = (provider.get('base_url') or DEFAULT_BASES['ollama']).rstrip('/')
    body = {'model': provider.get('model') or '', 'stream': False, 'format': guard.for_provider(schema),
            'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
            'options': {'num_predict': max_tokens}}
    data = _post(f'{base}/api/chat', {}, body, float(provider.get('timeout') or 120))
    try:
        text = data['message']['content']
    except (KeyError, TypeError):
        raise ModelError('unexpected reply shape', 'shape') from None
    if data.get('done_reason') == 'length':
        raise ModelError('the answer was cut off at the reply limit', 'truncated')
    return text or '', {'input_tokens': int(data.get('prompt_eval_count') or 0), 'output_tokens': int(data.get('eval_count') or 0)}, \
        str(data.get('model') or provider.get('model') or '')
