"""Model calls. No tools are ever offered to the model, so nothing it writes can make a request, read a file or run a command; it can only
answer.

Two paths:

* ``call`` serves the reviewer's own two jobs (finding review, operations check): a fixed system prompt, one user message, one JSON answer.
  Anthropic is called through its SDK, with the answer constrained to the schema (``output_config.format``) and the system prompt cached.
  OpenAI-compatible servers and Ollama are called with the standard library, asking for the same schema where the server supports it.
  Every answer is checked again by ``guard.parse_reply``.
* ``complete`` serves the pipeline's AI jobs (triage, validation planning, template drafting, detection authoring, the RDP reading and the
  rest, docs/AI-REVIEWER.md). It is the request logic the server used itself before 1.4 (web/reNgine/ai_providers.py), ported: the same
  endpoints, bodies, reply limits, pinned temperature and seed for a self-hosted server, structured output with its step-down ladder, the
  reasoning setting, Ollama's context window and keep-alive, images, and the same error categories. The server checks the answer.

The provider key is used only as the provider's auth header. It is never put into a prompt, a log line or an error message.
"""
import base64
import http.client
import json
import logging
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from cvengine_reviewer import guard, profiles

logger = logging.getLogger(__name__)

DEFAULT_BASES = {'openai': 'https://api.openai.com/v1', 'openrouter': 'https://openrouter.ai/api/v1',
                 'lmstudio': 'http://host.docker.internal:1234/v1', 'vllm': 'http://host.docker.internal:8000/v1',
                 'ollama': 'http://host.docker.internal:11434'}
# Claude models that take server-side refusal fallbacks on the Claude API (``fallbacks: "default"``): a declined review is re-run on the
# fallback model instead of being lost. Haiku has none.
FALLBACK_MODELS = ('claude-sonnet-5-5', 'claude-opus-5-5', 'claude-opus-5', 'claude-fable-5-1')
MAX_REPLY_BYTES = 200_000


class ModelError(RuntimeError):
    """The call failed; ``category`` says how (``call``: auth, refused, truncated, http, network, shape; ``complete``: the server's
    categories, provider_auth, output_truncated and the rest). ``http_status``, ``stop_reason`` and ``hint`` (the start of a refused
    request's body, lower-cased, read only to tell what was refused) are set where known."""

    def __init__(self, message, category, http_status=None, stop_reason=None, hint=''):
        super().__init__(message)
        self.category = category
        self.http_status = http_status
        self.stop_reason = stop_reason
        self.hint = hint


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


# ===================================================================================================== the pipeline's AI jobs: ``complete``
#
# Ported from the server's own provider layer (web/reNgine/ai_providers.py, as it was before 1.4), so a job asks exactly what the server
# used to ask. The server resolves the operator's settings (the Settings page, then the CVENGINE_AI_* variables of its .env) and hands
# them over in the job block of its configuration as ``runtime``; nothing here reads the environment.

ANTHROPIC_URL = profiles.PROFILES['anthropic'].default_base
ANTHROPIC_VERSION = '2023-06-01'
REQUEST_TIMEOUT = 120
PROVIDER_TIMEOUT = {'lmstudio': 300}  # LM Studio may load a model on its first request
CONNECT_TIMEOUT = 10
LIST_TIMEOUT = 30
MAX_COMPLETION_BYTES = 2_000_000
MAX_LIST_BYTES = 8_000_000
CEILING = 32768  # the largest reply limit ever sent
RANGES = {'request_timeout': (10, 3600), 'connect_timeout': (1, 300), 'max_tokens': (64, CEILING), 'context_tokens': (512, 1048576)}
STRUCTURED_MODES = ('auto', 'all', 'off')
KEEP_ALIVE = re.compile(r'^(?:-1|0|\d{1,5}[smh])$')
OPENROUTER_HEADERS = {'HTTP-Referer': 'https://github.com/hevnsnt/CVEngine', 'X-Title': 'CVEngine'}
_NAMES_STRUCTURE = re.compile(r'response_format|json_schema|json_object|schema|grammar|format|guided|structured')
_NON_CHAT = re.compile(r'embed|image|audio|tts|whisper|realtime|moderation|transcribe|search|dall|sora|codex|davinci|babbage|computer-use')
_CHEAP_TIERS = (('nano', 0), ('haiku', 0), ('luna', 0), ('flash-lite', 0), ('lite', 0), ('mini', 1), ('flash', 1))
_DATED = re.compile(r'-(?:\d{4}-\d{2}-\d{2}|\d{8})$')
_STRUCTURED = {}  # (provider, base_url, model) -> (expires, level): where a server that refused a level starts, for an hour
_RESOLVED = {}  # (provider, base_url) -> (expires, model): the default model of a provider that has one
_NOTED = set()


def _note_once(*key):
    if key in _NOTED:
        return False
    _NOTED.add(key)
    return True


def _number(name, value):
    low, high = RANGES[name]
    if isinstance(value, bool) or value in (None, ''):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if low <= value <= high else None


class Target:
    """One provider as the job block of the server's configuration describes it: ``{provider, base_url, api_key, model, runtime}``."""

    def __init__(self, block):
        self.name = str(block.get('provider') or '')
        self.profile = profiles.PROFILES.get(self.name)
        if self.profile is None:
            raise ModelError(f'unknown AI provider: {self.name[:40]!r}', 'provider_error')
        self.base_url = str(block.get('base_url') or '').strip()
        if self.base_url and not re.match(r'^https?://', self.base_url, re.I):
            raise ModelError('the server URL must start with http:// or https://', 'provider_error')
        if self.profile.needs_url and not self.base_url:
            raise ModelError(f'{self.name} needs the server URL', 'provider_error')
        self.api_key = str(block.get('api_key') or '')
        if self.profile.needs_key and not self.api_key:
            raise ModelError(f'{self.name} requires an API key', 'provider_error')
        self.model = str(block.get('model') or '')
        runtime = block.get('runtime') if isinstance(block.get('runtime'), dict) else {}
        self.request_timeout = _number('request_timeout', runtime.get('request_timeout')) or PROVIDER_TIMEOUT.get(self.name, REQUEST_TIMEOUT)
        self.connect_timeout = _number('connect_timeout', runtime.get('connect_timeout')) or CONNECT_TIMEOUT
        self.max_tokens = _number('max_tokens', runtime.get('max_tokens'))
        self.context_tokens = _number('context_tokens', runtime.get('context_tokens'))
        mode = str(runtime.get('structured_mode') or 'auto')
        self.structured_mode = mode if mode in STRUCTURED_MODES else 'auto'
        level = runtime.get('reasoning')
        self.reasoning = level if level in profiles.REASONING_LEVELS else None
        keep = str(runtime.get('keep_alive') or '')
        self.keep_alive = keep if KEEP_ALIVE.match(keep) else ''


# ----------------------------------------------------------------------------------------------------------------------------- HTTP

class _ConnectTimeout(OSError):
    """The server was not reached within the connect timeout (told apart from a slow answer)."""


def _connection(base, connect_timeout):
    class Connection(base):
        def connect(self):
            answer_timeout, self.timeout = self.timeout, connect_timeout
            try:
                super().connect()
            except (TimeoutError, socket.timeout) as exc:
                raise _ConnectTimeout('connect timed out') from exc
            finally:
                self.timeout = answer_timeout
            if self.sock is not None:
                self.sock.settimeout(answer_timeout)
    return Connection


class _HTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, connect_timeout):
        super().__init__()
        self._connect_timeout = connect_timeout

    def http_open(self, req):
        return self.do_open(_connection(http.client.HTTPConnection, self._connect_timeout), req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, connect_timeout):
        super().__init__()
        self._connect_timeout = connect_timeout

    def https_open(self, req):
        return self.do_open(_connection(http.client.HTTPSConnection, self._connect_timeout), req, context=self._context)


def _http(name, url, headers, body, timeout, connect_timeout, limit):
    """One request (POST when ``body`` is given, else GET); the parsed JSON answer. Raises ModelError with the server's categories."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method='POST' if data is not None else 'GET',
                                     headers={'Accept': 'application/json', **({'Content-Type': 'application/json'} if data else {}), **headers})
    opener = urllib.request.build_opener(_HTTPHandler(connect_timeout), _HTTPSHandler(connect_timeout))
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310 - the provider the admin configured
            raw = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            hint = exc.read(400).decode('utf-8', 'replace').lower()
        except (OSError, ValueError):
            hint = ''
        category = 'provider_auth' if status in (401, 403) else 'provider_rate_limit' if status == 429 else 'provider_http'
        raise ModelError(f'{name} HTTP request failed (status {status})', category, http_status=status, hint=hint) from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, _ConnectTimeout):
            raise ModelError(f'{name} connection timed out', 'provider_connect_timeout') from None
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise ModelError(f'{name} request timed out', 'provider_timeout') from None
        raise ModelError(f'{name} connection failed', 'provider_network') from None
    except (TimeoutError, socket.timeout):
        raise ModelError(f'{name} request timed out', 'provider_timeout') from None
    except (OSError, http.client.HTTPException):
        raise ModelError(f'{name} connection failed', 'provider_network') from None
    if len(raw) > limit:
        raise ModelError(f'{name} sent an oversized reply', 'provider_shape')
    try:
        return json.loads(raw)
    except ValueError:
        raise ModelError(f'{name} returned invalid JSON', 'provider_json') from None


# ---------------------------------------------------------------------------------------------------------------------- the model

def pick_cheapest_newest(models):
    """From [{'id', 'created'}] the newest model in the cheapest tier (nano/haiku/luna, then mini/flash); non-chat models are ignored and an
    undated alias beats a dated snapshot."""
    chat = [m for m in models if m.get('id') and not _NON_CHAT.search(m['id'].lower())]

    def tier(m):
        return min((rank for word, rank in _CHEAP_TIERS if word in m['id'].lower()), default=9)
    if not chat:
        return None
    best = min(tier(m) for m in chat)
    pool = [m for m in chat if tier(m) == best]
    pool = [m for m in pool if not _DATED.search(m['id'])] or pool
    return max(pool, key=lambda m: (m.get('created') or 0, m['id']))['id']


def _epoch(value):
    if isinstance(value, (int, float)):
        return int(value)
    try:
        from datetime import datetime
        return int(datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp())
    except ValueError:
        return 0


def _openai_base(target):
    base = (target.base_url or target.profile.default_base).rstrip('/')
    return base[:-len('/chat/completions')] if base.endswith('/chat/completions') else base


def _anthropic_url(target):
    """Anthropic's own messages endpoint unless a base URL is set: a bare address (or one ending in /v1) is the server and the endpoint is
    under it; an address with any other path is used as written."""
    if not target.base_url:
        return ANTHROPIC_URL
    url = target.base_url
    path = urllib.parse.urlsplit(url).path.rstrip('/')
    if not path:
        return url.rstrip('/') + '/v1/messages'
    if path == '/v1':
        return url.rstrip('/') + '/messages'
    return url


def _headers(target):
    if target.profile.transport == 'anthropic':
        return {'x-api-key': target.api_key, 'anthropic-version': ANTHROPIC_VERSION}
    if target.profile.transport == 'ollama':
        return {}
    headers = {'Authorization': f'Bearer {target.api_key}'} if target.api_key else {}
    return {**headers, **OPENROUTER_HEADERS} if target.name == 'openrouter' else headers


def list_models(target):
    """[{'id', 'created'}], newest first. Raises ModelError (category provider_error)."""
    try:
        if target.profile.transport == 'anthropic':
            base = _anthropic_url(target).split('/v1/')[0]
            data = _http(target.name, f'{base}/v1/models?limit=1000', _headers(target), None, LIST_TIMEOUT, target.connect_timeout, MAX_LIST_BYTES)
            models = [{'id': m['id'], 'created': _epoch(m.get('created_at'))} for m in data.get('data', []) if isinstance(m, dict) and m.get('id')]
        elif target.profile.transport == 'ollama':
            data = _http(target.name, f'{target.base_url.rstrip("/")}/api/tags', {}, None, LIST_TIMEOUT, target.connect_timeout, MAX_LIST_BYTES)
            models = [{'id': m['name'], 'created': _epoch(m.get('modified_at'))} for m in data.get('models', []) if isinstance(m, dict) and m.get('name')]
        else:
            data = _http(target.name, f'{_openai_base(target)}/models', _headers(target), None, LIST_TIMEOUT, target.connect_timeout, MAX_LIST_BYTES)
            models = [{'id': m['id'], 'created': _epoch(m.get('created'))} for m in data.get('data', []) if isinstance(m, dict) and m.get('id')]
            if target.name == 'lmstudio':  # LM Studio lists the embedding models it holds beside the chat ones
                models = [m for m in models if 'embed' not in m['id'].lower()]
    except ModelError as exc:
        raise ModelError(f'{target.name} model list failed', 'provider_error', http_status=exc.http_status) from None
    except (AttributeError, TypeError) as exc:
        raise ModelError(f'{target.name} model list has an unexpected shape', 'provider_error') from exc
    return sorted(models, key=lambda m: (-m['created'], str(m['id'])))


def resolve_model(target):
    """The model to ask when the operator chose none: the provider's only model (a self-hosted server serving one), or for Anthropic and
    OpenAI the newest of the cheapest tier from their list (an hour in memory), else the profile's default."""
    if target.model:
        return target.model
    if not target.profile.default_model:
        models = list_models(target)
        if len(models) == 1:
            target.model = str(models[0]['id'])
            return target.model
        raise ModelError(f'choose a model for {target.name}: it serves more than one, or none could be listed', 'provider_error')
    key = (target.name, target.base_url)
    cached = _RESOLVED.get(key)
    if cached and cached[0] > time.time():
        target.model = cached[1]
        return target.model
    try:
        chosen = pick_cheapest_newest(list_models(target))
    except ModelError:
        chosen = None
    target.model = chosen or target.profile.default_model
    _RESOLVED[key] = (time.time() + 3600, target.model)
    return target.model


# ------------------------------------------------------------------------------------------------------------------ request shape

def reply_limit(target, options, factor=None):
    """The reply limit to send, or None to send none. The operator's limit is the ANSWER room when they set one; else the stage's own (a
    self-hosted server) or at least the profile's default (Anthropic); OpenAI and OpenRouter get none. The thinking reserve of the model
    (``profiles.thinking_reserve``, by the Reasoning setting) is added on top, so reasoning cannot take the room of the answer. ``factor``
    lengthens the answer room; ``_reply_limit`` in ``options`` is the exact limit of a retry (see ``retry_limit``)."""
    if options.get('_reply_limit'):
        return int(options['_reply_limit'])
    answer = target.max_tokens
    if answer is None:
        answer = profiles.answer_room(target.profile, _number('max_tokens', options.get('max_tokens')))
    if not answer:
        return None
    return profiles.reply_total(answer, profiles.thinking_reserve(target.name, target.model, target.reasoning), factor)


def retry_limit(target, options, sent):
    """The limit of the one retry of a reply cut off at ``sent`` (see ``profiles.retry_total``), or 0 when there is none to ask for."""
    answer = target.max_tokens
    if answer is None:
        answer = profiles.answer_room(target.profile, _number('max_tokens', options.get('max_tokens')))
    return profiles.retry_total(answer, profiles.thinking_reserve(target.name, target.model, target.reasoning), sent)


def reasoning_fields(target, cap):
    if target.reasoning is None:
        return {}
    fields, why = profiles.reasoning_plan(target.name, target.model, target.reasoning, cap)
    if why and _note_once(target.name, target.model, why):
        logger.warning('the reasoning setting (%s) is ignored for %s %s: %s', target.reasoning, target.name, target.model or '(default model)', why)
    return fields


def structured_levels(target, schema):
    """The structured-output levels to try, best first, or () when this request carries no schema or this provider is not sent one."""
    profile = target.profile
    if not schema or target.structured_mode == 'off' or not profile.structured:
        return ()
    if not profile.structured_default and target.structured_mode != 'all':
        return ()
    levels = profile.structured
    cached = _STRUCTURED.get((target.name, target.base_url, target.model))
    if cached and cached[0] > time.time() and cached[1] in levels:
        return levels[levels.index(cached[1]):]
    return levels


def _refused_structure(error):
    return error.http_status in (400, 422) and bool(_NAMES_STRUCTURE.search(error.hint or ''))


def _openai_options(target, options, factor):
    out = {}
    cap = reply_limit(target, options, factor)
    if cap:
        host = (urllib.parse.urlsplit(_openai_base(target)).hostname or '').lower()
        out['max_completion_tokens' if host == 'api.openai.com' else 'max_tokens'] = cap
    if target.profile.temperature_ok and options.get('temperature') is not None:
        out['temperature'] = options['temperature']
    if target.profile.seed_ok and options.get('seed') is not None:
        out['seed'] = options['seed']
    return {**out, **reasoning_fields(target, cap)}


def _keep_alive_value(text):
    """Ollama reads a string as a Go duration, which cannot say "unload now" or "never unload": those go as the integers 0 and -1."""
    return int(text) if re.fullmatch(r'-?\d+', text) else text


def _ollama_options(target, options, factor):
    out = {}
    cap = reply_limit(target, options, factor)
    if cap:
        out['num_predict'] = cap
    if target.context_tokens:
        out['num_ctx'] = target.context_tokens
    for key, allowed in (('temperature', target.profile.temperature_ok), ('seed', target.profile.seed_ok)):
        if allowed and options.get(key) is not None:
            out[key] = options[key]
    keep = {'keep_alive': _keep_alive_value(target.keep_alive)} if target.keep_alive else {}
    return {**({'options': out} if out else {}), **keep, **reasoning_fields(target, cap)}


def _anthropic_text(data):
    if not isinstance(data, dict):
        raise ModelError('unexpected anthropic response shape', 'provider_shape')
    if data.get('stop_reason') == 'max_tokens':
        raise ModelError('anthropic response exceeded the output token limit', 'output_truncated', stop_reason='max_tokens')
    try:
        answer = ''.join(b.get('text', '') for b in data['content'] if b.get('type') == 'text')
    except (KeyError, TypeError, AttributeError):
        raise ModelError('unexpected anthropic response shape', 'provider_shape') from None
    if not answer.strip():
        raise ModelError('anthropic response contained no text', 'empty_response', stop_reason=str(data.get('stop_reason') or '')[:40])
    return answer


def _openai_text(data, name):
    try:
        choice = data['choices'][0]
        text = choice['message']['content']
    except (KeyError, IndexError, TypeError):
        raise ModelError(f'unexpected {name} response shape', 'provider_shape') from None
    if isinstance(choice, dict) and choice.get('finish_reason') == 'length':
        raise ModelError(f'{name} response exceeded the output token limit', 'output_truncated', stop_reason='length')
    if not isinstance(text, str) or not text.strip():
        reason = choice.get('finish_reason') if isinstance(choice, dict) else None
        raise ModelError(f'{name} response contained no text', 'empty_response', stop_reason=str(reason or '')[:40])
    return text


def _ollama_text(data):
    try:
        text = data['message']['content']
    except (KeyError, TypeError):
        raise ModelError('unexpected ollama response shape', 'provider_shape') from None
    if data.get('done_reason') == 'length':
        raise ModelError('ollama response exceeded the output token limit', 'output_truncated', stop_reason='length')
    if not isinstance(text, str) or not text.strip():
        raise ModelError('ollama response contained no text', 'empty_response', stop_reason=str(data.get('done_reason') or '')[:40])
    return text


def _text(target, data):
    transport = target.profile.transport
    if transport == 'anthropic':
        return _anthropic_text(data)
    if transport == 'ollama':
        return _ollama_text(data)
    return _openai_text(data, target.name)


def _usage(target, data):
    """``(input, output, cache read, cache write)`` tokens of one answer, None where the provider did not say."""
    def number(value):
        try:
            value = int(value)
            return value if value >= 0 else None
        except (TypeError, ValueError):
            return None
    if not isinstance(data, dict):
        return None, None, None, None
    raw = data.get('usage') or {'prompt_tokens': data.get('prompt_eval_count'), 'completion_tokens': data.get('eval_count')}
    if not isinstance(raw, dict):
        return None, None, None, None
    if target.name == 'anthropic':
        return tuple(number(raw.get(key)) for key in ('input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens'))
    details = raw.get('prompt_tokens_details') if isinstance(raw.get('prompt_tokens_details'), dict) else {}
    return (number(raw.get('prompt_tokens') if 'prompt_tokens' in raw else raw.get('input_tokens')),
            number(raw.get('completion_tokens') if 'completion_tokens' in raw else raw.get('output_tokens')),
            number(details.get('cached_tokens')), None)


def _request(target, system, user, schema, options, image, factor, level):
    """``(url, headers, body)`` of one completion at structured level ``level``."""
    transport, model = target.profile.transport, target.model
    if transport == 'anthropic':
        cap = reply_limit(target, options, factor)
        if image:
            content = [{'type': 'image', 'source': {'type': 'base64', 'media_type': image['media_type'], 'data': image['data']}},
                       {'type': 'text', 'text': user}]
        else:
            content = user
        body = {'model': model, 'max_tokens': cap, 'system': system, 'messages': [{'role': 'user', 'content': content}],
                **reasoning_fields(target, cap)}
        return _anthropic_url(target), _headers(target), body
    if transport == 'ollama':
        message = {'role': 'user', 'content': user, **({'images': [image['data']]} if image else {})}
        body = {'model': model, 'stream': False, 'messages': [{'role': 'system', 'content': system}, message],
                **_ollama_options(target, options, factor)}
        if level == 'json_schema':
            body['format'] = schema
        elif level == 'json':
            body['format'] = 'json'
        return f'{target.base_url.rstrip("/")}/api/chat', {}, body
    if image:
        url = f"data:{image['media_type']};base64,{image['data']}"
        content = [{'type': 'text', 'text': user}, {'type': 'image_url', 'image_url': {'url': url}}]
    else:
        content = user
    body = {'model': model, 'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': content}],
            **_openai_options(target, options, factor)}
    if level == 'json_schema':
        body['response_format'] = {'type': 'json_schema', 'json_schema': {'name': str(options.get('schema_name') or 'answer')[:40],
                                                                           'strict': True, 'schema': schema}}
    elif level == 'json_object':
        body['response_format'] = {'type': 'json_object'}
    if target.name == 'openrouter' and level != 'none':
        body['provider'] = {'require_parameters': True}  # only an endpoint that takes the field, not one that ignores it
    return f'{_openai_base(target)}/chat/completions', _headers(target), body


def _stop_reason(data):
    """The provider's stop reason of one answer (``end_turn``, ``max_tokens``, ``length``, ``stop``, ...), a short plain word or ''."""
    if not isinstance(data, dict):
        return ''
    reason = data.get('stop_reason') or data.get('done_reason')
    if not reason and isinstance(data.get('choices'), list) and data['choices'] and isinstance(data['choices'][0], dict):
        reason = data['choices'][0].get('finish_reason')
    reason = str(reason or '')
    return reason if re.fullmatch(r'[a-z_]{1,24}', reason) else ''


def _attempt(target, system, user, schema, options, image, factor, calls):
    """One completion as the server's ``complete()`` made it (stepping down the structured ladder when the server refuses a level or answers
    nothing under it); one entry in ``calls`` with its usage, outcome and time."""
    record = {'status': 'failed', 'category': '', 'model': target.model}
    started, tick, last = time.time(), time.monotonic(), {}
    try:
        levels = () if image else structured_levels(target, schema)
        levels = levels or ('none',)
        while True:
            url, headers, body = _request(target, system, user, schema, options, image, factor, levels[0])
            try:
                last['data'] = _http(target.name, url, headers, body, target.request_timeout, target.connect_timeout, MAX_COMPLETION_BYTES)
                if levels[0] != 'none' and len(levels) > 1:
                    _text(target, last['data'])  # an empty answer under a constraint is a reason to ask without it
                break
            except ModelError as error:
                if len(levels) > 1 and levels[0] != 'none' and (_refused_structure(error) or error.category == 'empty_response'):
                    _STRUCTURED[(target.name, target.base_url, target.model)] = (time.time() + 3600, levels[1])
                    logger.info('%s does not take structured output (%s); using %s', target.name, levels[0], levels[1])
                    levels = levels[1:]
                    continue
                raise
        text = _text(target, last['data'])
        if target.profile.transport == 'ollama':
            used = last['data'].get('prompt_eval_count') if isinstance(last['data'], dict) else None
            if target.context_tokens and isinstance(used, int) and used >= 0.95 * target.context_tokens:
                logger.warning('ollama read %d prompt tokens of a %d token context window: the start of the prompt may have been cut; raise '
                               'the context setting (Settings, AI model)', used, target.context_tokens)
        record['status'] = 'succeeded'
        return text
    except ModelError as error:
        record['category'] = error.category
        raise
    finally:
        counts = _usage(target, last.get('data'))
        actual = last.get('data', {}).get('model') if isinstance(last.get('data'), dict) else ''
        record.update(input_tokens=counts[0], output_tokens=counts[1], cache_read_tokens=counts[2], cache_write_tokens=counts[3],
                      stop_reason=_stop_reason(last.get('data')), actual_model=str(actual or '')[:200], started_at=int(started), duration_ms=max(0, int((time.monotonic() - tick) * 1000)))
        calls.append(record)


def complete(block, system, user, schema=None, options=None, image=None):
    """One answer for a pipeline job: ``(text, calls, model)``. ``block`` is the job block of the server's configuration, ``options`` the
    job's (``temperature`` and ``seed`` pinned for a self-hosted server, ``max_tokens`` the stage's own answer room, ``retry_truncated``,
    ``schema_name``), ``image`` ``{media_type, data (base64)}``. A reply cut off at a limit that was sent is asked ONCE more with a larger
    limit (``profiles.retry_total``: ``RETRY_FACTOR`` times the answer room plus the thinking reserve, never past ``RETRY_CEILING``), for every
    stage unless the job says ``retry_truncated: false``; no third request is ever made. Both requests are entries in ``calls``, and the
    first is marked ``retried`` (it was cut off and was asked again: the server records it as ``truncated_retried``) so only a cut-off that survived the retry counts as a failure.
    Raises ModelError, with the calls made so far in ``error.calls``."""
    options = dict(options or {})
    calls = []
    try:
        target = Target(block)
        try:
            resolve_model(target)
        except ModelError as error:
            calls.append({'status': 'failed', 'category': error.category, 'model': target.model, 'started_at': int(time.time()), 'duration_ms': 0})
            raise
        try:
            return _attempt(target, system, user, schema, options, image, None, calls), calls, target.model
        except ModelError as error:
            if error.category != 'output_truncated' or options.get('retry_truncated') is False:
                raise
            sent, why = reply_limit(target, options), error.stop_reason
            bigger = retry_limit(target, options, sent) if sent else 0
            if not bigger:  # nothing was sent to lengthen, or it is at the ceiling already
                raise
        logger.info('%s: reply cut off at %s tokens (stop reason %s); asking once more with %s', target.name, sent, why, bigger)
        calls[-1]['retried'] = True  # the server records it as recovered, not failed, once it sees the retry
        return _attempt(target, system, user, schema, {**options, '_reply_limit': bigger}, image, None, calls), calls, target.model
    except ModelError as error:
        error.calls = calls
        raise
