"""AI model servers and agent dashboards, read from outside: the version source entries for Ollama, llama.cpp's ``llama-server``, vLLM, LM Studio,
KoboldCpp, Gradio, Langflow, ComfyUI, LiteLLM, the Ray dashboard, Open WebUI, Flowise, AnythingLLM, the OpenClaw gateway and Hermes Agent's
dashboard (``version_catalogue.SOURCES`` adds them).

Why. These servers are often started on a laptop or a GPU box with their default bind changed to ``0.0.0.0`` and no authentication: whoever reaches
one can run prompts on its hardware, pull, push or delete its models (Ollama), run code through a workflow or a job (ComfyUI, Ray, Langflow,
Flowise) or drive an agent that runs tools on the host (OpenClaw, Hermes Agent, AnythingLLM). Several have known exploited flaws (Ollama's
CVE-2024-37032 "Probllama", Langflow's CVE-2025-3248 on CISA's KEV list, Ray's CVE-2023-48022 "ShadowRay", OpenClaw's CVE-2026-25253).

What is asked. Each entry is the product's own status or metadata endpoint, a GET of a fixed path, asked only on the product's default port when
the port scan left its service generic (or named the web framework the product runs on: ``APP_SERVERS``), or of a host already identified as the
product (a technology, a port product, a template check's detection). Never a prompt, a chat, a completion, an embedding, a model pull or delete, a tool
call, a WebSocket (the OpenClaw gateway's is never opened) or a login; never a token or a password. The Sentinel's ``version_read`` returns only
the named JSON fields (``models.0.name``: the first model's name), an excerpt from a literal, or the ``*_info`` metric samples.

How an answer is believed. Every reader takes only the exact shape its product answers with: Ollama's ``Ollama is running`` or its tags list,
``owned_by: llamacpp`` or llama.cpp's ``Server`` header and ``/props``, ``owned_by: vllm`` or a ``vllm:`` metric, ``"package": "Langflow"``, a
Control UI title. A thin answer (vLLM's one-field ``/version``, Flowise's) is believed only next to such a signal, so a catch-all that answers
every path with the same JSON or page gives nothing (the role the control path plays for the other entries).

Exposures. An entry's exposure is rated by what the answer shows is open (``Exposure.rate``): an agent that runs tools with no sign-in or a
Ray cluster that takes jobs from anyone is critical; Ollama (pull, push, delete) and a workflow runner (ComfyUI, Langflow, Flowise), and a
reachable agent dashboard that asks for a sign-in, are high; an inference API that only answers prompts (llama.cpp, vLLM, LM Studio, KoboldCpp)
is medium. An answer that shows the server asks for a key (a 401, ``protected``, ``auth_required``) files nothing and closes an earlier finding.

Untrusted text. Model names, ids and titles come from the host: only names made of ``_NAME`` characters (no space, no markup) are kept, at most
``MAX_NAMES`` and ``MAX_NAME`` characters each; the rest are counted, never shown.
"""
import re

MAX_NAMES = 10
MAX_NAME = 60
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$')  # a model name or id: library/llama3:8b, meta-llama/Llama-3.1-8B-Instruct
# the web frameworks these servers run on, as the port scan names a port's product: the entry's own port still warrants it (a generic service would)
APP_SERVERS = r'uvicorn|hypercorn|starlette|fastapi|aiohttp|express|node\.?js|werkzeug|simplehttp|basehttp|python'
OLLAMA_NAMES = tuple(f'models.{i}.name' for i in range(MAX_NAMES))
OPENAI_IDS = tuple(f'data.{i}.id' for i in range(8))


def _catalogue():
    from cveFeed import version_catalogue
    return version_catalogue


def _ok(answer, statuses=(200,)):
    return isinstance(answer, dict) and not answer.get('error') and answer.get('status') in statuses


def _doc(answer):
    return _catalogue()._json(answer)


def _text(answer):
    return _catalogue().clip(answer.get('text'), 1024) if _ok(answer) else ''


def _str(doc, key):
    value = (doc or {}).get(key)
    return value.strip() if isinstance(value, str) and value.strip() else ''


def _array(doc, key):
    """The size of the array ``key`` names in a JSON read, else None."""
    value = (doc or {}).get(key)
    return value['size'] if isinstance(value, dict) and value.get('type') == 'array' and isinstance(value.get('size'), int) else None


def _header(answers, name):
    for answer in answers:
        if isinstance(answer, dict) and not answer.get('error') and isinstance(answer.get('headers'), dict):
            value = answer['headers'].get(name)
            if isinstance(value, str) and value.strip():
                return _catalogue().clip(value, 80)
    return ''


def names(doc, keys):
    """The names ``keys`` read, each one ``_NAME`` allows, clipped; a name with a space, markup or a control character is never shown."""
    out = []
    for key in keys:
        value = (doc or {}).get(key)
        if isinstance(value, str) and _NAME.match(value.strip()):
            out.append(value.strip()[:MAX_NAME])
    return list(dict.fromkeys(out))[:MAX_NAMES]


def listed(count, shown, what='model'):
    """``3 models: a, b`` (the names that were safe to show), for a finding's evidence."""
    if count is None:
        return ''
    text = f'{count} {what}{"s" if count != 1 else ""}'
    return text + (': ' + ', '.join(shown) if shown else '')


def _version(raw):
    catalogue = _catalogue()
    version = catalogue.version_of(raw, keep_suffix=False)
    return '' if version in ('0.0.0', '0.0') else version


def _reading(component, label, version, evidence, url, source):
    return _catalogue().reading(component, label, version, evidence=evidence, url=url, source=source)


# ----------------------------------------------------------------------------- inference servers

def ollama_parts(answers):
    """``(identified, version, model count, model names, raw version)`` of the Ollama entry's answers."""
    root, ver, tags = (list(answers) + [None, None, None])[:3]
    doc, tag_doc = _doc(ver), _doc(tags)
    raw = _str(doc, 'version')
    count = _array(tag_doc, 'models')
    said = _text(root) == 'Ollama is running'  # server/routes.go: GET / answers exactly this, text/plain
    return (said or (bool(raw) and count is not None)), _version(raw), count, names(tag_doc, OLLAMA_NAMES), raw


def read_ollama(answers):
    identified, version, count, shown, raw = ollama_parts(answers)
    if not identified:
        return []
    evidence = f'Ollama {raw or "(version not stated)"} answered /api/version' if raw else 'GET / answered "Ollama is running"'
    if count is not None:
        evidence += f'; /api/tags lists {listed(count, shown)}'
    return [_reading('ollama', 'Ollama', version, evidence, '/api/version' if raw else '/', 'ollama')]


def rate_ollama(answers):
    """Ollama has no authentication: an answer of its own API means pull, push, create, copy and delete answer too. High. A root page that says
    "Ollama is running" while the API asks for a key (a proxy in front) is not open."""
    identified, _version, count, _shown, raw = ollama_parts(answers)
    return 3 if identified and (raw or count is not None) else None


_LLAMA_BUILD = re.compile(r'^b(\d{1,6})(?:-[0-9a-f]{4,40})?$')


def llamacpp_parts(answers):
    props, models = (list(answers) + [None, None])[:2]
    doc, listing = _doc(props), _doc(models)
    shaped = doc is not None and isinstance(doc.get('total_slots'), int) and isinstance(doc.get('default_generation_settings'), dict)
    owned = _str(listing, 'data.0.owned_by') == 'llamacpp'  # tools/server: every model of /v1/models is owned_by "llamacpp"
    header = _header([props, models], 'server') == 'llama.cpp'  # tools/server sets "Server: llama.cpp" on every answer, a 401 included
    build = _LLAMA_BUILD.match(_str(doc, 'build_info'))
    # the build tag (b5662) is what llama.cpp's advisories name ("< b5662"), but the feed's ranges do not read it as a version yet: the build is
    # evidence, and the reading states no version (the product is a lead, never a version match on a number it does not mean)
    return {'identified': shaped or owned or header, 'open': shaped or owned, 'version': '',
            'build': build.group(0) if build else '', 'ids': names(listing, OPENAI_IDS), 'count': _array(listing, 'data') if owned else None}


def read_llamacpp(answers):
    got = llamacpp_parts(answers)
    if not got['identified']:
        return []
    evidence = f'llama.cpp server, build {got["build"]}' if got['build'] else 'llama.cpp server (Server: llama.cpp)'
    if got['open']:
        evidence += ' answered /props or /v1/models without a key' + (f'; {listed(got["count"], got["ids"])}' if got['count'] is not None else '')
    return [_reading('llama.cpp', 'llama.cpp', got['version'], evidence, '/props', 'llama-cpp')]


def rate_llamacpp(answers):
    """llama-server keeps only /health and its web page public when an API key is set: /props or /v1/models answering means no key. Medium."""
    return 2 if llamacpp_parts(answers)['open'] else None


def vllm_parts(answers):
    ver, models, metrics = (list(answers) + [None, None, None])[:3]
    doc, listing = _doc(ver), _doc(models)
    lines = metrics.get('lines') if _ok(metrics) and isinstance(metrics.get('lines'), list) else []
    owned = _str(listing, 'data.0.owned_by') == 'vllm'  # vllm.entrypoints.openai: ModelCard.owned_by defaults to "vllm"
    metric = any(isinstance(line, str) and line.startswith('vllm:') for line in lines)  # vllm:cache_config_info, vllm:lora_requests_info
    return {'identified': owned or metric, 'open': owned, 'raw': _str(doc, 'version'), 'ids': names(listing, OPENAI_IDS),
            'count': _array(listing, 'data') if owned else None}


def read_vllm(answers):
    got = vllm_parts(answers)
    if not got['identified']:
        return []  # /version alone is a one-field JSON any catch-all could give: believed only next to vLLM's own model list or metrics
    evidence = f'vLLM {got["raw"]} answered /version' if got['raw'] else 'vLLM metrics or model list'
    if got['open']:
        evidence += f'; /v1/models answered without a key: {listed(got["count"], got["ids"])}'
    return [_reading('vllm', 'vLLM', _version(got['raw']), evidence, '/version', 'vllm')]


def rate_vllm(answers):
    """vLLM's --api-key guards every /v1 route and leaves /version, /health and /metrics public: /v1/models answering means no key. Medium."""
    return 2 if vllm_parts(answers)['open'] else None


_LMSTUDIO_TYPES = ('llm', 'vlm', 'embeddings')


def lmstudio_parts(answers):
    listing = _doc(answers[0] if answers else None)
    shaped = (_str(listing, 'object') == 'list' and _str(listing, 'data.0.type') in _LMSTUDIO_TYPES
              and bool(_str(listing, 'data.0.compatibility_type')) and bool(_str(listing, 'data.0.state')))
    return shaped, _array(listing, 'data'), names(listing, OPENAI_IDS)


def read_lmstudio(answers):
    shaped, count, ids = lmstudio_parts(answers)
    if not shaped:
        return []
    return [_reading('lm-studio', 'LM Studio', '', f'LM Studio /api/v0/models answered without a key: {listed(count, ids)}', '/api/v0/models',
                     'lm-studio')]


def rate_lmstudio(answers):
    return 2 if lmstudio_parts(answers)[0] else None


def koboldcpp_parts(answers):
    doc = _doc(answers[0] if answers else None)
    protected = doc.get('protected') if doc else None
    return _str(doc, 'result') == 'KoboldCpp', _str(doc, 'version'), protected


def read_koboldcpp(answers):
    identified, raw, protected = koboldcpp_parts(answers)
    if not identified:
        return []
    evidence = f'/api/extra/version: KoboldCpp {raw or "(no version)"}, ' + ('password protected' if protected is True else 'no password')
    return [_reading('koboldcpp', 'KoboldCpp', _version(raw), evidence, '/api/extra/version', 'koboldcpp')]


def rate_koboldcpp(answers):
    identified, _raw, protected = koboldcpp_parts(answers)
    return 2 if identified and protected is False else None


# ----------------------------------------------------------------------------- apps and workflow runners

_TITLE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._()&-]{0,59}$')


def read_gradio(answers):
    """A Gradio app's ``/config`` (no sign-in configured: with one it is behind ``login_check``): the Gradio release it runs."""
    doc = _doc(answers[0] if answers else None)
    raw = _str(doc, 'version')
    if not (raw and _str(doc, 'mode') and _array(doc, 'components') is not None):
        return []
    title = _str(doc, 'title')
    evidence = f'/config: Gradio {raw}, mode {_str(doc, "mode")[:20]}' + (f', app "{title}"' if _TITLE.match(title) else '')
    return [_reading('gradio', 'Gradio', _version(raw), evidence, '/config', 'gradio')]


def read_langflow(answers):
    doc = _doc(answers[0] if answers else None)
    if _str(doc, 'package') not in ('Langflow', 'Langflow Nightly'):  # langflow/utils/version.py get_version_info
        return []
    raw = _str(doc, 'main_version') or _str(doc, 'version')
    return [_reading('langflow', 'Langflow', _version(raw), f'/api/v1/version: {_str(doc, "package")} {raw}', '/api/v1/version', 'langflow')]


_PYTHON = re.compile(r'^(\d\.\d{1,2}\.\d{1,3})\b')


def read_comfyui(answers):
    """ComfyUI's ``/system_stats`` (server.py): its release (``system.comfyui_version``, newer releases) and the Python it runs. ``system.argv``
    (the command line) is never asked."""
    doc = _doc(answers[0] if answers else None)
    python = _str(doc, 'system.python_version')
    if not (python and _str(doc, 'system.os') and _array(doc, 'devices') is not None):
        return []
    raw = _str(doc, 'system.comfyui_version')
    out = [_reading('comfyui', 'ComfyUI', _version(raw), f'/system_stats: ComfyUI {raw or "(version not stated)"}, {_array(doc, "devices")} device(s)',
                    '/system_stats', 'comfyui')]
    found = _PYTHON.match(python)
    if found:
        out.append(_catalogue().reading('python', 'Python', found.group(1), kind='runtime', evidence=f'ComfyUI /system_stats python_version {found.group(1)}',
                                        url='/system_stats', source='comfyui'))
    return out


def rate_workflows(answers):
    """ComfyUI, Langflow and Flowise run what a workflow says (ComfyUI's custom nodes, Langflow's and Flowise's code components): reachable is high."""
    return 3


def litellm_parts(answers):
    ready, models = (list(answers) + [None, None])[:2]
    doc, listing = _doc(ready), _doc(models)
    raw = _str(doc, 'litellm_version')
    identified = bool(raw) and bool(_str(doc, 'status'))  # proxy/health_endpoints: /health/readiness is unauthenticated
    open_ = identified and _str(listing, 'object') == 'list' and _array(listing, 'data') is not None
    return identified, raw, open_, _array(listing, 'data'), names(listing, OPENAI_IDS)


def read_litellm(answers):
    identified, raw, open_, count, ids = litellm_parts(answers)
    if not identified:
        return []
    evidence = f'/health/readiness: LiteLLM {raw}' + (f'; /v1/models answered without a key: {listed(count, ids)}' if open_ else '')
    return [_reading('litellm', 'LiteLLM', _version(raw), evidence, '/health/readiness', 'litellm')]


def rate_litellm(answers):
    """A LiteLLM proxy with no master key answers /v1/models: anyone can spend the provider keys it holds and use its management routes. High."""
    return 3 if litellm_parts(answers)[2] else None


def read_ray(answers):
    doc = _doc(answers[0] if answers else None)
    raw = _str(doc, 'ray_version')
    if not (raw and _str(doc, 'ray_commit') and _str(doc, 'version')):  # dashboard/modules/version.py VersionResponse (session_name never asked)
        return []
    return [_reading('ray', 'Ray', _version(raw), f'/api/version: Ray {raw}, Jobs API version {_str(doc, "version")[:10]}', '/api/version', 'ray-dashboard')]


def rate_ray(answers):
    """With token authentication on (Ray 2.52 and later) /api/version answers 401; an answer means the Jobs API takes jobs from anyone. Critical."""
    return 4 if read_ray(answers) else None


# ----------------------------------------------------------------------------- chat front ends and agents

def openwebui_parts(answers):
    doc = _doc(answers[0] if answers else None)
    identified = 'Open WebUI' in _str(doc, 'name') and bool(_str(doc, 'version')) and doc.get('status') is True  # main.py get_app_config
    return identified, doc or {}


def read_openwebui(answers):
    identified, doc = openwebui_parts(answers)
    if not identified:
        return []
    auth, signup, onboarding = doc.get('features.auth'), doc.get('features.enable_signup'), doc.get('onboarding')
    said = ('no sign-in (WEBUI_AUTH off)' if auth is False else 'no account yet: the first sign-up becomes the administrator' if onboarding is True
            else 'open sign-up' if signup is True else 'sign-in required')
    return [_reading('open-webui', 'Open WebUI', _version(_str(doc, 'version')), f'/api/config: Open WebUI {_str(doc, "version")}, {said}',
                     '/api/config', 'open-webui')]


def rate_openwebui(answers):
    """No sign-in, or no administrator yet (the first sign-up becomes one, and an administrator runs Python tools on the server): critical. Open
    sign-up: medium (a new account waits for approval by default). Sign-in only: nothing to report."""
    identified, doc = openwebui_parts(answers)
    if not identified:
        return None
    if doc.get('features.auth') is False or doc.get('onboarding') is True:
        return 4
    return 2 if doc.get('features.enable_signup') is True else None


def read_flowise(answers):
    ver, page = (list(answers) + [None, None])[:2]
    if not _text(page).startswith('<title>Flowise'):  # "Flowise - Build AI Agents, Visually": the one-field /api/v1/version is believed only here
        return []
    raw = _str(_doc(ver), 'version')
    return [_reading('flowise', 'Flowise', _version(raw), f'Flowise {raw or "(version not stated)"}', '/api/v1/version', 'flowise')]


def anythingllm_parts(answers):
    doc = _doc(answers[0] if answers else None) or {}
    auth, multi = doc.get('results.RequiresAuth'), doc.get('results.MultiUserMode')  # server/models/systemSettings.js currentSettings
    return isinstance(auth, bool) and isinstance(multi, bool), auth, multi


def read_anythingllm(answers):
    identified, auth, multi = anythingllm_parts(answers)
    if not identified:
        return []
    said = 'multi-user mode' if multi else 'a password' if auth else 'no password and no user accounts'
    return [_reading('anythingllm', 'AnythingLLM', '', f'/api/setup-complete: AnythingLLM with {said}', '/api/setup-complete', 'anythingllm')]


def rate_anythingllm(answers):
    """No password and no accounts: anyone can use its workspaces, documents and agents (which run tools). Critical."""
    identified, auth, multi = anythingllm_parts(answers)
    return 4 if identified and not auth and not multi else None


_CONTROL_TITLE = re.compile(r'^<title>(OpenClaw|Clawdbot|Moltbot) Control</title>')
_CONTROL_BUILD = re.compile(r'^OPENCLAW_CONTROL_UI_BUILD_INFO=\{"version":"(\d{4}\.\d{1,2}\.\d{1,2}(?:-\d{1,3})?)"')


def read_openclaw(answers):
    """The OpenClaw gateway's Control UI (formerly Clawdbot, Moltbot), served on the gateway's own port: its title, and the build information
    recent releases put in the page. The gateway's WebSocket is never opened, so whether it asks for its token is not read."""
    title, build = (list(answers) + [None, None])[:2]
    named = _CONTROL_TITLE.match(_text(title))
    if not named:
        return []
    found = _CONTROL_BUILD.match(_text(build))
    raw = found.group(1) if found else ''
    evidence = f'{named.group(1)} Control UI' + (f', build {raw}' if raw else ' (build not stated)')
    return [_reading('openclaw', 'OpenClaw', _version(raw), evidence, '/', 'openclaw')]


def rate_openclaw(answers):
    """The gateway runs its agent's tools on the host. Its sign-in is on the WebSocket, never opened here: reachable is high."""
    return 3 if read_openclaw(answers) else None


def hermes_parts(answers):
    doc = _doc(answers[0] if answers else None) or {}
    identified = (bool(_str(doc, 'version')) and bool(_str(doc, 'release_date')) and isinstance(doc.get('auth_required'), bool)
                  and isinstance(doc.get('gateway_running'), bool))  # hermes_cli/web_routers/status.py: public /api/status
    return identified, doc


def read_hermes(answers):
    identified, doc = hermes_parts(answers)
    if not identified:
        return []
    raw = _str(doc, 'version')
    said = 'sign-in required' if doc['auth_required'] else 'no sign-in'
    return [_reading('hermes-agent', 'Hermes Agent', _version(raw), f'/api/status: Hermes Agent {raw} ({_str(doc, "release_date")[:12]}), {said}',
                     '/api/status', 'hermes-agent')]


def rate_hermes(answers):
    """No sign-in: anyone drives the agent and its tools. A sign-in page on a public address: high."""
    identified, doc = hermes_parts(answers)
    if not identified:
        return None
    return 3 if doc['auth_required'] else 4


# ----------------------------------------------------------------------------- the entries

_REMEDIATION = ('Bind it to 127.0.0.1 (or a private interface), or put it behind a reverse proxy or VPN that authenticates every request, and '
                'block the port at the firewall.')


def sources():
    """The AI model server and agent dashboard entries of the version source catalogue."""
    from cveFeed.version_catalogue import Exposure, Request, Source

    def exposure(template, name, severity, description, impact, remediation=_REMEDIATION, twins=(), rate=None):
        return Exposure(template, name, severity, description, impact, remediation, twins=twins, rate=rate)

    return (
        Source('ollama', 'Ollama', 'product',
               (Request('/', read='text'), Request('/api/version', fields=('version',)), Request('/api/tags', fields=('models',) + OLLAMA_NAMES)),
               read_ollama, leads=r'\bollama\b', ports=(11434,), servers=APP_SERVERS,
               verified='https://github.com/ollama/ollama/blob/main/server/routes.go (GET / "Ollama is running", /api/version, /api/tags ListHandler)',
               exposure=exposure('ollama-api-exposed', 'Ollama API open without authentication', 3,
                                 'An Ollama server answers its API from the network. Ollama has no authentication of its own.',
                                 'Anyone who reaches it can run prompts on its hardware and pull, push, copy, create and delete its models; older releases '
                                 'are open to path traversal through a model pull (CVE-2024-37032).',
                                 'Set OLLAMA_HOST=127.0.0.1 (the default), or put the API behind a reverse proxy that authenticates every request, and '
                                 'block port 11434 at the firewall.', rate=rate_ollama)),
        Source('llama-cpp', 'llama.cpp server', 'product',
               (Request('/props', fields=('build_info', 'total_slots', 'default_generation_settings')),
                Request('/v1/models', fields=('object', 'data', 'data.0.owned_by') + OPENAI_IDS)),
               read_llamacpp, leads=r'llama[._ -]?cpp|llama-server', ports=(8080,), servers=APP_SERVERS,
               verified='https://github.com/ggml-org/llama.cpp/tree/master/tools/server (Server: llama.cpp; /props build_info; /v1/models owned_by '
                        'llamacpp; with --api-key only /health and the web page are public)',
               note='the build tag (b5662) is kept as evidence: the feed\'s ranges do not read it as a version yet; the model\'s path is never asked',
               exposure=exposure('llamacpp-api-exposed', 'llama.cpp server answers without an API key', 2,
                                 'A llama.cpp server (llama-server) answers its API from the network without an API key.',
                                 'Anyone who reaches it can run prompts and completions on its hardware and read its model and settings.',
                                 'Start llama-server with --api-key, bind it to 127.0.0.1 (--host), and block its port at the firewall.',
                                 rate=rate_llamacpp)),
        Source('vllm', 'vLLM', 'product',
               (Request('/version', fields=('version',)), Request('/v1/models', fields=('object', 'data', 'data.0.owned_by') + OPENAI_IDS),
                Request('/metrics', read='metrics')),
               read_vllm, leads=r'\bvllm\b', ports=(8000,), servers=APP_SERVERS,
               verified='https://github.com/vllm-project/vllm/blob/v0.10.0/vllm/entrypoints/openai/api_server.py (/version; --api-key guards /v1 '
                        'only); serving_models.py ModelCard owned_by "vllm"; engine/metrics.py vllm:cache_config_info',
               exposure=exposure('vllm-api-exposed', 'vLLM OpenAI-compatible API answers without an API key', 2,
                                 'A vLLM server answers its OpenAI-compatible API from the network without an API key.',
                                 'Anyone who reaches it can run prompts on its GPUs and read which models it serves.',
                                 'Start vLLM with --api-key (or VLLM_API_KEY), bind it to 127.0.0.1 (--host), and block its port at the firewall.',
                                 twins=('vllm-openai-api-exposed',), rate=rate_vllm)),
        Source('lm-studio', 'LM Studio', 'product', (Request('/api/v0/models', fields=(
                   'object', 'data', 'data.0.type', 'data.0.compatibility_type', 'data.0.state') + OPENAI_IDS[:7]),),
               read_lmstudio, leads=r'lm ?studio', ports=(1234,), servers=APP_SERVERS,
               verified='https://lmstudio.ai/docs/developer/rest/endpoints (GET /api/v0/models: type, compatibility_type, state per model)',
               note='LM Studio states no version over its API',
               exposure=exposure('lmstudio-api-exposed', 'LM Studio server answers without authentication', 2,
                                 'LM Studio\'s local server answers its API from the network without a token.',
                                 'Anyone who reaches it can run prompts on the machine and load or unload its models.',
                                 'Turn off "Serve on Local Network" or require authentication in LM Studio\'s server settings, and block port 1234.',
                                 rate=rate_lmstudio)),
        Source('koboldcpp', 'KoboldCpp', 'product', (Request('/api/extra/version', fields=('result', 'version', 'protected')),),
               read_koboldcpp, leads=r'kobold', ports=(5001,), servers=APP_SERVERS,
               verified='https://github.com/LostRuins/koboldcpp/blob/concedo/koboldcpp.py (/api/extra/version: result "KoboldCpp", version, protected)',
               exposure=exposure('koboldcpp-api-exposed', 'KoboldCpp answers without a password', 2,
                                 'A KoboldCpp server answers its API from the network and says it has no password (protected: false).',
                                 'Anyone who reaches it can run prompts and generate images or audio on its hardware.',
                                 'Start KoboldCpp with --password, bind it to 127.0.0.1 (--host), and block port 5001.', rate=rate_koboldcpp)),
        Source('gradio', 'Gradio app', 'product', (Request('/config', fields=('version', 'mode', 'title', 'components')),),
               read_gradio, leads=r'\bgradio\b|text[ -]generation[ -]web ?ui|stable[ -]diffusion[ -]web ?ui', ports=(7860,), servers=APP_SERVERS,
               verified='https://github.com/gradio-app/gradio/blob/main/gradio/blocks.py (get_config_file: version, mode, components); '
                        'routes.py (/config behind login_check)',
               note='the Gradio release an app runs (text-generation-webui, Stable Diffusion web UI); the app itself is not rated'),
        Source('langflow', 'Langflow', 'product', (Request('/api/v1/version', fields=('version', 'main_version', 'package')),),
               read_langflow, leads=r'langflow', ports=(7860,), servers=APP_SERVERS,
               verified='https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/utils/version.py (version, main_version, '
                        'package "Langflow")',
               exposure=exposure('langflow-exposed', 'Langflow reachable from the network', 3,
                                 'A Langflow server answers from the network.',
                                 'Langflow runs the Python code its flows and custom components carry; releases before 1.3.0 run code for anyone who '
                                 'asks (CVE-2025-3248, on CISA\'s KEV list), and with AUTO_LOGIN on every visitor is its superuser.',
                                 'Keep Langflow on a private network or behind an authenticating proxy, set LANGFLOW_AUTO_LOGIN=false, and upgrade.',
                                 twins=('langflow-api-exposure',), rate=rate_workflows)),
        Source('comfyui', 'ComfyUI', 'product',
               (Request('/system_stats', fields=('system.comfyui_version', 'system.python_version', 'system.os', 'devices')),),
               read_comfyui, leads=r'comfy ?ui', ports=(8188,), servers=APP_SERVERS,
               verified='https://github.com/comfyanonymous/ComfyUI/blob/master/server.py (/system_stats: system.comfyui_version, python_version, '
                        'os, devices; argv is never asked)',
               exposure=exposure('comfyui-exposed', 'ComfyUI reachable without authentication', 3,
                                 'A ComfyUI server answers from the network. ComfyUI has no authentication of its own.',
                                 'Anyone who reaches it can queue workflows on its GPUs, read its outputs and, with a node manager installed, install '
                                 'custom nodes: code that runs on the host.',
                                 'Start ComfyUI with --listen 127.0.0.1 (the default), or behind an authenticating proxy, and block port 8188.',
                                 rate=rate_workflows)),
        Source('litellm', 'LiteLLM proxy', 'product',
               (Request('/health/readiness', fields=('status', 'db', 'litellm_version')), Request('/v1/models', fields=('object', 'data') + OPENAI_IDS)),
               read_litellm, leads=r'litellm', ports=(4000,), servers=APP_SERVERS,
               verified='https://github.com/BerriAI/litellm/blob/main/litellm/proxy/health_endpoints/_health_endpoints.py (/health/readiness: '
                        'litellm_version, unauthenticated)',
               exposure=exposure('litellm-proxy-open', 'LiteLLM proxy answers without a key', 3,
                                 'A LiteLLM proxy answers its API from the network without a key (no master key is set).',
                                 'Anyone who reaches it can spend the provider API keys it holds and use its management routes.',
                                 'Set a master key (LITELLM_MASTER_KEY), keep the proxy off networks that do not need it, and block port 4000.',
                                 rate=rate_litellm)),
        Source('ray-dashboard', 'Ray dashboard', 'platform', (Request('/api/version', fields=('version', 'ray_version', 'ray_commit')),),
               read_ray, leads=r'^ray\b|ray[ _-](?:dashboard|project)|anyscale', ports=(8265,), servers=APP_SERVERS,
               verified='https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/version.py (VersionResponse); '
                        'http_server_head.py (with token authentication /api/version is not public)',
               exposure=exposure('ray-jobs-api-exposed', 'Ray dashboard and Jobs API open without authentication', 4,
                                 'A Ray dashboard answers its API from the network without a token.',
                                 'Anyone who reaches it can submit a job: code execution on the cluster (CVE-2023-48022, "ShadowRay", exploited in '
                                 'the wild).',
                                 'Turn on token authentication (RAY_AUTH_MODE=token, Ray 2.52 and later), keep the dashboard on 127.0.0.1 '
                                 '(--dashboard-host), and block port 8265.', twins=('ray-dashboard',), rate=rate_ray)),
        Source('open-webui', 'Open WebUI', 'product',
               (Request('/api/config', fields=('status', 'name', 'version', 'onboarding', 'features.auth', 'features.enable_signup')),),
               read_openwebui, leads=r'open[ -]?webui', ports=(3000, 8080), servers=APP_SERVERS,
               verified='https://github.com/open-webui/open-webui/blob/main/backend/open_webui/main.py (get_app_config: name, version, onboarding, '
                        'features.auth, features.enable_signup, public before sign-in)',
               exposure=exposure('openwebui-open-access', 'Open WebUI open to anyone', 4,
                                 'An Open WebUI instance answers from the network with no sign-in, with no administrator yet, or with open sign-up.',
                                 'With no sign-in or no administrator, anyone is (or becomes) its administrator, who can add Python tools and '
                                 'functions that run on the server and read every chat; with open sign-up anyone can ask for an account.',
                                 'Keep WEBUI_AUTH on, create the administrator account, turn sign-up off (ENABLE_SIGNUP=false) unless it is meant '
                                 'to be public, and keep the instance behind a VPN or an authenticating proxy.', rate=rate_openwebui)),
        Source('flowise', 'Flowise', 'product', (Request('/api/v1/version', fields=('version',)), Request('/', read='text', find='<title>')),
               read_flowise, leads=r'flowise', ports=(3000,), servers=APP_SERVERS,
               verified='https://github.com/FlowiseAI/Flowise/blob/main/packages/server/src/services/versions/index.ts ({version}); the UI\'s title '
                        '"Flowise - Build AI Agents, Visually"',
               exposure=exposure('flowise-exposed', 'Flowise reachable from the network', 3,
                                 'A Flowise server answers from the network.',
                                 'Flowise runs the code its agent flows carry (custom tools, MCP servers); several releases run it for anyone who '
                                 'asks (CVE-2025-59528), and older ones have no sign-in by default.',
                                 'Keep Flowise on a private network or behind an authenticating proxy, require sign-in, and upgrade.',
                                 twins=('flowise-chatflows-exposure',), rate=rate_workflows)),
        Source('anythingllm', 'AnythingLLM', 'product',
               (Request('/api/setup-complete', fields=('results.RequiresAuth', 'results.MultiUserMode')),),
               read_anythingllm, leads=r'anything[ -]?llm', ports=(3001,), servers=APP_SERVERS,
               verified='https://github.com/Mintplex-Labs/anything-llm/blob/master/server/endpoints/system.js (/setup-complete, public; '
                        'models/systemSettings.js RequiresAuth, MultiUserMode)',
               note='only the two sign-in booleans are asked; AnythingLLM states no version over its API',
               exposure=exposure('anythingllm-open-access', 'AnythingLLM open without a password', 4,
                                 'An AnythingLLM server answers from the network with no password and no user accounts.',
                                 'Anyone who reaches it can read its documents and chats and drive its agents, which run tools.',
                                 'Set a password or turn on multi-user mode, and keep the instance behind a VPN or an authenticating proxy.',
                                 rate=rate_anythingllm)),
        Source('openclaw', 'OpenClaw gateway Control UI', 'product',
               (Request('/', read='text', find='<title>'), Request('/', read='text', find='OPENCLAW_CONTROL_UI_BUILD_INFO=')),
               read_openclaw, leads=r'openclaw|clawdbot|moltbot', ports=(18789,), servers=APP_SERVERS,
               verified='https://docs.openclaw.ai/web/control-ui (served on the gateway port 18789); dist/control-ui/index.html ("<title>OpenClaw '
                        'Control</title>", OPENCLAW_CONTROL_UI_BUILD_INFO); clawdbot\'s "<title>Clawdbot Control</title>"',
               note='the gateway\'s WebSocket is never opened, so whether it asks for its token is not read',
               exposure=exposure('openclaw-gateway-exposed', 'OpenClaw gateway reachable from the network', 3,
                                 'An OpenClaw gateway (formerly Clawdbot, Moltbot) serves its Control UI from the network.',
                                 'The gateway drives a personal AI agent that runs tools and commands on the host and holds its messaging '
                                 'accounts; a stolen or guessed gateway token, or a flaw such as CVE-2026-25253, gives full control of it.',
                                 'Keep gateway.bind on loopback and reach it over Tailscale Serve, SSH or a VPN; never publish port 18789.',
                                 rate=rate_openclaw)),
        Source('hermes-agent', 'Hermes Agent dashboard', 'product',
               (Request('/api/status', fields=('version', 'release_date', 'auth_required', 'gateway_running')),),
               read_hermes, leads=r'hermes[ -]?agent', ports=(9119,), servers=APP_SERVERS,
               verified='https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/web_routers/status.py (public /api/status: version, '
                        'release_date, auth_required, gateway_running); https://hermes-agent.nousresearch.com/docs/user-guide/features/web-dashboard',
               exposure=exposure('hermes-agent-dashboard-exposed', 'Hermes Agent dashboard reachable from the network', 4,
                                 'Nous Research\'s Hermes Agent dashboard answers from the network.',
                                 'The dashboard drives an agent that runs tools and commands on the host and manages its keys and messaging '
                                 'gateways; with no sign-in anyone can, and with a password sign-in it can be guessed from anywhere.',
                                 'Keep `hermes dashboard` on 127.0.0.1 (the default) and reach it over SSH or a VPN, or use the Nous Portal or OIDC '
                                 'sign-in behind a proxy.', rate=rate_hermes)),
    )

