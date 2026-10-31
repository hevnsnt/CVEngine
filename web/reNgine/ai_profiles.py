"""What each AI provider can do, in one table. Stdlib only (no Django, no requests), so the provider layer, the settings API, the models and
the tests all read the same facts instead of keeping their own lists.

``PROFILES`` is keyed by the provider ids that are stored in ``AIProviderSettings.provider``. A fact that is not confirmed by the repository
or by a request that was made against the real service carries an ``# UNVERIFIED:`` comment; ``reasoning_plan`` sends nothing it cannot name.
"""
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_REPLY_CAP = 2048  # the reply limit (tokens) of Anthropic and of a self-hosted server when nothing else is set
STAGE_REPLY_CAPS = {'triage': 400}  # a triage answer is a short JSON object: 300 cut off 14% of them on a local model (issue 209), 400 does not

REASONING_LEVELS = ('off', 'low', 'medium', 'high', 'max')  # CVENGINE_AI_REASONING; unset sends nothing
MECHANISMS = ('none', 'effort', 'toggle', 'budget', 'adaptive')
TRANSPORTS = ('anthropic', 'openai_chat', 'ollama')


# ----------------------------------------------------------------------------- reasoning: which mechanism a model has

_OPENAI_NO_EFFORT = re.compile(r'o1-mini|o1-preview|chat')  # o1-mini, o1-preview and the *-chat-latest aliases refuse reasoning_effort
_OPENAI_REASONING = re.compile(r'^(?:o\d+|gpt-5)(?:[.-]|$)')


def _openai_reasoning(model):
	"""OpenAI's o-series and gpt-5 family take ``reasoning_effort`` (chat completions)."""
	name = (model or '').lower().removeprefix('openai/')
	return 'effort' if _OPENAI_REASONING.match(name) and not _OPENAI_NO_EFFORT.search(name) else 'none'


_CLAUDE = re.compile(r'claude-(?:(opus|sonnet|haiku|fable|mythos)-(\d+)(?:-(\d{1,2}))?(?!\d)|(\d+)(?:-(\d{1,2}))?-(opus|sonnet|haiku)(?!\w))')


def claude_version(model):
	"""``(family, major, minor)`` from a Claude model id (``claude-sonnet-4-5-20250929``, ``claude-3-7-sonnet-latest``, ``claude-opus-5``, a
	Bedrock or Vertex spelling of either), or None when it is not one."""
	match = _CLAUDE.search((model or '').lower())
	if not match:
		return None
	family, major, minor, old_major, old_minor, old_family = match.groups()
	if family:
		return family, int(major), int(minor or 0)
	return old_family, int(old_major), int(old_minor or 0)


def _anthropic_reasoning(model):
	"""``adaptive`` (``thinking: {"type": "adaptive"}`` plus ``output_config.effort``) from 4.6 on, and for every Fable and Mythos; ``budget``
	(``thinking: {"type": "enabled", "budget_tokens": N}``) from 3.7 up to 4.5; ``none`` before that (no extended thinking) and for a name that is
	not a Claude model."""
	version = claude_version(model)
	if not version:
		return 'none'
	family, major, minor = version
	if family in ('fable', 'mythos'):
		return 'adaptive' if major >= 5 else 'none'  # UNVERIFIED: there is no Fable or Mythos before 5; assumed adaptive for any
	if (major, minor) >= (4, 6):
		return 'adaptive'
	if (major, minor) >= (3, 7):
		return 'budget'
	return 'none'


# Models that think when `thinking` is left out and still take an explicit `{"type": "disabled"}`. Every other adaptive model either does not
# think unless asked (Opus 4.6 to 4.8, Sonnet 4.6: nothing needs sending to turn it off) or cannot have it turned off (Fable, Mythos, Opus 5.5,
# Sonnet 5.5: `disabled` is rejected with a 400), so "off" sends nothing for them.
# UNVERIFIED: read from Anthropic's model documentation, not from a request made for this table: Opus 5 and Haiku 5.5 accept `disabled`
# only at effort `high` or below (no effort is sent here, their default is at or below it); Sonnet 5.5 would need `between_tools`, left out.
_CAN_DISABLE = {('opus', 5, 0), ('sonnet', 5, 0), ('haiku', 5, 5)}


def anthropic_can_disable(model):
	version = claude_version(model)
	return bool(version) and _anthropic_reasoning(model) == 'adaptive' and version in _CAN_DISABLE


# A local model that reasons by default and has a switch. Matched on the model's name: the server does not say.
# UNVERIFIED: the families are the ones that ship a reasoning mode as of this writing; a new one is not recognised until it is added here.
_LOCAL_REASONING = re.compile(r'qwen3|r1|gpt-oss|magistral', re.I)


def _local_reasoning(model):
	return 'toggle' if _LOCAL_REASONING.search(model or '') else 'none'


def _no_reasoning(model):
	return 'none'


@dataclass(frozen=True)
class ProviderProfile:
	id: str
	label: str
	transport: str  # anthropic | openai_chat | ollama
	default_base: str  # the vendor's own address ('' when there is none: you run the server). Anthropic's is the whole messages URL.
	default_model: str  # '' when the user must choose one
	needs_key: bool  # False: the key is optional (vLLM, LM Studio) or unused (Ollama)
	needs_url: bool  # True: you run the server, so there is no default address
	port: int  # a self-hosted server's usual port, for the address hints (0 for a hosted one)
	token_param: str  # max_tokens | max_completion_tokens | num_predict. OpenAI's own host takes the second; any other address says max_tokens
	reply_cap: int  # the reply limit sent when the operator set none (0: none is sent)
	reply_cap_by_stage: bool  # True: a stage's own limit (STAGE_REPLY_CAPS) replaces reply_cap
	temperature_ok: bool  # a stage's pinned temperature is sent
	seed_ok: bool  # a stage's pinned seed is sent
	structured: tuple  # the structured-output ladder, best first ('none' last); () when the provider is never sent a schema
	structured_default: bool  # sent a schema without CVENGINE_AI_STRUCTURED=all
	reasoning_detect: object  # model name -> one of MECHANISMS
	reasoning_field: str  # the request field the opt-in setting uses: reasoning_effort | thinking | think | '' (set it on the server)


PROFILES = {p.id: p for p in (
	ProviderProfile(
		id='anthropic', label='Anthropic', transport='anthropic', default_base='https://api.anthropic.com/v1/messages', default_model='claude-haiku-5-5',
		needs_key=True, needs_url=False, port=0, token_param='max_tokens', reply_cap=DEFAULT_REPLY_CAP, reply_cap_by_stage=False,
		temperature_ok=False, seed_ok=False, structured=(), structured_default=False,
		reasoning_detect=_anthropic_reasoning, reasoning_field='thinking'),
	ProviderProfile(
		id='openai', label='OpenAI', transport='openai_chat', default_base='https://api.openai.com/v1', default_model='gpt-5.4-nano',
		needs_key=True, needs_url=False, port=0, token_param='max_completion_tokens', reply_cap=0, reply_cap_by_stage=False,
		temperature_ok=False, seed_ok=False, structured=('json_schema', 'json_object', 'none'), structured_default=False,
		reasoning_detect=_openai_reasoning, reasoning_field='reasoning_effort'),
	ProviderProfile(
		id='openrouter', label='OpenRouter', transport='openai_chat', default_base='https://openrouter.ai/api/v1', default_model='',
		needs_key=True, needs_url=False, port=0, token_param='max_tokens', reply_cap=0, reply_cap_by_stage=False,
		temperature_ok=False, seed_ok=False, structured=('json_schema', 'json_object', 'none'), structured_default=False,
		# UNVERIFIED: OpenRouter has its own `reasoning` object; it is not used yet, so a model behind it gets nothing
		reasoning_detect=_no_reasoning, reasoning_field=''),
	ProviderProfile(
		id='ollama', label='Ollama', transport='ollama', default_base='', default_model='',
		needs_key=False, needs_url=True, port=11434, token_param='num_predict', reply_cap=DEFAULT_REPLY_CAP, reply_cap_by_stage=True,
		temperature_ok=True, seed_ok=True, structured=('json_schema', 'json', 'none'), structured_default=True,
		reasoning_detect=_local_reasoning, reasoning_field='think'),
	ProviderProfile(
		id='vllm', label='vLLM', transport='openai_chat', default_base='', default_model='',
		needs_key=False, needs_url=True, port=8000, token_param='max_tokens', reply_cap=DEFAULT_REPLY_CAP, reply_cap_by_stage=True,
		temperature_ok=True, seed_ok=True, structured=('json_schema', 'json_object', 'none'), structured_default=True,
		reasoning_detect=_local_reasoning, reasoning_field=''),
	ProviderProfile(
		id='lmstudio', label='LM Studio', transport='openai_chat', default_base='', default_model='',
		needs_key=False, needs_url=True, port=1234, token_param='max_tokens', reply_cap=DEFAULT_REPLY_CAP, reply_cap_by_stage=True,
		temperature_ok=True, seed_ok=True, structured=('json_schema', 'json_object', 'none'), structured_default=True,
		reasoning_detect=_local_reasoning, reasoning_field=''),
)}


# ----------------------------------------------------------------------------- reasoning: the fields to send

# Tokens `thinking.budget_tokens` asks for on a budget-era Claude model, by level. Anthropic's minimum is 1024 and the budget must be below
# max_tokens, so the budget leaves ANSWER_ROOM tokens of the reply limit for the answer and a limit that cannot hold both ignores the setting.
_BUDGET = {'low': 1024, 'medium': 4096, 'high': 8192, 'max': 16384}
BUDGET_MINIMUM = 1024
ANSWER_ROOM = 1024
# OpenAI: `max` is sent as `high`, `off` is not sent at all.
# UNVERIFIED: newer OpenAI models also take `minimal` (gpt-5), `none` (gpt-5.1 and later) and `xhigh`, and which model takes which was not
# checked, so a model that rejects one would fail the request; `off` and `max` stay on the values every effort model is documented to take.
_OPENAI_EFFORT = {'low': 'low', 'medium': 'medium', 'high': 'high', 'max': 'high'}
_OLLAMA_LEVEL = {'low': 'low', 'medium': 'medium', 'high': 'high', 'max': 'high'}


def reasoning_mechanism(provider_id, model):
	"""One of MECHANISMS for this provider and model name ('none' for a provider that is not in the table)."""
	profile = PROFILES.get(provider_id)
	return profile.reasoning_detect(model) if profile else 'none'


def reasoning_plan(provider_id, model, level, max_tokens=None):
	"""``(fields, why)``: the top-level request fields that apply ``level`` (one of REASONING_LEVELS, or None for not set) to this provider and
	model, and ``why`` when nothing is sent for a level that was set (a sentence for the log), else ''. ``fields`` is {} whenever nothing is
	sent. ``max_tokens`` is the reply limit of the request (Anthropic's budget must stay below it). Pure."""
	if level not in REASONING_LEVELS:
		return {}, ''
	profile = PROFILES.get(provider_id)
	if profile is None:
		return {}, f'{provider_id} is not a known provider'
	mechanism = profile.reasoning_detect(model)
	if mechanism == 'none':
		return {}, f'{profile.label} {model or "(default model)"} has no reasoning control cvENGINE knows'
	if not profile.reasoning_field:
		return {}, f'{profile.label} is switched on the server (its own setting for the model), not by a request field'
	if profile.reasoning_field == 'reasoning_effort':  # OpenAI
		effort = _OPENAI_EFFORT.get(level)
		if effort is None:
			return {}, f'{profile.label} models cannot be switched off from here'
		return {'reasoning_effort': effort}, ''
	if profile.reasoning_field == 'think':  # Ollama
		name = (model or '').lower()
		if 'gpt-oss' in name:  # UNVERIFIED: gpt-oss takes a level ("low", "medium", "high") for `think` and ignores true and false
			if level == 'off':
				return {}, 'gpt-oss cannot be switched off'
			return {'think': _OLLAMA_LEVEL[level]}, ''
		return {'think': level != 'off'}, ''
	# anthropic
	if mechanism == 'adaptive':
		if level == 'off':
			if anthropic_can_disable(model):
				return {'thinking': {'type': 'disabled'}}, ''
			return {}, 'this model either does not think unless asked or cannot have thinking switched off; nothing is sent'
		return {'thinking': {'type': 'adaptive'}, 'output_config': {'effort': level}}, ''
	if level == 'off':  # a budget-era model does not think unless asked
		return {}, ''
	budget = min(_BUDGET[level], (max_tokens or 0) - ANSWER_ROOM)
	if budget < BUDGET_MINIMUM:
		return {}, f'the reply limit ({max_tokens}) leaves no room for a thinking budget of at least {BUDGET_MINIMUM} tokens: raise CVENGINE_AI_MAX_TOKENS'
	return {'thinking': {'type': 'enabled', 'budget_tokens': budget}}, ''


# ----------------------------------------------------------------------------- which service an address is

_PORTS = {'http': 80, 'https': 443}


def _endpoint(provider_id, base_url):
	profile = PROFILES.get(provider_id)
	url = (base_url or '').strip() or (profile.default_base if profile else '')
	parts = urlsplit(url)
	try:
		port = parts.port
	except ValueError:
		port = None
	scheme = parts.scheme.lower()
	return scheme, (parts.hostname or '').lower().rstrip('.'), port or _PORTS.get(scheme), parts.path.rstrip('/')


def same_service(provider_a, url_a, provider_b, url_b):
	"""Whether a key stored for ``provider_a`` at ``url_a`` may be used for ``provider_b`` at ``url_b``: the same provider and the same
	scheme, host and port (an empty address is the vendor's own, see ``default_base``). When both are written out, the path must match too
	(one host can front several services). A change of host is a new service, however the address is spelled."""
	if provider_a != provider_b:
		return False
	a, b = _endpoint(provider_a, url_a), _endpoint(provider_b, url_b)
	if a[:3] != b[:3]:
		return False
	return not ((url_a or '').strip() and (url_b or '').strip() and a[3] != b[3])
