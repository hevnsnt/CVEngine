"""A recorded-style stand-in for Anthropic's messages endpoint, used to measure the spend changes on one fixture set with no live call.

``FakeAnthropic`` answers the way the real service is documented to: a reply that needs more tokens than ``max_tokens`` allows (thinking
counts) stops with ``stop_reason: max_tokens`` and no text; a system block marked ``cache_control`` is written to a cache on the first
request and read on later ones while its lifetime has not run out (5 minutes, or 1 hour with ``ttl: 1h``) and only when it is at least the
model's minimum length; ``usage`` reports ``input_tokens`` (uncached), ``cache_creation_input_tokens``, ``cache_read_input_tokens`` and
``output_tokens``. The time is a counter the fixture moves, so a 30 minute gap costs nothing to run.

The CVEs are invented (CVE-2099-*), and no request leaves the process.
"""
import json
import math
import random
from types import SimpleNamespace

from reNgine import ai_providers as ai
from reNgine.ai_profiles import cache_min_tokens

CHARS_PER_TOKEN = 3.5
SEED = 20261110
LEDGER_TRUNCATION_RATE = 1780 / 5335  # cve_detection calls that ended output_truncated, from the usage ledger, 10/24 to 11/10


def tokens(text):
	return math.ceil(len(text) / CHARS_PER_TOKEN)


def system_text(system):
	return system if isinstance(system, str) else ''.join(block['text'] for block in system)


class FakeResponse:
	def __init__(self, body):
		self.body = body

	def raise_for_status(self):
		return None

	def json(self):
		return self.body


class FakeAnthropic:
	def __init__(self, needs):
		self.needs = needs  # user prompt -> output tokens the model would use in full (thinking plus the answer)
		self.now = 0.0
		self.cache = {}  # (model, system text) -> (expires, ttl)
		self.requests = []

	def post(self, url, headers=None, json=None, timeout=None):
		body = json
		system, user = body['system'], body['messages'][0]['content']
		text = system_text(system)
		marked = (system[-1].get('cache_control') if not isinstance(system, str) else None)
		sys_tokens, user_tokens = tokens(text), tokens(user)
		read = wrote = 0
		if marked and sys_tokens >= cache_min_tokens(body['model']):
			key = (body['model'], text)
			ttl = 3600 if marked.get('ttl') == '1h' else 300
			held = self.cache.get(key)
			if held and held[0] > self.now:
				read = sys_tokens
				self.cache[key] = (self.now + held[1], held[1])  # a read renews the lifetime
			else:
				wrote = sys_tokens
				self.cache[key] = (self.now + ttl, ttl)
		need = self.needs[user]
		cut = need > body['max_tokens']
		out = min(need, body['max_tokens'])
		self.requests.append({'max_tokens': body['max_tokens'], 'cached': bool(marked), 'read': read, 'wrote': wrote, 'cut': cut})
		usage = {'input_tokens': user_tokens + (0 if (read or wrote) else sys_tokens), 'output_tokens': out,
				 'cache_read_input_tokens': read, 'cache_creation_input_tokens': wrote}
		return FakeResponse({'model': body['model'], 'stop_reason': 'max_tokens' if cut else 'end_turn', 'usage': usage,
							 'content': [] if cut else [{'type': 'text', 'text': '{}'}]})


def cve_fixture(count=400, sigma=1.0):
	"""``count`` invented CVE records and, for each, the output tokens the model would use in full. The answer is 600 to 1,400 tokens; the
	thinking is lognormal (``sigma`` sets how heavy its tail is), scaled so that 33.4% (the ledger's rate) would not fit in 2048 tokens: the scale is fitted to the fixture, so the
	'before' rate is the ledger's by construction and only the 'after' figure is a result."""
	rng = random.Random(SEED)
	rows = []
	for i in range(count):
		words = ' '.join(rng.choice(['remote', 'attacker', 'overflow', 'parser', 'header', 'authentication', 'bypass', 'library', 'version']) for _ in range(rng.randint(40, 260)))
		cve = SimpleNamespace(cve_id=f'CVE-2099-{i:05d}', title=f'Invented flaw {i}', original_description=words, summary=words[:200],
							  cvss=round(rng.uniform(3, 10), 1), cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', kev=False,
							  exploit_db=False, affected=[{'vendor': 'acme', 'product': 'widget', 'ranges': [{'introduced': '1.0', 'fixed': '1.4'}]}],
							  references=[{'url': 'https://example.test/advisory'}])
		rows.append((cve, rng.randint(600, 1400), rng.lognormvariate(0, sigma)))
	low, high = 1.0, 20000.0
	for _ in range(60):  # bisection on the thinking scale
		mid = (low + high) / 2
		rate = sum(a + t * mid > 2048 for _, a, t in rows) / count
		low, high = (mid, high) if rate < LEDGER_TRUNCATION_RATE else (low, mid)
	scale = (low + high) / 2
	return [(cve, round(answer + t * scale)) for cve, answer, t in rows]


def run(provider_name_model, fixture, *, after, run_size=11, gap=1800, step=20, workers=4):
	"""Author every fixture CVE once through the real provider code and the real ledger writer, in runs of ``run_size`` calls ``gap`` seconds
	apart (the authoring task's 30 minute cadence at 500 a day). ``after`` False is the code before this change: no cache marker, the 2048
	default limit, a cut-off reply is lost. Returns the per-call truth the fake server saw. Needs a database (AIUsage rows)."""
	import os
	from unittest import mock
	from cveFeed import detection_author as da

	needs = {}
	users = []
	for cve, need in fixture:
		user = da.build_user_prompt(cve)
		needs[user] = need
		users.append(user)
	server = FakeAnthropic(needs)
	provider = ai.get_provider('anthropic', api_key='k', model=provider_name_model)
	outcomes = []
	env = {} if after else {'CVENGINE_AI_PROMPT_CACHE': 'off'}
	floors = ai.STAGE_REPLY_FLOORS if after else {}
	with mock.patch('requests.post', side_effect=server.post), mock.patch.dict(os.environ, env), mock.patch.object(ai, 'STAGE_REPLY_FLOORS', floors):
		for index, user in enumerate(users):
			position = index % run_size
			server.now = (index // run_size) * gap + (position * step if position < 1 else step + (position - 1) * step / workers)
			try:
				with ai.usage_stage('cve_detection'):
					(ai.complete_retrying_truncation(provider, da.SYSTEM_PROMPT, user) if after else provider.complete(da.SYSTEM_PROMPT, user))
				outcomes.append(True)
			except ai.AIProviderError as error:
				outcomes.append(False if error.category == 'output_truncated' else None)
	return {'calls': len(server.requests), 'cves': len(users), 'failed': outcomes.count(False), 'server': server.requests}
