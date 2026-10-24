"""Vulnerability report text and attack-surface suggestions, written by the AI model configured in
Settings > AI model (any provider: Anthropic, OpenAI, OpenRouter, Ollama or vLLM).

This replaces the old per-vendor code (the OpenAI 0.28 SDK and LangChain's Ollama wrapper) with the provider layer
in reNgine.ai_providers, so the same model, key and server address are used everywhere. Scan data in the prompts
(vulnerability descriptions, hostnames) comes from the internet, so it is passed as delimited, sanitised data.
"""
import re

from reNgine.ai_providers import AIProviderError, UNTRUSTED_NOTICE, clean_text, untrusted_block
from reNgine.ai_settings import get_configured_provider
from reNgine.common_func import parse_llm_vulnerability_report
from reNgine.definitions import ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT, VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE

NO_MODEL = 'No AI model is configured: connect one in Settings > AI model.'


def _complete(system, label, text):
	"""Ask the configured model. Returns (reply, None) or (None, error message)."""
	try:
		provider = get_configured_provider()
	except AIProviderError as e:
		return None, str(e)
	if provider is None:
		return None, NO_MODEL
	system = re.sub(r'\t', '', system) + '\n\n' + UNTRUSTED_NOTICE
	try:
		from reNgine.ai_providers import usage_stage
		with usage_stage('report_writing'):
			return provider.complete(system, untrusted_block(label, clean_text(text, 6000))), None
	except AIProviderError as e:
		return None, str(e)


class LLMVulnerabilityReportGenerator:

	def __init__(self, logger):
		self.logger = logger

	def get_vulnerability_description(self, description):
		"""Generate a vulnerability description, impact, remediation and references.

		Returns {'status': True, 'description', 'impact', 'remediation', 'references': [urls]}
		or {'status': False, 'error'}.
		"""
		self.logger.info(f'Generating Vulnerability Description for: {description}')
		reply, error = _complete(VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE, 'VULNERABILITY', description)
		if error:
			return {'status': False, 'error': error}
		response = parse_llm_vulnerability_report(reply)
		if not response:
			return {'status': False, 'error': 'Failed to parse LLM response'}
		return {
			'status': True,
			'description': response.get('description', ''),
			'impact': response.get('impact', ''),
			'remediation': response.get('remediation', ''),
			'references': response.get('references', []),
		}


class LLMAttackSuggestionGenerator:

	def __init__(self, logger):
		self.logger = logger

	def get_attack_suggestion(self, user_input):
		"""user_input (str): what is known about the target."""
		reply, error = _complete(ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT, 'TARGET', user_input)
		if error:
			return {'status': False, 'error': error, 'input': user_input}
		self.logger.info(reply)
		return {'status': True, 'description': reply, 'input': user_input}
