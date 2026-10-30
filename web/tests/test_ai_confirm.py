import unittest
from types import SimpleNamespace
from unittest import mock

from cveFeed.correlation import ai_confirm_match
from reNgine.ai_providers import AIProviderError


def make_match(**extra):
	cve = SimpleNamespace(cve_id='CVE-1', title='t', original_description='d', summary='', cvss=9.8, affected=[], kev=False, epss_reached=False, exploit_db=False, references=[], sources=[],
		published_at=None, stated_severity='')
	return SimpleNamespace(
		pk=1, cve_entry=cve, subdomain=SimpleNamespace(name='a.example.com'),
		matched_product='nginx', matched_version='1.18', version_in_range=True, source='port',
		ai_verdict='', ai_reason='', ai_model='', save=mock.Mock(), **extra)


@mock.patch('cveFeed.activity.log', return_value=None)  # these tests must not write to a real database
class AIConfirmTests(unittest.TestCase):
	def test_stores_verdict(self, _log):
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = '{"classification": "likely", "reason": "in range"}'
		m = ai_confirm_match(make_match(template_result='vulnerable'), provider=provider)  # a template hit is evidence beyond the version
		self.assertEqual((m.ai_verdict, m.ai_model), ('affected', 'anthropic:m'))
		self.assertTrue(m.ai_reason)
		m.save.assert_called_once()

	def test_a_version_alone_is_never_called_affected_by_the_model(self, _log):
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = '{"classification": "likely", "reason": "in range"}'
		m = ai_confirm_match(make_match(), provider=provider)  # a banner version inside the range and nothing else
		self.assertEqual(m.ai_verdict, 'uncertain')
		self.assertIn('version', m.ai_reason.lower())

	def test_the_model_alone_never_confirms_and_a_bad_reply_is_uncertain(self, _log):
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = '{"classification": "confirmed", "reason": "sure"}'
		match = make_match()
		match.version_in_range = None  # no hard evidence: text alone cannot confirm
		self.assertIn('no hard evidence', ai_confirm_match(match, provider=provider).ai_reason)
		provider.complete.return_value = 'I cannot say'  # a malformed reply is a provider error: unconfirmed, asked again later
		self.assertEqual(ai_confirm_match(make_match(), provider=provider).ai_verdict, '')

	def test_the_prompt_has_no_hostname(self, _log):
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = '{"classification": "likely", "reason": "x"}'
		ai_confirm_match(make_match(), provider=provider)
		self.assertNotIn('example.com', provider.complete.call_args[0][1])

	def test_provider_error_leaves_match_unconfirmed(self, _log):
		provider = mock.Mock()
		provider.complete.side_effect = AIProviderError('down')
		m = ai_confirm_match(make_match(), provider=provider)
		self.assertEqual(m.ai_verdict, '')
		m.save.assert_not_called()

	def _not_affected(self, **fields):
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = '{"classification": "likely_false_positive", "reason": "banner says patched"}'
		match = make_match()
		for key, value in fields.items():
			setattr(match, key, value)
		return ai_confirm_match(match, provider=provider)

	def test_ai_cannot_clear_a_version_confirmed_match(self, _log):
		self.assertEqual(self._not_affected(version_in_range=True).ai_verdict, 'uncertain')

	def test_ai_may_clear_a_match_with_no_version_evidence(self, _log):
		# an advisory with no version bound (version_in_range None) is a lead, not hard evidence
		self.assertEqual(self._not_affected(version_in_range=None).ai_verdict, 'not_affected')


if __name__ == '__main__':
	unittest.main()
