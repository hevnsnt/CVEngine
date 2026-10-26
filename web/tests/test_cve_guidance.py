import json

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import services as svc
from cveFeed import detection, detection_author
from cveFeed.models import CVEDetection, CVEEntry
from tests.test_cve_detection import NGINX, good_ai


def ai_with_guidance():
	data = json.loads(good_ai())
	data.update({
		'summary': 'A crafted header makes nginx read past a buffer; the attacker gains code execution as the worker.',
		'identify': 'nginx 1.0.0 up to 1.19.x answering on a public port; the Server header or the package version shows it.',
		'confirm_steps': ['Read the exact nginx version from the Server header or `nginx -v`.', 'Compare it with 1.20.0.',
						  'Check your distribution tracker for a backported fix.'],
		'true_positive_signs': ['nginx -v prints a version below 1.20.0 and the distro lists the CVE as unfixed.'],
		'false_positive_signs': ['The package changelog names this CVE as fixed.', 'The Server header is a CDN, not your nginx.']})
	return json.dumps(data)


class SchemaV2Tests(SimpleTestCase):
	def test_the_guidance_fields_are_validated_and_bounded(self):
		strategy, problems = detection.parse_ai_strategy(ai_with_guidance())
		self.assertEqual(problems, [])
		self.assertEqual(len(strategy['confirm_steps']), 3)
		self.assertTrue(strategy['identify'].startswith('nginx 1.0.0'))
		data = json.loads(ai_with_guidance())
		data.update(confirm_steps=['x' * 500] * 9, true_positive_signs='not a list', identify='y' * 900)
		strategy, problems = detection.validate_strategy(data)
		self.assertLessEqual(len(strategy['confirm_steps']), 6)
		self.assertTrue(all(len(step) <= 240 for step in strategy['confirm_steps']))
		self.assertEqual(strategy['true_positive_signs'], [])
		self.assertLessEqual(len(strategy['identify']), 320)
		self.assertIn('true_positive_signs is not a list', problems)

	def test_a_record_with_guidance_and_no_executable_check_is_kept(self):
		strategy, _ = detection.validate_strategy({'summary': 's', 'identify': 'a local kernel flaw', 'confirm_steps': ['Check the build number.']})
		self.assertEqual(strategy['confirm_steps'], ['Check the build number.'])
		self.assertEqual((strategy['remote_checks'], strategy['local_checks']), ([], []))
		self.assertIsNone(detection.validate_strategy({'summary': 'nothing else'})[0])
		self.assertIsNotNone(detection.parse_ai_strategy('{"identify": "text only", "confirm_steps": ["Look."]}')[0])

	def test_a_version_1_record_without_the_new_keys_still_finalizes(self):
		old = {'safety': 'read_only', 'summary': 's', 'remote_checks': [], 'local_checks': [
			{'id': 'pkg', 'kind': 'package_version', 'confidence': 'high', 'description': 'd',
			 'params': {'ecosystem': 'dpkg', 'package': 'nginx', 'fixed_version': '1.20.0-1'}}],
			'prerequisites': [], 'false_positive_notes': '', 'remediation': ''}
		out = detection.finalize(old)
		self.assertTrue(out['local_checks'][0]['commands'])
		self.assertIn('validation', out)

	def test_the_ai_wording_wins_over_the_rules_wording_and_the_rules_fill_what_is_missing(self):
		rules = detection.validate_strategy({'summary': 'title', 'identify': 'Affects nginx before 1.20.0.',
			'confirm_steps': ['generic step'], 'false_positive_signs': ['generic'],
			'remote_checks': [{'id': 'v', 'kind': 'version_banner', 'confidence': 'medium', 'description': 'd',
							   'params': {'product': 'nginx', 'ranges': [{'fixed': '1.20.0'}], 'source': 'any'}}]})[0]
		ai = detection.validate_strategy({'summary': 'what it does', 'confirm_steps': ['specific step'],
										  'local_checks': [{'id': 'ai-p', 'kind': 'package_version', 'confidence': 'high', 'description': 'd',
															'params': {'ecosystem': 'dpkg', 'package': 'nginx', 'fixed_version': '1.20.0-1'}}]})[0]
		merged = detection.merge_strategies(rules, ai)
		self.assertEqual((merged['summary'], merged['confirm_steps']), ('what it does', ['specific step']))
		self.assertEqual((merged['identify'], merged['false_positive_signs']), ('Affects nginx before 1.20.0.', ['generic']))


class GuidanceFlowTests(TestCase):
	def setUp(self):
		self.cve = CVEEntry.objects.create(
			cve_id='CVE-2099-7001', title='nginx header overflow', original_description='A crafted header overflows a buffer in nginx.',
			affected=NGINX, cvss=9.8, cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', published_at=timezone.now(), kev=True)

	def test_the_rules_author_writes_plain_guidance_with_no_ai(self):
		self.assertEqual(detection_author.author_rules(batch=10), 1)
		row = CVEDetection.objects.get(cve_entry=self.cve)
		s = row.strategy
		self.assertEqual(row.schema_version, 2)
		self.assertIn('nginx', s['identify'])
		self.assertIn('1.20.0', s['identify'])
		self.assertTrue(any('1.20.0' in step for step in s['confirm_steps']))
		self.assertTrue(any('backport' in sign for sign in s['false_positive_signs']))
		self.assertTrue(s['local_checks'][0]['commands'])  # commands are rendered by the app, never written by a model

	def test_an_ai_answer_adds_its_guidance_and_the_match_detail_carries_the_record(self):
		detection_author.author_rules(batch=10)
		row = CVEDetection.objects.get(cve_entry=self.cve)

		class Provider:
			name, model = 'anthropic', 'test-model'

			def complete(self, system, user):
				assert 'confirm_steps' in system and 'CVE-2099-7001' in user
				return ai_with_guidance()
		self.assertTrue(detection_author.enrich_with_ai(row, Provider()))
		row.refresh_from_db()
		self.assertEqual(row.source, 'ai')
		self.assertEqual(row.strategy['confirm_steps'][0].split()[0], 'Read')
		self.assertTrue(row.strategy['summary'].startswith('A crafted header'))
		shown = svc._detection(CVEEntry.objects.get(pk=self.cve.pk))
		self.assertEqual((shown['source'], shown['ai_model']), ('ai', 'anthropic:test-model'))
		self.assertTrue(shown['strategy']['true_positive_signs'])
		admin = User.objects.create_user('g-admin', password='x', is_superuser=True)
		got = svc.get_cve_detection(svc.Ctx(user=admin), 'CVE-2099-7001')
		self.assertEqual(got['strategy']['identify'], shown['strategy']['identify'])

	def test_the_ai_prompt_sees_the_guidance_as_a_hint(self):
		from cveFeed import triage
		detection_author.author_rules(batch=10)
		guidance = detection.prompt_guidance(CVEEntry.objects.get(pk=self.cve.pk))
		self.assertIn('nginx', guidance['identify'])
		self.assertEqual(guidance['written_by'], 'rules')
		self.assertIsNone(detection.prompt_guidance(CVEEntry.objects.create(cve_id='CVE-2099-7002', published_at=timezone.now())))
		from reNgine.ai_providers import TRIAGE_SYSTEM_PROMPT
		self.assertIn('hint that may be wrong', TRIAGE_SYSTEM_PROMPT)
		self.assertTrue(callable(triage.describe_cve_match))


def answer(**extra):
	base = json.loads(ai_with_guidance())
	base.update(extra)
	return json.dumps(base)


class Provider:
	name, model = 'anthropic', 'test-model'

	def __init__(self, reply):
		self.reply, self.seen = reply, []

	def complete(self, system, user):
		self.seen.append((system, user))
		return self.reply


class IntakeTests(TestCase):
	def entry(self, cve_id, vector='', desc='A flaw.', affected=None, kev=True):
		return CVEEntry.objects.create(cve_id=cve_id, title=cve_id, original_description=desc, affected=affected or NGINX, cvss=9.8, kev=kev,
									   cvss_vector=vector, published_at=timezone.now())

	def test_the_prompt_carries_the_intake_policy_and_the_model_decides_the_scope(self):
		cve = self.entry('CVE-2099-7101', desc='The Windows kernel allows an elevation of privilege.', affected=[{'product': 'Windows'}])
		detection_author.author_rules(batch=5)
		row = CVEDetection.objects.get(cve_entry=cve)
		provider = Provider(answer(scope='local_only', scope_reason='Kernel elevation of privilege needs code on the host.',
								   remote_checks=[], local_checks=[]))
		self.assertTrue(detection_author.enrich_with_ai(row, provider))
		system, user = provider.seen[0]
		self.assertIn('local_only', system)
		self.assertIn('not make a CVE local', system)
		self.assertNotIn('CURRENT_RECORD', user)  # a first answer is not a revision
		cve.refresh_from_db()
		self.assertTrue(cve.local_only)  # no attack vector in the record, so the model's reading stands
		row.refresh_from_db()
		self.assertEqual(row.strategy['scope'], 'local_only')
		self.assertEqual(len(row.ai_input_hash), 16)

	def test_a_cvss_vector_is_never_overridden_by_the_model_and_unclear_changes_nothing(self):
		network = self.entry('CVE-2099-7102', vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
		unclear = self.entry('CVE-2099-7103')
		detection_author.author_rules(batch=5)
		for cve, scope in ((network, 'local_only'), (unclear, 'unclear')):
			self.assertTrue(detection_author.enrich_with_ai(CVEDetection.objects.get(cve_entry=cve), Provider(answer(scope=scope, scope_reason='r'))))
			cve.refresh_from_db()
			self.assertFalse(cve.local_only, cve.cve_id)

	def test_refresh_keeps_the_model_scope_for_a_record_with_no_vector(self):
		from cveFeed import locality
		cve = self.entry('CVE-2099-7104', desc='A weird flaw with no hint.')
		detection_author.author_rules(batch=5)
		detection_author.enrich_with_ai(CVEDetection.objects.get(cve_entry=cve), Provider(answer(scope='local_only', scope_reason='r')))
		CVEEntry.objects.filter(pk=cve.pk).update(synced_at=timezone.now() + timezone.timedelta(seconds=5))
		locality.refresh()
		self.assertTrue(CVEEntry.objects.get(pk=cve.pk).local_only)  # the text rules alone would say "not local"

	def test_a_changed_cve_is_revised_not_rewritten(self):
		cve = self.entry('CVE-2099-7105')
		detection_author.author_rules(batch=5)
		row = CVEDetection.objects.get(cve_entry=cve)
		detection_author.enrich_with_ai(row, Provider(answer(scope='external', scope_reason='r')))
		self.assertEqual(detection_author.mark_changed_for_revision(), 0)  # nothing changed
		CVEEntry.objects.filter(pk=cve.pk).update(original_description='Now also exploitable without login.', synced_at=timezone.now())
		self.assertEqual(detection_author.mark_changed_for_revision(), 1)
		row = CVEDetection.objects.get(cve_entry=cve)
		self.assertIsNone(row.ai_attempted_at)
		provider = Provider(answer(scope='external', scope_reason='r', revision_note='Added that no login is needed.',
								   identify='nginx before 1.20.0; no login needed.'))
		self.assertTrue(detection_author.enrich_with_ai(row, provider))
		system, user = provider.seen[0]
		self.assertIn('CURRENT_RECORD', user)
		self.assertNotIn('"commands"', user)  # rendered commands are the app's, not part of what the model revises
		row.refresh_from_db()
		self.assertEqual(row.strategy['revision_note'], 'Added that no login is needed.')
		self.assertEqual(sum(c['id'].startswith('ai-') for c in row.strategy['remote_checks']), 2)  # replaced, not doubled
		self.assertEqual(detection_author.mark_changed_for_revision(), 0)

	def test_an_admin_updates_a_record_with_guidance_or_a_whole_strategy(self):
		from unittest import mock
		cve = self.entry('CVE-2099-7106')
		admin = User.objects.create_user('intake-admin', password='x', is_superuser=True)
		user = User.objects.create_user('intake-user', password='x')
		with self.assertRaises(svc.ApiError) as cm:
			svc.update_cve_detection(svc.Ctx(user=user), cve.cve_id, guidance='x' * 30)
		self.assertEqual(cm.exception.status, 403)
		ctx = svc.Ctx(user=admin)
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None), self.assertRaises(svc.ApiError) as cm:
			svc.update_cve_detection(ctx, cve.cve_id, guidance='The vendor says 1.19.9 is also fixed.')
		self.assertEqual(cm.exception.status, 409)
		provider = Provider(answer(scope='external', scope_reason='r', revision_note='Added 1.19.9 as fixed.'))
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=provider):
			out = svc.update_cve_detection(ctx, cve.cve_id, guidance='The vendor says 1.19.9 is also fixed.')
		self.assertEqual((out['source'], out['strategy']['revision_note']), ('ai', 'Added 1.19.9 as fixed.'))
		self.assertIn('NEW_GUIDANCE', provider.seen[0][1])
		whole = {'summary': 'Written by hand.', 'identify': 'by a person', 'confirm_steps': ['Check it.'], 'scope': 'external',
				 'local_checks': [{'id': 'pkg', 'kind': 'package_version', 'confidence': 'high', 'description': 'd',
								   'params': {'ecosystem': 'dpkg', 'package': 'nginx', 'fixed_version': '1.20.0-1'}}]}
		out = svc.update_cve_detection(ctx, cve.cve_id, strategy=whole)
		self.assertEqual(out['source'], 'manual')
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=provider), self.assertRaises(svc.ApiError) as cm:
			svc.update_cve_detection(ctx, cve.cve_id, guidance='More facts for this record please.')
		self.assertEqual(cm.exception.status, 409)  # a person's record is never rewritten by the model
		row = CVEDetection.objects.get(cve_entry=cve)
		self.assertFalse(detection_author.enrich_with_ai(row, provider))
		with self.assertRaises(svc.ApiError):
			svc.update_cve_detection(ctx, cve.cve_id, strategy={'local_checks': [{'kind': 'shell', 'params': {'command': 'id'}}]})
		with self.assertRaises(svc.ApiError):
			svc.update_cve_detection(ctx, cve.cve_id)
