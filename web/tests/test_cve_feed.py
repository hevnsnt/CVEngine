from django.test import TestCase
from django.utils import timezone

from cveFeed.models import CVEEntry
from cveFeed.threat import FIRE, ICE, SMOKE, classify_threat_tier
from cveFeed.views import tier_counts


class ThreatTierTests(TestCase):
	def test_rules(self):
		self.assertEqual(classify_threat_tier(kev=True, cvss=2.0), FIRE)  # known exploited, whatever the score
		self.assertEqual(classify_threat_tier(exploit_db=True, cvss=2.0), FIRE)
		self.assertEqual(classify_threat_tier(cvss=9.0), FIRE)  # critical, as cve.now's own rule says
		self.assertEqual(classify_threat_tier(cvss=9.8), FIRE)
		self.assertEqual(classify_threat_tier(epss_reached=True, cvss=7.5), FIRE)
		self.assertEqual(classify_threat_tier(cvss=8.9), SMOKE)
		self.assertEqual(classify_threat_tier(epss_reached=True, cvss=3.0), SMOKE)
		self.assertEqual(classify_threat_tier(cvss=6.9), ICE)
		self.assertEqual(classify_threat_tier(), ICE)

	def test_database_counts_agree_with_the_classifier_for_every_cve(self):
		rows = [dict(cvss=9.8), dict(cvss=9.0), dict(kev=True, cvss=3.0), dict(exploit_db=True), dict(epss_reached=True, cvss=7.1),
				dict(cvss=8.0), dict(epss_reached=True, cvss=2.0), dict(cvss=5.0), dict(), dict(kev=False, epss_reached=False, cvss=None)]
		for i, kw in enumerate(rows):
			CVEEntry.objects.create(cve_id=f'CVE-2099-{i}', published_at=timezone.now(), **kw)
		expected = {FIRE: 0, SMOKE: 0, ICE: 0}
		for e in CVEEntry.objects.all():
			expected[e.threat_tier] += 1
		self.assertEqual(tier_counts(), expected)
		self.assertEqual(sum(expected.values()), len(rows))  # every stored CVE is counted, not a window of them


class FeedEntryStorageTests(TestCase):
	def _entry(self, **over):
		entry = {'id': 'CVE-2026-109618', 'title': 'PHP-CGI argument injection', 'severity': {'cvss': 9.8, 'vector': 'CVSS:3.1/AV:N',
				'source': 'b15e7b5b-3da4-40ae-a43c-f7aa60e62599'}, 'statedSeverity': 'critical', 'status': 'Published'}
		entry.update(over)
		return entry

	def test_a_36_character_severity_source_is_stored(self):
		obj, created = CVEEntry.from_api(self._entry())  # this value failed on the old varchar(32) column
		self.assertTrue(created)
		self.assertEqual(CVEEntry.objects.get(cve_id='CVE-2026-109618').severity_source, 'b15e7b5b-3da4-40ae-a43c-f7aa60e62599')

	def test_an_over_long_value_is_clipped_not_fatal(self):
		long = 'x' * 500
		obj, _ = CVEEntry.from_api(self._entry(statedSeverity=long, status=long, severity={'source': long, 'cvss': 5.0}))
		stored = CVEEntry.objects.get(pk=obj.pk)
		self.assertEqual((len(stored.stated_severity), len(stored.status), len(stored.severity_source)), (128, 128, 128))
		self.assertEqual(stored.cvss, 5.0)  # the rest of the row is intact


	def test_the_modelled_columns_hold_the_feed_entry(self):
		obj, _ = CVEEntry.from_api(self._entry(references=['https://example.com/a']))
		stored = CVEEntry.objects.get(pk=obj.pk)
		self.assertEqual(stored.references, ['https://example.com/a'])


class ActivityPagingTests(TestCase):
	def test_150_new_rows_come_back_in_two_pages_oldest_first_with_no_gaps(self):
		from django.contrib.auth.models import User
		from cveFeed.models import AgentActivity
		from tests.test_tenancy import client_for
		user = User.objects.create_superuser('pagingroot', 'p@x.io', 'x')
		first = AgentActivity.objects.create(kind='feed', message='cursor').id
		ids = [AgentActivity.objects.create(kind='feed', message=f'row {i}').id for i in range(150)]
		c = client_for(user)
		page1 = [i['id'] for i in c.get(f'/cve/api/activity?after={first}').json()['items']]
		self.assertEqual(page1, ids[:100])  # the oldest hundred above the cursor, not the newest
		page2 = [i['id'] for i in c.get(f'/cve/api/activity?after={page1[-1]}').json()['items']]
		self.assertEqual(page2, ids[100:])


class ActivityCollapseTests(TestCase):
	def test_the_same_line_again_bumps_the_newest_row_instead_of_adding_one(self):
		from cveFeed import activity
		from cveFeed.models import AgentActivity
		first = activity.log('discovery', 'Nuclei is scanning 2 targets for X, scan #1')
		again = activity.log('discovery', 'Nuclei is scanning 2 targets for X, scan #1')
		self.assertEqual(AgentActivity.objects.count(), 1)
		self.assertEqual((again.pk, again.repeat), (first.pk, 2))
		activity.log('discovery', 'Nuclei is scanning 2 targets for X, scan #1')
		self.assertEqual(AgentActivity.objects.get().repeat, 3)

	def test_a_different_line_a_different_project_scan_or_an_old_row_is_a_new_entry(self):
		from datetime import timedelta
		from cveFeed import activity
		from cveFeed.models import AgentActivity
		from dashboard.models import Org, Project
		org = Org.objects.create(name='AC', slug='ac')
		p1 = Project.objects.create(name='A', slug='ac1', insert_date=timezone.now(), org=org)
		activity.log('scan', 'x', project=p1)
		activity.log('scan', 'y', project=p1)  # another message
		activity.log('scan', 'y', project=p1, scan_id=5)  # another scan
		activity.log('scan', 'y')  # another project (global)
		activity.log('hygiene', 'y', project=p1, scan_id=5)  # another kind
		self.assertEqual(AgentActivity.objects.count(), 5)
		old = activity.log('scan', 'z', project=p1)
		AgentActivity.objects.filter(pk=old.pk).update(created_at=timezone.now() - timedelta(minutes=30))
		activity.log('scan', 'z', project=p1)
		self.assertEqual(AgentActivity.objects.filter(message='z').count(), 2)  # outside the ten-minute window

	def test_a_repeat_is_offered_to_a_client_that_already_has_the_row(self):
		from django.contrib.auth.models import User
		from cveFeed import activity
		from tests.test_tenancy import client_for
		row = activity.log('feed', 'same')
		c = client_for(User.objects.create_superuser('collroot', 'c@x.io', 'x'))
		d = c.get(f'/cve/api/activity?after={row.pk}').json()
		activity.log('feed', 'same')
		again = c.get(f'/cve/api/activity?after={row.pk}&since={d["now"]}'.replace('+', '%2B')).json()
		self.assertEqual([(a['id'], a['repeat']) for a in again['bumped']], [(row.pk, 2)])
		self.assertEqual(again['items'], [])

	def test_a_feed_read_that_finds_nothing_is_not_logged_but_one_that_finds_something_is(self):
		from unittest import mock
		from cveFeed import tasks
		from cveFeed.models import AgentActivity
		client = mock.Mock()
		client.iter_entries.return_value = iter([])
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), mock.patch('cveFeed.tasks.logger.debug') as debug:
			out = tasks.sync_cve_now_feed()
		self.assertEqual(out['created'], 0)
		self.assertFalse(AgentActivity.objects.filter(kind='feed').exists())  # not even the "running" line is left behind
		debug.assert_called()
		client.iter_entries.return_value = iter([{'id': 'CVE-2099-5'}])
		client.get_entry.return_value = {'id': 'CVE-2099-5', 'title': 't', 'published_at': timezone.now().isoformat()}
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), mock.patch('cveFeed.tasks.CVEEntry.from_api') as from_api, \
				mock.patch('cveFeed.tasks.auto_fire_new_cves.delay'):
			from_api.return_value = (mock.Mock(threat_tier='ice'), True)
			tasks.sync_cve_now_feed()
		self.assertTrue(AgentActivity.objects.filter(kind='feed', message__startswith='cve.now: 1 new CVEs').exists())


class RejectedAndScoringTests(TestCase):
	def test_the_best_cvss_wins_not_the_first_container(self):
		from cveFeed import intel
		doc = {'cveMetadata': {'state': 'PUBLISHED', 'datePublished': '2024-01-01T00:00:00Z'},
			   'containers': {'cna': {'metrics': [{'cvssV2_0': {'baseScore': 4.3, 'vectorString': 'AV:N/AC:M/Au:N/C:P/I:N/A:N'}}], 'descriptions': []},
							  'adp': [{'metrics': [{'cvssV3_1': {'baseScore': 9.8, 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
																'baseSeverity': 'CRITICAL'}}]}]}}
		entry = intel.entry_from_cve5(doc, {})
		self.assertEqual((entry['cvss'], entry['stated_severity']), (9.8, 'CRITICAL'))
		self.assertTrue(entry['cvss_vector'].startswith('CVSS:3.1'))

	def test_a_rejected_cve_leaves_the_pool_and_its_open_matches_are_closed(self):
		from django.utils import timezone

		from cveFeed import correlation
		from cveFeed.models import CVEEntry, CVEMatch
		from dashboard.models import Org, Project
		from startScan.models import Subdomain
		from targetApp.models import Domain
		project = Project.objects.create(name='Rj', slug='rj', insert_date=timezone.now(), org=Org.objects.create(name='Rj', slug='rjo'))
		domain = Domain.objects.create(name='rj.test', project=project, insert_date=timezone.now())
		sub = Subdomain.objects.create(name='www.rj.test', target_domain=domain)
		rejected = CVEEntry.objects.create(cve_id='CVE-2099-8000', status='REJECTED', affected=[{'product': 'nginx'}], published_at=timezone.now())
		live = CVEEntry.objects.create(cve_id='CVE-2099-8001', status='PUBLISHED', affected=[{'product': 'nginx'}], published_at=timezone.now())
		m1 = CVEMatch.objects.create(cve_entry=rejected, subdomain=sub, source='tech')
		m2 = CVEMatch.objects.create(cve_entry=live, subdomain=sub, source='tech')
		correlation._INDEX_CACHE.update(key=None, value=None)
		pool, _ = correlation.cve_pool()
		self.assertEqual(set(pool), {live.id})
		self.assertEqual(correlation.close_rejected(), 1)
		m1.refresh_from_db()
		m2.refresh_from_db()
		self.assertEqual(m1.ai_verdict, 'not_affected')
		self.assertIn('rejected', m1.ai_reason)
		self.assertNotEqual(m2.ai_verdict, 'not_affected')
		self.assertEqual(correlation.close_rejected(), 0)  # already closed
