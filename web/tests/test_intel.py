import gzip
import json
import os
import tempfile
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import intel
from cveFeed.models import CVEEntry, IntelSource

KEV = {'catalogVersion': '2026.10.23', 'vulnerabilities': [
    {'cveID': 'CVE-2021-44228', 'vendorProject': 'Apache', 'product': 'Log4j2', 'vulnerabilityName': 'Apache Log4j2 RCE',
     'dateAdded': '2021-12-10', 'knownRansomwareCampaignUse': 'Known'},
    {'cveID': 'CVE-2099-0001', 'vendorProject': 'Acme', 'product': 'Widget', 'vulnerabilityName': 'Acme Widget RCE',
     'dateAdded': '2026-10-01', 'knownRansomwareCampaignUse': 'Unknown'}]}
EPSS = '#model_version:v2026.06.15,score_date:2026-10-24T12:03:08Z\ncve,epss,percentile\nCVE-2021-44228,0.94358,0.99962\n' \
       'CVE-2099-0002,0.00041,0.1\nCVE-2099-0003,0.5,0.98\n'
EXPLOITDB = 'id,file,description,codes\n50592,exploits/java/remote/50592.py,Log4Shell,CVE-2021-44228;OSVDB-1\n' \
            '50593,exploits/php/webapps/50593.txt,Widget,CVE-2099-0004\n'
MSF = {'exploit_multi_http_log4shell': {'fullname': 'exploit/multi/http/log4shell_header_injection',
                                        'references': ['CVE-2021-44228', 'URL-https://example.com']}}
EUVD_PAGES = [{'items': [{'id': 'EUVD-2021-0001', 'aliases': 'CVE-2099-0005\nGHSA-xxxx\n', 'exploitedSince': 'Oct 1, 2026'}], 'total': 1}]

LOG4SHELL_RECORD = {
    'cveMetadata': {'cveId': 'CVE-2021-44228', 'state': 'PUBLISHED', 'datePublished': '2021-12-10T00:00:00.000Z'},
    'containers': {
        'cna': {'title': 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP',
                'descriptions': [{'lang': 'en', 'value': 'Apache Log4j2 JNDI features ...'}],
                'affected': [{'vendor': 'Apache Software Foundation', 'product': 'Apache Log4j2', 'versions': [
                    {'version': '2.0-beta9', 'status': 'affected', 'lessThan': 'log4j-core*', 'versionType': 'custom',
                     'changes': [{'at': '2.3.1', 'status': 'unaffected'}, {'at': '2.4', 'status': 'affected'},
                                 {'at': '2.12.2', 'status': 'unaffected'}, {'at': '2.13.0', 'status': 'affected'},
                                 {'at': '2.15.0', 'status': 'unaffected'}]}]}],
                'references': [{'url': 'https://logging.apache.org/log4j/2.x/security.html'}], 'metrics': []},
        'adp': [{'title': 'CISA ADP Vulnrichment', 'metrics': [{'cvssV3_1': {'baseScore': 10.0, 'baseSeverity': 'CRITICAL',
                                                                             'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'}}]}]}}


class Resp:
    def __init__(self, status=200, body=b'', headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def iter_content(self, size):
        yield self._body

    def close(self):
        pass


def fake_get(url, headers=None, **_kw):
    if url == intel.SOURCES['cisa_kev']['url']:
        return Resp(body=json.dumps(KEV).encode(), headers={'ETag': '"kev1"'})
    if url == intel.SOURCES['epss']['url']:
        return Resp(body=gzip.compress(EPSS.encode()))
    if url == intel.SOURCES['exploit_db']['url']:
        return Resp(body=EXPLOITDB.encode())
    if url == intel.SOURCES['metasploit']['url']:
        return Resp(body=json.dumps(MSF).encode())
    if 'euvdservices' in url:
        return Resp(body=json.dumps(EUVD_PAGES[0]).encode())
    if url == intel.cve5_url('CVE-2021-44228'):
        return Resp(body=json.dumps(LOG4SHELL_RECORD).encode())
    if 'cvelistV5' in url:
        return Resp(status=404)
    raise AssertionError(f'unexpected request {url}')


class ConversionTests(SimpleTestCase):
	def test_changes_split_the_affected_range_like_the_advisory(self):
		items = intel.convert_affected(LOG4SHELL_RECORD['containers']['cna']['affected'])
		self.assertEqual(items[0]['ranges'], [{'type': 'SEMVER', 'introduced': '2.0-beta9', 'fixed': '2.3.1'},
											  {'type': 'SEMVER', 'introduced': '2.4', 'fixed': '2.12.2'},
											  {'type': 'SEMVER', 'introduced': '2.13.0', 'fixed': '2.15.0'}])

	def test_bounds_that_are_not_plain_versions(self):
		self.assertEqual(intel._ranges({'versions': [{'version': 'Ver2.20', 'status': 'affected', 'lessThan': 'Ver8.00 Update 5'}]}),
						 [{'type': 'SEMVER', 'introduced': '2.20', 'lastAffected': '8.00'}])
		self.assertEqual(intel._ranges({'versions': [{'version': '0', 'status': 'affected', 'lessThan': '1.4.2', 'versionType': 'semver'}]}),
						 [{'type': 'SEMVER', 'fixed': '1.4.2'}])
		self.assertEqual(intel._ranges({'versions': [{'version': '3.1', 'status': 'affected'}]}),
						 [{'type': 'SEMVER', 'introduced': '3.1', 'lastAffected': '3.1'}])
		self.assertEqual(intel._ranges({'versions': [{'version': 'n/a', 'status': 'affected'}, {'version': '2.0', 'status': 'unaffected'}]}), [])

	def test_a_cpe_names_the_product_the_way_scanners_do(self):
		item = intel.convert_affected([{'vendor': 'Apache', 'product': 'Apache Log4j2', 'cpes': ['cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'],
										'versions': []}])[0]
		self.assertEqual(item['package'], 'log4j')

	def test_a_rejected_record_is_not_imported(self):
		self.assertIsNone(intel.entry_from_cve5({'cveMetadata': {'state': 'REJECTED'}}, {}))

	def test_signals_only_add_evidence_and_epss_is_todays_value(self):
		self.assertEqual(intel.merged_flags({'kev': False, 'epssReached': True, 'exploitDb': False}, {}), (False, True, False))
		self.assertEqual(intel.merged_flags({'kev': False}, {'kev': {'euvd': {}}, 'exploits': {'metasploit': ['x']},
															'epss': {'score': 0.05, 'percentile': 0.9}}), (True, False, True))
		self.assertEqual(intel.merged_flags(None, {}), (None, None, None))


class RunTests(TestCase):
	def setUp(self):
		self.dir = tempfile.mkdtemp()
		patch = mock.patch.dict(os.environ, {'CVENGINE_INTEL_DIR': self.dir})
		patch.start()
		self.addCleanup(patch.stop)
		self.feed_entry = CVEEntry.objects.create(cve_id='CVE-2099-0003', cvss=7.5, title='feed CVE', published_at=timezone.now(),
												  epss_reached=False, kev=False, exploit_db=False)

	def run_intel(self, **env):
		with mock.patch.dict(os.environ, env), mock.patch('cveFeed.intel.cache_dir', return_value=self.dir), \
				mock.patch('cveFeed.intel._get', side_effect=lambda url, headers=None, get=None: fake_get(url, headers)):
			return intel.run()

	def test_a_historical_exploited_cve_is_imported_with_its_record_and_signals(self):
		result = self.run_intel()
		self.assertEqual(result['errors'], {})
		self.assertEqual(result['sources'], {'cisa_kev': 2, 'euvd': 1, 'epss': 3, 'exploit_db': 2, 'metasploit': 1})
		log4shell = CVEEntry.objects.get(cve_id='CVE-2021-44228')
		self.assertEqual((log4shell.kev, log4shell.exploit_db, log4shell.epss_reached, log4shell.cvss), (True, True, True, 10.0))
		self.assertEqual(log4shell.threat_tier, 'fire')
		self.assertEqual(log4shell.affected[0]['product'], 'Apache Log4j2')
		self.assertEqual(log4shell.published_at.year, 2021)  # first seen when published, not "new this week"
		self.assertEqual(set(log4shell.intel), {'kev', 'epss', 'exploits'})
		self.assertTrue(log4shell.intel['kev']['cisa_kev']['ransomware'])
		self.assertEqual(log4shell.intel['exploits'], {'exploit_db': ['50592'], 'metasploit': ['exploit/multi/http/log4shell_header_injection']})
		self.assertIn('CISA KEV', log4shell.sources)
		self.assertFalse(CVEEntry.objects.filter(cve_id='CVE-2099-0001').exists())  # no CVE List record: skipped for a week

	def test_a_stored_cve_gets_the_signals_the_feed_did_not_report(self):
		self.run_intel()
		self.feed_entry.refresh_from_db()
		self.assertEqual((self.feed_entry.epss_reached, self.feed_entry.kev), (True, False))  # EPSS 0.5 today
		self.assertEqual(self.feed_entry.intel['epss'], {'score': 0.5, 'percentile': 0.98})
		self.assertEqual(self.feed_entry.threat_tier, 'fire')  # EPSS reached with CVSS 7.5

	def test_cve_now_rewriting_an_entry_keeps_the_other_sources_evidence(self):
		self.run_intel()
		CVEEntry.from_api({'id': 'CVE-2099-0003', 'title': 'feed CVE', 'severity': {'cvss': 7.5},
						   'exploitation': {'kev': False, 'epssReached': False, 'exploitDb': False}})
		self.feed_entry.refresh_from_db()
		self.assertTrue(self.feed_entry.epss_reached)

	def test_a_signal_the_feed_set_is_kept_when_no_source_names_the_cve(self):
		kept = CVEEntry.objects.create(cve_id='CVE-2099-0090', cvss=3.0, title='feed only', published_at=timezone.now(),
									   kev=True, epss_reached=False, exploit_db=False)
		self.run_intel()
		kept.refresh_from_db()
		self.assertEqual((kept.kev, kept.epss_reached, kept.exploit_db), (True, False, False))

	def test_a_failing_source_keeps_its_last_copy_and_is_reported(self):
		self.run_intel()
		IntelSource.objects.filter(name='cisa_kev').update(last_checked=timezone.now() - timezone.timedelta(days=1))

		def broken(url, headers=None):
			if url == intel.SOURCES['cisa_kev']['url']:
				return Resp(status=503)
			return fake_get(url, headers)
		with mock.patch('cveFeed.intel.cache_dir', return_value=self.dir), \
				mock.patch('cveFeed.intel._get', side_effect=lambda url, headers=None, get=None: broken(url, headers)):
			result = intel.run()
		self.assertIn('503', result['errors']['cisa_kev'])
		self.assertEqual(result['sources']['cisa_kev'], 2)  # the cached copy is still used
		self.assertTrue(CVEEntry.objects.get(cve_id='CVE-2021-44228').kev)

	def test_import_is_bounded_and_can_be_turned_off(self):
		self.assertEqual(self.run_intel(CVENGINE_INTEL_IMPORT_PER_RUN='0')['imported'], [])
		self.assertEqual(self.run_intel(CVENGINE_INTEL='0'), {'status': 'disabled'})
		self.assertNotIn('vulncheck_kev', intel.enabled_sources())  # needs CVENGINE_VULNCHECK_API_KEY

	def test_the_task_logs_imports_and_announces_new_fire_cves(self):
		from cveFeed.models import AgentActivity
		from cveFeed.tasks import sync_threat_intel
		with mock.patch('cveFeed.intel.cache_dir', return_value=self.dir), \
				mock.patch('cveFeed.intel._get', side_effect=lambda url, headers=None, get=None: fake_get(url, headers)), \
				mock.patch('cveFeed.tasks.auto_fire_new_cves.delay') as announce:
			out = sync_threat_intel()
		self.assertEqual(out['imported'], 1)
		announce.assert_called_once()
		line = AgentActivity.objects.filter(message__startswith='Threat intelligence').latest('id')
		self.assertIn('1 CVEs imported from the CVE List (1 fire', line.message)

	def test_threat_signal_changes_rescore_matches_beyond_old_limits(self):
		from cveFeed.tasks import sync_threat_intel
		changed = list(range(1, 5002))
		with mock.patch('django.core.cache.cache.add', return_value=True), \
				mock.patch('django.core.cache.cache.delete'), \
				mock.patch('cveFeed.intel.run', return_value={'imported': [], 'signals_changed': changed, 'errors': {}, 'sources': {}}), \
				mock.patch('cveFeed.models.CVEMatch.objects.filter') as find_matches, \
				mock.patch('cveFeed.scoring.rescore_for_matches') as rescore, \
				mock.patch('cveFeed.activity.log'):
			result = sync_threat_intel()
		self.assertEqual(result['signals_changed'], len(changed))
		batches = [call.kwargs['cve_entry_id__in'] for call in find_matches.call_args_list]
		self.assertEqual([cve_id for batch in batches for cve_id in batch], changed)
		self.assertTrue(all(len(batch) <= 500 for batch in batches))
		self.assertEqual(rescore.call_count, len(batches))

	def test_the_advisory_panel_names_who_reported_each_signal(self):
		from agentapi.services import _cve_context
		self.run_intel()
		exploitation = _cve_context(CVEEntry.objects.get(cve_id='CVE-2021-44228'))['exploitation']
		self.assertEqual(exploitation['exploited_by'][0], {'source': 'CISA KEV', 'since': '2021-12-10', 'ransomware': True})
		self.assertEqual(exploitation['public_exploits'], {'Exploit-DB': 1, 'Metasploit': 1})
		self.assertEqual(exploitation['epss']['score'], 0.94358)

	def test_scheduled_and_running_during_a_pause(self):
		from django_celery_beat.models import PeriodicTask
		from cveFeed.scan_control import PAUSE_EXEMPT_TASKS
		self.assertEqual(PeriodicTask.objects.get(name='cvengine-threat-intel').task, 'sync_threat_intel')
		self.assertIn('sync_threat_intel', PAUSE_EXEMPT_TASKS)
