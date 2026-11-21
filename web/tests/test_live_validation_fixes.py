"""What validating a live server turned up (Nov 20): AI jobs held back by their stage were reported as a stalled reviewer, a Sentinel too old for
the nuclei template index was shown with its nuclei kinds "on", an instance-wide Sentinel was warned it would get no work, one Sentinel's detail
was 3 MB of screenshot results, and an address every Sentinel refuses was offered again at every UDP sweep."""
import datetime
from unittest import mock

from django.utils import timezone

from agentapi import agent_broker, sentinel_broker
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import SentinelTask
from cveFeed import ai_jobs
from cveFeed.models import AIJob
from dashboard.models import ApiToken
from tests.test_ai_jobs import Base as AIBase
from tests.test_sentinel_dispatch import DispatchBase


class HeldJobsAreNotAStalledReviewerTests(AIBase):
    def queue_old_job(self):
        self.match()
        self.ask()
        AIJob.objects.update(created_at=timezone.now() - datetime.timedelta(minutes=40))

    def test_a_reviewer_that_called_a_minute_ago_is_serving_even_with_an_old_job_queued(self):
        self.queue_old_job()
        ApiToken.objects.filter(scope='reviewer').update(last_used_at=timezone.now() - datetime.timedelta(minutes=1))
        state = ai_jobs.waiting()
        self.assertFalse(state['waiting_for_reviewer'])
        self.assertIn('held back by their stage', state['why'])
        self.assertEqual(ai_jobs.waiting_message(state), '')

    def test_a_reviewer_that_has_not_called_for_an_hour_is_still_reported(self):
        self.queue_old_job()
        ApiToken.objects.filter(scope='reviewer').update(last_used_at=timezone.now() - datetime.timedelta(hours=1))
        state = ai_jobs.waiting()
        self.assertTrue(state['waiting_for_reviewer'])
        self.assertIn('has not taken work for 40 minutes', state['why'])


class SentinelDetailTests(DispatchBase):
    def test_nuclei_kinds_of_a_client_before_the_template_index_say_outdated(self):
        agent = self.make_sentinel(['nuclei_light', 'nmap'])
        agent.info = {'features': ['credential_filter'], 'contract_version': 10}
        agent.save(update_fields=['info'])
        kinds = sentinel_broker.kind_report(agent)
        self.assertEqual((kinds['nuclei_light']['effective'], kinds['nuclei_light']['state']), (False, 'outdated'))
        self.assertIn('template index', kinds['nuclei_light']['note'])
        self.assertEqual(kinds['nmap']['state'], 'on')

    def test_an_instance_wide_scope_gets_no_no_work_warning(self):
        agent = self.make_sentinel(['nmap'])
        agent.scope = {'orgs': [], 'projects': [], 'hosts': [], 'instance': True}
        self.assertFalse(any('no work will be assigned' in w for w in agent_broker._warnings(agent)))
        agent.scope = {'orgs': [], 'projects': [], 'hosts': ['web.example.test']}
        self.assertTrue(any('no work will be assigned' in w for w in agent_broker._warnings(agent)))

    def test_a_large_result_is_left_out_of_the_recent_tasks(self):
        agent = self.make_sentinel(['web_screenshot'])
        big = SentinelTask.objects.create(project=self.project, kind='web_screenshot', status='done', agent=agent, target={},
                                          result={'shots': ['x' * 50_000]})
        small = SentinelTask.objects.create(project=self.project, kind='web_screenshot', status='done', agent=agent, target={},
                                            result={'shots': []})
        rows = {row['id']: row for row in sentinel_broker.recent_tasks(agent)}
        self.assertTrue(rows[big.pk]['result']['omitted'])
        self.assertGreater(rows[big.pk]['result']['bytes'], 50_000)
        self.assertEqual(rows[small.pk]['result'], {'shots': []})


class RefusedUdpAddressTests(DispatchBase):
    def test_an_address_the_sentinel_refuses_is_a_failure_of_the_address_not_a_missing_scanner(self):
        from cveFeed.udp_scan import UdpScanError
        self.make_sentinel(['nmap_udp'])

        def refuse(_seconds):
            task = SentinelTask.objects.filter(status__in=('queued', 'claimed', 'running')).order_by('-id').first()
            if task:
                SentinelTask.objects.filter(pk=task.pk).update(
                    status='failed', finished_at=timezone.now(), result={'outcome': 'error'},
                    error="not a usable target: '192.0.2.10' (that address is never scanned (documentation space))")
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=refuse):
            with self.assertRaises(UdpScanError) as caught:
                dispatch.try_nmap_udp(self.project, '192.0.2.10', timeout=5)
        self.assertIn('refuses to scan 192.0.2.10', str(caught.exception))
