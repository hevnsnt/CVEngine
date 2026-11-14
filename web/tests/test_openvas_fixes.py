"""Review fixes for the OpenVAS sweep: pause, names that share an address, the server's own address, the
project's own choice over its organization's, and the order the projects are visited in. The fixtures are the ones of tests.test_openvas."""
import os
import socket
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from agentapi.models import SentinelTask
from cveFeed import openvas_scan as ov
from cveFeed.models import OpenvasOrg, OpenvasProject, OpenvasRun, ScanControl, ServiceRun
from dashboard.models import Project
from startScan.models import Subdomain
from tests.test_openvas import APACHE, Fixture, as_item


class ReviewFixTests(Fixture, TestCase):
    # --- pause (S05-1)
    def test_an_update_drain_pause_lets_the_running_sentinel_task_finish_but_starts_nothing(self):
        self.make_sentinel()
        self.tick()
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True})
        self.assertEqual(self.tick()['status'], 'running')
        self.assertEqual(OpenvasRun.objects.get().sentinel_task.status, 'queued')  # not expired: a drain lets running work finish
        task = OpenvasRun.objects.get().sentinel_task
        task.result = {'results': [as_item(APACHE)], 'scanned_addresses': ['93.184.216.5'], 'without_cve': 0, 'unusable': 0}
        task.status = 'done'
        task.save(update_fields=['result', 'status'])
        self.assertEqual(self.tick()['status'], 'done')  # it finishes and is imported during the drain
        self.assertEqual(self.tick(), {'skipped': 'scanning is paused'})
        self.assertEqual(SentinelTask.objects.filter(kind='openvas').count(), 1)

    def test_pause_all_scanning_expires_a_running_sentinel_task_and_marks_no_host_failed(self):
        self.make_sentinel()
        self.assertEqual(self.tick()['via'], 'sentinel')
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        self.assertEqual(self.tick()['status'], 'failed')
        run = OpenvasRun.objects.get()
        self.assertEqual((run.status, run.sentinel_task.status), ('failed', 'expired'))
        self.assertIn('scanning is paused', run.error)
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())

    def test_a_paused_instance_dispatches_nothing_to_a_sentinel(self):
        self.make_sentinel()
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        self.assertEqual(self.tick(), {'skipped': 'scanning is paused'})
        self.assertFalse(OpenvasRun.objects.exists())


    # --- a gvmd that does not answer (S05-3)


    # --- names that share an address (S05-10)
    def test_every_name_of_a_scanned_address_is_fresh_not_just_the_one_scanned(self):
        from cveFeed import ledger
        self.scan(names=('alias.rt.test',), ip='93.184.216.5')  # a second name of the machine www.rt.test is on
        self.link.hosts = self.link.forced_hosts = ['www.rt.test']
        self.link.save()
        self.run_scan([APACHE])
        self.assertEqual(OpenvasRun.objects.get().status, 'done')
        fresh = ledger.fresh(ov.SERVICE, ['www.rt.test', 'alias.rt.test', 'api.rt.test'], self.project.id)
        self.assertEqual(set(fresh), {'www.rt.test', 'alias.rt.test'})

    # --- a truncated result set (S05-14)

    # --- the server's own address (S05-13)
    def test_a_failed_lookup_of_the_servers_own_name_is_not_remembered_for_an_hour(self):
        with mock.patch.dict(os.environ, {'CVENGINE_OWN_ADDRESSES': ''}), mock.patch.dict(ov._own, {'at': 0.0}), override_settings(DOMAIN_NAME='cve.example.test'):
            with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror(-2, 'Name or service not known')):
                self.assertEqual(ov.own_addresses(), frozenset())
            with mock.patch('time.monotonic', return_value=ov._own['at'] + ov.OWN_TTL + 1), \
                    mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('198.51.100.77', 0))]):
                self.assertEqual(ov.own_addresses(), frozenset({'198.51.100.77'}))

    def test_own_addresses_are_compared_in_one_form(self):
        with mock.patch.dict(os.environ, {'CVENGINE_OWN_ADDRESSES': '2606:4700:0000:0000:0000:0000:0000:0099, 93.184.216.99'}), mock.patch.dict(ov._own, {'at': 0.0}):
            self.assertEqual(ov.refuse_reason('2606:4700::99'), 'this cvENGINE server')

    # --- a busy project cannot hold the slot (S05-11)
    def test_the_project_scanned_longest_ago_goes_first(self):
        other = Project.objects.create(name='Second', slug='second', insert_date=timezone.now(), org=self.project.org)
        second = OpenvasProject.objects.create(project=other, enabled=True)
        self.assertEqual([l.pk for l in ov.sweep_links()], [self.link.pk, second.pk])  # never run: by id
        OpenvasRun.objects.create(project=self.project, status='done')
        self.assertEqual([l.pk for l in ov.sweep_links()], [second.pk, self.link.pk])  # the first project just ran
        OpenvasRun.objects.create(project=other, status='done')
        self.assertEqual([l.pk for l in ov.sweep_links()], [self.link.pk, second.pk])

    # --- the project's own choice wins over its organization's (S05-4, S05-9)
    def test_an_excluded_project_of_an_opted_in_organization_is_not_scanned(self):
        OpenvasOrg.objects.create(org=self.project.org, enabled=True)
        self.link.enabled, self.link.excluded = False, True
        self.link.save()
        later = Project.objects.create(name='Later', slug='later', insert_date=timezone.now(), org=self.project.org)
        self.assertEqual({l.project_id for l in ov.sweep_links()}, {later.pk})
        self.assertEqual({l.project_id for l in ov.links_for([self.project.id, later.id])}, {later.pk})

    def test_a_project_with_its_own_opt_in_is_scanned_even_if_the_flag_says_excluded(self):
        OpenvasOrg.objects.create(org=self.project.org, enabled=True)
        self.link.excluded = True  # enabled stays True: the project's own opt-in wins
        self.link.save()
        self.assertIn(self.project.id, {l.project_id for l in ov.sweep_links()})

    def test_check_coverage_sees_a_project_opted_in_through_its_organization(self):
        from cveFeed import check_coverage as cc
        sub = Subdomain.objects.get(name='www.rt.test')
        self.link.delete()
        self.assertEqual(cc.load([(sub, [sub], self.project.id)]).openvas, {})
        OpenvasOrg.objects.create(org=self.project.org, enabled=True)
        self.assertIn(self.project.id, cc.load([(sub, [sub], self.project.id)]).openvas)
        OpenvasProject.objects.update_or_create(project=self.project, defaults={'enabled': False, 'excluded': True})
        self.assertEqual(cc.load([(sub, [sub], self.project.id)]).openvas, {})
