"""The names an IP host answers to are read once per Hosts page (review finding A5).

``_host`` read the reverse DNS and certificate names of every IP host with its own ``DiscoveryEvent`` query, on a table whose only index on the
target was ``(domain, id)``: 17 ms each on the largest target, up to 200 per page. ``_host_names_for`` reads them for the whole page in one query,
keyed by each row's own target and name, so a row never gets the names recorded for another target or another project.
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services
from agentapi.auth import create_token
from cveFeed.models import DiscoveryEvent
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call


class HostNamesBatchTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Hn', slug='hn-org')
        cls.project = Project.objects.create(name='hn', slug='hn-proj', insert_date=now, org=org)
        other = Project.objects.create(name='hn-other', slug='hn-other', insert_date=now, org=Org.objects.create(name='Hn2', slug='hn-org-2'))
        first = Domain.objects.create(name='192.0.2.10', project=cls.project, insert_date=now)
        second = Domain.objects.create(name='192.0.2.11', project=cls.project, insert_date=now)
        named = Domain.objects.create(name='hn.example', project=cls.project, insert_date=now)
        foreign = Domain.objects.create(name='192.0.2.10', project=other, insert_date=now)
        for domain in (first, second, named):
            sub = Subdomain.objects.create(target_domain=domain, name=domain.name)
            sub.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{domain.pk % 200 + 1}'))
        ev = lambda domain, host, module, label: DiscoveryEvent.objects.create(domain=domain, host=host, module=module, label=label, type='DNS_NAME')  # noqa: E731
        ev(first, '192.0.2.10', 'ptr', 'ten.example.net')
        ev(first, '192.0.2.10', 'tls-san', 'shop.example.org')
        ev(first, '192.0.2.10', 'tls-san', 'shop.example.org')  # the same name twice: listed once
        ev(first, '192.0.2.10', 'bbot', 'not-a-name.example')  # another module: never a name of the host
        ev(first, '192.0.2.11', 'ptr', 'eleven-on-the-wrong-target.example')  # the other address's name recorded under this target
        ev(second, '192.0.2.11', 'ptr', 'eleven.example.net')
        ev(named, 'hn.example', 'ptr', 'never-for-a-hostname.example')
        ev(foreign, '192.0.2.10', 'ptr', 'other-project.example')  # the same address in another project
        user = User.objects.create_user('hn-user', password='x')
        ProjectMembership.objects.create(user=user, project=cls.project, role='user')
        cls.token = create_token(user, 'agent')[1]

    def setUp(self):
        cache.clear()

    def test_a_page_reads_the_names_once_and_each_host_keeps_its_own(self):
        with CaptureQueriesContext(connection) as ctx:
            status, body = call(self.token, 'GET', '/api/v1/projects/hn-proj/hosts?page_size=50')
        self.assertEqual(status, 200, body)
        names = {h['host']: [tuple(n) for n in h['names']] for h in body['results']}
        self.assertEqual(names, {'192.0.2.10': [('ptr', 'ten.example.net'), ('tls-san', 'shop.example.org')],
                                 '192.0.2.11': [('ptr', 'eleven.example.net')], 'hn.example': []})
        self.assertEqual(sum(1 for q in ctx.captured_queries if 'cveFeed_discoveryevent' in q['sql']), 1)

    def test_the_batch_gives_what_the_single_read_gives(self):
        subs = list(Subdomain.objects.filter(target_domain__project=self.project).select_related('target_domain'))
        shared = {'host_names': services._host_names_for(subs)}
        for sub in subs:
            with self.subTest(host=sub.name):
                self.assertEqual(services._host_names(sub, shared), services._host_names(sub))

    def test_a_page_without_an_ip_host_asks_nothing(self):
        subs = list(Subdomain.objects.filter(name='hn.example'))
        with CaptureQueriesContext(connection) as ctx:
            self.assertEqual(services._host_names_for(subs), {})
        self.assertEqual(len(ctx.captured_queries), 0)
