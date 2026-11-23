"""A Hosts page reads the hot CVEs of its findings and the technology links of its hosts' other rows once (review findings A7 and A8).

``_heat_reasons`` asked ``threat.hot_cve_names`` once for every host row and every other row of the same host that has a live finding, and ``_host``
read the technology links of each host's other rows with a query of its own. Both are now read once for the page (``_hot_names_for``,
``shared['other_links']``); each row only looks up its own CVE names and its own rows' links, so every row says what it said before.
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services
from agentapi.auth import create_token
from cveFeed.models import CVEEntry
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import CveId, IpAddress, Subdomain, SubdomainTechnology, Technology, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_heat_policy import Policy


class HostPageBatchTests(Policy, TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Hp', slug='hp-org')
        cls.project = Project.objects.create(name='hp', slug='hp-proj', insert_date=now, org=org)
        domain = Domain.objects.create(name='hp.example', project=cls.project, insert_date=now)
        CVEEntry.objects.create(cve_id='CVE-2099-7701', cvss=9.8, kev=True, published_at=now, affected=[])
        CVEEntry.objects.create(cve_id='CVE-2099-7702', cvss=9.8, published_at=now, affected=[])
        hot, cold = CveId.objects.create(name='CVE-2099-7701'), CveId.objects.create(name='cve-2099-7702 ')
        tech = {n: Technology.objects.create(name=n) for n in ('nginx', 'php', 'jquery')}
        for i in range(4):
            shared_ip = IpAddress.objects.create(address=f'203.0.113.{i + 1}')
            # two names on the same address: one host shown as one row, the other name folded under it
            for name in (f'h{i}.hp.example', f'www.h{i}.hp.example'):
                sub = Subdomain.objects.create(target_domain=domain, name=name)
                sub.ip_addresses.add(shared_ip)
                SubdomainTechnology.objects.create(subdomain=sub, technology=tech['nginx' if name.startswith('h') else 'php'],
                                                   source='nuclei' if name.startswith('h') else 'vsrc:panel', cpe=f'cpe:2.3:a:x:{name}')
                vuln = Vulnerability.objects.create(name=f'flaw {name}', severity=4 if i % 2 else 3, subdomain=sub, target_domain=domain,
                                                    open_status=True, http_url=f'https://{name}/', source='nuclei')
                vuln.cve_ids.add(hot if (i + len(name)) % 2 else cold)
        user = User.objects.create_user('hp-user', password='x')
        ProjectMembership.objects.create(user=user, project=cls.project, role='user')
        cls.token = create_token(user, 'agent')[1]

    def setUp(self):
        super().setUp()
        cache.clear()

    def page(self):
        with CaptureQueriesContext(connection) as ctx:
            status, body = call(self.token, 'GET', '/api/v1/projects/hp-proj/hosts?page_size=50')
        self.assertEqual(status, 200, body)
        return body, ctx.captured_queries

    def test_the_page_asks_for_hot_cves_once(self):
        body, queries = self.page()
        self.assertEqual(body['count'], 4)
        self.assertEqual(sum(1 for q in queries if 'cveFeed_cveentry' in q['sql'] and '"kev"' in q['sql'] and 'CVE-2099-77' in str(q['sql'])), 1)
        heats = {r['label']: r['temp'] for h in body['results'] for r in h['heat_reasons'] if r['kind'] == 'finding'}
        self.assertEqual(len(heats), 8)  # every row of every host still gives its reason
        self.assertIn('ice', heats.values())  # a finding naming a CVE that is not hot

    def test_the_page_reads_the_technology_links_at_most_twice(self):
        body, queries = self.page()
        self.assertLessEqual(sum(1 for q in queries if 'startScan_subdomain_technologies' in q['sql'] and '"source"' in q['sql']), 2)
        for h in body['results']:
            with self.subTest(host=h['host']):
                self.assertEqual(sorted(h['technologies']), ['nginx', 'php'])

    def test_each_row_says_what_it_said_when_read_on_its_own(self):
        subs = list(services._one_per_host(Subdomain.objects.filter(target_domain__project=self.project)).select_related('target_domain').prefetch_related(
            'ip_addresses__ports', 'cve_matches__cve_entry', 'vulnerability_set', 'vulnerability_set__cve_ids', 'vulnerability_set__tags', 'technologies'))
        others = services._name_siblings(self.project, subs)
        hot = services._hot_names_for(subs, *others.values())
        links = services._technology_links({o.pk for rows in others.values() for o in rows})
        for sub in subs:
            with self.subTest(host=sub.name):
                self.assertEqual(services._merge_group(sub, others[sub.id], hot)[1], services._merge_group(sub, others[sub.id])[1])
                for other in others[sub.id]:
                    self.assertEqual(links.get(other.pk), services._technology_links([other.pk]).get(other.pk))
        self.assertTrue(links)  # the hosts do have other rows with links: the comparison above compared something
