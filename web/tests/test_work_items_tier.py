"""The agent's work list filters by tier in the database, and says when it was cut (review finding A4).

``work_items`` read the 2,000 best-ranked matches (highest confidence first) and dropped those not of the asked tier in Python, so
``?tier=fire`` found only the fire items among those 2,000: a fire item with a lower confidence was missing from the agent's list, with no sign that the
list was cut. The tier is now a filter of the query (``threat.match_heat_rank_expr``, the database form of the heat every other list shows), and a list cut
at the window says so (``truncated``).
"""
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import services as svc
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain

WINDOW = 2000


class WorkItemsTierTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='W', slug='wi-org')
        cls.project = Project.objects.create(name='W', slug='wi-proj', insert_date=now, org=org)
        domain = Domain.objects.create(name='wi.example.com', project=cls.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='wi-engine', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=now, tasks=[])
        cls.user = User.objects.create_superuser('wi-root', 'root@wi.example.test', 'x')
        Subdomain.objects.bulk_create([Subdomain(name=f'h{i}.wi.example.com', target_domain=domain, scan_history=scan) for i in range(WINDOW + 2)])
        cls.subs = list(Subdomain.objects.filter(target_domain=domain).order_by('id'))
        mild = CVEEntry.objects.create(cve_id='CVE-2099-4001', cvss=5.0, published_at=now, affected=[])
        kev = CVEEntry.objects.create(cve_id='CVE-2099-4002', cvss=9.8, kev=True, published_at=now, affected=[])
        # WINDOW + 1 well-ranked matches that are ice, and one fire match (known exploited, proven by a template) that ranks below all of them
        CVEMatch.objects.bulk_create([CVEMatch(cve_entry=mild, subdomain=s, matched_product='nginx', confidence=.9) for s in cls.subs[:WINDOW + 1]])
        cls.fire = CVEMatch.objects.create(cve_entry=kev, subdomain=cls.subs[WINDOW + 1], matched_product='apache', confidence=.1, template_result='vulnerable')

    def work(self, **params):
        return svc.work_items(svc.Ctx(user=self.user), 'wi-proj', {'page_size': '100', **params})

    def test_a_fire_item_below_the_window_is_found_by_tier(self):
        out = self.work(tier='fire')
        self.assertEqual([i['id'] for i in out['results']], [self.fire.pk])
        self.assertEqual((out['count'], out['matches']), (1, 1))

    def test_ice_by_tier_is_the_rest(self):
        out = self.work(tier='ice')
        self.assertEqual(out['matches'], WINDOW)  # the window of the asked tier: 2,001 exist and 2,000 are read
        self.assertTrue(out['truncated'])

    def test_a_list_cut_at_the_window_says_so_and_a_whole_list_does_not(self):
        self.assertTrue(self.work()['truncated'])
        self.assertFalse(self.work(tier='fire')['truncated'])
        self.assertFalse(self.work(tier='smoke')['truncated'])
        self.assertEqual(self.work(tier='smoke')['results'], [])

    def test_the_tier_of_an_item_is_the_tier_asked_for(self):
        for tier in ('fire', 'smoke', 'ice'):
            self.assertEqual({i['cve']['tier'] for i in self.work(tier=tier)['results']} - {tier}, set())


class WorkItemsDocsTests(TestCase):
    def test_the_agent_api_doc_names_truncated_the_tier_filter_and_the_window(self):
        """Review 621 defect 5: the docs say what ``truncated`` means (and that it is project-wide, before the asset filter) and that the tier filters in the database."""
        from pathlib import Path
        text = (Path(__file__).resolve().parents[2] / 'docs' / 'AGENT-API.md').read_text()
        line = next(l for l in text.splitlines() if l.startswith('2. `get_remediation_work`'))
        for needle in ('`truncated`', '?tier=fire|smoke|ice', 'in the database', '2,000', 'before `?assets=` narrows them'):
            self.assertIn(needle, line)
