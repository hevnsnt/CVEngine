"""Every contributor of a host score is explained and linked (docs/SECRETS-PLAN.md section 11, "Why a host scores"): the lines add up to the
score, each says what, where and why in a sentence, each names the evidence it stands on, and no line, API answer or tile payload ever holds a secret value."""
import json

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.services import Ctx, search_hosts
from cveFeed import scoring
from cveFeed import secrets_inventory as inv
from cveFeed.views import graph_payload
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain

# a canary in the shape of the real finding: never the real key, never a value any test or page may show
CANARY = 'CANARYvalue0123456789abcdefghijklmnopqrstuvwxyz12dea4'
RULE = 'betterleaks.rapidapi-access-token'
SECRET_LINE = {'id': 4, 'severity': 2, 'klass': 'S', 'path': '/', 'url': 'https://example.com/', 'line': 1270, 'masked': '…dea4',
               'label': 'Rapidapi access token', 'basis': 'an uncatalogued secret (rapidapi-access-token): treated as a server secret of medium severity until a person reviews it'}


def everything():
    """One input of every kind of contributor."""
    return {'cves': [{'id': 'CVE-2026-1', 'match_id': 11, 'temp': 'fire', 'ai_verdict': 'affected'}, {'id': 'CVE-2026-2', 'match_id': 12, 'temp': 'ice'},
                     {'id': 'CVE-2026-3', 'match_id': 13, 'temp': 'ice', 'version_unknown': True}],
            'findings': [{'id': 21, 'severity': 3, 'name': 'Exposed panel'}],
            'hygiene': [{'id': 31, 'severity': 3, 'title': 'TLS 1.0 enabled'}, {'id': 32, 'severity': 2, 'title': 'No DMARC'}],
            'routes': [{'path': '/admin', 'auth_state': 'open', 'sensitive_score': 0}],
            'secrets': [SECRET_LINE], 'secrets_covered': True, 'public_ip': True, 'recent': ['host_new'], 'zombie_host': True, 'zombie_route': True}


class ExplainedLines(SimpleTestCase):
    def test_every_line_has_a_sentence_a_kind_and_evidence_and_the_lines_are_the_score(self):
        score, detail = scoring.score_host(everything())
        self.assertGreater(len(detail), 8)
        for line in detail:
            self.assertTrue(line['text'].endswith('.'), line)
            self.assertTrue(line['kind'], line)
            self.assertIsInstance(line['ref'], dict, line)
            self.assertGreater(len(line['text']), 40, line)
        self.assertEqual(score, min(100, sum(line['points'] for line in detail)))

    def test_lines_link_to_the_evidence_they_stand_on(self):
        _, detail = scoring.score_host(everything())
        refs = {line['kind']: line['ref'] for line in detail}
        self.assertEqual(refs['cve'], {'type': 'match', 'id': 11})
        self.assertEqual(refs['finding'], {'type': 'vulnerability', 'id': 21})
        self.assertEqual(refs['hygiene'], {'type': 'hygiene', 'id': 31})
        self.assertEqual(refs['secret'], {'type': 'secret', 'id': 4})
        self.assertEqual(refs['route'], {'type': 'host_tab', 'tab': 'web'})

    def test_the_secret_line_says_what_where_and_why(self):
        score, detail = scoring.score_host({'secrets': [SECRET_LINE], 'secrets_covered': True})
        self.assertEqual((score, len(detail)), (10, 1))
        line = detail[0]
        self.assertEqual((line['label'], line['points'], line['kind']), ('Server credential served on /', 10, 'secret'))
        for word in ('Rapidapi access token', '…dea4', 'found at https://example.com/ (line 1270)', 'server credential', 'Why medium: an uncatalogued secret', 'uncatalogued', '10 points'):
            self.assertIn(word, line['text'])

    def test_a_stored_line_without_a_sentence_is_still_a_line(self):
        # lines stored before the sentences existed hold a label and points only: the page shows them and reads the rest as absent
        part = __import__('cveFeed.views', fromlist=['score_part']).score_part({'label': 'Fire CVE match CVE-1', 'points': 40})
        self.assertEqual(part, {'label': 'Fire CVE match CVE-1', 'points': 40, 'kind': '', 'text': '', 'ref': None})

    def test_capped_lines_keep_their_evidence(self):
        many = {'cves': [{'id': f'CVE-2026-{n}', 'match_id': n, 'temp': 'ice', 'version_unknown': True} for n in range(1, 6)]}
        _, detail = scoring.score_host(many)
        self.assertEqual([(d['points'], d['ref']) for d in detail], [(2, {'type': 'matches'})])


class StoredAndServed(TestCase):
    def setUp(self):
        inv.reset_key_cache()
        self.addCleanup(inv.reset_key_cache)
        org = Org.objects.create(name='Acme', slug='acme-explain')
        self.project = Project.objects.create(name='Acme', slug='acme-explain', insert_date=timezone.now(), org=org)
        domain = Domain.objects.create(name='example.com', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e-explain', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2, results_dir='/tmp')
        self.sub = Subdomain.objects.create(scan_history=scan, target_domain=domain, name='example.com')
        self.sub.ip_addresses.add(IpAddress.objects.create(address='93.184.216.34'))  # a live host: the map draws it
        self.row = inv.record(self.project.pk, host='example.com', url='https://example.com/', source='kingfisher', rule_id=RULE, value=CANARY,
                              domain_id=domain.pk, scan_id=scan.pk, line=1270)
        scoring.rescore_hosts(self.project.pk, ['example.com'])
        self.sub.refresh_from_db()

    def test_the_stored_score_links_to_the_secret_and_the_tile_carries_every_line(self):
        secret = [d for d in self.sub.score_detail if d['kind'] == 'secret'][0]
        self.assertEqual((secret['ref'], secret['points']), ({'type': 'secret', 'id': self.row.pk}, 10))
        self.assertIn('line 1270', secret['text'])
        node = [n for n in graph_payload(scan_id=self.sub.scan_history_id)['nodes'] if n['kind'] == 'subdomain'][0]
        info = node['info']
        self.assertEqual(len(info['score_parts']), len(self.sub.score_detail))
        self.assertEqual((info['score_sum'], info['project_slug']), (sum(d['points'] for d in self.sub.score_detail), 'acme-explain'))
        self.assertEqual(node['score'], info['score_sum'])  # what the tile says is what its lines add up to

    def test_the_canary_value_is_in_no_stored_line_tile_or_answer(self):
        from django.contrib.auth.models import User
        admin = User.objects.create_superuser('root-explain', password='x')
        node = [n for n in graph_payload(scan_id=self.sub.scan_history_id)['nodes'] if n['kind'] == 'subdomain'][0]
        answer = search_hosts(Ctx(user=admin, token=None), self.project.slug, {'q': 'example.com', 'facets': 'none'})
        for blob in (self.sub.score_detail, node, answer):
            text = json.dumps(blob, default=str)
            self.assertNotIn(CANARY, text)
            self.assertNotIn(CANARY[4:-4], text)
        self.assertIn('…dea4', json.dumps(self.sub.score_detail, ensure_ascii=False))
