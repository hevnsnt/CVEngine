"""GET /cve/api/graph sends less: what no page reads is left out (``views.compact_graph``), the graph page asks without the hover cards
(``?info=0``), and the JSON has no blanks. Measured on the production install: 535 KB for every project, 22 to 66 KB for one.

A host node's ``info`` is read only by the dashboard's host map, and the map draws only the hosts that score more than its floor
(static/cve/dashboard.js MAP_SCORE_OVER); the graph page reads no ``info`` at all, and reads ``internal`` and ``network`` only for truth."""
import json
import re
from pathlib import Path

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase

from cveFeed import views
from tests.test_graph_payload_queries import build_world
from tenancy import scope

STATIC = Path(__file__).resolve().parent.parent / 'static' / 'cve'
TEMPLATE = Path(__file__).resolve().parent.parent / 'cveFeed' / 'templates' / 'cveFeed' / 'graph.html'


def host(node_id, score, **extra):
    return {'id': node_id, 'kind': 'subdomain', 'label': node_id, 'score': score, 'info': {'cves': 1, 'score_parts': [{'label': 'x'}]},
            'internal': False, 'network': None, **extra}


class CompactGraphTests(SimpleTestCase):
    def test_info_only_on_a_host_the_map_can_draw(self):
        payload = {'nodes': [host('a', views.GRAPH_INFO_SCORE_OVER + 1), host('b', views.GRAPH_INFO_SCORE_OVER), host('c', 0), host('d', None)],
                   'edges': [{'from': 'a', 'to': 'b'}], 'hosts': {'drawn': 4}, 'projects': {}}
        out = views.compact_graph(payload)
        self.assertEqual([('info' in n) for n in out['nodes']], [True, False, False, False])
        self.assertEqual(out['nodes'][0]['info'], payload['nodes'][0]['info'])
        self.assertEqual({k: v for k, v in out.items() if k != 'nodes'}, {k: v for k, v in payload.items() if k != 'nodes'})
        self.assertTrue(all('info' in n for n in payload['nodes']), 'the payload it was given is not changed')

    def test_internal_and_network_only_on_an_internal_host(self):
        inside = host('a', 0, internal=True, network='10.20.0.0/24')
        out = views.compact_graph({'nodes': [inside, host('b', 0)]})['nodes']
        self.assertEqual((out[0]['internal'], out[0]['network']), (True, '10.20.0.0/24'))
        self.assertNotIn('internal', out[1])
        self.assertNotIn('network', out[1])

    def test_other_nodes_are_sent_as_they_are(self):
        others = [{'id': 'dom:1', 'kind': 'domain', 'label': 'x', 'project': 'p', 'root': 'x'}, {'id': 'ip:1', 'kind': 'ip', 'label': '10.0.0.1'},
                  {'id': 'cve:1', 'kind': 'cve', 'label': 'CVE-1', 'tier': 'fire'}]
        self.assertEqual(views.compact_graph({'nodes': others})['nodes'], others)
        self.assertEqual(views.compact_graph({'nodes': [], 'edges': []}), {'nodes': [], 'edges': []})

    def test_without_info_leaves_no_info_and_nothing_else_out(self):
        payload = {'nodes': [host('a', 99), {'id': 'ip:1', 'kind': 'ip', 'label': '10.0.0.1'}], 'version': 'v'}
        out = views.without_info(payload)
        self.assertEqual(out['nodes'][0], {k: v for k, v in payload['nodes'][0].items() if k != 'info'})
        self.assertEqual(out['nodes'][1], payload['nodes'][1])
        self.assertEqual(out['version'], 'v')


class PageContractTests(SimpleTestCase):
    """The two pages that read the graph read nothing compact_graph leaves out."""

    def test_the_server_floor_is_the_maps_floor(self):
        js = (STATIC / 'dashboard.js').read_text()
        self.assertEqual(int(re.search(r'const MAP_SCORE_OVER = (\d+);', js).group(1)), views.GRAPH_INFO_SCORE_OVER)
        # the map keeps only the hosts above the floor before it reads any host's info
        draw = js[js.index('function drawMap('):]
        self.assertLess(draw.index('> MAP_SCORE_OVER'), draw.index('.info'))

    def test_the_graph_page_asks_without_info_and_reads_none(self):
        page = TEMPLATE.read_text()
        self.assertIn("info: '0'", page)
        for source in (page, (STATIC / 'graph.js').read_text()):
            self.assertIsNone(re.search(r'\.info\b|\[["\']info["\']\]', source))
            self.assertIsNone(re.search(r'\.(internal|network)\s*(===|!==|==|!=)', source), 'internal and network are read for truth only')


class GraphEndpointSizeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.world = build_world('sz', hosts=10)
        cls.user = User.objects.create_user('sz-root', password='x', is_superuser=True)

    def setUp(self):
        cache.clear()
        views.clear_stats_cache()
        self.client.force_login(self.user)

    def built(self, project):
        tokens = scope.set_scope({project.id})
        try:
            cache.clear()
            return views.graph_payload()
        finally:
            scope.reset_scope(tokens)

    def test_the_endpoint_sends_the_compact_graph_with_no_blanks(self):
        project = self.world['projects'][0]
        response = self.client.get(f'/cve/api/graph?project={project.slug}')
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertNotIn('", "', body)
        self.assertNotIn('": ', body)
        payload = json.loads(body)
        payload.pop('version')
        full = self.built(project)
        self.assertEqual(payload, views.compact_graph(full))
        hosts = [n for n in payload['nodes'] if n['kind'] == 'subdomain']
        self.assertTrue(any('info' in n for n in hosts) and any('info' not in n for n in hosts), 'the fixture has hosts on both sides of the floor')
        self.assertLess(len(body), len(json.dumps(full)))

    def test_the_graph_page_gets_the_same_graph_without_info(self):
        project = self.world['projects'][0]
        lean = self.client.get(f'/cve/api/graph?project={project.slug}&info=0').json()
        full = self.client.get(f'/cve/api/graph?project={project.slug}').json()
        self.assertFalse(any('info' in n for n in lean['nodes']))
        self.assertEqual(lean, views.without_info(full))
        self.assertEqual([n['id'] for n in lean['nodes']], [n['id'] for n in full['nodes']])
        self.assertEqual(lean['edges'], full['edges'])

    def test_an_unchanged_version_is_still_a_304_with_info_0(self):
        project = self.world['projects'][1]
        version = self.client.get(f'/cve/api/graph?project={project.slug}&info=0').json()['version']
        self.assertEqual(self.client.get(f'/cve/api/graph?project={project.slug}&info=0&v={version}').status_code, 304)
