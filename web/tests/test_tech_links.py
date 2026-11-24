"""Where a host's technology links come from (``cveFeed.tech_links``): the three gaps the explicit link model of startScan 0028 left open.

* An adopted Sentinel ``nuclei_light`` result writes the technology links the light pass writes (source, CPE, time), not only the findings.
* Every pass that links a technology records a ``source`` from one vocabulary (``tech_links.SOURCES``) and refreshes ``observed_at`` when it reads
  the technology again: discovery (bbot), the probes, the version sources, the route check's fingerprint, the WAF fingerprint, the WordPress scan;
  the API shows it.
* A name a template names by matcher (``tech-detect``) gets the CPE the server's own name normalisation gives it (the product alias data, the
  templates' metadata), under ``nuclei:derived``: it never replaces a CPE a template stated, and in correlation it only adds."""
import json
from pathlib import Path
from types import SimpleNamespace

from django.test import SimpleTestCase
from django.utils import timezone

from agentapi import sentinel_adopt
from cveFeed import nuclei_scan, probes, source_versions, tech_links, tech_rows, waf_fingerprint
from cveFeed.models import CVEMatch
from startScan.models import Subdomain, SubdomainTechnology, Technology
from tests.test_template_identity import HOST, TOMCAT, Base, cve, line

FIXTURES = Path(__file__).parent / 'fixtures'


def detect(matcher):
    """A ``tech-detect`` result line a Sentinel reported for ``matcher``."""
    return line('tech-detect', 'Wappalyzer Technology Detection', ['tech', 'discovery'], matcher=matcher)


class VocabularyTests(SimpleTestCase):
    def test_one_small_vocabulary_that_fits_the_column(self):
        self.assertEqual(set(tech_links.SOURCES), {'nuclei', 'nuclei:derived', 'vsrc:panel', 'bbot', 'probe', 'vsrc', 'route', 'waf', 'wpscan'})
        width = SubdomainTechnology._meta.get_field('source').max_length
        self.assertTrue(all(len(s) <= width for s in tech_links.SOURCES))
        self.assertEqual(tech_links.PANEL, source_versions.PANEL_PROBE)  # the panel source kept the value 0028 gave it
        self.assertEqual(nuclei_scan.TECH_SOURCE, tech_links.NUCLEI)
        self.assertEqual(tech_links.DERIVED, {tech_links.NUCLEI_DERIVED})

    def test_an_unknown_source_is_refused(self):
        with self.assertRaises(ValueError):
            tech_links.link({(1, 1): ''}, 'httpx')


class DerivedCpeTests(SimpleTestCase):
    def test_the_alias_data_and_the_templates_metadata_name_the_product(self):
        self.assertEqual(tech_links.derived_cpe('apachegeneric'), 'cpe:2.3:a:apache:http_server')  # product_aliases.json evidence
        self.assertEqual(tech_links.derived_cpe('wordpress'), 'cpe:2.3:a:wordpress:wordpress')  # a technology template's product
        self.assertEqual(tech_links.derived_cpe('atlassian-jira'), 'cpe:2.3:a:atlassian:jira')  # its vendor and product together
        self.assertEqual(tech_links.derived_cpe('Jenkins'), 'cpe:2.3:a:jenkins:jenkins')
        self.assertEqual(tech_links.derived_cpe('php:8.2.30'), 'cpe:2.3:a:php:php')  # the name as correlation reads it: no version
        self.assertIn(tech_links.derived_cpe('nginx'), ('cpe:2.3:a:f5:nginx', 'cpe:2.3:a:nginx:nginx'))  # one vendor across its renames

    def test_no_cpe_when_the_name_is_not_one_vendors_product(self):
        self.assertEqual(tech_links.derived_cpe('sentry'), '')  # Sentry's and MobileIron's (Ivanti's) Sentry
        self.assertEqual(tech_links.derived_cpe('express'), '')  # the alias data keeps "Express" to expressjs
        self.assertEqual(tech_links.derived_cpe('amp'), '')  # Google's AMP pages as much as CubeCoders' AMP: too short to stand alone
        self.assertEqual(tech_links.derived_cpe('cloudflare'), '')  # a service, never software with a CPE
        self.assertEqual(tech_links.derived_cpe('jquery'), '')  # a library: its version is read from its own file
        self.assertEqual(tech_links.derived_cpe(''), '')

    def test_coverage_of_the_tech_detect_names_of_the_fixtures(self):
        """The distinct ``tech-detect`` names the Sentinel result fixtures and these tests carry: which now get a CPE."""
        names = set()
        for path in FIXTURES.glob('sentinel_*/**/*.json'):
            text = path.read_text()
            if 'tech-detect' in text:
                for finding in json.loads(text).get('findings') or []:
                    if finding.get('template_id') == 'tech-detect' and finding.get('matcher_name'):
                        names.add(finding['matcher_name'])
        names |= {'WordPress', 'Jenkins', 'nginx/1.28.3', 'ms-httpapi', 'imperva', 'cloudflare', 'jquery'}
        got = {n: tech_links.derived_cpe(nuclei_scan.tech_name_from(detect(n))) for n in sorted(names)}
        self.assertEqual({n for n, c in got.items() if c}, {'nginx', 'nginx/1.28.3', 'WordPress', 'Jenkins'}, got)


class LightPassTests(Base):
    def test_a_tech_detect_name_takes_a_derived_cpe(self):
        before = timezone.now()
        out = self.light([detect('wordpress'), detect('cloudflare'), TOMCAT])
        self.assertEqual(out['techs'], {HOST: ['Tomcat:9.0.50', 'cloudflare', 'wordpress']})
        self.assertEqual(self.links(), {('wordpress', 'nuclei:derived', 'cpe:2.3:a:wordpress:wordpress'), ('cloudflare', 'nuclei', ''),
                                        ('Tomcat:9.0.50', 'nuclei', 'cpe:2.3:a:apache:tomcat')})
        self.assertTrue(all(r.observed_at >= before for r in SubdomainTechnology.objects.filter(subdomain=self.sub)))

    def test_a_derived_cpe_never_replaces_a_stated_one(self):
        tomcat = tech_rows.technology('Tomcat:9.0.50')
        stated = 'cpe:2.3:a:apache:tomcat'
        tech_links.link({(self.sub.pk, tomcat.pk): stated}, tech_links.NUCLEI)
        tech_links.link({(self.sub.pk, tomcat.pk): 'cpe:2.3:a:other:tomcat'}, tech_links.NUCLEI_DERIVED)
        self.assertEqual(self.links(), {('Tomcat:9.0.50', 'nuclei', stated)})
        # a derived CPE fills a link without one and replaces a derived one; a stated one replaces it
        wp = tech_rows.technology('wordpress')
        tech_links.link({(self.sub.pk, wp.pk): ''}, tech_links.BBOT)
        tech_links.link({(self.sub.pk, wp.pk): 'cpe:2.3:a:old:wordpress'}, tech_links.NUCLEI_DERIVED)
        tech_links.link({(self.sub.pk, wp.pk): 'cpe:2.3:a:wordpress:wordpress'}, tech_links.NUCLEI_DERIVED)
        self.assertIn(('wordpress', 'nuclei:derived', 'cpe:2.3:a:wordpress:wordpress'), self.links())
        tech_links.link({(self.sub.pk, wp.pk): ''}, tech_links.PROBE)  # a reading without a CPE never clears one
        self.assertIn(('wordpress', 'nuclei:derived', 'cpe:2.3:a:wordpress:wordpress'), self.links())
        tech_links.link({(self.sub.pk, wp.pk): 'cpe:2.3:a:wordpress:wordpress'}, tech_links.NUCLEI)
        self.assertIn(('wordpress', 'nuclei', 'cpe:2.3:a:wordpress:wordpress'), self.links())

    def test_within_one_pass_a_stated_cpe_wins_whatever_the_order(self):
        named = detect('tomcat')  # tech-detect's own "tomcat" match and the template that states the CPE: one technology row (any case)
        stated = line('tomcat-detect', 'Tomcat Detection', ['tech', 'apache', 'tomcat'])
        for lines in ([named, stated], [stated, named]):
            SubdomainTechnology.objects.all().delete()
            self.light(lines)
            self.assertEqual({(s, c) for _n, s, c in self.links()}, {('nuclei', 'cpe:2.3:a:apache:tomcat')}, lines[0]['template-id'])

    def test_correlation_matches_it_and_says_it_was_derived_and_never_narrows_the_name(self):
        own = cve('CVE-2026-520001', 'wordpress', 'wordpress', '6.0', '6.4.3')
        other = cve('CVE-2026-520002', 'WordPress Foundation', 'WordPress', '6.0', '6.4.3')  # a vendor the CPE does not name: the name still reaches it
        self.light([detect('wordpress')])
        link = SubdomainTechnology.objects.get(subdomain=self.sub)
        versioned = Technology.objects.create(name='wordpress:6.4.2')
        SubdomainTechnology.objects.create(subdomain=self.sub, technology=versioned, source=tech_links.NUCLEI_DERIVED, cpe=link.cpe)
        self.assertTrue(probes.recorrelate(self.fresh()))
        matches = {m.cve_entry_id: m for m in CVEMatch.objects.filter(subdomain=self.sub)}
        self.assertEqual(set(matches), {own.id, other.id})
        self.assertEqual((matches[own.id].evidence['cpe'], matches[own.id].evidence.get('cpe_derived')), ('cpe:2.3:a:wordpress:wordpress', True))


class AdoptionTests(Base):
    def adopt(self, kind, findings):
        task = SimpleNamespace(kind=kind, target={'targets': [HOST]}, scan=self.scan)
        return sentinel_adopt._nuclei(task, {'outcome': 'done', 'findings': findings}, None)

    def test_an_adopted_light_result_writes_the_links_the_light_pass_writes(self):
        fixture = json.loads((FIXTURES / 'sentinel_results' / 'nuclei_light.json').read_text())
        findings = [{**f, 'host': HOST, 'matched_at': f'https://{HOST}/'} for f in fixture['findings']]
        findings.append({'template_id': 'tomcat-detect', 'name': 'Tomcat Detection', 'severity': 'info', 'host': HOST, 'matched_at': f'https://{HOST}/',
                         'tags': ['tech', 'apache', 'tomcat'], 'extracted_results': ['9.0.50']})
        before = timezone.now()
        out = self.adopt('nuclei_light', findings)
        self.assertEqual((out['findings'], out['technologies']), (2, 2))
        links = self.links()
        self.assertIn(('Tomcat:9.0.50', 'nuclei', 'cpe:2.3:a:apache:tomcat'), links)
        self.assertEqual({(n, s) for n, s, _c in links}, {('Tomcat:9.0.50', 'nuclei'), ('nginx', 'nuclei:derived')})
        self.assertTrue(all(r.observed_at >= before for r in SubdomainTechnology.objects.filter(subdomain=self.sub)))

    def test_it_is_the_same_writing_as_the_stage(self):
        lines = [detect('wordpress'), TOMCAT]
        self.light(lines)
        stage = self.links()
        SubdomainTechnology.objects.all().delete()
        self.adopt('nuclei_light', [{'template_id': li['template-id'], 'name': li['info']['name'], 'severity': 'info', 'host': HOST,
                                     'matched_at': f'https://{HOST}/', 'matcher_name': li['matcher-name'], 'tags': li['info']['tags'],
                                     'extracted_results': li['extracted-results']} for li in lines])
        self.assertEqual(self.links(), stage)

    def test_a_targeted_result_links_no_technology(self):
        out = self.adopt('nuclei_targeted', [{'template_id': 'CVE-2021-41773', 'name': 'Apache 2.4.49 - Path Traversal', 'severity': 'critical',
                                              'host': HOST, 'matched_at': f'https://{HOST}/cgi-bin/', 'tags': ['cve'], 'extracted_results': []}])
        self.assertNotIn('technologies', out)
        self.assertEqual(self.links(), set())


class SourceTests(Base):
    """Each pass records its source, and a reading of a technology the host already has refreshes its time."""

    def link_row(self, name, sub=None):
        return SubdomainTechnology.objects.get(subdomain=sub or self.sub, technology__name=name)

    def test_discovery(self):
        from cvengine import discovery_events as bbot_lib
        from cvengine.tasks import persist_bbot_result
        ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id, 'subdomain_id': None, 'subscan_id': None}
        persist_bbot_result(bbot_lib.BbotResult(subdomains={HOST}, technologies={(HOST, 'Caddy'), (HOST, 'nginx/1.28.3')}), ctx=ctx)
        self.assertEqual({(n, s) for n, s, _c in self.links()}, {('Caddy', 'bbot'), ('nginx:1.28.3', 'bbot')})

    def test_probes_and_version_sources(self):
        found = [probes._observation('version', 'nginx', '1.24.0', confidence=0.9)]
        self.assertEqual(probes.apply_to_subdomain(self.sub, found), 1)
        self.assertEqual(self.link_row('nginx:1.24.0').source, 'probe')
        self.assertEqual(probes.apply_to_subdomain(self.sub, [probes._observation('version', 'Grafana', '10.2.3')], tech_links.VERSION_SOURCE), 1)
        self.assertEqual(self.link_row('Grafana:10.2.3').source, 'vsrc')
        first = self.link_row('nginx:1.24.0').observed_at
        self.assertEqual(probes.apply_to_subdomain(self.sub, found), 0)  # read again: not new, its time refreshed
        self.assertGreater(self.link_row('nginx:1.24.0').observed_at, first)

    def test_a_later_scans_row_takes_what_earlier_probes_and_version_sources_read(self):
        probe_id = next(iter(probes.BY_ID))
        probes.record(self.project.id, self.domain.id, HOST, probe_id, [probes._observation('version', 'nginx', '1.24.0', confidence=0.9)])
        probes.record(self.project.id, self.domain.id, HOST, 'vsrc:grafana', [probes._observation('version', 'Grafana', '10.2.3')])
        row = Subdomain.objects.create(scan_history=self.new_scan(), target_domain=self.domain, name=HOST)
        self.assertEqual(probes.apply_known(row.scan_history), 2)
        self.assertEqual({(n, s) for n, s, _c in self.links(row)}, {('nginx:1.24.0', 'probe'), ('Grafana:10.2.3', 'vsrc')})

    def test_route_check_waf_and_wordpress_scan(self):
        from cveFeed import route_auth, wpscan_scan
        route_auth.link_technologies(self.scan, {f'https://{HOST}/': {'evidence': {'fingerprints': [{'name': 'PHP:8.2.30', 'source': 'header:x-powered-by'}]}}})
        waf_fingerprint.store_products(self.project, self.sub, [{'firewall': 'FortiWeb', 'manufacturer': 'Fortinet'}], self.scan)
        wpscan_scan.persist_report(self.scan, self.sub, f'https://{HOST}/', {'version': {'number': '6.4.2'}})
        self.assertEqual({(n, s) for n, s, _c in self.links()}, {('PHP:8.2.30', 'route'), ('FortiWeb', 'waf'), ('WordPress:6.4.2', 'wpscan')})

    def test_a_link_stored_before_sources_takes_the_source_that_reads_it_again(self):
        tech = Technology.objects.create(name='FortiWeb')
        self.sub.technologies.add(tech)
        SubdomainTechnology.objects.filter(subdomain=self.sub).update(source='', observed_at=None)
        waf_fingerprint.store_products(self.project, self.sub, [{'firewall': 'FortiWeb', 'manufacturer': ''}], self.scan)
        row = self.link_row('FortiWeb')
        self.assertEqual(row.source, 'waf')
        self.assertIsNotNone(row.observed_at)
        tech_links.link({(self.sub.pk, tech.pk): ''}, tech_links.BBOT)  # another source confirms it: the source stays the first one recorded
        self.assertEqual(self.link_row('FortiWeb').source, 'waf')

    def test_a_copied_discovery_keeps_where_each_link_came_from(self):
        from cveFeed import discovery
        self.light([TOMCAT])
        scan = self.new_scan()
        self.assertEqual(discovery.seed_from_scan(scan, self.scan), 1)
        row = Subdomain.objects.get(scan_history=scan, name=HOST)
        self.assertEqual(self.links(row), {('Tomcat:9.0.50', 'nuclei', 'cpe:2.3:a:apache:tomcat')})
        self.assertIsNotNone(self.link_row('Tomcat:9.0.50', row).observed_at)

    def test_merged_spellings_keep_the_stated_cpe_over_a_derived_one(self):
        Technology.objects.create(name='Grafana')  # the row kept
        lower, shout = Technology.objects.create(name='grafana'), Technology.objects.create(name='GRAFANA')
        SubdomainTechnology.objects.create(subdomain=self.sub, technology=lower, source=tech_links.NUCLEI_DERIVED, cpe='cpe:2.3:a:zz:grafana')
        SubdomainTechnology.objects.create(subdomain=self.sub, technology=shout, source=tech_links.NUCLEI, cpe='cpe:2.3:a:grafana:grafana')
        tech_rows.merge_duplicates(apply=True)
        self.assertEqual(self.links(), {('Grafana', 'nuclei', 'cpe:2.3:a:grafana:grafana')})

    def test_the_host_record_shows_where_each_technology_came_from(self):
        from agentapi import services
        self.light([detect('wordpress'), TOMCAT])
        legacy = Technology.objects.create(name='next.js')
        SubdomainTechnology.objects.create(subdomain=self.sub, technology=legacy, source='', cpe='', observed_at=None)
        details = {d['name']: d for d in services.host_group(self.project, self.fresh())['technology_details']}
        self.assertEqual((details['wordpress']['source'], details['wordpress']['cpe'], details['wordpress']['cpe_derived']),
                         ('nuclei:derived', 'cpe:2.3:a:wordpress:wordpress', True))
        self.assertEqual((details['Tomcat']['source'], details['Tomcat']['cpe']), ('nuclei', 'cpe:2.3:a:apache:tomcat'))
        self.assertNotIn('cpe_derived', details['Tomcat'])
        self.assertIn('observed_at', details['Tomcat'])
        self.assertEqual(details['next.js']['source'], 'scan')  # stored before sources were recorded
        self.assertNotIn('observed_at', details['next.js'])
