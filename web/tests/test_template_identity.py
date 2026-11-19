"""What a nuclei template's own metadata says about the product it detects (the template index the Sentinel library ships, nuclei-templates v10.5.2):

* a technology template's CPE is kept on the host's technology link (``SubdomainTechnology.cpe``, ``nuclei_scan.tech_cpe_from``), correlation matches the
  technology CPE first and ``tech:`` finds it by that CPE;
* a panel hit without a version is an identity reading (``vsrc:panel``, outcome ``hidden``, the template's CPE) and a technology with no version, so
  ``tech:X@unknown``, ``vsource:panel``, ``component:`` and ``os:`` find the host and the edge build reads see the lead, never a CVE match;
* an adopted Sentinel result reads its panel hits the same way, and the update step re-reads the stored findings.

The template ids are real ones of the index (``tomcat-detect``: ``a:apache:tomcat``; ``default-apache2-page``: ``a:apache:http_server``;
``fortinet-fortigate-panel``: no metadata; ``fortios-panel``: ``o:fortinet:fortios``; ``globalprotect-panel``: ``a:paloaltonetworks:globalprotect``)."""
from io import StringIO
from types import SimpleNamespace
from unittest import mock
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_adopt, sentinel_broker
from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from cveFeed import (identities, nuclei_fp, nuclei_scan, nuclei_templates, probes, source_versions, tech_carry, template_identity, upgrade_backfills,
                     version_sources)
from cveFeed.models import CVEEntry, CVEMatch, ProbeObservation, ServiceRun
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, SubdomainTechnology, Technology, Vulnerability, VulnerabilityTags
from targetApp.models import Domain

PANEL = source_versions.PANEL_PROBE
HOST = 'edge.tmeta.test'


def line(template_id, name, tags, extracted=(), matched=f'https://{HOST}/', matcher=''):
    """A result line a Sentinel reported, as the broker keeps it and the stage reads it: no template metadata."""
    finding = {'template_id': template_id, 'name': name, 'severity': 'info', 'host': matched, 'matched_at': matched,
               'extracted_results': list(extracted), 'tags': list(tags), 'type': 'http'}
    if matcher:
        finding['matcher_name'] = matcher
    findings, _dropped = sentinel_broker._clean_findings([finding])
    return dispatch._finding_to_nuclei_line(findings[0])


TOMCAT = line('tomcat-detect', 'Tomcat Detection', ['tech', 'apache', 'tomcat', 'discovery'], ['9.0.50'])
APACHE_PAGE = line('default-apache2-page', 'Apache2 Default Page', ['tech', 'apache', 'discovery'])
FORTIGATE = line('fortinet-fortigate-panel', 'Fortinet FortiGate SSL VPN Login Panel - Detect', ['panel', 'fortigate', 'vpn', 'discovery'])
FORTIOS = line('fortios-panel', 'FortiOS Admin Login Panel - Detect', ['panel', 'fortinet', 'fortios', 'login', 'detect', 'discovery'])
GLOBALPROTECT = line('globalprotect-panel', 'PaloAlto Networks GlobalProtect Panel - Detect', ['panel', 'globalprotect', 'paloaltonetworks'])


def cve(cve_id, vendor, product, introduced, fixed):
    return CVEEntry.objects.create(cve_id=cve_id, title=cve_id, cvss=9.8, published_at=timezone.now(),
                                   affected=[{'vendor': vendor, 'product': product,
                                              'ranges': [{'type': 'ECOSYSTEM', 'introduced': introduced, 'fixed': fixed}]}])


class IndexTests(SimpleTestCase):
    def test_the_index_names_the_product_of_a_technology_template(self):
        products = nuclei_templates.technology_products()
        self.assertEqual(products['tomcat-detect'], {'vendor': 'apache', 'product': 'tomcat', 'part': 'a'})
        self.assertEqual(products['default-apache2-page'], {'vendor': 'apache', 'product': 'http_server', 'part': 'a'})
        self.assertNotIn('tech-detect', products)  # names many products by its matchers, none in its metadata
        self.assertNotIn('nginx-version', products)
        self.assertGreater(len(products), 500)
        self.assertNotIn('tomcat-detect', nuclei_templates.panel_products())

    def test_the_cpe_of_a_result_line_comes_from_the_installed_template(self):
        self.assertEqual(nuclei_scan.tech_cpe_from(TOMCAT), 'cpe:2.3:a:apache:tomcat')
        self.assertEqual(nuclei_scan.tech_cpe_from(APACHE_PAGE), 'cpe:2.3:a:apache:http_server')
        self.assertEqual(nuclei_scan.tech_cpe_from(line('nginx-version', 'Nginx Version Detect', ['tech', 'nginx'], ['1.24.0'])), '')
        # tech-detect's matcher names the product, so no metadata of the template says which one
        self.assertEqual(nuclei_scan.tech_cpe_from(line('tech-detect', 'Wappalyzer Technology Detection', ['tech'], matcher='apache')), '')
        # the line's own metadata, when nuclei wrote it, is read first
        own = {**TOMCAT, 'info': {**TOMCAT['info'], 'metadata': {'vendor': 'apache', 'product': 'tomcat'}}}
        self.assertEqual(nuclei_scan.tech_cpe_from(own, {}), 'cpe:2.3:a:apache:tomcat')

    def test_a_panel_without_a_version_is_an_identity_with_the_cpe_of_any_part(self):
        from cveFeed import panel_versions
        fortigate = panel_versions.identity(FORTIGATE)
        self.assertEqual((fortigate['label'], fortigate['version'], fortigate.get('cpe', ''), fortigate['port'], fortigate['source']),
                         ('Fortinet FortiGate SSL VPN', '', '', 443, 'panel'))
        self.assertEqual(panel_versions.identity(FORTIOS)['cpe'], 'cpe:2.3:o:fortinet:fortios')
        self.assertEqual(panel_versions.identity(GLOBALPROTECT)['cpe'], 'cpe:2.3:a:paloaltonetworks:globalprotect')
        self.assertIsNone(panel_versions.identity({**FORTIGATE, 'extracted-results': ['7.2.5']}))  # a version: panel_versions.reading reads it
        self.assertIsNone(panel_versions.identity(TOMCAT))  # not a panel hit


class Base(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='TM', slug='tm')
        self.project = Project.objects.create(name='TM', slug='tm-p', insert_date=now, org=self.org)
        self.domain = Domain.objects.create(name='tmeta.test', project=self.project, insert_date=now)
        self.engine = EngineType.objects.create(engine_name='e-tm', yaml_configuration='x', default_engine=True)
        self.scan = self.new_scan()
        self.sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=HOST)
        self.sub.ip_addresses.add(IpAddress.objects.create(address='192.0.2.70'))

    def new_scan(self):
        return ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, results_dir='/tmp')

    def fresh(self, sub=None):
        return Subdomain.objects.get(pk=(sub or self.sub).pk)

    def techs(self, sub=None):
        return {t.name for t in self.fresh(sub).technologies.all()}

    def links(self, sub=None):
        return {(r.technology.name, r.source, r.cpe) for r in SubdomainTechnology.objects.filter(subdomain=sub or self.sub).select_related('technology')}

    def light(self, lines):
        def stream(_path, **_kwargs):
            return iter(lines)
        return nuclei_scan.run_light_nuclei(self.scan.id, stream=stream, force=True)

    def template_pass(self, lines):
        def stream(_path, **_kwargs):
            return iter(lines)
        with mock.patch.object(nuclei_fp, 'control_get', mock.Mock(return_value={})):
            return nuclei_scan._run_nuclei(self.scan.id, stream=stream, targets=[HOST], force=True)

    def search(self, q):
        from tests.test_agentapi import call
        if not hasattr(self, 'token'):
            user = User.objects.create_user('tm-alice', password='x')
            ProjectMembership.objects.create(user=user, project=self.project, role='user')
            _, self.token = create_token(user, 'tm')
        status, data = call(self.token, 'GET', f'/api/v1/projects/{self.project.slug}/search?' + urlencode({'q': q}))
        self.assertEqual(status, 200, data)
        return sorted(h['host'] for h in data['results'])


class TechnologyCpeTests(Base):
    def test_the_light_pass_keeps_the_templates_cpe_on_the_link_and_correlation_matches_it_cpe_first(self):
        inside = cve('CVE-2026-510001', 'apache', 'tomcat', '9.0.0', '9.0.60')
        before = timezone.now()
        out = self.light([TOMCAT, APACHE_PAGE, line('nginx-version', 'Nginx Version Detect', ['tech', 'nginx'], ['1.24.0'])])
        self.assertEqual(out['techs'], {HOST: ['Apache2 Default Page', 'Nginx:1.24.0', 'Tomcat:9.0.50']})
        self.assertEqual(self.links(), {('Tomcat:9.0.50', 'nuclei', 'cpe:2.3:a:apache:tomcat'),
                                        ('Apache2 Default Page', 'nuclei', 'cpe:2.3:a:apache:http_server'), ('Nginx:1.24.0', 'nuclei', '')})
        self.assertTrue(all(r.observed_at >= before for r in SubdomainTechnology.objects.filter(subdomain=self.sub)))
        self.assertEqual(source_versions.technology_cpes(self.fresh())['Tomcat:9.0.50'], 'cpe:2.3:a:apache:tomcat')
        self.assertTrue(probes.recorrelate(self.fresh()))
        match = CVEMatch.objects.get(cve_entry=inside)
        self.assertEqual((match.matched_version, match.version_in_range, match.evidence['cpe']), ('9.0.50', True, 'cpe:2.3:a:apache:tomcat'))

    def test_a_name_without_a_version_stays_a_lead_whatever_its_cpe(self):
        cve('CVE-2026-510002', 'apache', 'http_server', '2.4.0', '2.4.60')
        self.light([APACHE_PAGE])
        probes.recorrelate(self.fresh())
        self.assertFalse(CVEMatch.objects.exists())

    def test_a_link_without_a_cpe_never_clears_one_another_template_gave(self):
        self.light([TOMCAT])
        tomcat = Technology.objects.get(name='Tomcat:9.0.50')
        nuclei_scan.link_technologies({(self.sub.pk, tomcat.pk): ''})
        self.assertEqual(self.links(), {('Tomcat:9.0.50', 'nuclei', 'cpe:2.3:a:apache:tomcat')})

    def test_a_reading_cpe_wins_over_the_templates(self):
        self.light([TOMCAT])
        probes.record(self.project.id, self.domain.id, HOST, source_versions.NMAP_PROBE, [probes._observation(
            'version', 'Tomcat', '9.0.50', '', 'found', 0.9, 'vsrc:nmap', port=8080, evidence={'cpe': 'cpe:/a:apache:tomcat:9.0.50', 'version_source': True})])
        self.assertEqual(source_versions.technology_cpes(self.fresh())['Tomcat:9.0.50'], 'cpe:/a:apache:tomcat:9.0.50')

    def test_tech_search_finds_a_technology_by_its_templates_cpe(self):
        self.light([APACHE_PAGE, TOMCAT])
        self.assertEqual(self.search('tech:http_server'), [HOST])  # the name says "Apache2 Default Page", the template's CPE says http_server
        self.assertEqual(self.search('tech:http_server@unknown'), [HOST])
        self.assertEqual(self.search('tech:http_server@known'), [])
        self.assertEqual(self.search('tech:tomcat@9.0'), [HOST])

    def test_the_cpe_is_carried_onto_a_later_scans_row(self):
        self.light([TOMCAT])
        scan = self.new_scan()
        row = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name=HOST)
        ServiceRun.objects.filter(service=nuclei_scan.LIGHT_SERVICE).update(scan_id=self.scan.pk)
        carried = tech_carry.carry(scan, self.project.id, {HOST: HOST}, nuclei_scan.LIGHT_SERVICE)
        self.assertEqual(carried, {HOST: ['Tomcat:9.0.50']})
        self.assertEqual(self.links(row), {('Tomcat:9.0.50', 'nuclei', 'cpe:2.3:a:apache:tomcat')})


class PanelIdentityTests(Base):
    def test_a_panel_without_a_version_is_an_identity_reading_and_a_bare_technology(self):
        out = self.template_pass([FORTIGATE, FORTIOS, GLOBALPROTECT])
        self.assertEqual(out['info'], 3)
        self.assertEqual(Vulnerability.objects.count(), 3)  # the findings are unchanged
        rows = {(r.product, r.version, r.outcome, r.port, r.evidence.get('cpe', '')) for r in ProbeObservation.objects.filter(probe=PANEL)}
        self.assertEqual(rows, {('Fortinet FortiGate SSL VPN', '', 'hidden', 443, ''), ('FortiOS', '', 'hidden', 443, 'cpe:2.3:o:fortinet:fortios'),
                                ('PaloAlto Networks GlobalProtect', '', 'hidden', 443, 'cpe:2.3:a:paloaltonetworks:globalprotect')})
        self.assertEqual(self.links(), {('Fortinet FortiGate SSL VPN', PANEL, ''), ('FortiOS', PANEL, 'cpe:2.3:o:fortinet:fortios'),
                                        ('PaloAlto Networks GlobalProtect', PANEL, 'cpe:2.3:a:paloaltonetworks:globalprotect')})

    def test_every_search_finds_it_and_the_version_is_unknown(self):
        self.template_pass([FORTIGATE, FORTIOS])
        self.assertEqual(self.search('tech:fortigate'), [HOST])
        self.assertEqual(self.search('tech:fortigate@unknown'), [HOST])
        self.assertEqual(self.search('tech:fortigate@known'), [])
        self.assertEqual(self.search('vsource:panel'), [HOST])
        self.assertEqual(self.search('component:fortinet-fortigate-ssl-vpn'), [HOST])
        self.assertEqual(self.search('os:fortios'), [HOST])

    def test_it_is_a_lead_for_the_edge_build_reads_and_correlation_never_a_match(self):
        globalprotect = cve('CVE-2026-510101', 'paloaltonetworks', 'globalprotect', '5.0.0', '6.2.0')
        cve('CVE-2026-510102', 'fortinet', 'fortios', '7.0.0', '7.2.6')
        self.template_pass([FORTIGATE, FORTIOS, GLOBALPROTECT])
        sub = self.fresh()
        self.assertIn(('Fortinet FortiGate SSL VPN', ''), identities.products(sub))
        leads = [s.id for s in version_sources.catalogue.SOURCES if s.lead_re() and any(s.lead_re().search(n) for n, _v in version_sources.host_products(sub, []))]
        self.assertTrue(any('forti' in lead for lead in leads), leads)
        self.assertTrue(any('globalprotect' in lead or 'panos' in lead or 'pan-os' in lead for lead in leads), leads)
        from cveFeed import correlation
        cve_by_id, index = correlation.cve_pool()
        leads_of = {}
        identities.collect_leads(sub, index, cve_by_id, [], leads=leads_of)
        self.assertIn(globalprotect.id, leads_of)  # a lead for the targeted checks
        probes.recorrelate(sub)
        self.assertFalse(CVEMatch.objects.exists())  # naming a product says nothing about which advisory applies

    def test_a_version_reading_of_the_product_stands(self):
        from tests.test_panel_versions import GRAFANA_LOCAL
        self.template_pass([{**GRAFANA_LOCAL, 'matched-at': f'https://{HOST}/login', 'host': f'https://{HOST}/login'}])
        bare = {**GRAFANA_LOCAL, 'matched-at': f'https://{HOST}/login', 'host': f'https://{HOST}/login', 'extracted-results': []}
        self.template_pass([bare])  # the next pass's hit shows no version: the version read before is not replaced by "none"
        self.assertEqual({(r.product, r.version, r.outcome) for r in ProbeObservation.objects.filter(probe=PANEL, kind='version')},
                         {('Grafana', '10.2.3', 'found')})
        self.assertEqual(self.techs(), {'Grafana:10.2.3'})

    def test_no_bare_technology_beside_one_that_names_the_product(self):
        self.sub.technologies.add(Technology.objects.create(name='GlobalProtect:6.1.0'))
        self.template_pass([GLOBALPROTECT])
        self.assertEqual(self.techs(), {'GlobalProtect:6.1.0'})
        self.assertTrue(ProbeObservation.objects.filter(probe=PANEL, product='PaloAlto Networks GlobalProtect', outcome='hidden').exists())


class AdoptionTests(Base):
    def test_an_adopted_result_reads_its_panel_hits_like_the_stage(self):
        from tests.test_panel_versions import GRAFANA_LOCAL
        task = SimpleNamespace(kind='nuclei_targeted', target={'targets': [HOST]}, scan=self.scan)
        findings = [{'template_id': 'fortinet-fortigate-panel', 'name': FORTIGATE['info']['name'], 'severity': 'info', 'host': HOST,
                     'matched_at': f'https://{HOST}/', 'tags': ['panel', 'fortigate', 'vpn'], 'extracted_results': []},
                    {'template_id': 'grafana-detect', 'name': GRAFANA_LOCAL['info']['name'], 'severity': 'info', 'host': HOST,
                     'matched_at': f'https://{HOST}/login', 'tags': ['panel', 'grafana'], 'extracted_results': ['10.2.3']}]
        out = sentinel_adopt._nuclei(task, {'outcome': 'done', 'findings': findings}, None)
        self.assertEqual(out['findings'], 2)
        self.assertGreaterEqual(out['panel_readings'], 2)
        self.assertEqual({(r.product, r.version) for r in ProbeObservation.objects.filter(probe=PANEL, kind='version')},
                         {('Fortinet FortiGate SSL VPN', ''), ('Grafana', '10.2.3')})
        self.assertEqual(self.techs(), {'Fortinet FortiGate SSL VPN', 'Grafana:10.2.3'})


class BackfillTests(Base):
    def finding(self, template_id, name, tags, extracted=(), url=f'https://{HOST}/', matcher='', severity=0):
        vuln = Vulnerability.objects.create(scan_history=self.scan, target_domain=self.domain, subdomain=self.sub, source='nuclei', name=name,
                                            template_id=template_id, matcher_name=matcher, severity=severity, http_url=url,
                                            extracted_results=list(extracted), discovered_date=timezone.now())
        for tag in tags:
            vuln.tags.add(VulnerabilityTags.objects.get_or_create(name=tag)[0])
        return vuln

    def test_stored_findings_give_links_their_cpe_and_panels_their_identity(self):
        inside = cve('CVE-2026-510201', 'apache', 'tomcat', '9.0.0', '9.0.60')
        self.sub.technologies.add(Technology.objects.create(name='Tomcat:9.0.50'))  # linked before the columns existed: no source, no CPE
        SubdomainTechnology.objects.filter(subdomain=self.sub).update(observed_at=None)
        self.finding('tomcat-detect', 'Tomcat Detection', ['tech', 'apache', 'tomcat'], ['9.0.50'])
        self.finding('fortinet-fortigate-panel', FORTIGATE['info']['name'], ['panel', 'fortigate', 'vpn'])
        self.finding('nginx-version', 'Nginx Version Detect', ['tech', 'nginx'], ['1.24.0'])  # no metadata: not read
        self.finding('fortios-panel', FORTIOS['info']['name'], ['panel', 'fortios'], severity=2)  # not info: not a panel hit
        self.assertEqual(template_identity.pending(), 2)
        out = StringIO()
        call_command('backfill_template_identities', stdout=out)
        self.assertIn('Dry run: 2', out.getvalue())
        self.assertFalse(ProbeObservation.objects.exists())
        self.assertEqual(self.links(), {('Tomcat:9.0.50', '', '')})
        out = StringIO()
        call_command('backfill_template_identities', apply=True, limit=1, stdout=out)  # one finding a pass: the walk resumes where it stopped
        self.assertIn('Applied: 2 stored findings read; 1 technology links', out.getvalue())
        self.assertEqual(self.links(), {('Tomcat:9.0.50', 'nuclei', 'cpe:2.3:a:apache:tomcat'), ('Fortinet FortiGate SSL VPN', PANEL, '')})
        self.assertIsNotNone(SubdomainTechnology.objects.get(subdomain=self.sub, technology__name='Tomcat:9.0.50').observed_at)
        self.assertEqual({(r.product, r.outcome) for r in ProbeObservation.objects.filter(probe=PANEL)}, {('Fortinet FortiGate SSL VPN', 'hidden')})
        self.assertEqual(CVEMatch.objects.get(cve_entry=inside).evidence['cpe'], 'cpe:2.3:a:apache:tomcat')
        self.assertEqual(template_identity.pending(), 0)
        call_command('backfill_template_identities', apply=True, reset=True, stdout=StringIO())  # again from the start: nothing changes
        self.assertEqual(CVEMatch.objects.filter(cve_entry=inside).count(), 1)
        self.assertEqual(ProbeObservation.objects.filter(probe=PANEL).count(), 1)

    def test_it_runs_on_the_hosts_current_row(self):
        self.finding('fortinet-fortigate-panel', FORTIGATE['info']['name'], ['panel', 'fortigate'])
        newer = Subdomain.objects.create(scan_history=self.new_scan(), target_domain=self.domain, name=HOST)
        template_identity.read_pass()
        self.assertEqual(self.techs(newer), {'Fortinet FortiGate SSL VPN'})
        self.assertEqual(self.techs(), set())

    def test_it_reads_the_findings_the_template_scanner_files(self):
        from cveFeed import panel_versions
        from reNgine.definitions import NUCLEI
        self.assertEqual(panel_versions.FINDING_SOURCE, NUCLEI)

    def test_it_is_registered_before_the_rescore(self):
        names = upgrade_backfills.BACKFILLS
        self.assertLess(names.index('backfill_panel_versions'), names.index('backfill_template_identities'))
        self.assertLess(names.index('backfill_template_identities'), names.index('rerate_findings'))
