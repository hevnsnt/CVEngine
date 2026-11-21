"""The version a nuclei panel template extracted becomes a version reading of the host (cveFeed.panel_versions): the product the template names (its
metadata, else the installed template of that id), only a version-shaped value, never over a better version another source states, local and Sentinel
result shapes through the template pass, correlation, the ``tech:`` search, and the update's backfill.

The template heads under fixtures/panel_templates are the real nuclei-templates files (``info`` only, up to their ``http:`` block)."""
from io import StringIO
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker
from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from cveFeed import nuclei_fp, nuclei_scan, nuclei_templates, panel_versions, probes, source_versions, upgrade_backfills
from cveFeed.models import CVEEntry, CVEMatch, ProbeObservation
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology, Vulnerability, VulnerabilityTags
from targetApp.models import Domain

TEMPLATES = str(Path(__file__).with_name('fixtures') / 'panel_templates')
PROBE = source_versions.PANEL_PROBE


def local_line(template_id, name, tags, extracted, matched, metadata=None, cpe=None, severity='info'):
    """A result line as nuclei's own ``-jsonl`` writes it (the local scanner): the template's ``info`` with its metadata and classification."""
    info = {'name': name, 'author': ['pdteam'], 'tags': tags, 'severity': severity, 'description': f'{name.split(" ")[0]} login panel was detected.'}
    if metadata:
        info['metadata'] = {'max-request': 1, **metadata}
    if cpe:
        info['classification'] = {'cvss-metrics': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 'cwe-id': ['cwe-200'], 'cpe': cpe}
    return {'template': f'http/exposed-panels/{template_id}.yaml', 'template-id': template_id, 'template-path': f'/root/nuclei-templates/http/exposed-panels/{template_id}.yaml',
            'info': info, 'type': 'http', 'host': matched, 'matched-at': matched, 'extracted-results': extracted, 'ip': '192.0.2.50',
            'timestamp': '2026-11-18T10:00:00.000000000Z', 'matcher-status': True}


GRAFANA_LOCAL = local_line('grafana-detect', 'Grafana Login Panel - Detect', ['panel', 'grafana', 'detect', 'discovery'], ['9.5.1', '10.2.3'],
                           'https://app.panel.test/login', metadata={'vendor': 'grafana', 'product': 'grafana', 'category': 'devops'},
                           cpe='cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*')


def sentinel_line(template_id, name, tags, extracted, matched):
    """A result line a Sentinel reported: its finding as the broker keeps it (``_clean_findings``), reshaped by ``_finding_to_nuclei_line``. It
    carries no template metadata."""
    findings, _dropped = sentinel_broker._clean_findings([{'template_id': template_id, 'name': name, 'severity': 'info', 'host': matched,
                                                           'matched_at': matched, 'extracted_results': extracted, 'tags': tags, 'type': 'http'}])
    return dispatch._finding_to_nuclei_line(findings[0])


def cve(cve_id, vendor, product, introduced, fixed):
    return CVEEntry.objects.create(cve_id=cve_id, title=cve_id, cvss=9.8, published_at=timezone.now(),
                                   affected=[{'vendor': vendor, 'product': product,
                                              'ranges': [{'type': 'ECOSYSTEM', 'introduced': introduced, 'fixed': fixed}]}])


def fixture_index():
    """The template index (``cvengine_scanner.template_index``) of the fixture panel templates, as the Sentinel library's generator records them: the
    server keeps no template files and reads only such an index."""
    import hashlib
    import re

    import yaml
    templates = {}
    for path in sorted(Path(TEMPLATES).rglob('*.yaml')):
        raw = path.read_bytes()
        doc = yaml.safe_load(raw)
        info = doc.get('info') or {}
        meta, classification = info.get('metadata') or {}, info.get('classification') or {}
        entry = {'sha256': hashlib.sha256(raw).hexdigest(), 'id': doc['id']}
        for key in ('vendor', 'product'):
            if meta.get(key):
                entry[key] = str(meta[key]).strip().lower()
        cpe = re.match(r'^cpe:2\.3:([aho]):([^:\s]+):([^:\s]+)', str(classification.get('cpe') or '').strip().lower())
        if cpe:
            entry['cpe'] = ':'.join(cpe.groups())
        templates[path.relative_to(TEMPLATES).as_posix()] = entry
    return {'nuclei_templates': 'fixture', 'rules': 1, 'reasons': [], 'templates': templates, 'sha256': hashlib.sha256(repr(sorted(templates)).encode()).hexdigest()}


class Templates:
    def setUp(self):
        super().setUp()
        from cvengine_scanner import template_index
        self.index = fixture_index()
        patcher = mock.patch.object(template_index, 'load', return_value=self.index)
        patcher.start()
        self.addCleanup(patcher.stop)
        nuclei_templates._products.clear()


class ReadingTests(Templates, SimpleTestCase):
    def test_the_installed_templates_metadata_is_read_by_id(self):
        got = nuclei_templates.panel_products(self.index)
        self.assertEqual(got['grafana-detect'], {'vendor': 'grafana', 'product': 'grafana', 'part': 'a'})
        self.assertEqual(got['jenkins-login'], {'vendor': 'jenkins', 'product': 'jenkins', 'part': 'a'})
        self.assertEqual(got['citrix-adc-gateway-panel'], {'vendor': 'citrix', 'product': 'gateway', 'part': 'a'})
        self.assertNotIn('fortinet-fortigate-panel', got)  # it names no vendor or product

    def test_the_template_name_without_what_it_says_about_the_page(self):
        for name, product in (('Grafana Login Panel - Detect', 'Grafana'), ('Jenkins Login Detected', 'Jenkins'), ('Gitlab Login Panel - Detect', 'Gitlab'),
                              ('Fortinet FortiSIEM - Panel', 'Fortinet FortiSIEM'), ('Zabbix Admin', 'Zabbix'), ('Netscaler Gateway', 'Netscaler Gateway'),
                              ('Fortinet FortiGate SSL VPN Login Panel - Detect', 'Fortinet FortiGate SSL VPN')):
            self.assertEqual(panel_versions.product_name(name), product)

    def test_only_a_version_shaped_value_and_the_highest_of_several(self):
        for value, version in (('10.2.3', '10.2.3'), ('v2.426.1', '2.426.1'), ('7.0.7.0398', '7.0.7.0398'), ('8.9p1', '8.9p1'), ('2023.5.1', '2023.5.1')):
            self.assertEqual(panel_versions.version_of(value), version, value)
        # a FortiGate ETag's hash, a git hash, a build date, a bare major, a long string, text
        for value in ('5f1a2b3c', '1e84fede5', '2.1.0-a5565ad3', '2024.01.15', '10', '1.2.3.4.5.6.7.8.9.10.11.12.13.14', 'FortiManager-VM64', '7.2.5 build1517'):
            self.assertEqual(panel_versions.version_of(value), '', value)
        self.assertEqual(panel_versions.highest_version(['9.5.1', '10.2.3', '10.10.0', 'abc']), '10.10.0')

    def test_a_local_line_names_the_product_by_its_metadata_with_the_cpe(self):
        got = panel_versions.reading(GRAFANA_LOCAL)
        self.assertEqual((got['label'], got['version'], got['cpe'], got['port'], got['source']),
                         ('Grafana', '10.2.3', 'cpe:2.3:a:grafana:grafana:10.2.3', 443, 'panel'))

    def test_a_sentinel_line_takes_the_metadata_of_the_installed_template(self):
        line = sentinel_line('jenkins-login', 'Jenkins Login Detected', ['panel', 'jenkins', 'discovery'], ['2.426.1'], 'http://ci.panel.test:8080/login')
        self.assertNotIn('metadata', line['info'])
        got = panel_versions.reading(line)
        self.assertEqual((got['label'], got['version'], got['cpe'], got['port']), ('Jenkins', '2.426.1', 'cpe:2.3:a:jenkins:jenkins:2.426.1', 8080))

    def test_a_generic_product_word_takes_its_vendor(self):
        line = sentinel_line('citrix-adc-gateway-panel', 'Citrix ADC Gateway Login Panel - Detect', ['panel', 'citrix', 'discovery'], ['13.1.49.15'],
                             'https://vpn.panel.test/')
        got = panel_versions.reading(line)
        self.assertEqual((got['label'], got['cpe']), ('Citrix Gateway', 'cpe:2.3:a:citrix:gateway:13.1.49.15'))

    def test_no_reading_without_a_version_a_panel_tag_or_info_severity(self):
        gitlab = sentinel_line('gitlab-detect', 'Gitlab Login Panel - Detect', ['panel', 'gitlab', 'discovery'], [], 'https://git.panel.test/users/sign_in')
        self.assertIsNone(panel_versions.reading(gitlab))  # the template extracts nothing: no version is invented
        fortigate = sentinel_line('fortinet-fortigate-panel', 'Fortinet FortiGate SSL VPN Login Panel - Detect', ['panel', 'fortigate', 'vpn', 'discovery'],
                                  ['5f1a2b3c'], 'https://vpn.panel.test/')
        self.assertIsNone(panel_versions.reading(fortigate))  # the ETag hash it extracts is no version
        self.assertIsNone(panel_versions.reading({**GRAFANA_LOCAL, 'info': {**GRAFANA_LOCAL['info'], 'tags': ['tech', 'grafana']}}))
        self.assertIsNone(panel_versions.reading({**GRAFANA_LOCAL, 'info': {**GRAFANA_LOCAL['info'], 'severity': 'high'}}))

    def test_a_template_without_metadata_names_the_product_by_its_name(self):
        line = local_line('acme-panel', 'Acme Console Login Panel - Detect', ['panel', 'acme'], ['4.1.0'], 'https://acme.panel.test/')
        got = panel_versions.reading(line)
        self.assertEqual((got['label'], got['version']), ('Acme Console', '4.1.0'))
        self.assertNotIn('cpe', got)


class PanelBase(Templates, TestCase):
    def setUp(self):
        super().setUp()
        now = timezone.now()
        self.org = Org.objects.create(name='PV', slug='pv')
        self.project = Project.objects.create(name='PV', slug='pv-p', insert_date=now, org=self.org)
        self.domain = Domain.objects.create(name='panel.test', project=self.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='e-pv', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=now, scan_status=2, results_dir='/tmp')
        self.sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='app.panel.test')
        self.ip = IpAddress.objects.create(address='192.0.2.50')
        self.sub.ip_addresses.add(self.ip)

    def run_lines(self, lines):
        """Feed ``lines`` through the template pass as a stream would; ``again`` counts the hosts correlated again (the real correlation runs)."""
        def stream(_path, **_kwargs):
            return iter(lines)
        with mock.patch.object(nuclei_fp, 'control_get', mock.Mock(return_value={})), \
                mock.patch('cveFeed.probes.recorrelate', wraps=probes.recorrelate) as again:
            return nuclei_scan._run_nuclei(self.scan.id, stream=stream, targets=['app.panel.test'], force=True), again

    def techs(self):
        return {t.name for t in Subdomain.objects.get(pk=self.sub.pk).technologies.all()}

    def tech(self, name):
        self.sub.technologies.add(Technology.objects.get_or_create(name=name)[0])

    def readings(self):
        return {(r.product, r.version, r.port) for r in ProbeObservation.objects.filter(probe=PROBE, kind='version')}


class IngestTests(PanelBase):
    def test_a_local_panel_hit_is_a_finding_and_a_version_reading_and_a_technology(self):
        out, again = self.run_lines([GRAFANA_LOCAL])
        self.assertEqual(out['info'], 1)
        vuln = Vulnerability.objects.get(template_id='grafana-detect')
        self.assertEqual(vuln.extracted_results, ['9.5.1', '10.2.3'])  # the finding is unchanged
        row = ProbeObservation.objects.get(probe=PROBE, kind='version')
        self.assertEqual((row.product, row.version, row.port, row.kind, row.outcome), ('Grafana', '10.2.3', 443, 'version', 'found'))
        self.assertEqual((row.evidence['cpe'], row.url), ('cpe:2.3:a:grafana:grafana:10.2.3', 'https://app.panel.test/login'))
        self.assertIn('Grafana:10.2.3', self.techs())
        self.assertEqual(source_versions.technology_cpes(Subdomain.objects.get(pk=self.sub.pk))['Grafana:10.2.3'], 'cpe:2.3:a:grafana:grafana:10.2.3')
        again.assert_called_once()

    def test_a_sentinel_panel_hit_is_read_the_same_way(self):
        line = sentinel_line('jenkins-login', 'Jenkins Login Detected', ['panel', 'jenkins', 'discovery'], ['2.426.1'], 'http://app.panel.test:8080/login')
        self.run_lines([line])
        self.assertEqual(self.readings(), {('Jenkins', '2.426.1', 8080)})
        self.assertIn('Jenkins:2.426.1', self.techs())

    def test_a_hash_or_no_value_is_no_version_only_an_identity_and_a_non_panel_hit_stores_nothing(self):
        lines = [sentinel_line('fortinet-fortigate-panel', 'Fortinet FortiGate SSL VPN Login Panel - Detect', ['panel', 'fortigate', 'vpn', 'discovery'],
                               ['5f1a2b3c'], 'https://app.panel.test/'),
                 sentinel_line('fortinet-panel', 'Fortinet Login Panel - Detect', ['panel', 'fortinet', 'login', 'detect', 'discovery'], [],
                               'https://app.panel.test/login'),
                 local_line('nginx-version', 'Nginx Version Detect', ['tech', 'nginx'], ['1.24.0'], 'https://app.panel.test/')]
        self.run_lines(lines)
        self.assertEqual(Vulnerability.objects.count(), 3)
        # no version is invented: each panel names its product with none (cveFeed.panel_versions.identity), the nginx technology hit nothing here
        self.assertEqual({(r.product, r.version, r.outcome, r.evidence.get('cpe', '')) for r in ProbeObservation.objects.filter(probe=PROBE)},
                         {('Fortinet FortiGate SSL VPN', '', 'hidden', ''), ('Fortiportal', '', 'hidden', 'cpe:2.3:a:fortinet:fortiportal')})
        self.assertEqual(self.techs(), {'Fortinet FortiGate SSL VPN', 'Fortiportal'})

    def test_a_reading_that_cannot_be_stored_never_stops_the_pass(self):
        with mock.patch.object(panel_versions, 'store', side_effect=RuntimeError('boom')):
            out, _again = self.run_lines([GRAFANA_LOCAL])
        self.assertEqual(out['findings'], 1)


class NoDowngradeTests(PanelBase):
    def test_a_better_version_from_the_technology_pass_stands(self):
        self.tech('Grafana:10.4.1')
        self.run_lines([GRAFANA_LOCAL])  # the panel says 10.2.3
        self.assertEqual(self.readings(), set())
        self.assertEqual(self.techs(), {'Grafana:10.4.1'})

    def test_the_same_version_from_another_source_is_not_added_twice(self):
        self.tech('Grafana:10.2.3')
        self.run_lines([GRAFANA_LOCAL])
        self.assertEqual(self.readings(), set())

    def test_a_port_that_states_the_product_stands(self):
        self.ip.ports.add(Port.objects.create(number=8080, product='Jenkins', version='2.440.1', state='open', service_name='http'))
        line = sentinel_line('jenkins-login', 'Jenkins Login Detected', ['panel', 'jenkins', 'discovery'], ['2.426.1'], 'http://app.panel.test:8080/login')
        self.run_lines([line])
        self.assertEqual(self.readings(), set())

    def test_a_less_precise_version_is_refined_and_a_bare_name_takes_the_version(self):
        self.tech('Grafana:10.2')
        self.tech('Jenkins')
        line = sentinel_line('jenkins-login', 'Jenkins Login Detected', ['panel', 'jenkins', 'discovery'], ['2.426.1'], 'http://app.panel.test:8080/login')
        self.run_lines([GRAFANA_LOCAL, line])
        self.assertEqual(self.readings(), {('Grafana', '10.2.3', 443), ('Jenkins', '2.426.1', 8080)})

    def test_its_own_earlier_reading_does_not_hold_back_a_newer_one(self):
        self.run_lines([GRAFANA_LOCAL])
        newer = {**GRAFANA_LOCAL, 'extracted-results': ['10.2.4']}
        self.run_lines([newer])
        self.assertEqual(self.readings(), {('Grafana', '10.2.4', 443)})


class CorrelationTests(PanelBase):
    def test_a_panel_version_inside_a_range_matches_and_one_outside_does_not(self):
        inside = cve('CVE-2026-410001', 'grafana', 'grafana', '10.0.0', '10.2.4')
        outside = cve('CVE-2026-410002', 'grafana', 'grafana', '10.0.0', '10.2.3')
        other = cve('CVE-2026-410003', 'someoneelse', 'grafana-image-renderer', '1.0.0', '99.0.0')
        self.run_lines([GRAFANA_LOCAL])
        match = CVEMatch.objects.get(cve_entry=inside)
        self.assertEqual((match.source, match.matched_version, match.version_in_range), ('tech', '10.2.3', True))
        self.assertEqual(match.evidence['cpe'], 'cpe:2.3:a:grafana:grafana:10.2.3')
        self.assertFalse(CVEMatch.objects.filter(cve_entry=outside, version_in_range=True).exists())
        self.assertFalse(CVEMatch.objects.filter(cve_entry=other).exists())


class TechSearchTests(PanelBase):
    def test_tech_search_finds_the_host_at_the_panels_version(self):
        from tests.test_agentapi import call
        user = User.objects.create_user('pv-alice', password='x')
        ProjectMembership.objects.create(user=user, project=self.project, role='user')
        _, token = create_token(user, 'pv')
        self.run_lines([GRAFANA_LOCAL])

        def names(q):
            status, data = call(token, 'GET', f'/api/v1/projects/{self.project.slug}/search?' + urlencode({'q': q}))
            self.assertEqual(status, 200, data)
            return sorted(h['host'] for h in data['results'])
        self.assertEqual(names('tech:grafana@10.2'), ['app.panel.test'])
        self.assertEqual(names('tech:grafana@9.5'), [])
        self.assertEqual(names('vsource:panel'), ['app.panel.test'])


class BackfillTests(PanelBase):
    def finding(self, template_id, name, tags, extracted, url, sub=None, severity=0):
        vuln = Vulnerability.objects.create(scan_history=self.scan, target_domain=self.domain, subdomain=sub or self.sub, source='nuclei', name=name,
                                            template_id=template_id, severity=severity, http_url=url, extracted_results=extracted)
        for tag in tags:
            vuln.tags.add(VulnerabilityTags.objects.get_or_create(name=tag)[0])
        return vuln

    def test_stored_panel_findings_become_readings_and_their_hosts_are_correlated(self):
        inside = cve('CVE-2026-410101', 'jenkins', 'jenkins', '2.400', '2.426.2')
        self.finding('jenkins-login', 'Jenkins Login Detected', ['panel', 'jenkins', 'discovery'], ['2.426.1'], 'http://app.panel.test:8080/login')
        self.finding('fortinet-fortigate-panel', 'Fortinet FortiGate SSL VPN Login Panel - Detect', ['panel', 'fortigate'], ['5f1a2b3c'],
                     'https://app.panel.test/')
        self.finding('grafana-detect', 'Grafana Login Panel - Detect', ['panel', 'grafana'], ['10.2.3'], 'https://app.panel.test/login', severity=2)
        self.finding('nginx-version', 'Nginx Version Detect', ['tech', 'nginx'], ['1.24.0'], 'https://app.panel.test/')
        self.assertEqual(panel_versions.catch_up(apply=False)['findings'], 1)
        self.assertFalse(ProbeObservation.objects.exists())  # a dry run writes nothing
        out = panel_versions.catch_up(apply=True)
        self.assertEqual((out['findings'], out['hosts']), (1, 1))
        self.assertGreaterEqual(out['readings'], 1)  # with the Jetty jenkins.war bundles (cveFeed.bundled_components)
        self.assertEqual(self.readings(), {('Jenkins', '2.426.1', 8080)})
        self.assertIn('Jenkins:2.426.1', self.techs())
        self.assertTrue(CVEMatch.objects.filter(cve_entry=inside, version_in_range=True).exists())
        again = panel_versions.catch_up(apply=True)  # idempotent
        self.assertEqual(again['hosts'], 0)
        self.assertEqual(ProbeObservation.objects.filter(probe=PROBE, kind='version').count(), 1)
        self.assertEqual(CVEMatch.objects.filter(cve_entry=inside).count(), 1)

    def test_the_newest_finding_wins_and_a_better_version_elsewhere_stands(self):
        self.finding('jenkins-login', 'Jenkins Login Detected', ['panel', 'jenkins'], ['2.400.1'], 'http://app.panel.test:8080/')
        self.finding('jenkins-login', 'Jenkins Login Detected', ['panel', 'jenkins'], ['2.426.1'], 'http://app.panel.test:8080/login')
        other = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='ci.panel.test')
        other.technologies.add(Technology.objects.get_or_create(name='Jenkins:2.440.3')[0])
        self.finding('jenkins-login', 'Jenkins Login Detected', ['panel', 'jenkins'], ['2.426.1'], 'http://ci.panel.test/login', sub=other)
        panel_versions.catch_up(apply=True)
        self.assertEqual({(r.host, r.version) for r in ProbeObservation.objects.filter(probe=PROBE, kind='version')}, {('app.panel.test', '2.426.1')})
        self.assertEqual({t.name for t in other.technologies.all()}, {'Jenkins:2.440.3'})

    def test_it_is_registered_before_the_rescore_and_runs_as_a_command(self):
        self.assertIn('backfill_panel_versions', upgrade_backfills.BACKFILLS)
        self.assertLess(upgrade_backfills.BACKFILLS.index('backfill_panel_versions'), upgrade_backfills.BACKFILLS.index('rerate_findings'))
        out = StringIO()
        call_command('backfill_panel_versions', stdout=out)
        self.assertIn('Dry run', out.getvalue())
        out = StringIO()
        call_command('backfill_panel_versions', apply=True, stdout=out)
        self.assertIn('Applied', out.getvalue())
