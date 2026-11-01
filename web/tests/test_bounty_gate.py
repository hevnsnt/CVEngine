"""The bug bounty scan gates: one shared check (cveFeed.bounty_gate) that every unattended scan entry point asks.

Two promises, proved for every entry point in ENTRY_POINTS (a table, so a new sweep is one more row):
  project  a project whose engagement has not confirmed automated testing (policy acknowledged, automated testing allowed, still being
           worked, scope unchanged since the acknowledgement) is not scanned on its own;
  host     a host the program's scope does not name (out of scope, not listed) is never aimed at, whoever started the scan.
Each row also has a control: the same entry point does act on an in-scope host of a confirmed project, so the gate is not simply
refusing everything.
"""
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import bounty_gate, conductor, discovery
from cveFeed.models import BountyAsset, BountyEngagement, BountyProgram, HostState
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain

PUBLIC_IP = '93.184.216.9'
IN_HOST = 'www.acme.test'       # named by the wildcard
OUT_HOST = 'admin.acme.test'    # listed out of scope
UNLISTED = 'www.exact.test'     # only exact.test itself is listed, not its subdomains
APEX = 'acme.test'              # the wildcard does not name its own apex: ambiguous until a person adds it as a target


class Gated(TestCase):
    """A bug bounty project whose program lists ``*.acme.test`` and ``exact.test`` and excludes ``admin.acme.test``."""

    def setUp(self):
        self.now = timezone.now()
        self.org = Org.objects.create(name='Bounty', slug='bounty-gate')
        self.engine = EngineType.objects.create(engine_name='gate-engine', yaml_configuration='x', default_engine=True)
        self.program = BountyProgram.objects.create(platform='hackerone', handle='acme', name='Acme')
        for kind, ident, inside in (('wildcard', '*.acme.test', True), ('domain', 'exact.test', True), ('domain', 'admin.acme.test', False)):
            BountyAsset.objects.create(program=self.program, kind=kind, identifier=ident, in_scope=inside)
        for patcher in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
                        mock.patch('targetApp.target_types.blocked_names', return_value=set()),
                        mock.patch('reNgine.tasks.geo_localize.delay'),
                        mock.patch('cveFeed.scan_control.pause_requested', return_value=False),
                        mock.patch('cveFeed.ledger.sweep_claim', return_value=True),
                        mock.patch('cveFeed.coverage_topup.backlog_exists', return_value=False)):
            patcher.start()
        self.addCleanup(mock.patch.stopall)

    def world(self, host, confirmed=True, status='active'):
        """A bug bounty project holding a target (the registrable domain of ``host``), a finished scan with ``host`` found by it, and an
        address on it. ``confirmed`` is the person's acknowledgement plus the automated-testing switch."""
        n = Project.objects.count()
        org = Org.objects.create(name=f'O{n}', slug=f'bounty-o{n}')  # one organization each: a target name is unique within one
        project = Project.objects.create(name=f'P{n}', slug=f'bounty-p{n}', insert_date=self.now, org=org)
        engagement = BountyEngagement.objects.create(
            project=project, program=self.program, status=status, automated_ok=confirmed,
            policy_ack_at=self.now if confirmed else None, ack_content_hash=self.program.content_hash)
        root = '.'.join(host.split('.')[-2:])
        domain = Domain.objects.create(name=root, project=project, insert_date=self.now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=self.engine, scan_status=2, start_scan_date=self.now, results_dir='/tmp')
        sub = Subdomain.objects.create(name=host, target_domain=domain, scan_history=scan)
        ip = IpAddress.objects.create(address=PUBLIC_IP, org=org)
        sub.ip_addresses.add(ip)
        return type('World', (), {'host': host, 'project': project, 'engagement': engagement, 'domain': domain, 'scan': scan, 'sub': sub,
                                  'ip': ip})


# --- the entry points: each returns True when it started work on the host --------------------------------------------------

def conductor_round(self, w):
    target = Domain.objects.create(name=w.host, project=w.project, insert_date=self.now) if w.host != w.domain.name else w.domain
    ScanHistory.objects.filter(domain=w.domain).update(start_scan_date=self.now - timedelta(days=3))
    return target.id in conductor.next_targets(10)


def ct_watch_finds_a_host(self, w):
    from cveFeed import ctmonitor
    Subdomain.objects.filter(pk=w.sub.pk).delete()
    with mock.patch('cveFeed.tasks.host_pipeline.delay') as queued:
        ctmonitor.run_ct_watch(w.domain.id, fetch=lambda name: {w.host})
    return queued.called


def ct_sweep(self, w):
    from cveFeed.tasks import watch_certificates_all
    with mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async') as queued, \
            mock.patch('cveFeed.ct_queue._client', return_value=None):
        watch_certificates_all()
    return queued.called


def archive_rediscovery(self, w):
    from cveFeed.archive_rediscovery import check_one
    row = HostState.objects.create(project=w.project, domain=w.domain, host=w.host, archived_at=self.now - timedelta(days=31))
    resolver = lambda name: ('absent', set()) if name.startswith('cvengine-nonexistent-') else ('resolved', {PUBLIC_IP})
    with mock.patch('cveFeed.tasks.assess_host.apply_async') as sent:
        sent.return_value.id = 'task'
        return check_one(row, resolver=resolver) == 'reactivated'


def host_assessment_enqueue(self, w):
    from cveFeed.host_assessment import enqueue
    with mock.patch('cveFeed.tasks.assess_host.apply_async') as sent:
        sent.return_value.id = 'task'
        try:
            enqueue(w.project, w.sub, source='review')
        except ValueError:
            return False
        return sent.called


def _pipeline_scans(w):
    return ScanHistory.objects.filter(domain=w.domain, tasks__contains=[discovery.HOST_PIPELINE_TASK]).count()


def host_pipeline_unattended(self, w):
    with mock.patch('cveFeed.discovery._run_stages', return_value={'status': 2}), mock.patch('reNgine.tasks.persist_bbot_result'):
        discovery.run_host_pipeline(w.domain.id, [w.host], resolver=lambda names: {(n, PUBLIC_IP) for n in names})
    return _pipeline_scans(w) > 0


def retest_hosts_task(self, w):
    from cveFeed.tasks import retest_hosts
    with mock.patch('cveFeed.discovery._run_stages', return_value={'status': 2}), mock.patch('reNgine.tasks.persist_bbot_result'), \
            mock.patch('cveFeed.discovery.resolve_names', side_effect=lambda names, **kw: {(n, PUBLIC_IP) for n in names}):
        retest_hosts(w.domain.id, [w.host])
    return _pipeline_scans(w) > 0


def full_port_sweep(self, w):
    from cveFeed import fullscan
    return fullscan.pick() is not None


def weekly_deep_nuclei(self, w):
    from cveFeed.tasks import weekly_deep_nuclei as sweep
    with mock.patch('cveFeed.nuclei_scan.approved_templates', return_value=('/tmp/approved', 'rev1', 1)), \
            mock.patch('cveFeed.nuclei_scan.scan_targets', return_value=({w.host}, set(), set())), \
            mock.patch('cveFeed.nuclei_scan.run_nuclei', return_value={'targets': 1, 'findings': 0}) as run:
        sweep()
    return run.called


def deep_apex_sweep(self, w):
    from cveFeed.tasks import deep_scan_apexes
    before = Domain.objects.count()
    with mock.patch('cveFeed.discovery.start_discoveries', return_value=[]) as started:
        deep_scan_apexes()
    return started.called or Domain.objects.count() != before


def thorough_wpscan(self, w):
    from cveFeed import wpscan_scan
    wpscan_scan.record_thorough(w.project.id, w.domain.id, w.host, 'pending', 'queued')
    runner = mock.Mock(side_effect=ValueError('not running WordPress'))
    with mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
        wpscan_scan.run_thorough(w.project.id, runner=runner, sleep=lambda s: None, probe_get=mock.Mock())
    return runner.called


def openvas_assess(self, w):
    from cveFeed import openvas_scan
    ready, _verdicts = openvas_scan.assess(w.project.id, [w.host], forced={w.host}, resolve=lambda host, project: PUBLIC_IP, blocked=lambda host: False)
    return bool(ready)


def discovery_pipeline(self, w):
    target = Domain.objects.create(name=w.host, project=w.project, insert_date=self.now) if w.host != w.domain.name else w.domain
    scan = ScanHistory.objects.create(domain=target, scan_type=self.engine, scan_status=-1, start_scan_date=self.now, results_dir='/tmp')
    with mock.patch('cveFeed.discovery.run_discovery', return_value={'status': 'stopped'}) as found:
        discovery._run_pipeline(scan.id)
    return found.called


def template_tests(self, w):
    from cveFeed.models import CVEEntry
    from cveFeed.tasks import template_test_for_cve
    cve = CVEEntry.objects.get_or_create(cve_id='CVE-2024-0001', defaults={'title': 'x', 'published_at': self.now, 'cvss': 9.8})[0]
    with mock.patch('cveFeed.templategen.run_cve_tests', return_value={'source': 'x', 'results': []}) as ran:
        template_test_for_cve(cve.pk, [w.host], w.project.id)
    return ran.called


def validation_sweep(self, w):
    from cveFeed.tasks import validate_sweep
    with mock.patch('cveFeed.validation.due_ids', return_value=[1]), mock.patch('cveFeed.tasks.validate_findings.delay') as queued:
        validate_sweep()
    return any(call.args[0] == w.project.id for call in queued.call_args_list)


def hygiene_sweep(self, w):
    from cveFeed.tasks import run_hygiene_all
    with mock.patch('cveFeed.tasks.run_hygiene_task.delay') as queued:
        run_hygiene_all()
    return queued.called


def stored_host_list(self, w):
    from targetApp.target_types import scannable_hosts
    return bool(scannable_hosts([w.host], project=w.project.id))


def stage_targets(self, w):
    from cveFeed import nuclei_scan
    hostnames, _ips, _ports = nuclei_scan.scan_targets(w.scan)
    return w.host in hostnames


def database_exposure_stage(self, w):
    from cveFeed import db_exposure
    from startScan.models import Port
    port = Port.objects.create(number=6379, service_name='redis', protocol='tcp', state='open')
    w.ip.ports.add(port)
    probe = mock.Mock(return_value=False)
    db_exposure.run_db_exposure_checks(w.scan.id, checks={'redis': ('Redis', probe)})
    return probe.called


def route_auth_stage(self, w):
    from cveFeed import route_auth
    from startScan.models import Port
    w.ip.ports.add(Port.objects.create(number=443, service_name='https', protocol='tcp', state='open'))
    return w.host in route_auth._plan(w.scan)


# name, function, refused for a project that has not confirmed, refused for a host the scope does not name, acts when everything is allowed
ENTRY_POINTS = [
    ('conductor', conductor_round, True, True, True),
    ('ct watch of one target', ct_watch_finds_a_host, True, True, True),
    ('ct sweep', ct_sweep, True, False, True),
    ('archived host rediscovery', archive_rediscovery, True, True, True),
    ('host assessment queue', host_assessment_enqueue, True, True, True),
    ('new-hosts pipeline', host_pipeline_unattended, True, True, True),
    ('retest of changed hosts', retest_hosts_task, True, True, True),
    ('full TCP port sweep', full_port_sweep, True, True, True),
    ('weekly deep nuclei', weekly_deep_nuclei, True, True, True),
    ('deep apex discovery', deep_apex_sweep, True, False, False),  # never touches a bug bounty project at all: it would widen the scope
    ('thorough WPScan', thorough_wpscan, True, True, True),
    ('OpenVAS', openvas_assess, True, True, True),
    ('discovery pipeline', discovery_pipeline, True, True, True),
    ('template tests', template_tests, True, False, True),
    ('validation sweep', validation_sweep, True, False, True),
    ('hygiene sweep', hygiene_sweep, True, False, True),
    ('stored host lists (scannable_hosts)', stored_host_list, False, True, True),
    ('scan stage targets', stage_targets, False, True, True),
    ('database exposure stage', database_exposure_stage, False, True, True),
    ('route auth stage', route_auth_stage, False, True, True),
]


class EveryEntryPointTests(Gated):
    def test_a_project_that_has_not_confirmed_automated_testing_is_never_scanned_on_its_own(self):
        for name, fn, project_gated, _host_gated, _acts in ENTRY_POINTS:
            if not project_gated:
                continue
            with self.subTest(name):
                w = self.world(IN_HOST, confirmed=False)
                self.assertFalse(fn(self, w))

    def test_a_confirmed_project_whose_engagement_is_over_or_paused_is_not_scanned_either(self):
        for status in ('paused', 'done'):
            for name, fn, project_gated, _host_gated, _acts in ENTRY_POINTS:
                if project_gated:
                    with self.subTest(f'{name} {status}'):
                        self.assertFalse(fn(self, self.world(IN_HOST, status=status)))

    def test_a_program_scope_that_changed_since_the_acknowledgement_blocks_scanning_until_it_is_acknowledged_again(self):
        w = self.world(IN_HOST)
        self.assertNotIn(w.project.id, conductor.bounty_blocked_projects())
        BountyProgram.objects.filter(pk=self.program.pk).update(content_hash='scope-changed-upstream')
        self.assertIn(w.project.id, conductor.bounty_blocked_projects())
        for name, fn, project_gated, _host_gated, _acts in ENTRY_POINTS:
            if project_gated:
                with self.subTest(name):
                    self.assertFalse(fn(self, self.world(IN_HOST)))
        BountyEngagement.objects.filter(pk=w.engagement.pk).update(ack_content_hash='scope-changed-upstream')  # a person acknowledged the new scope
        self.assertNotIn(w.project.id, conductor.bounty_blocked_projects())

    def test_a_host_the_program_forbids_or_does_not_list_is_never_scanned_even_in_a_confirmed_project(self):
        for host in (OUT_HOST, UNLISTED):
            for name, fn, _project_gated, host_gated, _acts in ENTRY_POINTS:
                if host_gated:
                    with self.subTest(f'{name}: {host}'):
                        self.assertFalse(fn(self, self.world(host)))

    def test_the_same_entry_points_do_act_on_an_in_scope_host_of_a_confirmed_project(self):
        for name, fn, _project_gated, _host_gated, acts in ENTRY_POINTS:
            with self.subTest(name):
                self.assertEqual(fn(self, self.world(IN_HOST)), acts)

    def test_the_apex_of_an_in_scope_wildcard_waits_for_a_person_and_a_target_row_is_that_confirmation(self):
        w = self.world(APEX)  # the project's target is acme.test itself: a person added it
        self.assertTrue(conductor_round(self, w))
        self.assertEqual(bounty_gate.Gate().refusal(w.project.id, APEX), '')
        Domain.objects.filter(pk=w.domain.pk).delete()  # without a target row the apex is only ambiguous
        self.assertIn('wildcard does not name', bounty_gate.Gate().refusal(w.project.id, APEX))


class GateSemanticsTests(Gated):
    def test_a_project_without_an_engagement_is_never_affected(self):
        project = Project.objects.create(name='Plain', slug='plain-gate', insert_date=self.now, org=self.org)
        gate = bounty_gate.Gate()
        for host in (IN_HOST, OUT_HOST, UNLISTED, 'anything.example', PUBLIC_IP):
            self.assertEqual(gate.refusal(project.id, host), '', host)
        self.assertEqual(gate.refusal(None, OUT_HOST), '')

    def test_a_scan_a_person_started_is_held_to_the_scope_but_not_to_the_project_confirmation(self):
        w = self.world(IN_HOST, confirmed=False)
        gate = bounty_gate.Gate()
        self.assertTrue(gate.refusal(w.project.id, IN_HOST))
        self.assertEqual(gate.refusal(w.project.id, IN_HOST, unattended=False), '')
        self.assertTrue(gate.refusal(w.project.id, OUT_HOST, unattended=False))

    def test_a_person_can_still_assess_a_host_of_an_unconfirmed_project_and_rescan_it(self):
        from django.contrib.auth.models import User
        from cveFeed.host_assessment import enqueue
        w = self.world(IN_HOST, confirmed=False)
        user = User.objects.create_user('gate-person', password='x')
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as sent:
            sent.return_value.id = 'task'
            job, created = enqueue(w.project, w.sub, user=user)
        self.assertTrue(created)
        with mock.patch('cveFeed.discovery._run_stages', return_value={'status': 2}), mock.patch('reNgine.tasks.persist_bbot_result'):
            discovery.run_host_pipeline(w.domain.id, [IN_HOST], resolver=lambda names: {(n, PUBLIC_IP) for n in names}, by_person=True)
        self.assertEqual(_pipeline_scans(w), 1)

    def test_an_address_behind_an_allowed_name_is_refused_only_by_an_out_of_scope_entry(self):
        BountyAsset.objects.create(program=self.program, kind='cidr', identifier='198.51.100.0/24', in_scope=False)
        w = self.world(IN_HOST)
        gate = bounty_gate.Gate()
        self.assertEqual(gate.refusal(w.project.id, PUBLIC_IP, derived=True), '')
        self.assertTrue(gate.refusal(w.project.id, PUBLIC_IP))  # as a target in its own right nothing lists it
        self.assertTrue(gate.refusal(w.project.id, '198.51.100.7', derived=True))

    def test_the_reason_is_readable(self):
        w = self.world(OUT_HOST)
        self.assertIn('out of scope', bounty_gate.Gate().refusal(w.project.id, OUT_HOST))
        self.assertIn('not its subdomains', bounty_gate.Gate().refusal(w.project.id, UNLISTED))


# --- the bug bounty API findings that ride along: working a program, report scope, report status -------------------------------

from tests import test_bounty_api as api  # noqa: E402 - the module, not its classes: its tests are not collected a second time here


class WorkingAProgramTests(api.BountyBase):
    def create(self, user):
        return api.call(api.client_for(user), 'POST', api.B + 'engagements', {'program_id': self.acme.pk})

    def test_a_project_that_outlived_its_engagement_is_not_taken_over_by_someone_with_no_role_in_it(self):
        status, first = self.create(self.granted)
        self.assertEqual(status, 201)
        project = Project.objects.get(slug=first['project'])
        self.assertEqual(api.call(api.client_for(self.granted), 'DELETE', f'{api.B}engagements/{first["id"]}?project={project.slug}')[0], 200)
        self.assertFalse(BountyEngagement.objects.filter(project=project).exists())
        status, body = self.create(self.granted_b)  # a different user, no role in the project
        self.assertEqual(status, 409)
        self.assertIn(project.slug, body['error'])
        self.assertFalse(BountyEngagement.objects.filter(project=project).exists())  # nothing was written into the other user's project
        self.assertEqual(self.create(self.granted)[0], 201)  # a member can work the program again
        self.assertEqual(BountyEngagement.objects.filter(project=project).count(), 1)


class ReportScopeAndStatusTests(api.ReportBase):
    def patch(self, rid, **body):
        return api.call(self.c, 'PATCH', f'{api.B}reports/{rid}', {'project': 'a1', **body})

    def test_a_report_is_judged_by_the_worse_of_its_asset_and_its_location(self):
        _, r = self.draft()
        rid = r['id']
        self.assertEqual(self.patch(rid, asset='www.acme.test', location_url='https://www.acme.test/admin')[1]['scope']['state'], 'in_scope')
        status, d = self.patch(rid, location_url='https://status.acme.test/health')  # the asset is in scope, the URL points at an excluded host
        self.assertEqual((status, d['scope']['state']), (200, 'out_of_scope'))
        self.assertIn('out_of_scope', {c['code'] for c in d['checks'] if c['level'] == 'block'})
        self.assertEqual(self.patch(rid, location_url='https://www.acme.test/admin')[1]['scope']['state'], 'in_scope')
        self.assertEqual(self.patch(rid, asset='', location_url='')[1]['scope']['state'], 'not_listed')

    def test_a_report_answering_a_request_for_information_can_be_submitted_again_and_a_ready_one_is_not_offered_the_move(self):
        rid = self.draft()[1]['id']
        self.complete(rid)
        _, d = self.patch(rid, status='ready')
        self.assertNotIn('submitted', d['next_states'])  # it is sent with submit or mark-submitted
        self.assertEqual(self.patch(rid, status='submitted')[0], 409)
        api.call(self.c, 'POST', f'{api.B}reports/{rid}/mark-submitted', {'project': 'a1', 'platform_url': 'https://hackerone.com/reports/1'})
        status, d = self.patch(rid, status='needs_info')
        self.assertEqual((status, 'submitted' in d['next_states']), (200, True))
        status, d = self.patch(rid, status='submitted', note='answered the triager')
        self.assertEqual((status, d['status']), (200, 'submitted'))
