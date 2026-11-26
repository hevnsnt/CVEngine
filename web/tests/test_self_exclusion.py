"""This cvENGINE server is never a scan target: its own names (from settings) and the public addresses they resolve to are refused for every project,
in the scope a discovery carries and at every Sentinel dispatch, and shown beside the do-not-scan list.

The server's names are example.com names; its public address is 8.8.4.4 and 9.9.9.9 (Python's ``ipaddress`` counts the documentation ranges as private,
and only a public address the names resolve to is taken). The lookup is patched: the test rig blocks DNS.
"""
import os
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from agentapi import address_guard, excluded_addresses, sentinel_stream
from cveFeed import exclusions, self_exclusion
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain

SERVER = 'scanner.example.com'
SERVER_IP = '8.8.4.4'
HOSTS = ['scanner.example.com', 'localhost', '127.0.0.1', '[::1]', 'web', '.example.com', 'alias.example.net', '9.9.9.9', '10.1.2.3']


def resolving(answers):
    """A stand-in for the lookup: ``{name: [addresses]}``; a name it does not know fails like a resolver would."""
    def resolve(name):
        if name not in answers:
            raise OSError('no such name')
        return set(answers[name])
    return mock.patch.object(self_exclusion, '_resolve', side_effect=resolve)


@override_settings(DOMAIN_NAME='scanner.example.com', ALLOWED_HOSTS=HOSTS, CSRF_TRUSTED_ORIGINS=['https://front.example.org'],
                   CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})
class Fixture(TestCase):
    def setUp(self):
        self_exclusion.forget()
        self.addCleanup(self_exclusion.forget)
        env = mock.patch.dict(os.environ, {'CVENGINE_OWN_ADDRESSES': '', 'CVENGINE_SELF_ADDRESSES': ''})
        env.start()
        self.addCleanup(env.stop)
        nics = mock.patch.object(self_exclusion, '_interface_addresses', create=True, return_value=set())  # the machine running the tests is not the server
        self.nics = nics.start()
        self.addCleanup(nics.stop)
        lookup = resolving({SERVER: [SERVER_IP, '10.0.0.5'], 'alias.example.net': ['192.168.1.9'], 'front.example.org': []})
        self.lookup = lookup.start()
        self.addCleanup(lookup.stop)
        now = timezone.now()
        self.org = Org.objects.create(name='Self', slug='self-org')
        self.project = Project.objects.create(name='S', slug='self-p', insert_date=now, org=self.org)
        self.lone = Project.objects.create(name='L', slug='lone-p', insert_date=now)  # no organization, so no do-not-scan list of its own
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='e-self', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=now, scan_status=1, results_dir='/tmp')

    def host(self, name, *addresses):
        sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=name)
        for address in addresses:
            sub.ip_addresses.add(IpAddress.objects.get_or_create(address=address)[0])
        return sub


class SelfExclusion(Fixture):
    # --- what counts as the server --------------------------------------------------------------------------------------------------------------
    def test_the_names_are_the_servers_exact_public_names_never_the_parent_domain(self):
        self.assertEqual(self_exclusion.names(), {SERVER, 'alias.example.net', 'front.example.org'})
        for left_out in ('example.com', 'localhost', 'web', '127.0.0.1'):
            self.assertNotIn(left_out, self_exclusion.names(), left_out)

    def test_the_addresses_are_the_public_ones_the_names_resolve_to_plus_public_literals(self):
        got = {str(a) for a in self_exclusion.addresses()}
        self.assertEqual(got, {SERVER_IP, '9.9.9.9'})  # 10.0.0.5, 192.168.1.9 and the literal 10.1.2.3 are private: another network's host too

    def test_own_addresses_setting_is_taken_as_written(self):
        with mock.patch.dict(os.environ, {'CVENGINE_OWN_ADDRESSES': '172.16.5.5, 2001:4860:4860::8844'}):
            got = {str(a) for a in self_exclusion.addresses()}
        self.assertTrue({'172.16.5.5', '2001:4860:4860::8844', SERVER_IP} <= got, got)

    def test_the_lookup_is_kept_briefly_and_a_failed_one_keeps_the_last_good_answer(self):
        self_exclusion.addresses()
        calls = self.lookup.call_count
        self_exclusion.addresses()
        self.assertEqual(self.lookup.call_count, calls, 'asked again inside the TTL')
        self_exclusion._state['at'] -= self_exclusion.TTL + 1
        with resolving({}):  # DNS is down now
            got = {str(a) for a in self_exclusion.addresses()}
        self.assertIn(SERVER_IP, got, 'a failed lookup dropped an address that was known')

    def test_no_names_in_the_test_settings_means_nothing_extra_is_refused(self):
        with override_settings(DOMAIN_NAME='localhost', ALLOWED_HOSTS=['localhost', '127.0.0.1', 'web'], CSRF_TRUSTED_ORIGINS=[]):
            self_exclusion.forget()
            self.assertEqual(self_exclusion.names(), frozenset())
            self.assertEqual(self_exclusion.addresses(), frozenset())
            self.assertIsNone(exclusions.address_excluded(self.project.pk, 'www.example.com'))

    # --- the rule every scan path asks -------------------------------------------------------------------------------------------------------------
    def test_the_servers_name_and_address_are_refused_for_every_project(self):
        for project in (self.project, self.lone):
            for value in (SERVER, f'https://{SERVER}/wp-content/plugins/x/readme.txt', f'{SERVER}:443', SERVER_IP, f'{SERVER_IP}:8443'):
                refusal = exclusions.address_excluded(project.pk, value)
                self.assertTrue(refusal, (project.slug, value))
                self.assertIn('this cvENGINE server', refusal)
        for allowed in ('example.com', 'www.example.com', 'notscanner.example.com', '8.8.8.8'):
            self.assertIsNone(exclusions.address_excluded(self.project.pk, allowed), allowed)

    def test_a_name_that_resolves_to_the_servers_address_is_refused(self):
        self.host('home.example.com', SERVER_IP)
        self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, 'home.example.com'))
        self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, 'other.example.com', resolved=[SERVER_IP]))

    def test_the_servers_addresses_alone_never_hold_back_a_name_nothing_resolved_yet(self):
        refusals = address_guard.task_refusals(self.project, 'nuclei', {'hosts': [{'name': 'new.example.com'}]})
        self.assertEqual(refusals, {}, 'a name with no known address waited for a lookup although the organization has no list')

    def test_excluded_names_carries_the_server_for_scans_but_not_for_the_inventory(self):
        self.host('home.example.com', SERVER_IP)
        banned = exclusions.excluded_names(self.project.pk)
        for value in (SERVER, SERVER_IP, 'home.example.com'):
            self.assertIn(value, banned, value)
        self.assertNotIn('example.com', banned)
        self.assertNotIn('www.example.com', banned)
        inventory = exclusions.excluded_names(self.project.pk, names_only=True)
        self.assertNotIn(SERVER, inventory)  # the inventory keeps the host visible; it is only never scanned

    def test_dispatch_refuses_work_at_the_server(self):
        for kind, target in (('nuclei', {'hosts': [{'name': SERVER}]}), ('testssl', {'host': SERVER, 'port': 443}), ('nmap', {'ip': SERVER_IP})):
            with self.subTest(kind=kind):
                self.assertIn('this cvENGINE server', address_guard.dispatch_refusal(self.project, kind, target, note=False))
        self.assertIsNone(address_guard.dispatch_refusal(self.project, 'nuclei', {'hosts': [{'name': 'www.example.com', 'ip': '8.8.8.8'}]}, note=False))

    def test_a_range_sweep_result_that_names_the_servers_address_is_kept(self):
        task = mock.Mock(kind='nmap', project_id=self.project.pk, target={'cidr': '8.8.4.0/24'}, host='', ips=[])
        self.assertIsNone(address_guard.result_refusal(task, {'ports': {SERVER_IP: [443], '8.8.4.5': [22]}}))

    # --- the scope a discovery carries --------------------------------------------------------------------------------------------------------------
    def test_the_discovery_scope_excludes_the_servers_name_and_denies_its_addresses(self):
        scope = sentinel_stream.scope_policy(self.domain)
        self.assertIn({'host': SERVER, 'subtree': False}, scope['exclusions'])
        self.assertNotIn('example.com', [row['host'] for row in scope['exclusions']])
        self.assertEqual(scope['in_scope_domains'], ['example.com'])
        self.assertIn(f'{SERVER_IP}/32', scope['deny_ranges'])
        self.assertIn('9.9.9.9/32', scope['deny_ranges'])
        server_side = sentinel_stream.Scope(scope)  # the server holds what comes back to the same scope
        self.assertIsNone(server_side.name(SERVER))
        self.assertIsNone(server_side.address(SERVER_IP))
        self.assertEqual(server_side.name('www.example.com'), 'www.example.com')

    def test_a_discovery_of_the_servers_own_name_is_refused(self):
        target = sentinel_stream.bbot_target(Domain.objects.create(name=SERVER, project=self.project, insert_date=timezone.now()), 'standard', 3600)
        self.assertIn('this cvENGINE server', address_guard.dispatch_refusal(self.project, 'bbot_discovery', target, note=False))

    # --- shown where the exclusions are listed --------------------------------------------------------------------------------------------------------
    def test_the_list_shows_the_server_beside_the_organizations_entries(self):
        rows = excluded_addresses.list_rows(self.org.pk)
        self.assertEqual(rows['results'], [])
        self.assertEqual(rows['this_server']['label'], 'This cvENGINE server, never scanned')
        self.assertIn(SERVER, rows['this_server']['names'])
        self.assertIn(SERVER_IP, rows['this_server']['addresses'])


CF_V4, CF_V4B = '104.21.54.43', '172.67.223.148'
CF_V6 = '2606:4700:3034::6815:362b'


class CloudflareFrontedServer(Fixture):
    """The server's public name is behind Cloudflare (production: scanner.fieldcraftcyber.com): it resolves to Cloudflare's anycast addresses, which
    front many unrelated sites. The name is excluded; those addresses are never denied."""

    def setUp(self):
        super().setUp()
        self.lookup.side_effect = resolving({SERVER: [CF_V4, CF_V4B, CF_V6]}).kwargs['side_effect']

    def test_the_name_is_excluded_but_its_cloudflare_addresses_are_not_denied(self):
        self.assertIn(SERVER, self_exclusion.names())
        got = {str(a) for a in self_exclusion.addresses()}
        for cf in (CF_V4, CF_V4B, CF_V6):
            self.assertNotIn(cf, got, cf)
            self.assertIsNone(exclusions.address_excluded(self.project.pk, cf), cf)
        self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, SERVER))
        self.assertIn('this cvENGINE server', address_guard.dispatch_refusal(self.project, 'nuclei', {'hosts': [{'name': SERVER}]}, note=False))

    def test_an_unrelated_host_on_the_same_cloudflare_address_is_still_scannable(self):
        self.host('shop.customer.org', CF_V4)
        self.assertIsNone(exclusions.address_excluded(self.project.pk, 'shop.customer.org'))
        self.assertIsNone(exclusions.address_excluded(self.project.pk, 'other.customer.org', resolved=[CF_V4]))
        self.assertNotIn('shop.customer.org', exclusions.excluded_names(self.project.pk))
        self.assertIsNone(address_guard.dispatch_refusal(self.project, 'nuclei', {'hosts': [{'name': 'shop.customer.org', 'ip': CF_V4}]}, note=False))
        self.assertIsNone(address_guard.dispatch_refusal(self.project, 'nmap', {'ip': CF_V4}, note=False))
        self.assertNotIn(f'{CF_V4}/32', sentinel_stream.scope_policy(self.domain)['deny_ranges'])

    def test_the_list_says_which_addresses_were_left_out_and_why(self):
        own = excluded_addresses.list_rows(self.org.pk)['this_server']
        self.assertIn(SERVER, own['names'])
        self.assertEqual(own['addresses'], ['9.9.9.9'])  # the public literal in the host settings, nothing from Cloudflare
        left = {r['address']: r['reason'] for r in own['not_denied']}
        self.assertEqual(set(left), {CF_V4, CF_V4B, CF_V6})
        self.assertIn('Cloudflare', left[CF_V4])
        self.assertIn('not denied', left[CF_V4])

    def test_an_origin_address_set_in_the_settings_is_denied_with_its_reason(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SELF_ADDRESSES': '8.8.4.4'}):
            self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, '8.8.4.4'))
            self.host('origin-alias.other.org', '8.8.4.4')
            self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, 'origin-alias.other.org'))
            reasons = {r['address']: r['reason'] for r in self_exclusion.summary()['address_reasons']}
        self.assertEqual(reasons['8.8.4.4'], 'set in CVENGINE_SELF_ADDRESSES')

    def test_a_setting_wins_over_a_cdn_range(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SELF_ADDRESSES': CF_V4}):  # an owner who says so is believed
            self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, CF_V4))
            self.assertNotIn(CF_V4, [r['address'] for r in self_exclusion.summary()['not_denied']])

    def test_the_machines_own_public_interface_address_is_denied(self):
        self.nics.return_value = {self_exclusion._address('8.8.8.4')}
        self_exclusion.forget()
        self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, '8.8.8.4'))
        reasons = {r['address']: r['reason'] for r in self_exclusion.summary()['address_reasons']}
        self.assertIn('network interface', reasons['8.8.8.4'])

    def test_openvas_never_takes_a_cloudflare_address_for_this_server(self):
        from cveFeed import openvas_scan as ov
        answer = [(2, 1, 6, '', (CF_V4, 0)), (2, 1, 6, '', ('8.8.4.4', 0))]
        with mock.patch.dict(ov._own, {'at': 0.0}), mock.patch('socket.getaddrinfo', return_value=answer):
            own = ov.own_addresses()
        self.assertEqual(own, frozenset({'8.8.4.4'}))


class SharedOrOwnResolvedAddress(Fixture):
    """A name that resolves outside any CDN range: denied, unless unrelated hosts in the inventory resolve to the same address (shared hosting)."""

    def test_a_resolved_address_outside_any_cdn_is_denied_with_its_reason(self):
        self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, SERVER_IP))
        reasons = {r['address']: r['reason'] for r in self_exclusion.summary()['address_reasons']}
        self.assertEqual(reasons[SERVER_IP], f'{SERVER} resolves to it')

    def test_an_address_unrelated_hosts_resolve_to_is_shared_and_not_denied(self):
        self.host('blog.unrelated.org', SERVER_IP)
        self_exclusion.forget()
        self.assertIsNone(exclusions.address_excluded(self.project.pk, SERVER_IP))
        self.assertIsNone(exclusions.address_excluded(self.project.pk, 'blog.unrelated.org'))
        left = {r['address']: r['reason'] for r in self_exclusion.summary()['not_denied']}
        self.assertIn('blog.unrelated.org', left[SERVER_IP])
        self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, SERVER))  # the name stays excluded

    def test_the_owners_own_hosts_beside_the_server_do_not_make_it_shared(self):
        self.host('www.example.com', SERVER_IP)
        self_exclusion.forget()
        self.assertIn('this cvENGINE server', exclusions.address_excluded(self.project.pk, SERVER_IP))

    def test_an_address_flagged_as_a_cdn_in_the_inventory_is_not_denied(self):
        IpAddress.objects.create(address=SERVER_IP, is_cdn=True)
        self_exclusion.forget()
        self.assertIsNone(exclusions.address_excluded(self.project.pk, SERVER_IP))
