import importlib
from unittest import mock

from django.apps import apps
from django.contrib.auth.models import User
from django.db import IntegrityError, connection, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from agentapi import services
from agentapi.services import Ctx
from dashboard.models import Org, OrgMembership, Project
from startScan.ip_rows import get_or_create_ip
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain, org_domains


class Fixture:
	def build(self):
		now = timezone.now()
		self.org_a, self.org_b = Org.objects.create(name='A', slug='oa'), Org.objects.create(name='B', slug='ob')
		self.pa = Project.objects.create(name='PA', slug='pa-ou', insert_date=now, org=self.org_a)
		self.pa2 = Project.objects.create(name='PA2', slug='pa2-ou', insert_date=now, org=self.org_a)
		self.pb = Project.objects.create(name='PB', slug='pb-ou', insert_date=now, org=self.org_b)
		self.admin_a = User.objects.create_user('ou-a', password='x')
		self.admin_b = User.objects.create_user('ou-b', password='x')
		OrgMembership.objects.create(user=self.admin_a, org=self.org_a, role='admin')
		OrgMembership.objects.create(user=self.admin_b, org=self.org_b, role='admin')
		patches = [mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
				   mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'),
				   mock.patch('cveFeed.tasks.run_bbot_discovery.delay'), mock.patch('cveFeed.tasks.watch_certificate_transparency.delay'),
				   mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async')]
		for p in patches:
			p.start()
		self.addCleanup(mock.patch.stopall)


class DomainPerOrganizationTests(Fixture, TestCase):
	def setUp(self):
		self.build()

	def test_two_organizations_can_each_track_the_same_name_and_neither_sees_the_other(self):
		a = services.add_target(Ctx(user=self.admin_a), 'pa-ou', 'shared.example.com', discover=False)
		b = services.add_target(Ctx(user=self.admin_b), 'pb-ou', 'shared.example.com', discover=False)
		self.assertTrue(a['created'] and b['created'])  # no "already exists" for a name another organization holds
		self.assertEqual(Domain.objects.filter(name='shared.example.com').count(), 2)
		self.assertEqual(set(Domain.objects.filter(name='shared.example.com').values_list('org_id', flat=True)), {self.org_a.id, self.org_b.id})

	def test_the_same_organization_still_holds_a_name_once_across_its_projects(self):
		services.add_target(Ctx(user=self.admin_a), 'pa-ou', 'once.example.com', discover=False)
		again = services.add_targets(Ctx(user=self.admin_a), 'pa2-ou', ['once.example.com'], discover=False)
		self.assertEqual(again['created'], 0)
		self.assertEqual(Domain.objects.filter(name='once.example.com').count(), 1)

	def test_the_database_enforces_it(self):
		now = timezone.now()
		Domain.objects.create(name='db.example.com', project=self.pa, insert_date=now)
		Domain.objects.create(name='db.example.com', project=self.pb, insert_date=now)  # another organization
		with self.assertRaises(IntegrityError), transaction.atomic():
			Domain.objects.create(name='db.example.com', project=self.pa2, insert_date=now)  # same organization, other project

	def test_save_takes_the_organization_from_the_project_even_when_it_was_placed_after_creation(self):
		now = timezone.now()
		project = Project.objects.create(name='Late', slug='late-ou', insert_date=now)  # placed in an organization by a signal after save
		domain = Domain.objects.create(name='late.example.com', project=project, insert_date=now)
		project.refresh_from_db()
		self.assertEqual(domain.org_id, project.org_id)

	def test_org_domains_is_the_organizations_set(self):
		now = timezone.now()
		Domain.objects.create(name='x1.example.com', project=self.pa, insert_date=now)
		Domain.objects.create(name='x2.example.com', project=self.pa2, insert_date=now)
		Domain.objects.create(name='x3.example.com', project=self.pb, insert_date=now)
		self.assertEqual(set(org_domains(self.pa).values_list('name', flat=True)), {'x1.example.com', 'x2.example.com'})
		self.assertEqual(set(org_domains(self.pb.pk).values_list('name', flat=True)), {'x3.example.com'})


class IpPerOrganizationTests(Fixture, TestCase):
	def setUp(self):
		self.build()
		now = timezone.now()
		self.da = Domain.objects.create(name='ip.example.com', project=self.pa, insert_date=now)
		self.db = Domain.objects.create(name='ip.example.com', project=self.pb, insert_date=now)

	def test_the_same_address_is_a_separate_row_per_organization_with_its_own_ports(self):
		from cveFeed import nmap_scan
		inventory = lambda banner: [{'ip': '203.0.113.50', 'ports': [{'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh',
									 'product': 'OpenSSH', 'version': '8.9', 'banner': banner, 'scripts': {}, 'cpes': []}]}]
		nmap_scan.persist_inventory(inventory('SSH-2.0-A-SECRET-BANNER'), org_id=self.org_a.id)
		nmap_scan.persist_inventory(inventory('SSH-2.0-other'), org_id=self.org_b.id)
		rows = {ip.org_id: ip for ip in IpAddress.objects.filter(address='203.0.113.50')}
		self.assertEqual(set(rows), {self.org_a.id, self.org_b.id})
		self.assertEqual(rows[self.org_b.id].ports.get().banner, 'SSH-2.0-other')
		self.assertNotIn('SECRET', ' '.join(rows[self.org_b.id].ports.values_list('banner', flat=True)))

	def test_a_host_only_reads_its_own_organizations_ip_data(self):
		from reNgine.tasks import save_ip_address
		sa = Subdomain.objects.create(name='www.ip.example.com', target_domain=self.da)
		sb = Subdomain.objects.create(name='www.ip.example.com', target_domain=self.db)
		ip_a, _ = save_ip_address('203.0.113.51', subdomain=sa)
		ip_b, _ = save_ip_address('203.0.113.51', subdomain=sb)
		self.assertNotEqual(ip_a.pk, ip_b.pk)
		ip_a.ports.add(Port.objects.create(number=443, banner='only-org-a'))
		self.assertEqual(list(sb.ip_addresses.get().ports.all()), [])

	def test_get_or_create_ip_is_per_organization_and_race_safe(self):
		winner = IpAddress.objects.create(address='203.0.113.52', org=self.org_a)
		with mock.patch.object(IpAddress.objects, 'get_or_create', side_effect=IntegrityError('duplicate')):
			row, created = get_or_create_ip('203.0.113.52', self.org_a.id)
		self.assertEqual((row.pk, created), (winner.pk, False))
		other, created = get_or_create_ip('203.0.113.52', self.org_b.id)
		self.assertTrue(created)
		self.assertNotEqual(other.pk, winner.pk)

	def test_subdomain_helpers_do_not_mix_same_named_hosts_of_two_organizations(self):
		from startScan.models import Vulnerability
		sa = Subdomain.objects.create(name='www.ip.example.com', target_domain=self.da)
		sb = Subdomain.objects.create(name='www.ip.example.com', target_domain=self.db)
		Vulnerability.objects.create(name='a-only', severity=3, subdomain=sa, target_domain=self.da)
		Vulnerability.objects.create(name='b-only', severity=3, subdomain=sb, target_domain=self.db)
		self.assertEqual([v.name for v in sa.get_vulnerabilities], ['a-only'])
		self.assertEqual([v.name for v in sb.get_vulnerabilities], ['b-only'])


class SplitMigrationTests(Fixture, TransactionTestCase):
	def test_a_row_shared_by_two_organizations_is_split_with_copies_of_its_ports(self):
		self.build()
		now = timezone.now()
		da = Domain.objects.create(name='mig.example.com', project=self.pa, insert_date=now)
		db = Domain.objects.create(name='mig.example.com', project=self.pb, insert_date=now)
		sa = Subdomain.objects.create(name='a.mig.example.com', target_domain=da)
		sb = Subdomain.objects.create(name='b.mig.example.com', target_domain=db)
		shared = IpAddress.objects.create(address='198.51.100.77', os_guess='Linux 5')  # as the old shared row: no organization
		shared.ports.add(Port.objects.create(number=22, banner='old-banner'))
		sa.ip_addresses.add(shared)
		sb.ip_addresses.add(shared)
		solo = IpAddress.objects.create(address='198.51.100.78')
		sa.ip_addresses.add(solo)
		migration = importlib.import_module('startScan.migrations.0020_ipaddress_per_org')
		migration.split_by_org(apps, None)
		rows = list(IpAddress.objects.filter(address='198.51.100.77'))
		self.assertEqual({r.org_id for r in rows}, {self.org_a.id, self.org_b.id})
		for row in rows:
			self.assertEqual(row.os_guess, 'Linux 5')
			self.assertEqual(row.ports.get().banner, 'old-banner')
		self.assertEqual(sa.ip_addresses.get(address='198.51.100.77').org_id, self.org_a.id)
		self.assertEqual(sb.ip_addresses.get().org_id, self.org_b.id)
		self.assertEqual(IpAddress.objects.get(address='198.51.100.78').org_id, self.org_a.id)
		self.assertNotEqual(sa.ip_addresses.get(address='198.51.100.77').pk, sb.ip_addresses.get().pk)
