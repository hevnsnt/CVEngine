"""1.3.5 hygiene audit items 7, 19, 20 and 22: endpoint-aware ratings, DNS findings that need two resolvers or two runs, the DMARC
organizational-domain fallback reported once on the parent, and no findings for the vendor's own endpoints. Every fixture is synthetic
(example.com / example.net); all DNS is mocked."""
import datetime
import functools
from io import StringIO
from unittest import mock

import dns.exception
import dns.resolver
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import hygiene as hy
from cveFeed import hygiene_rating as hr
from cveFeed import mailfail as mf
from cveFeed import tls_audit
from cveFeed.models import HostLabel, HygieneFinding, RouteAuth
from cveFeed.threat import host_heat
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.test_discovery_mode import call, tool
from tests import hygiene_harness

NOW = datetime.datetime(2026, 11, 4, 12, 0, tzinfo=datetime.timezone.utc)


def checks(findings):
	return {f.check for f in findings}


def by_check(findings):
	return {f.check: f for f in findings}


def heat_of(severity):
	return host_heat('scanned', [], [severity])


def cert(host, port=443, **kw):
	info = {'host': host, 'port': port, 'subject': host, 'sans': [host], 'not_after': NOW + datetime.timedelta(days=200),
			'signature_algorithm': 'sha256', 'key_description': 'RSA 2048', 'protocol': 'TLSv1.3', 'chain_error': '', 'issuer': 'Example CA'}
	info.update(kw)
	return info


class Base(TestCase):
	def setUp(self):
		now = timezone.now()
		self.project = Project.objects.create(name='R', slug='r', insert_date=now, org=Org.objects.create(name='R', slug='r'))
		self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=now)
		patcher = mock.patch('cveFeed.hosting.canonical_name', return_value='')  # no live DNS: CNAMEs come from the stored hosts
		patcher.start()
		self.addCleanup(patcher.stop)

	def host(self, name, cname=None):
		return Subdomain.objects.create(name=name, target_domain=self.domain, cname=cname)

	def store(self, found, **kw):
		hy.store_findings(self.domain, found, **kw)
		return {(r.host, r.check_name): r for r in HygieneFinding.objects.filter(domain=self.domain)}


# ----------------------------------------------------------------------------- item 7 and 22: vendor endpoints

class VendorEndpointTests(Base):
	def test_microsoft_discovery_cname_mismatch_is_info_and_the_endpoint_raises_nothing_else(self):
		"""Fixture shape: msoid.<client> CNAME clientconfig.microsoftonline-p.net served Microsoft's certificate (fire, mismatch) and BREACH."""
		self.host('msoid.example.com', 'clientconfig.microsoftonline-p.net')
		self.host('enterpriseenrollment.example.com', 'enterpriseenrollment-s.manage.microsoft.com')
		found = hy.evaluate_cert(cert('msoid.example.com', sans=['*.microsoftonline-p.net'], subject='stamp2.login.microsoftonline-p.net'), now=NOW)
		found += hy.evaluate_cert(cert('enterpriseenrollment.example.com', sans=['manage.microsoft.com'], subject='manage.microsoft.com',
									   legacy_tls=True), now=NOW)
		self.assertEqual({f.severity for f in found if f.check == 'tls_hostname_mismatch'}, {hy.HIGH})  # the old fire rating
		found.append(hy.Finding('tlsa_breach', hy.MEDIUM, 'msoid.example.com:443: BREACH may apply', host='msoid.example.com:443'))
		rows = self.store(found, live_cnames=True)
		self.assertEqual(set(rows), {('msoid.example.com:443', 'tls_hostname_mismatch'), ('enterpriseenrollment.example.com:443', 'tls_hostname_mismatch')})
		for row in rows.values():
			self.assertEqual((row.severity, row.evidence['owner'], heat_of(row.severity)), (hy.INFO, 'Microsoft', 'clean'))
			self.assertEqual(row.evidence['rating']['from'], hy.HIGH)

	def test_a_microsoft_discovery_name_is_recognised_by_its_certificate_when_no_cname_is_stored(self):
		found = hy.evaluate_cert(cert('autodiscover.example.com', sans=['*.outlook.com', 'outlook.office365.com'], subject='outlook.com'), now=NOW)
		self.assertEqual([(f.check, f.severity) for f in hr.rate(self.domain, found, cnames={})], [('tls_hostname_mismatch', hy.INFO)])
		# an on-premises autodiscover with the client's own certificate is the client's: it keeps its rating
		own = hy.evaluate_cert(cert('autodiscover.example.com', sans=['mail.example.com'], subject='mail.example.com'), now=NOW)
		self.assertEqual([(f.check, f.severity) for f in hr.rate(self.domain, own, cnames={})], [('tls_hostname_mismatch', hy.HIGH)])

	def test_item_22_the_vendors_endpoint_finding_already_open_is_resolved(self):
		self.host('msoid.example.com', 'clientconfig.microsoftonline-p.net')
		HygieneFinding.objects.create(domain=self.domain, host='msoid.example.com:443', check_name='tlsa_breach', severity=hy.MEDIUM,
									  title='msoid.example.com:443: BREACH may apply')
		result = tls_audit.evaluate([{'id': 'BREACH', 'severity': 'MEDIUM', 'cve': 'CVE-2013-3587',
										 'finding': "potentially VULNERABLE, gzip HTTP compression detected - only supplied '/' tested"}],
									   'msoid.example.com:443')
		tls_audit.store(self.domain, 'msoid.example.com', 443, result, 'msoid.example.com:443')
		row = HygieneFinding.objects.get(host='msoid.example.com:443', check_name='tlsa_breach')
		self.assertEqual(row.status, 'resolved')  # Microsoft's sign-in service, not a client asset

	def test_vendor_managed_endpoints_are_tagged_and_rated_ice_or_info(self):
		"""Fixture shape: zendeskN.<client> CNAME to the vendor, TLS 1.0 and 3DES findings from testssl."""
		self.host('help.example.com', 'example.zendesk.com')
		self.host('app.example.com', 'app-production.up.railway.app')
		found = [hy.Finding('tlsa_cipherlist_3des_idea', hy.HIGH, 'help.example.com:443 offers 3DES or IDEA ciphers', host='help.example.com:443'),
				 hy.Finding('tls_legacy_protocol', hy.MEDIUM, 'help.example.com:443 still accepts TLS 1.0 / 1.1', host='help.example.com:443')]
		found += hy.evaluate_cert(cert('app.example.com', sans=['*.up.railway.app'], subject='*.up.railway.app'), now=NOW)
		rows = self.store(found)
		self.assertEqual(rows[('help.example.com:443', 'tlsa_cipherlist_3des_idea')].severity, hy.LOW)
		self.assertEqual(rows[('help.example.com:443', 'tls_legacy_protocol')].severity, hy.LOW)
		self.assertEqual(rows[('app.example.com:443', 'tls_hostname_mismatch')].severity, hy.INFO)
		for row in rows.values():
			self.assertEqual(row.evidence['tags'], ['vendor-managed'])
			self.assertIn(heat_of(row.severity), ('ice', 'clean'))
		self.assertEqual(rows[('help.example.com:443', 'tls_legacy_protocol')].evidence['vendor'], 'Zendesk')
		self.assertEqual(set(HostLabel.objects.filter(project=self.project, label='vendor-managed').values_list('host', flat=True)),
						 {'help.example.com', 'app.example.com'})

	def test_the_vendor_list_is_data(self):
		for vendor in ('Zendesk', 'Squarespace', 'Microsoft', 'Palantir', 'Listrak', 'GoDaddy Payments', 'Azure VPN gateway', 'Railway'):
			self.assertIn(vendor, [v for v, _ in hr.platforms()['platforms']])
		self.assertEqual(hr.vendor_of('azuregateway-0000.vpn.azure.com'), 'Azure VPN gateway')
		self.assertEqual(hr.vendor_of('notzendesk.com'), '')  # suffixes match on a label boundary


# ----------------------------------------------------------------------------- item 7: private CA, BREACH, certificates

class PrivateCaTests(Base):
	def test_an_expected_private_ca_rates_the_chain_info(self):
		found = hy.evaluate_cert(cert('cam.example.com', chain_error='unable to get local issuer certificate'), now=NOW)
		found += hy.evaluate_cert(cert('nvr.example.com', chain_error='self-signed certificate'), now=NOW)
		self.assertEqual({f.severity for f in hr.rate(self.domain, [*found], cnames={})}, {hy.MEDIUM})  # not expected: medium (smoke)
		self.domain.expect_private_ca = True
		self.domain.save(update_fields=['expect_private_ca'])
		found = hy.evaluate_cert(cert('cam.example.com', chain_error='unable to get local issuer certificate'), now=NOW)
		found += hy.evaluate_cert(cert('nvr.example.com', chain_error='self-signed certificate'), now=NOW)
		rows = self.store(found)
		self.assertEqual({(k[1], r.severity, r.evidence['expected_private_ca']) for k, r in rows.items()},
						 {('tls_untrusted_chain', hy.INFO, True), ('tls_self_signed', hy.INFO, True)})

	def test_the_setting_is_on_the_target_through_rest_and_mcp(self):
		user = User.objects.create_user('u', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, token = create_token(user, 't')
		self.assertFalse(Domain.objects.get(pk=self.domain.pk).expect_private_ca)  # the database default
		status, data = call(token, 'POST', f'/api/v1/projects/r/targets/{self.domain.id}/private-ca', {'expect_private_ca': True})
		self.assertEqual((status, data['expect_private_ca']), (200, True))
		self.assertTrue(Domain.objects.get(pk=self.domain.pk).expect_private_ca)
		error, data = tool(token, 'set_target_private_ca', {'project': 'r', 'target_id': self.domain.id, 'expect_private_ca': False})
		self.assertFalse(error)
		self.assertFalse(data['expect_private_ca'])
		status, _ = call(token, 'POST', f'/api/v1/projects/r/targets/{self.domain.id}/private-ca', {'expect_private_ca': 'maybe'})
		self.assertEqual(status, 400)


class BreachTests(Base):
	ITEM = {'id': 'BREACH', 'severity': 'MEDIUM', 'cve': 'CVE-2013-3587',
			'finding': "potentially VULNERABLE, gzip HTTP compression detected - only supplied '/' tested"}

	def breach(self, host):
		where = f'{host}:443'
		tls_audit.store(self.domain, host, 443, tls_audit.evaluate([self.ITEM], where), where)
		return HygieneFinding.objects.get(host=where, check_name='tlsa_breach')

	def route(self, host, state='open', cookies=()):
		RouteAuth.objects.create(project=self.project, domain=self.domain, host=host, url=f'https://{host}/', path='/', auth_state=state,
								 evidence={'cookies': list(cookies)})

	def test_breach_without_a_session_is_ice(self):
		"""A static site (no session or auth cookie, no sign-in page): compression leaks nothing secret."""
		self.route('www.example.com', cookies=['__cf_bm', '_ga'])
		row = self.breach('www.example.com')
		self.assertEqual((row.severity, heat_of(row.severity)), (hy.LOW, 'ice'))
		self.assertEqual(row.evidence['session_context'], {'authenticated': [], 'session_cookies': []})

	def test_breach_with_a_session_cookie_or_a_signed_in_page_stays_smoke(self):
		self.route('portal.example.com', cookies=['PHPSESSID'])
		self.route('login.example.com', state='login')
		for host in ('portal.example.com', 'login.example.com'):
			row = self.breach(host)
			self.assertEqual((row.severity, heat_of(row.severity)), (hy.MEDIUM, 'smoke'), host)


class CertificateExpiryTests(Base):
	def expiring(self, host, days, **kw):
		return hy.evaluate_cert(cert(host, not_after=NOW + datetime.timedelta(days=days, hours=1), **kw), now=NOW)

	def test_a_managed_auto_renewing_certificate_with_a_week_left_is_ice(self):
		cnames = {'site.example.com': ['example-site.netlify.app']}
		self.assertEqual([(f.check, f.severity) for f in self.expiring('site.example.com', 20)], [('tls_expiring', hy.MEDIUM)])
		self.assertEqual([f.severity for f in hr.rate(self.domain, self.expiring('site.example.com', 20), cnames=cnames)], [hy.LOW])
		self.assertEqual([f.severity for f in hr.rate(self.domain, self.expiring('acm.example.com', 20, issuer='Amazon'), cnames={})], [hy.LOW])
		# under a week the platform's renewal may be stuck: still high
		self.assertEqual([f.severity for f in hr.rate(self.domain, self.expiring('site.example.com', 3), cnames=cnames)], [hy.HIGH])
		# a self-managed certificate keeps its band
		self.assertEqual([f.severity for f in hr.rate(self.domain, self.expiring('www.example.com', 20), cnames={})], [hy.MEDIUM])

	def test_an_expired_certificate_on_a_dev_host_is_smoke_not_fire(self):
		dev = hr.rate(self.domain, self.expiring('api-dev.example.com', -10), cnames={})
		self.assertEqual([(f.check, f.severity, heat_of(f.severity)) for f in dev], [('tls_expired', hy.MEDIUM, 'smoke')])
		self.assertEqual([f.severity for f in hr.rate(self.domain, self.expiring('uat.example.com', -10), cnames={})], [hy.MEDIUM])
		prod = hr.rate(self.domain, self.expiring('shop.example.com', -10), cnames={})
		self.assertEqual([(f.severity, heat_of(f.severity)) for f in prod], [(hy.CRITICAL, 'fire')])
		self.assertFalse(hr.is_dev_host('developer.example.com'))


class DmarcReportAuthorizationTests(SimpleTestCase):
	def test_a_report_authorisation_gap_under_an_enforcing_policy_is_info(self):
		for policy, severity in (('reject', hy.INFO), ('quarantine', hy.INFO), ('none', hy.MEDIUM), ('', hy.MEDIUM)):
			found = mf.evaluate_report_authorization('example.com', 'reports.example.net', [], policy)
			self.assertEqual([(f.check, f.severity) for f in found], [('dmarc_report_unauthorized', severity)], policy)


# ----------------------------------------------------------------------------- item 19: two resolvers or two runs

def asker(zone, failing=()):
	"""A resolver over ``zone`` ({name: [records]}): a name in ``failing`` times out, a missing name is NXDOMAIN."""
	def ask(name):
		if name in failing or '*' in failing:
			return {'result': 'error', 'records': [], 'error': 'Timeout'}
		if name not in zone:
			return {'result': 'nxdomain', 'records': []}
		return {'result': 'answer', 'records': list(zone[name])}
	return ask


class FakeResolver:
	"""A dnspython resolver over ``zone``: a missing name is NXDOMAIN. ``asked`` lists the TXT names it was sent."""

	def __init__(self, zone):
		self.zone, self.asked, self.nameservers = zone, [], []

	def resolve(self, name, rtype):
		self.asked.append(name)
		if name not in self.zone:
			raise dns.resolver.NXDOMAIN()

		class Rdata:
			def __init__(self, text):
				self.strings = [text.encode()]
		return [Rdata(t) for t in self.zone[name]]


def os_environ_without(key):
	import os
	os.environ.pop(key, None)


class DnsConsensusTests(Base):
	ZONE = {'example.com': ['v=spf1 include:_spf.example.net -all'], '_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com']}

	def emailer(self, askers, zone=None):
		zone = self.ZONE if zone is None else zone
		return functools.partial(hygiene_harness.email_findings, fetch=lambda n: zone.get(n, []), mx=lambda n, t: t == 'MX', askers=askers)

	def sweep(self, emailer):
		hygiene_harness.run_hygiene(self.domain.id, probe=lambda host, port: None, emailer=emailer, mx=lambda n, t: False)
		return {r.check_name: r for r in HygieneFinding.objects.filter(domain=self.domain, check_name__in=hy.ABSENCE_CHECKS)}

	def test_a_one_off_failure_never_opens_a_finding(self):
		"""Fixture shape: the apex DMARC record recorded missing once, no evidence, while it was published all along."""
		flaky = [('system', asker(self.ZONE, failing=['_dmarc.example.com'])), ('192.0.2.53', asker(self.ZONE, failing=['*']))]
		rows = self.sweep(self.emailer(flaky))
		row = rows['dmarc_missing']
		self.assertEqual(row.status, hy.PENDING)  # stored with its evidence, not opened
		self.assertEqual(row.evidence['dns_confirmed'], False)
		self.assertEqual([o['result'] for o in row.evidence['dns']], ['error', 'error'])
		self.assertEqual(HygieneFinding.objects.filter(domain=self.domain, status='open', check_name='dmarc_missing').count(), 0)
		# the next run reads the record: the pending observation is resolved, never opened
		rows = self.sweep(self.emailer([('system', asker(self.ZONE)), ('192.0.2.53', asker(self.ZONE))]))
		self.assertEqual(rows['dmarc_missing'].status, 'resolved')

	def test_one_resolver_missing_the_record_is_outvoted_by_one_that_has_it(self):
		stale = dict(self.ZONE)
		del stale['_dmarc.example.com']
		findings, _ = hygiene_harness.email_findings('example.com', fetch=lambda n: self.ZONE.get(n, []), mx=lambda n, t: t == 'MX',
										askers=[('system', asker(stale)), ('192.0.2.53', asker(self.ZONE))])
		self.assertNotIn('dmarc_missing', checks(findings))

	def test_two_resolvers_agreeing_open_the_finding_at_once(self):
		zone = {'example.com': ['v=spf1 -all']}
		rows = self.sweep(self.emailer([('system', asker(zone)), ('192.0.2.53', asker(zone))], zone=zone))
		row = rows['dmarc_missing']
		self.assertEqual((row.status, row.evidence['dns_confirmed']), ('open', True))
		self.assertEqual([o['resolver'] for o in row.evidence['dns']], ['system', '192.0.2.53'])

	def test_two_consecutive_observations_open_it_when_resolvers_cannot_agree(self):
		zone = {'example.com': ['v=spf1 -all']}
		lonely = [('system', asker(zone)), ('192.0.2.53', asker(zone, failing=['*']))]
		self.assertEqual(self.sweep(self.emailer(lonely, zone=zone))['dmarc_missing'].status, hy.PENDING)
		row = self.sweep(self.emailer(lonely, zone=zone))['dmarc_missing']
		self.assertEqual((row.status, row.evidence['confirmed_by']), ('open', 'seen again on the next run'))

	def test_a_fixed_record_that_goes_missing_twice_reopens(self):
		zone = {'example.com': ['v=spf1 -all']}
		lonely = [('system', asker(zone)), ('192.0.2.53', asker(zone, failing=['*']))]
		HygieneFinding.objects.create(domain=self.domain, host='example.com', check_name='dmarc_missing', severity=hy.HIGH, title='No DMARC',
									  status='resolved', remediation_status='fixed')
		self.assertEqual(self.sweep(self.emailer(lonely, zone=zone))['dmarc_missing'].status, hy.PENDING)
		row = self.sweep(self.emailer(lonely, zone=zone))['dmarc_missing']
		self.assertEqual((row.status, row.remediation_status), ('open', 'open'))


	def real_dns_emailer(self, zone):
		"""the scanner library's email_findings with the resolvers its ``dns_askers`` builds (the installation's setting), over fake DNS objects."""
		return lambda name: hygiene_harness.email_findings(name, fetch=lambda n: zone.get(n, []), mx=lambda n, t: t == 'MX', askers=hygiene_harness.scanner_hygiene.dns_askers(hy.confirm_resolvers()))

	def test_by_default_no_third_party_resolver_is_asked_and_a_missing_record_needs_two_runs(self):
		zone = {'example.com': ['v=spf1 -all']}
		system = FakeResolver(zone)
		with mock.patch.dict('os.environ', {}), mock.patch.object(hygiene_harness.scanner_hygiene, '_resolver', return_value=system), \
				mock.patch('dns.resolver.Resolver', side_effect=AssertionError('no extra resolver may be built')) as extra:
			os_environ_without('CVENGINE_HYGIENE_CONFIRM_RESOLVERS')
			self.assertEqual(hy.confirm_resolvers(), ())
			self.assertEqual([label for label, _ in hygiene_harness.scanner_hygiene.dns_askers(hy.confirm_resolvers())], ['system'])
			row = self.sweep(self.real_dns_emailer(zone))['dmarc_missing']
			self.assertEqual((row.status, [o['resolver'] for o in row.evidence['dns']]), (hy.PENDING, ['system']))
			row = self.sweep(self.real_dns_emailer(zone))['dmarc_missing']
			self.assertEqual((row.status, row.evidence['confirmed_by']), ('open', 'seen again on the next run'))
		extra.assert_not_called()  # no client name was sent to any resolver but the system's
		self.assertEqual(set(system.asked), {'example.com', '_dmarc.example.com'})

	def test_configured_resolvers_confirm_an_absence_in_one_run(self):
		zone = {'example.com': ['v=spf1 -all']}
		system, built = FakeResolver(zone), []

		def build(configure=True):
			built.append(FakeResolver(zone))
			return built[-1]
		with mock.patch.dict('os.environ', {'CVENGINE_HYGIENE_CONFIRM_RESOLVERS': '192.0.2.53,198.51.100.53'}), \
				mock.patch.object(hygiene_harness.scanner_hygiene, '_resolver', return_value=system), mock.patch('dns.resolver.Resolver', side_effect=build):
			row = self.sweep(self.real_dns_emailer(zone))['dmarc_missing']
		self.assertEqual((row.status, row.evidence['dns_confirmed']), ('open', True))
		self.assertEqual([o['resolver'] for o in row.evidence['dns']], ['system', '192.0.2.53'])
		self.assertEqual(built[0].nameservers, ['192.0.2.53'])
		self.assertEqual(built[0].asked, ['_dmarc.example.com'])  # only the name whose record seemed missing
		self.assertEqual(built[1].asked, [])  # two votes were enough

	def test_the_confirming_resolvers_are_configurable(self):
		with mock.patch.dict('os.environ', {'CVENGINE_HYGIENE_CONFIRM_RESOLVERS': ''}):
			self.assertEqual(hy.confirm_resolvers(), ())
		with mock.patch.dict('os.environ', {'CVENGINE_HYGIENE_CONFIRM_RESOLVERS': '192.0.2.53, 198.51.100.53'}):
			self.assertEqual([label for label, _ in hygiene_harness.scanner_hygiene.dns_askers(hy.confirm_resolvers())], ['system', '192.0.2.53', '198.51.100.53'])


# ----------------------------------------------------------------------------- item 20: organizational domain, sp=, CNAMEs, one row

class OrganizationalDomainTests(Base):
	def findings(self, name, zone, askers=None):
		return hygiene_harness.email_findings(name, fetch=lambda n: zone.get(n, []), mx=lambda n, t: t == 'MX', askers=askers)[0]

	def test_a_subdomain_covered_by_the_parents_policy_has_no_dmarc_finding(self):
		"""Fixture shape: a mail subdomain with no record of its own under a parent p=quarantine; sp=quarantine."""
		zone = {'_dmarc.example.com': ['v=DMARC1;p=quarantine;sp=quarantine;pct=100;rua=mailto:d@example.com'],
				'gh-mail.example.com': ['v=spf1 include:_spf.example.net -all']}
		self.assertEqual({c for c in checks(self.findings('gh-mail.example.com', zone)) if c.startswith('dmarc')}, set())

	def test_missing_spf_on_a_subdomain_under_an_enforcing_parent_is_info(self):
		"""Fixture shape: a subdomain target with no SPF of its own under a parent p=reject (medium before)."""
		zone = {'_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com']}
		spf = by_check(self.findings('events.example.com', zone))['spf_missing']
		self.assertEqual((spf.severity, spf.evidence['dmarc_policy']), (hy.INFO, 'reject'))
		zone['_dmarc.example.com'] = ['v=DMARC1; p=reject; sp=none']  # the parent's sp= decides for its subdomains
		self.assertEqual(by_check(self.findings('events.example.com', zone))['spf_missing'].severity, hy.MEDIUM)
		self.assertEqual(by_check(self.findings('example.com', {'_dmarc.example.com': ['v=DMARC1; p=reject']}))['spf_missing'].severity,
						 hy.MEDIUM)  # the organizational domain itself is not a subdomain

	def test_spf_is_read_through_a_cname(self):
		"""Fixture shape: help.<client> CNAME to the help-desk vendor's mail host, whose SPF record answers the TXT lookup."""
		zone = {'_dmarc.example.com': ['v=DMARC1; p=none']}
		via_cname = {'help.example.com': ['v=spf1 include:_netblocks.example.net ~all']}
		def system(name):  # the resolver followed the CNAME: the answer is the vendor host's TXT
			if name in via_cname:
				return {'result': 'answer', 'records': via_cname[name], 'cname': 'mail3.example.net'}
			return asker(zone)(name)
		found = self.findings('help.example.com', zone, askers=[('system', system), ('192.0.2.53', asker(zone))])
		self.assertNotIn('spf_missing', checks(found))
		self.assertIn('spf_softfail', checks(found))

	def test_the_names_a_parent_finding_shows_do_not_depend_on_the_order_they_were_found_in(self):
		from cveFeed.hygiene import Finding, merge_findings
		names = [f'm{i}.example.com' for i in range(20)]
		def run(order):
			found = [Finding('dmarc_none', 2, 'DMARC policy none', 'p=none', 'example.com', {'inherited_from': 'example.com', 'covers': [n]}) for n in order]
			return merge_findings(found)[0]
		forward, backward = run(names), run(list(reversed(names)))
		self.assertEqual(forward.detail, backward.detail)
		self.assertEqual(forward.evidence['covers'], backward.evidence['covers'])
		self.assertIn('m0.example.com', forward.detail)

	def test_a_p_none_parent_is_one_finding_not_one_per_subdomain(self):
		zone = {'_dmarc.example.com': ['v=DMARC1; p=none; rua=mailto:d@example.com'], 'example.com': ['v=spf1 -all']}
		names = [f'm{i}.example.com' for i in range(20)]
		for name in names:
			self.host(name)
			zone[name] = ['v=spf1 -all']
		emailer = functools.partial(hygiene_harness.email_findings, fetch=lambda n: zone.get(n, []), mx=lambda n, t: t == 'MX')
		hygiene_harness.run_hygiene(self.domain.id, probe=lambda host, port: None, emailer=emailer, mx=lambda n, t: t == 'MX')
		rows = HygieneFinding.objects.filter(domain=self.domain, status='open', check_name='dmarc_none')
		self.assertEqual([r.host for r in rows], ['example.com'])
		self.assertEqual(sorted(rows[0].evidence['covers']), sorted(names))
		self.assertIn('m0.example.com', rows[0].detail)
		self.assertEqual(HygieneFinding.objects.filter(domain=self.domain, check_name='dmarc_missing').count(), 0)


# ----------------------------------------------------------------------------- the backfill

class RerateCommandTests(Base):
	def test_dry_run_counts_and_apply_writes(self):
		self.host('help.example.com', 'example.zendesk.com')
		self.host('msoid.example.com', 'clientconfig.microsoftonline-p.net')
		lowered = HygieneFinding.objects.create(domain=self.domain, host='help.example.com:443', check_name='tlsa_cipherlist_3des_idea',
												severity=hy.HIGH, title='help.example.com:443 offers 3DES or IDEA ciphers')
		dropped = HygieneFinding.objects.create(domain=self.domain, host='msoid.example.com:443', check_name='tlsa_breach', severity=hy.MEDIUM,
												title='BREACH may apply')
		kept = HygieneFinding.objects.create(domain=self.domain, host='example.com', check_name='dmarc_none', severity=hy.MEDIUM, title='p=none',
											 remediation_status='false_positive')
		out = StringIO()
		call_command('rerate_hygiene', stdout=out)
		self.assertIn('r: 3 open; Would lower 1, Would resolve 1 (fire->ice: 1, smoke->resolved: 1)', out.getvalue())
		for row in (lowered, dropped, kept):
			before = (row.severity, row.status)
			row.refresh_from_db()
			self.assertEqual((row.severity, row.status), before)  # a dry run writes nothing
		call_command('rerate_hygiene', '--apply', stdout=StringIO())
		lowered.refresh_from_db()
		dropped.refresh_from_db()
		kept.refresh_from_db()
		self.assertEqual((lowered.severity, lowered.evidence['tags']), (hy.LOW, ['vendor-managed']))
		self.assertEqual(dropped.status, 'resolved')
		self.assertEqual((kept.severity, kept.status, kept.remediation_status), (hy.MEDIUM, 'open', 'false_positive'))
