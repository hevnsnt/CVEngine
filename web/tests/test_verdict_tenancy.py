"""A closing verdict reached on one tenant's host never closes another tenant's finding (task 256).

Two tables hold answers shared by every host with the same evidence: ``MatchVerdict`` (keyed by CVE, matched product, version, range result and
source: correlation seeds a new CVE match from it) and ``TriageVerdict`` (keyed by kind and evidence signature: triage reuses it instead of asking
the AI again). Neither has a tenant. What one tenant's host says (a banner, a port's product, a CPE, a page title, a script) can lead to a closing
answer on that host: an automatic identity closure (the sighting no longer names the advisory's product), or an AI answer to the host's text. Before
the fix that answer was stored in the shared tables and handed to another organization's new finding with the same key, which started closed.

The rule these tests hold: a shared answer may raise attention on another host (affected, needs validation) but never close or downgrade a
finding there; an answer that closes is reused only for the tenant (and, where the prompt showed host text the signature does not carry, the host)
it was reached on; and even then it never closes a finding a person or hard evidence stands behind.
"""
import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, match_policy, triage
from cveFeed.models import CVEEntry, CVEMatch, MatchVerdict, RouteAuth, Triage, TriageVerdict
from cveFeed.tasks import correlate_cves, reconcile_invalid_correlations
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology, Vulnerability
from targetApp.models import Domain

CLOSING = ('likely_false_positive', 'not_applicable')
JENKINS_KEV = [{'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': []}]  # a KEV record with no version bound: "version unknown"
LIBRARY_REASON = ("Closed automatically: this JavaScript library version is not on the host's own page (the page loads another version).")


def answer(classification, reason='the model said so'):
	return json.dumps({'classification': classification, 'reason': reason, 'impact': '', 'severity_adjust': 0, 'severity_reason': '',
					   'remediation': '', 'validation_steps': []})


class Tenant:
	"""One organization with one project, one domain, one scan and one host with one address."""

	def __init__(self, slug, engine):
		self.org = Org.objects.create(name=slug, slug=slug)
		self.project = Project.objects.create(name=slug, slug=f'{slug}-p', insert_date=timezone.now(), org=self.org)
		self.domain = Domain.objects.create(name=f'{slug}.test', project=self.project, insert_date=timezone.now())
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		self.sub = self.host(f'www.{slug}.test')

	def host(self, name, ip=None):
		sub = Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=self.scan)
		address = IpAddress.objects.create(address=ip or f'192.0.2.{Subdomain.objects.count() + 10}')
		sub.ip_addresses.add(address)
		return sub

	def port(self, product, version='', number=8080, cpe='', sub=None):
		port = Port.objects.create(number=number, product=product, version=version, cpe=cpe)
		(sub or self.sub).ip_addresses.first().ports.add(port)
		return port

	def tech(self, name, sub=None):
		tech = Technology.objects.create(name=name)
		(sub or self.sub).technologies.add(tech)
		return tech


class TenancyFixture(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.a = Tenant('attacker', engine)  # the organization whose host the attacker controls (a bug bounty target, a lab, a customer)
		self.b = Tenant('victim', engine)  # another organization on the same instance

	def cve(self, cve_id='CVE-2024-23897', affected=None, kev=True, cvss=9.8):
		return CVEEntry.objects.create(cve_id=cve_id, kev=kev, cvss=cvss, published_at=timezone.now(), title='flaw',
									   affected=affected if affected is not None else JENKINS_KEV)

	def correlate(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		return correlate_cves()

	def match_of(self, tenant, cve=None):
		qs = CVEMatch.objects.filter(subdomain__target_domain=tenant.domain)
		return (qs.filter(cve_entry=cve) if cve else qs).get()

	def provider(self, text):
		p = mock.Mock(model='m')
		p.name = 'anthropic'
		p.complete.return_value = text
		return p

	def triage(self, findings, provider=None):
		return triage.run_triage(triage.track(findings), provider=provider)

	def assertOpen(self, match, label=''):
		match.refresh_from_db()
		self.assertNotEqual(match.ai_verdict, 'not_affected', label)
		row = Triage.objects.filter(match=match).first()
		if row is not None:
			self.assertNotIn(row.classification, CLOSING, label)


@mock.patch('cveFeed.activity.log', return_value=None)
class IdentityClosureTests(TenancyFixture):
	"""The automatic identity closure reads the host's current sighting (the port's product as nmap stores it in place), so a banner the
	attacker changes closes the attacker's own match. That closure is about one sighting on one host."""

	def poisoned(self):
		cve = self.cve()
		port = self.a.port('Jenkins', '2.426.2')
		self.correlate()
		mine = self.match_of(self.a)
		self.assertEqual((mine.matched_product, mine.version_in_range, mine.evidence.get('unbounded')), ('Jenkins', None, True))
		Port.objects.filter(pk=port.pk).update(product='Acme portal')  # the next banner names another product: nmap updates the row
		reconcile_invalid_correlations(limit=100)
		mine.refresh_from_db()
		self.assertEqual(mine.ai_verdict, 'not_affected')  # the attacker's own candidate closes: that part is right
		self.assertTrue(mine.ai_reason.startswith(correlation.DIFFERENT_PRODUCT))
		return cve

	def test_an_identity_closure_on_one_tenant_is_not_seeded_onto_another_tenants_new_match(self, _log):
		cve = self.poisoned()
		self.b.port('Jenkins', '2.426.2')  # the victim really runs the exposed Jenkins
		self.correlate()
		victim = self.match_of(self.b, cve)
		self.assertEqual((victim.matched_product, victim.matched_version, victim.version_in_range), ('Jenkins', '2.426.2', None))
		self.assertOpen(victim, 'seeded at correlation')

	def test_nor_handed_to_the_other_tenants_triage_as_a_stored_answer(self, _log):
		cve = self.poisoned()
		self.b.port('Jenkins', '2.426.2')
		self.correlate()
		victim = self.match_of(self.b, cve)
		CVEMatch.objects.filter(pk=victim.pk).update(ai_verdict='', ai_reason='', ai_model='')  # whatever correlation did, triage alone
		self.triage(triage.with_cves([victim]))
		self.assertOpen(victim, 'reused by triage')
		self.assertEqual(Triage.objects.get(match=victim).classification, 'needs_validation')

	def test_the_closure_writes_nothing_another_host_can_reuse(self, _log):
		self.poisoned()
		self.assertFalse(MatchVerdict.objects.filter(ai_verdict='not_affected').exists())
		self.assertFalse(TriageVerdict.objects.filter(classification__in=CLOSING).exists())

	def test_a_replayed_closure_is_still_not_seeded(self, _log):
		self.poisoned()
		self.b.port('Jenkins', '2.426.2')
		self.correlate()
		for n in range(2):  # the attacker repeats it from more hosts, after the victim's match exists and before its next host appears
			sub = self.a.host(f'r{n}.attacker.test')
			port = self.a.port('Jenkins', '2.426.2', sub=sub)
			self.correlate()
			Port.objects.filter(pk=port.pk).update(product='Acme portal')
			reconcile_invalid_correlations(limit=100)
			self.assertEqual(CVEMatch.objects.get(subdomain=sub).ai_verdict, 'not_affected')
		self.b.port('Jenkins', '2.426.2', sub=self.b.host('two.victim.test'))
		self.correlate()
		for victim in CVEMatch.objects.filter(subdomain__target_domain=self.b.domain):
			self.assertOpen(victim, victim.subdomain.name)

	def test_an_os_fingerprint_closure_is_not_seeded_either(self, _log):
		cve = self.cve('CVE-2099-501', [{'product': 'Widget Server', 'ranges': [{'introduced': '5.0', 'fixed': '5.9'}]}], kev=False)
		port = self.a.port('Widget Server', '4.2')
		mine = CVEMatch.objects.create(cve_entry=cve, subdomain=self.a.sub, source='port', matched_product='Widget Server', matched_version='4.2',
									   version_in_range=None, confidence=0.5,
									   evidence={'source': 'port', 'source_id': port.pk, 'branch_unlisted': True})
		Port.objects.filter(pk=port.pk).update(product='server', cpe='cpe:/o:linux:linux_kernel:5.15')  # the CPE now names an OS
		self.assertTrue(correlation.close_invalid_correlation(mine))
		correlation.save_matches([{
			'cve_entry_id': cve.pk, 'subdomain_id': self.b.sub.pk, 'source': 'port', 'matched_product': 'Widget Server', 'matched_version': '4.2',
			'version_in_range': None, 'confidence': 0.5, 'scan_history_id': self.b.scan.pk, 'distro_status': 'no_data', 'distro_fixed_version': '',
			'evidence': {'source': 'port', 'branch_unlisted': True}}])
		self.assertOpen(self.match_of(self.b, cve))


@mock.patch('cveFeed.activity.log', return_value=None)
class StoredSeedTests(TenancyFixture):
	"""Rows already in the shared table (written before the fix, by any path) never seed a closure onto a new or moved match."""

	def row(self, tenant, cve, version='2.426.2', in_range=None, **extra):
		return {'cve_entry_id': cve.pk, 'subdomain_id': tenant.sub.pk, 'source': 'tech', 'matched_product': 'Jenkins', 'matched_version': version,
				'version_in_range': in_range, 'confidence': 0.5, 'scan_history_id': tenant.scan.pk, 'distro_status': extra.pop('distro', 'no_data'),
				'distro_fixed_version': '', 'evidence': {'source': 'tech', **extra}}

	def stored(self, cve, verdict='not_affected', reason=correlation.DIFFERENT_PRODUCT + '; it was recorded as "x".', version='2.426.2',
			   in_range=None, model='deterministic-correlation'):
		return MatchVerdict.objects.create(cve_entry=cve, matched_product='Jenkins', matched_version=version, version_in_range=in_range,
										   source='tech', ai_verdict=verdict, ai_reason=reason, ai_model=model)

	def test_no_stored_closing_reason_seeds_a_new_match(self, _log):
		cve = self.cve()
		reasons = {'identity': correlation.DIFFERENT_PRODUCT + '; it was recorded as "x".',
				   'old identity wording': 'Closed automatically: invalid product correlation; x',
				   'os fingerprint': match_policy.REASON_OS, 'local only': 'Closed automatically: local-only vulnerability. x',
				   'library': LIBRARY_REASON, 'ai': 'The page says it is a honeypot.'}
		for label, reason in reasons.items():
			for in_range, extra in ((None, {'branch_unlisted': True}), (None, {'unbounded': True}), (False, {}), (True, {'distro': 'patched'})):
				CVEMatch.objects.all().delete()
				MatchVerdict.objects.all().delete()
				self.stored(cve, reason=reason, in_range=in_range)
				correlation.save_matches([self.row(self.b, cve, in_range=in_range, **extra)])
				self.assertNotEqual(self.match_of(self.b).ai_verdict, 'not_affected', (label, in_range, extra))

	def test_a_moved_match_is_not_seeded_closed_either(self, _log):
		cve = self.cve()
		correlation.save_matches([self.row(self.b, cve, version='2.426.1', in_range=False)])
		self.stored(cve, reason='The model said so.', in_range=False, model='a-model')
		correlation.save_matches([self.row(self.b, cve, version='2.426.2', in_range=False)])  # the version moved onto the stored signature
		match = self.match_of(self.b)
		self.assertEqual(match.matched_version, '2.426.2')
		self.assertNotEqual(match.ai_verdict, 'not_affected')

	def test_a_verdict_that_raises_attention_is_still_shared(self, _log):
		cve = self.cve()
		self.stored(cve, verdict='affected', reason='a check confirmed it', in_range=True, model='a-model')
		correlation.save_matches([self.row(self.b, cve, in_range=True, distro='vulnerable')])
		self.assertEqual(self.match_of(self.b).ai_verdict, 'affected')

	def test_an_uncertain_verdict_is_not_seeded_onto_a_match_with_hard_evidence(self, _log):
		# "uncertain" keeps a fire match with hard evidence other than a template hit or a tracker listing out of the fire page
		# (notify.fire_matches): from another tenant's answer that is a downgrade, so the match's own triage decides
		cve = self.cve()
		self.stored(cve, verdict='uncertain', reason='the page says it is a test system', in_range=True, model='a-model')
		correlation.save_matches([self.row(self.b, cve, in_range=True, runzero={'id': 'r1'})])
		self.assertEqual(self.match_of(self.b).ai_verdict, '')
		CVEMatch.objects.all().delete()
		correlation.save_matches([self.row(self.b, cve, in_range=True)])  # version-only: uncertain is its ceiling anyway, still shared
		self.assertEqual(self.match_of(self.b).ai_verdict, 'uncertain')

	def test_another_products_verdict_for_the_same_version_string_is_never_used(self, _log):
		cve = self.cve()
		MatchVerdict.objects.create(cve_entry=cve, matched_product='Jenkins Lookalike', matched_version='2.426.2', version_in_range=True,
									source='tech', ai_verdict='affected', ai_reason='x', ai_model='m')
		correlation.save_matches([self.row(self.b, cve, in_range=True, distro='vulnerable')])
		self.assertEqual(self.match_of(self.b).ai_verdict, '')


@mock.patch('cveFeed.activity.log', return_value=None)
class AiAnswerTests(TenancyFixture):
	"""An AI answer is about the text the model was shown. For a CVE match that text is in the signature, but the signature is the same on
	any host that shows the same text, and for the other kinds the prompt carries host text (a title, a path, a response) the signature does
	not: one tenant's crafted page can make the model close the question for every tenant."""

	def route(self, tenant, title):
		return RouteAuth.objects.create(project=tenant.project, domain=tenant.domain, host=tenant.sub.name, url=f'https://{tenant.sub.name}/backup/',
										path='/backup/', auth_state='open', http_status=200, title=title, sensitive_score=10)

	def test_an_ai_closure_of_one_tenants_route_does_not_close_another_tenants(self, _log):
		crafted = self.route(self.a, 'Decoy page for a scanner demo, nothing here is real')
		real = self.route(self.b, 'Index of /backup')
		self.assertEqual(triage.describe(crafted)['signature'], triage.describe(real)['signature'])  # the title is not in the key
		self.triage([crafted], provider=self.provider(answer('likely_false_positive')))
		self.assertEqual(Triage.objects.get(route=crafted).classification, 'likely_false_positive')  # the attacker's own row
		provider = self.provider(answer('likely'))
		self.triage([real], provider=provider)
		self.assertNotIn(Triage.objects.get(route=real).classification, CLOSING)

	def test_one_run_over_both_tenants_does_not_close_the_other_with_the_first_ones_answer(self, _log):
		crafted = self.route(self.a, 'Decoy page')
		real = self.route(self.b, 'Index of /backup')
		self.triage([crafted, real], provider=self.provider(answer('not_applicable')))  # the instance-wide sweep groups both
		self.assertNotIn(Triage.objects.get(route=real).classification, CLOSING)

	def test_a_scanner_finding_answer_does_not_cross_tenants(self, _log):
		made = []
		for tenant, body in ((self.a, 'HTTP/1.1 404 Not Found'), (self.b, 'HTTP/1.1 200 OK')):
			made.append(Vulnerability.objects.create(target_domain=tenant.domain, subdomain=tenant.sub, source='nuclei', name='Debug page', severity=1,
													 template_id='debug-page', http_url=f'https://{tenant.sub.name}/debug', response=body,
													 discovered_date=timezone.now()))
		self.triage(triage.vulnerabilities(Vulnerability.objects.filter(pk=made[0].pk)), provider=self.provider(answer('not_applicable')))
		self.triage(triage.vulnerabilities(Vulnerability.objects.filter(pk=made[1].pk)), provider=self.provider(answer('likely')))
		self.assertNotIn(Triage.objects.get(vulnerability=made[1]).classification, CLOSING)

	def cve_match(self, tenant, sub=None, **fields):
		cve = CVEEntry.objects.get_or_create(cve_id='CVE-2099-777', defaults=dict(
			kev=False, cvss=7.5, published_at=timezone.now(), title='flaw',
			affected=[{'product': 'Widget Server', 'ranges': [{'introduced': '5.0', 'fixed': '5.9'}]}]))[0]
		# in range on a distribution-patched package (the banner names the package release): no floor, so the model may close it
		fields.setdefault('version_in_range', True)
		fields.setdefault('distro_status', 'patched')
		return CVEMatch.objects.create(cve_entry=cve, subdomain=sub or tenant.sub, source='port', matched_product='Widget Server',
									   matched_version='5.2', confidence=0.2, evidence={'source': 'port', 'service_extra': 'Widget'}, **fields)

	def test_an_identical_cve_match_signature_on_another_tenant_is_not_closed_by_the_stored_answer(self, _log):
		# the attacker copies the victim's evidence byte for byte (product, version, banner): the signatures collide on purpose
		mine, theirs = self.cve_match(self.a), self.cve_match(self.b)
		pairs = triage.track(triage.with_cves([mine, theirs]))
		self.assertEqual(pairs[0][1]['signature'], pairs[1][1]['signature'])
		self.triage(triage.with_cves([mine]), provider=self.provider(answer('not_applicable')))
		mine.refresh_from_db()
		self.assertEqual(mine.ai_verdict, 'not_affected')
		self.triage(triage.with_cves([theirs]), provider=self.provider(answer('likely')))
		self.assertOpen(theirs)
		# and the shared correlation table holds nothing that closes a third tenant's new match
		self.assertFalse(MatchVerdict.objects.filter(ai_verdict='not_affected').exists())

	def test_the_same_tenant_still_reuses_its_own_answer_for_another_host(self, _log):
		mine = self.cve_match(self.a)
		other = self.cve_match(self.a, sub=self.a.host('two.attacker.test'))
		provider = self.provider(answer('not_applicable'))
		self.triage(triage.with_cves([mine]), provider=provider)
		self.triage(triage.with_cves([other]), provider=provider)
		self.assertEqual(provider.complete.call_count, 1)  # one question per evidence within the tenant, as before
		other.refresh_from_db()
		self.assertEqual((other.ai_verdict, Triage.objects.get(match=other).classification), ('not_affected', 'not_applicable'))

	def test_a_reused_closure_never_closes_a_match_a_person_stands_behind(self, _log):
		user = User.objects.create(username='owner')
		mine = self.cve_match(self.a)
		assigned = self.cve_match(self.a, sub=self.a.host('two.attacker.test'), assignee=user)
		worked = self.cve_match(self.a, sub=self.a.host('three.attacker.test'), remediation_status='in_progress')
		self.triage(triage.with_cves([mine]), provider=self.provider(answer('not_applicable')))
		self.triage(triage.with_cves([assigned, worked]), provider=self.provider(answer('likely')))
		for match in (assigned, worked):
			self.assertOpen(match)

	def test_a_stored_closing_answer_of_unknown_origin_is_not_reused(self, _log):
		theirs = self.cve_match(self.b)
		pairs = triage.track(triage.with_cves([theirs]))
		TriageVerdict.objects.create(kind='cve_match', signature=pairs[0][0].signature, classification='not_applicable',
									 reason='stored before the fix', model='a-model')  # no origin: written before tenancy was recorded
		self.triage(triage.with_cves([theirs]))
		self.assertOpen(theirs)
		self.assertEqual(Triage.objects.get(match=theirs).classification, 'needs_validation')

	def test_a_validation_result_on_one_tenant_stays_there(self, _log):
		mine, theirs = self.cve_match(self.a), self.cve_match(self.b)
		triage.track(triage.with_cves([mine, theirs]))
		Triage.objects.filter(match=mine).update(validation_status='miss', reason='no check matched')
		self.triage(triage.with_cves([mine]), provider=self.provider(answer('likely_false_positive')))
		self.triage(triage.with_cves([theirs]), provider=self.provider(answer('likely')))
		self.assertOpen(theirs)
		self.assertEqual(Triage.objects.get(match=theirs).validation_status, 'none')


	def test_a_reused_closure_never_closes_a_match_with_hard_evidence_on_another_host(self, _log):
		# runZero's report and the host's own inventory are hard evidence (match_policy.has_hard_evidence) that set no floor and are not in the
		# signature: the same project's answer for another host must not close them
		mine = self.cve_match(self.a)
		runzero = self.cve_match(self.a, sub=self.a.host('two.attacker.test'))
		reported = self.cve_match(self.a, sub=self.a.host('three.attacker.test'))
		CVEMatch.objects.filter(pk=runzero.pk).update(evidence={'source': 'port', 'service_extra': 'Widget', 'runzero': {'id': 'r1'}})
		CVEMatch.objects.filter(pk=reported.pk).update(evidence={'source': 'port', 'service_extra': 'Widget', 'host_reported': True})
		pairs = triage.track(triage.with_cves([mine, runzero, reported]))
		self.assertEqual(len({d['signature'] for _, d in pairs}), 1)
		self.triage(triage.with_cves([mine]), provider=self.provider(answer('not_applicable')))
		provider = self.provider(answer('likely'))
		self.triage(triage.with_cves([runzero, reported]), provider=provider)
		for match in (runzero, reported):
			self.assertOpen(match)
			self.assertEqual(Triage.objects.get(match=match).classification, 'needs_validation')

	def test_a_downgraded_severity_from_another_tenant_is_not_shown(self, _log):
		from agentapi import services
		crafted = self.route(self.a, 'Decoy')
		real = self.route(self.b, 'Index of /backup')
		again = RouteAuth.objects.create(project=self.a.project, domain=self.a.domain, host=self.a.sub.name, url=f'https://{self.a.sub.name}/backup/?x',
										 path='/backup/', auth_state='open', http_status=200, title='Decoy', sensitive_score=10)
		lowered = json.dumps({'classification': 'needs_validation', 'reason': 'r', 'impact': '', 'severity_adjust': -1,
							  'severity_reason': 'the page says it is a test system', 'remediation': '', 'validation_steps': []})
		self.triage([crafted], provider=self.provider(lowered))
		self.triage([real, again], provider=self.provider(answer('likely')))
		self.assertEqual(services._triage_brief(Triage.objects.get(route=crafted))['severity_adjust'], -1)  # where it was reached
		self.assertEqual(services._triage_brief(Triage.objects.get(route=real))['severity_adjust'], 0)  # never on another tenant's finding
		self.assertEqual(services._triage_brief(Triage.objects.get(route=again))['severity_adjust'], -1)  # the same host keeps it

@mock.patch('cveFeed.activity.log', return_value=None)
class SameHostReuseTests(TenancyFixture):
	"""What the fix keeps: a rescan of the same host starts from what that host's own finding earned (issue 206)."""

	def test_a_rescan_of_the_same_host_keeps_its_own_ai_closure(self, _log):
		cve = CVEEntry.objects.create(cve_id='CVE-2099-778', kev=False, cvss=7.5, published_at=timezone.now(), title='flaw',
									  affected=[{'product': 'Widget Server', 'ranges': [{'introduced': '5.0', 'fixed': '5.9'}]}])
		first = CVEMatch.objects.create(cve_entry=cve, subdomain=self.a.sub, source='port', matched_product='Widget Server', matched_version='5.2',
										version_in_range=True, distro_status='patched', confidence=0.2, evidence={'source': 'port'})
		self.triage(triage.with_cves([first]), provider=self.provider(answer('not_applicable')))
		first.refresh_from_db()
		self.assertEqual(first.ai_verdict, 'not_affected')
		scan = ScanHistory.objects.create(domain=self.a.domain, scan_type=self.a.scan.scan_type, scan_status=2, start_scan_date=timezone.now())
		again = Subdomain.objects.create(name=self.a.sub.name, target_domain=self.a.domain, scan_history=scan)
		correlation.save_matches([{
			'cve_entry_id': cve.pk, 'subdomain_id': again.pk, 'source': 'port', 'matched_product': 'Widget Server', 'matched_version': '5.2',
			'version_in_range': True, 'confidence': 0.2, 'scan_history_id': scan.pk, 'distro_status': 'patched', 'distro_fixed_version': '',
			'evidence': {'source': 'port'}}])
		new = CVEMatch.objects.get(subdomain=again)
		provider = self.provider(answer('likely'))
		self.triage(triage.with_cves([new]), provider=provider)
		new.refresh_from_db()
		self.assertEqual(provider.complete.call_count, 0)
		self.assertEqual((new.ai_verdict, Triage.objects.get(match=new).classification), ('not_affected', 'not_applicable'))


@mock.patch('cveFeed.activity.log', return_value=None)
class CleanupTests(TenancyFixture):
	"""What an earlier version already stored: the origin migration 0139 can prove, and the findings ``release_shared_closures`` reopens."""

	def closed_pair(self, origin=None, model='a-model', fresh=False, signature=None):
		"""The state before the fix: one stored closing answer held by a finding of each tenant, both matches closed by it."""
		matches = []
		for tenant in (self.a, self.b):
			sub = tenant.host(f'{Subdomain.objects.count()}.{tenant.domain.name}') if fresh else tenant.sub
			matches.append(CVEMatch.objects.create(
				cve_entry=CVEEntry.objects.get_or_create(cve_id='CVE-2099-779', defaults=dict(
					kev=False, cvss=7.5, published_at=timezone.now(), title='flaw',
					affected=[{'product': 'Widget Server', 'ranges': [{'introduced': '5.0', 'fixed': '5.9'}]}]))[0],
				subdomain=sub, source='port', matched_product='Widget Server', matched_version='5.2', version_in_range=True,
				distro_status='patched', confidence=0.2, evidence={'source': 'port'}))
		pairs = triage.track(triage.with_cves(matches))
		verdict = TriageVerdict.objects.create(kind='cve_match', signature=signature or pairs[0][0].signature, classification='not_applicable',
											   reason='the model said so', model=model, **(origin or {}))
		for row, _ in pairs:
			Triage.objects.filter(pk=row.pk).update(verdict=verdict, status='triaged', classification='not_applicable', reason='the model said so')
		CVEMatch.objects.filter(pk__in=[m.pk for m in matches]).update(ai_verdict='not_affected', ai_reason='the model said so', ai_model=model)
		return verdict, matches

	def test_the_migration_gives_a_closing_answer_the_project_that_asked_for_it(self, _log):
		import importlib

		from django.apps import apps
		from cveFeed.models import TriageCall
		verdict, (mine, theirs) = self.closed_pair()
		TriageCall.objects.create(kind='cve_match', signature=verdict.signature, project=self.a.project, status='succeeded',
								  expires_at=timezone.now())
		twice, _ = self.closed_pair(fresh=True, signature='e' * 40)
		for tenant in (self.a, self.b):
			TriageCall.objects.create(kind='cve_match', signature='e' * 40, project=tenant.project, status='succeeded', expires_at=timezone.now())
		deterministic = TriageVerdict.objects.create(kind='cve_match', signature='d' * 40, classification='not_applicable',
													 model='deterministic-correlation')
		lowered = TriageVerdict.objects.create(kind='cve_match', signature='f' * 40, classification='needs_validation', severity_adjust=-1,
											   model='a-model')  # a step down in severity is shown only where it was reached
		TriageCall.objects.create(kind='cve_match', signature='f' * 40, project=self.a.project, status='succeeded', expires_at=timezone.now())
		raised = TriageVerdict.objects.create(kind='cve_match', signature='c' * 40, classification='likely', model='a-model')
		TriageCall.objects.create(kind='cve_match', signature='c' * 40, project=self.a.project, status='succeeded', expires_at=timezone.now())
		migration = importlib.import_module('cveFeed.migrations.0139_triageverdict_origin')
		migration.neutralise_shared_closures(apps, None)
		lowered.refresh_from_db()
		raised.refresh_from_db()
		self.assertEqual((lowered.project_id, raised.project_id), (self.a.project.pk, None))  # a raising answer needs no origin
		verdict.refresh_from_db()
		self.assertEqual((verdict.project_id, verdict.host), (self.a.project.pk, self.a.sub.name))
		for unproven in (twice, deterministic):
			unproven.refresh_from_db()
			self.assertIsNone(unproven.project_id)

	def test_release_reopens_the_other_tenants_finding_and_keeps_the_origins(self, _log):
		verdict, (mine, theirs) = self.closed_pair(origin={'project': self.a.project, 'host': self.a.sub.name})
		from cveFeed import verdict_tenancy
		self.assertEqual(verdict_tenancy.release_shared_closures()['triage_rows'], 1)  # a dry run counts
		theirs.refresh_from_db()
		self.assertEqual(theirs.ai_verdict, 'not_affected')  # ...and changes nothing
		self.assertEqual(verdict_tenancy.release_shared_closures(apply=True)['triage_rows'], 1)
		self.assertOpen(theirs)
		self.assertEqual((theirs.ai_verdict, Triage.objects.get(match=theirs).classification), ('uncertain', 'needs_validation'))
		mine.refresh_from_db()
		self.assertEqual((mine.ai_verdict, Triage.objects.get(match=mine).classification), ('not_affected', 'not_applicable'))
		self.assertEqual(verdict_tenancy.release_shared_closures(apply=True)['triage_rows'], 0)  # idempotent

	def test_release_holds_every_finding_of_an_answer_with_no_origin(self, _log):
		from cveFeed import verdict_tenancy
		self.closed_pair()
		self.assertEqual(verdict_tenancy.release_shared_closures(apply=True)['triage_rows'], 2)
		self.assertFalse(CVEMatch.objects.filter(ai_verdict='not_affected').exists())

	def test_release_reopens_a_match_seeded_closed_and_deletes_the_shared_rows(self, _log):
		from cveFeed import verdict_tenancy
		cve = self.cve()
		reason = correlation.DIFFERENT_PRODUCT + '; it was recorded as "Acme portal".'
		own = CVEMatch.objects.create(cve_entry=cve, subdomain=self.a.sub, source='port', matched_product='Jenkins', matched_version='2.426.2',
									  version_in_range=None, confidence=0.0, evidence={'source': 'port', 'unbounded': True},
									  ai_verdict='not_affected', ai_reason=reason, ai_model='deterministic-correlation')
		Triage.objects.filter(pk=triage.track(triage.with_cves([own]))[0][0].pk).update(status='triaged', classification='not_applicable', reason=reason)
		seeded = CVEMatch.objects.create(cve_entry=cve, subdomain=self.b.sub, source='port', matched_product='Jenkins', matched_version='2.426.2',
										 version_in_range=None, confidence=0.5, evidence={'source': 'port', 'unbounded': True},
										 ai_verdict='not_affected', ai_reason=reason, ai_model='deterministic-correlation')
		MatchVerdict.objects.create(cve_entry=cve, matched_product='Jenkins', matched_version='2.426.2', version_in_range=None, source='port',
									ai_verdict='not_affected', ai_reason=reason, ai_model='deterministic-correlation')
		MatchVerdict.objects.create(cve_entry=cve, matched_product='Jenkins', matched_version='2.426.3', version_in_range=None, source='port',
									ai_verdict='affected', ai_reason='x', ai_model='m')
		counts = verdict_tenancy.release_shared_closures(apply=True)
		self.assertEqual((counts['seeded_matches'], counts['shared_rows']), (1, 1))
		seeded.refresh_from_db()
		own.refresh_from_db()
		self.assertEqual((seeded.ai_verdict, own.ai_verdict), ('', 'not_affected'))
		self.assertEqual(list(MatchVerdict.objects.values_list('ai_verdict', flat=True)), ['affected'])

	def test_the_background_release_runs_once(self, _log):
		from cveFeed import verdict_tenancy
		self.closed_pair()
		self.assertEqual(verdict_tenancy.release_once()['triage_rows'], 2)
		self.closed_pair(fresh=True, signature='e' * 40)
		with mock.patch.object(verdict_tenancy, 'release_shared_closures') as again:
			self.assertIsNone(verdict_tenancy.release_once())
			self.correlate()  # correlation calls it too: a no-op from now on
		again.assert_not_called()
