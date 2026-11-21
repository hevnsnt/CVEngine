"""Shodan InternetDB readings are leads for our own checks, never findings (cveFeed.source_versions).

InternetDB is keyed by IP address: behind a CDN's shared edge address it describes whatever other site Shodan once saw there. So a reading never
makes a CVE match, never counts as "the host runs X", queues our own first-party check of the product (the WordPress probe, the version source
reads) unless the address is a shared edge or our own check already ruled it out, and an open match that rested only on one is closed for good.
runZero's readings (the customer's own active scanner) keep matching, held at ice until a first-party read or a check confirms them."""
from datetime import timedelta
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from agentapi import services
from cveFeed import check_coverage, closure, correlation, match_explain, source_versions, threat, upgrade_backfills, version_sources, wpscan_scan
from cveFeed.models import CVEEntry, CVEMatch, FindingAuditEvent, ProbeObservation
from startScan.models import IpAddress, Subdomain
from tests.test_source_versions import OPENSSH, ReportedFixture, cve

CLOUDFLARE = '104.21.84.242'
WORDPRESS = ('wordpress', 'wordpress', '7.0.9', 'cpe:/a:wordpress:wordpress:7.0.9')
REDIS = ('redislabs', 'redis', '', 'cpe:/a:redislabs:redis')
GRAFANA = ('grafana', 'grafana', '10.2.3', 'cpe:/a:grafana:grafana:10.2.3')


class Leads(ReportedFixture):
    def shodan(self, sub, cpe_parts=WORDPRESS, port=0):
        vendor, product, version, cpe = cpe_parts
        reading = source_versions.shodan_reading(cpe)
        source_versions.store_reported(sub.target_domain.project_id, sub.target_domain_id, sub.name, source_versions.SHODAN_PROBE, [reading],
                                       source_versions.SHODAN_PROVIDER, timezone.now(), port=port, undated=True)
        return ProbeObservation.objects.get(probe=source_versions.SHODAN_PROBE, host=sub.name, product=reading['label'])

    def host(self, address=None, **kw):
        scan = self.host_scan(address=address, **kw)
        scan.scan_status = 2  # a finished scan: its hosts are the current ones (correlation.latest_scan_q)
        scan.save(update_fields=['scan_status'])
        return self.fresh(scan.subdomain_set.get())

    def fresh(self, sub):
        return Subdomain.objects.select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports').get(pk=sub.pk)


class ShodanNeverMatchesTests(Leads, TestCase):
    def test_the_wordpress_cpe_of_a_cloudflare_address_makes_no_match_and_runzero_beside_it_still_does(self):
        row = cve('CVE-2026-87902', 'wordpress', 'wordpress', '7.0.0', '7.1.0', kev=True)
        sub = self.host(address=CLOUDFLARE)
        self.shodan(sub)
        self.assertEqual(self.correlate(row), [])
        self.assertFalse(CVEMatch.objects.filter(cve_entry=row).exists())
        self.reported(sub, product='wordpress', version='7.0.9', cpe='cpe:/a:wordpress:wordpress:7.0.9')  # runZero says the same
        match, = self.correlate(row)
        self.assertEqual(match.evidence['reported_by'], 'runzero')

    def test_collect_reported_skips_the_shodan_rows_itself(self):
        row = cve('CVE-2026-300071', *OPENSSH)
        sub = self.host()
        self.shodan(sub, ('openbsd', 'openssh', '8.9p1', 'cpe:/a:openbsd:openssh:8.9p1'))
        cve_by_id, index = correlation.cve_pool()
        found = []
        with mock.patch.object(source_versions, 'in_use', return_value=list(ProbeObservation.objects.filter(probe=source_versions.SHODAN_PROBE))):
            self.assertEqual(source_versions.collect_reported(self.fresh(sub), index, cve_by_id, found), 0)
        self.assertEqual((found, row.pk is not None), ([], True))

    def test_the_candidate_walk_ignores_a_host_with_only_shodan_readings(self):
        sub = self.host()
        self.shodan(sub)
        self.assertFalse(Subdomain.objects.filter(pk__in=source_versions.reported_host_ids(Subdomain.objects.all())).exists())
        self.reported(sub, product='openssh')
        self.assertTrue(Subdomain.objects.filter(pk__in=source_versions.reported_host_ids(Subdomain.objects.all())).exists())

    def test_the_host_page_lists_the_readings_apart_never_as_version_sources(self):
        sub = self.host()
        self.shodan(sub)
        self.assertEqual(version_sources.readings_for([self.project.pk], ['app.rt.test']), {})
        item, = source_versions.leads_of(sub)
        self.assertEqual((item['product'], item['version'], item['state'], item['label']),
                         ('wordpress', '7.0.9', 'open', 'Reported by Shodan (unverified lead)'))


class LeadStateTests(Leads, TestCase):
    def test_a_shared_edge_address_is_labelled_and_queues_nothing(self):
        sub = self.host(address=CLOUDFLARE, web=True)
        self.shodan(sub)
        item, = source_versions.leads_of(sub)
        self.assertEqual((item['state'], item['edge']), ('edge', 'Cloudflare'))
        self.assertEqual(item['label'], 'Shodan data for a shared edge address (Cloudflare), probably another site')
        self.assertEqual(source_versions.wordpress_leads([sub]), set())
        self.assertEqual(source_versions.lead_products(sub), [])

    def test_the_cdn_flag_names_the_edge_too(self):
        sub = self.host(web=True)
        IpAddress.objects.filter(address=self.ADDRESS).update(is_cdn=True)
        self.shodan(sub)
        item, = source_versions.leads_of(self.fresh(sub))
        self.assertEqual(item['state'], 'edge')

    def test_a_first_party_negative_rules_the_wordpress_lead_out(self):
        sub = self.host(web=True)
        self.shodan(sub)
        self.assertEqual(source_versions.wordpress_leads([sub]), {'app.rt.test'})  # asked first by the probe
        wpscan_scan.record_state(self.project.pk, self.domain.pk, 'app.rt.test', 'not_wordpress', 'the probe found no WordPress signature')
        item, = source_versions.leads_of(self.fresh(sub))
        self.assertEqual((item['state'], item['ruled_out'], item['label']), ('ruled_out', True, 'Reported by Shodan, ruled out by our probe'))
        self.assertEqual(source_versions.wordpress_leads([sub]), set())  # no more re-queuing

    def test_a_probe_observation_of_absent_rules_it_out_too(self):
        sub = self.host(web=True)
        self.shodan(sub)
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='app.rt.test', probe='wordpress-detect', kind='wordpress',
                                        product='WordPress', outcome='absent', source='probe', evidence={})
        self.assertEqual(source_versions.leads_of(self.fresh(sub))[0]['state'], 'ruled_out')
        self.assertEqual(source_versions.wordpress_leads([sub]), set())

    def test_a_port_that_answers_with_another_product_rules_a_port_lead_out(self):
        sub = self.host(web=True, ports=((3000, 'http', 'nginx', '1.25.3'),))
        self.shodan(sub, GRAFANA, port=3000)
        self.assertEqual(source_versions.leads_of(self.fresh(sub))[0]['state'], 'ruled_out')
        self.assertEqual(source_versions.lead_products(self.fresh(sub)), [])

    def test_a_product_our_own_scan_names_is_confirmed_not_a_lead(self):
        sub = self.host(web=True, techs=('Grafana:10.2.3',))
        self.shodan(sub, GRAFANA)
        self.assertEqual(source_versions.leads_of(self.fresh(sub))[0]['state'], 'confirmed')
        self.assertEqual(source_versions.lead_products(self.fresh(sub)), [])


class LeadsDriveFirstPartyChecksTests(Leads, TestCase):
    def test_a_wordpress_lead_moves_the_host_to_the_front_of_the_probe_without_making_it_a_candidate(self):
        scan = self.host_scan(names=('a.rt.test', 'b.rt.test'), web=True)
        subs = list(Subdomain.objects.filter(scan_history=scan).select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports'))
        b = next(s for s in subs if s.name == 'b.rt.test')
        self.shodan(b)
        leads = source_versions.wordpress_leads(subs)
        self.assertEqual(leads, {'b.rt.test'})
        asked = []

        def ask(_scan, chosen):
            asked.append([sub.name for sub, _bases in chosen])
            return {}
        with mock.patch.object(wpscan_scan, '_ask_wordpress', side_effect=ask):
            wpscan_scan.detect(scan, subs, {}, leads=leads)
        self.assertEqual(asked[0][0], 'b.rt.test')
        self.assertEqual(wpscan_scan.candidate_signals(scan, subs), {})  # a lead is no sign of WordPress: nothing is scanned because of it

    def host_by(self, scan):
        return self.fresh(scan.subdomain_set.get())

    def test_a_product_on_a_port_queues_the_existing_version_source_read(self):
        scan = self.host_scan(web=True)
        self.assertEqual(version_sources.candidates(scan), {})
        sub = self.host_by(scan)
        self.shodan(sub, GRAFANA)
        found = version_sources.candidates(scan)
        (entry,) = found.values()
        self.assertEqual([(s.id, base) for s, base in entry['reads']], [('grafana', 'https://app.rt.test')])

    def test_no_read_is_queued_on_a_shared_edge_address_or_after_a_first_party_negative(self):
        edge = self.host_scan(address=CLOUDFLARE, web=True)
        self.shodan(self.host_by(edge), GRAFANA)
        self.assertEqual(version_sources.candidates(edge), {})
        ruled = self.host_scan(web=True, ports=((3000, 'http', 'nginx', '1.25.3'),), names=('x.rt.test',), address='203.0.113.9')
        self.shodan(self.host_by(ruled), GRAFANA, port=3000)
        self.assertEqual(version_sources.candidates(ruled), {})

    def test_the_work_planner_sees_the_lead(self):
        sub = self.host_scan(web=True).subdomain_set.get()
        row = self.shodan(sub, GRAFANA)
        facts = check_coverage.HostFacts('app.rt.test', self.project.pk, addresses=[check_coverage.Addr(self.ADDRESS)], web_bases=['https://app.rt.test'])
        ev = check_coverage.Evidence()
        self.assertIsInstance(check_coverage.plan_versions(facts, ev), str)  # no product, no entry
        ev.leads[(self.project.pk, 'app.rt.test')] = [row]
        units = check_coverage.plan_versions(facts, ev)
        self.assertEqual([u.label for u in units], ['app.rt.test'])
        edge = check_coverage.HostFacts('app.rt.test', self.project.pk, addresses=[check_coverage.Addr(CLOUDFLARE)], web_bases=['https://app.rt.test'])
        self.assertIsInstance(check_coverage.plan_versions(edge, ev), str)  # a shared edge: Shodan's data is about another site
        ev_loaded = check_coverage.Evidence()
        check_coverage._load_leads(ev_loaded, [self.project.pk], {'app.rt.test'})
        self.assertEqual([r.pk for r in ev_loaded.leads[(self.project.pk, 'app.rt.test')]], [row.pk])


class CleanupTests(Leads, TestCase):
    def match(self, row, sub, **evidence):
        fields = {'source': 'tech', 'version_in_range': True, 'matched_product': 'WordPress', 'matched_version': '7.0.9', 'confidence': 0.5}
        for key in ('remediation_status', 'template_result', 'source'):
            if key in evidence:
                fields[key] = evidence.pop(key)
        return CVEMatch.objects.create(cve_entry=row, subdomain=sub, evidence={'source': 'tech', **evidence}, **fields)

    def setUp(self):
        super().setUp()
        self.sub = self.host(address=CLOUDFLARE, web=True)
        self.reading = self.shodan(self.sub)
        self.cves = [CVEEntry.objects.create(cve_id=f'CVE-2026-3100{i}', title='x', kev=True, cvss=9.8, published_at=timezone.now()) for i in range(7)]
        shodan = {'reported': True, 'reported_by': 'shodan_idb', 'reading_id': self.reading.pk}
        self.shodan_match = self.match(self.cves[0], self.sub, **shodan)
        self.by_reading = self.match(self.cves[1], self.sub, reported=True, reading_id=self.reading.pk)
        self.runzero = self.match(self.cves[2], self.sub, reported=True, reported_by='runzero', reading_id=999999)
        self.worked = self.match(self.cves[3], self.sub, remediation_status='accepted_risk', **shodan)
        self.hard = self.match(self.cves[4], self.sub, template_result='vulnerable', **shodan)
        self.first_party = self.match(self.cves[5], self.sub)
        self.portless = self.match(self.cves[6], self.sub, reported=True, reported_by='runzero')

    def state(self, match):
        return CVEMatch.objects.get(pk=match.pk)

    def test_only_the_open_shodan_only_matches_close_automatically_as_false_positives(self):
        self.assertEqual(source_versions.cleanup_shodan_matches(), {'matches': 2, 'closed': 0})  # a dry run writes nothing
        self.assertEqual(self.state(self.shodan_match).remediation_status, 'open')
        out = source_versions.cleanup_shodan_matches(apply=True)
        self.assertEqual(out['closed'], 2)
        for closed in (self.shodan_match, self.by_reading):
            row = self.state(closed)
            self.assertEqual((row.remediation_status, row.ai_verdict, row.confidence), ('false_positive', 'not_affected', 0.0))
            note, user, _when, automatic = closure.closure_of('match', row)
            self.assertEqual((user, automatic), (None, True))
            self.assertEqual(note, 'Closed automatically: based only on Shodan InternetDB data for the host\'s address, which cvENGINE uses as a lead, '
                                   'not as a finding; our own checks did not confirm WordPress 7.0.9 on this host.')
        for kept, status in ((self.runzero, 'open'), (self.worked, 'accepted_risk'), (self.hard, 'open'), (self.first_party, 'open'), (self.portless, 'open')):
            self.assertEqual(self.state(kept).remediation_status, status)
            self.assertEqual(self.state(kept).ai_verdict, '')
        self.assertEqual(FindingAuditEvent.objects.filter(finding_kind='match', after__by='shodan_lead_rule').count(), 2)
        self.assertEqual(source_versions.cleanup_shodan_matches(apply=True), {'matches': 0, 'closed': 0})  # idempotent

    def test_the_next_correlation_of_the_host_closes_them_with_the_same_note(self):
        self.runzero.delete()
        self.portless.delete()
        self.correlate(self.cves[0])
        row = self.state(self.shodan_match)
        self.assertEqual(row.remediation_status, 'false_positive')
        self.assertTrue(row.remediation_note.startswith('Closed automatically: based only on Shodan InternetDB data'))
        self.assertEqual(self.state(self.worked).remediation_status, 'accepted_risk')  # a person's decision stands
        self.assertEqual(self.state(self.hard).remediation_status, 'open')  # a template hit is more than Shodan's word

    def test_it_runs_on_upgrade_and_by_hand(self):
        self.assertIn('cleanup_shodan_matches', upgrade_backfills.BACKFILLS)
        self.assertLess(upgrade_backfills.BACKFILLS.index('cleanup_shodan_matches'), upgrade_backfills.BACKFILLS.index('rerate_findings'))
        out = StringIO()
        call_command('cleanup_shodan_matches', stdout=out)
        self.assertIn('Dry run: 2', out.getvalue())
        self.assertEqual(self.state(self.shodan_match).remediation_status, 'open')
        out = StringIO()
        call_command('cleanup_shodan_matches', apply=True, stdout=out)
        self.assertIn('2 of 2', out.getvalue())

    def test_a_closed_shodan_match_is_not_counted_by_the_digest_before_or_after(self):
        from cveFeed import report_threats
        ids = [self.project.pk]
        before = report_threats.impact(ids, [self.cves[0]])[self.cves[0].id]
        self.assertEqual(before['matched'], set())  # the exclusion holds even before the cleanup ran
        source_versions.cleanup_shodan_matches(apply=True)
        self.assertEqual(report_threats.impact(ids, [self.cves[0]])[self.cves[0].id]['matched'], set())
        self.assertEqual(len(report_threats.impact(ids, [self.cves[5]])[self.cves[5].id]['matched']), 1)  # a first-party match still counts


class WordingTests(Leads, TestCase):
    def runzero_match(self, **evidence):
        row, _ = CVEEntry.objects.get_or_create(cve_id='CVE-2026-300090', defaults={'title': 'x', 'kev': True, 'cvss': 9.8, 'published_at': timezone.now()})
        sub = Subdomain.objects.first() or self.host()
        return CVEMatch.objects.update_or_create(
            cve_entry=row, subdomain=sub, source='tech', matched_product='WordPress',
            defaults={'matched_version': '7.0.9', 'version_in_range': True, 'confidence': 0.5, 'evidence': {'source': 'tech', 'reported': True, **evidence}})[0]

    def test_how_found_names_the_provider_never_our_fingerprint(self):
        for by, name in (('runzero', 'runZero'), ('shodan_idb', 'Shodan InternetDB')):
            steps = {k: v for k, v in ((s['label'], s['value']) for s in services._how_found_match(self.runzero_match(reported_by=by,
                                                                                                                       reported_at='2026-11-02T10:00:00Z'))['steps'])}
            self.assertIn(f'reported by {name} as of 2026-11-02', steps['Observed'])
            self.assertIn(name, steps['Found by'])
            self.assertNotIn('fingerprint', steps['Observed'] + steps['Found by'])
            self.assertNotEqual(steps['Found by'], 'technology detection')

    def test_a_fingerprint_match_keeps_its_wording(self):
        match = self.runzero_match()
        match.evidence = {'source': 'tech'}
        steps = {s['label']: s['value'] for s in services._how_found_match(match)['steps']}
        self.assertEqual(steps['Found by'], 'technology detection')

    def test_the_explain_text_names_the_provider(self):
        text = match_explain._found(self.runzero_match(reported_by='runzero'), '', 'wordpress', 'WordPress', '7.0.9')
        self.assertIn('runZero reports WordPress 7.0.9', text)
        self.assertNotIn('technology fingerprint', text)
        text = match_explain._found(self.runzero_match(reported_by='shodan_idb'), '', 'wordpress', 'WordPress', '7.0.9')
        self.assertIn('Shodan InternetDB reports', text)


class HeatCeilingTests(Leads, TestCase):
    def setUp(self):
        super().setUp()
        self.kev = CVEEntry.objects.create(cve_id='CVE-2026-300091', title='x', kev=True, cvss=9.8, published_at=timezone.now())
        self.sub = self.host()

    def match(self, **fields):
        evidence = {'source': 'tech', **fields.pop('evidence', {})}
        return CVEMatch.objects.create(cve_entry=self.kev, subdomain=self.sub, source='tech', matched_product=fields.pop('product', 'WordPress'),
                                       matched_version='7.0.9', version_in_range=True, confidence=0.5, evidence=evidence, **fields)

    def test_a_reported_only_match_on_the_kev_stays_ice_until_something_first_party_confirms_it(self):
        reported = self.match(evidence={'reported': True, 'reported_by': 'runzero'})
        confirmed = self.match(product='Other', evidence={'reported': True, 'reported_by': 'runzero'}, template_result='vulnerable')
        banner = self.match(product='Banner', evidence={})
        def heat(m):
            m = CVEMatch.objects.select_related('cve_entry', 'triage').get(pk=m.pk)
            return threat.match_heat(m), threat.HEAT_RANK[threat.match_heat(m)], threat.heat_reason(m)
        self.assertEqual(heat(reported)[0], threat.ICE)
        self.assertEqual(heat(reported)[2], threat.REASON_REPORTED_ONLY)
        self.assertEqual(heat(confirmed)[0], threat.FIRE)  # a check showed the flaw
        self.assertEqual(heat(banner)[0], threat.SMOKE)  # a first-party version read keeps the existing rule
        self.assertEqual(threat.validation_heat(CVEMatch.objects.select_related('cve_entry').get(pk=reported.pk)), threat.FIRE)  # proving it would make it fire
        ranks = dict(CVEMatch.objects.annotate(rank=threat.match_heat_rank_expr()).values_list('pk', 'rank'))  # the database form agrees
        self.assertEqual((ranks[reported.pk], ranks[confirmed.pk], ranks[banner.pk]), (threat.HEAT_RANK[threat.ICE], threat.HEAT_RANK[threat.FIRE],
                                                                                         threat.HEAT_RANK[threat.SMOKE]))

    def test_the_version_not_proven_wording_is_for_first_party_reads(self):
        banner = CVEMatch.objects.select_related('cve_entry').get(pk=self.match(evidence={}).pk)
        self.assertEqual(threat.heat_reason(banner), 'on the KEV; version not proven')


class DigestCountTests(Leads, TestCase):
    def test_a_shodan_only_product_does_not_inflate_the_product_counts(self):
        from cveFeed import report_threats
        row = CVEEntry.objects.create(cve_id='CVE-2026-300092', title='x', kev=True, cvss=9.8, published_at=timezone.now() - timedelta(days=30),
                                      affected=[{'product': 'php', 'ranges': [{'fixed': '8.3.0'}]}])
        sub = self.host(address=CLOUDFLARE)
        self.shodan(sub, ('php', 'php', '', 'cpe:/a:php:php'))
        out = report_threats.impact([self.project.pk], [row])[row.id]
        self.assertEqual((out['matched'], out['product_only']), (set(), set()))
