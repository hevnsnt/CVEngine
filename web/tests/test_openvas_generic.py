"""An OpenVAS behaviour check does not confirm a CVE whose record names no vendor and no product (the AI review coverage fixes, F5): the TRACE
NVT (1.3.6.1.4.1.25623.1.0.11213) lists CVE-2005-3398, whose CVE List record says ``vendor: n/a, product: n/a``; it passed as one vendor, was
stored as a template hit, and the triage floored it to confirmed over a correct AI verdict. The upgrade step ``recheck_openvas_generic_checks``
applies the rule to the matches already stored."""
import io
from types import SimpleNamespace

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import openvas_scan as ov, triage, upgrade_backfills
from cveFeed.models import CVEEntry, CVEMatch, Triage
from tests.test_openvas import APACHE, Fixture

TRACE_OID = '1.3.6.1.4.1.25623.1.0.11213'
NA = [{'vendor': 'n/a', 'product': 'n/a', 'versions': [{'version': 'n/a', 'status': 'affected'}]}]


def cve(affected):
    return SimpleNamespace(affected=affected)


class GenericCheckTests(SimpleTestCase):
    def test_a_record_that_names_nobody_makes_an_unidentified_check_generic(self):
        self.assertTrue(ov.generic_check({}, [cve(NA)]))
        self.assertTrue(ov.generic_check({}, [cve([{'vendor': 'apache', 'product': 'http_server'}]), cve(NA)]))  # one named vendor and one n/a
        self.assertTrue(ov.generic_check({}, [cve([{'vendor': 'unknown', 'product': ''}])]))

    def test_what_stays_hard_evidence(self):
        self.assertFalse(ov.generic_check({'product': 'http server'}, [cve(NA)]))  # the NVT says what it tested
        self.assertFalse(ov.generic_check({'installed_version': '2.4.49'}, [cve(NA)]))
        self.assertFalse(ov.generic_check({}, [cve([{'vendor': 'apache', 'product': 'http_server'}])] * 2))  # one vendor's product
        self.assertFalse(ov.generic_check({}, [cve([{'vendor': 'n/a', 'product': 'Acme Portal'}])]))  # a product named without a vendor
        self.assertFalse(ov.generic_check({}, [cve([])]))  # no record yet decides nothing
        self.assertTrue(ov.generic_check({}, [cve([{'vendor': 'sun', 'product': 'x'}]), cve([{'vendor': 'microsoft', 'product': 'y'}])]))  # as before


class ImportTests(Fixture, TestCase):
    def test_the_trace_check_does_not_confirm_an_na_record(self):
        na = CVEEntry.objects.create(cve_id='CVE-2005-3398', title='TRACE', published_at=timezone.now(), cvss=4.3, affected=NA)
        self.run_scan([dict(APACHE, oid=TRACE_OID, name='HTTP Debugging Methods (TRACE/TRACK) Enabled', severity=5.8, qod=99, qod_type='remote_vul',
                            cves=[na.cve_id])])
        m = CVEMatch.objects.select_related('cve_entry', 'subdomain').get(cve_entry=na, source='openvas')
        self.assertEqual((m.template_result, m.version_in_range), ('', None))
        self.assertTrue(m.evidence['generic_check'])
        self.assertEqual(triage.hard_evidence('cve_match', triage.describe_cve_match(m)['facts'])[0], '')  # no floor: the AI may rule it out


class BackfillTests(Fixture, TestCase):
    def stored_before_the_fix(self):
        """A TRACE match as the import stored it before: a template hit on an n/a record, its triage floored to confirmed."""
        na = CVEEntry.objects.create(cve_id='CVE-2005-3398', title='TRACE', published_at=timezone.now(), cvss=4.3, affected=NA)
        self.run_scan([dict(APACHE, oid=TRACE_OID, name='HTTP Debugging Methods (TRACE/TRACK) Enabled', severity=5.8, qod=99, qod_type='remote_vul',
                            cves=[na.cve_id])])
        m = CVEMatch.objects.get(cve_entry=na, source='openvas')
        evidence = {k: v for k, v in m.evidence.items() if k != 'generic_check'}
        CVEMatch.objects.filter(pk=m.pk).update(template_result='vulnerable', template_id=f'openvas:{TRACE_OID}', version_in_range=True,
                                                confidence=0.95, evidence=evidence)
        triage.track(triage.with_cves(CVEMatch.objects.filter(pk=m.pk).select_related('subdomain__target_domain')))
        Triage.objects.filter(match_id=m.pk).update(status='triaged', classification='confirmed')
        return m

    def test_the_upgrade_step_unconfirms_it_and_its_triage_starts_over(self):
        m = self.stored_before_the_fix()
        out = io.StringIO()
        call_command('recheck_openvas_generic_checks', stdout=out)
        self.assertIn('would unconfirm', out.getvalue())
        self.assertEqual(CVEMatch.objects.get(pk=m.pk).template_result, 'vulnerable')  # a dry run writes nothing
        call_command('recheck_openvas_generic_checks', apply=True, stdout=io.StringIO())
        m.refresh_from_db()
        self.assertEqual((m.template_result, m.version_in_range), ('', None))
        self.assertLessEqual(m.confidence, 0.5)
        self.assertTrue(m.evidence['generic_check'])
        row = Triage.objects.get(match_id=m.pk)
        self.assertEqual((row.status, row.classification), ('pending', ''))  # judged again, without the floor
        call_command('recheck_openvas_generic_checks', apply=True, stdout=out)
        self.assertIn('unconfirmed 0', out.getvalue())  # idempotent

    def test_a_product_check_is_left_alone(self):
        apache = CVEEntry.objects.get(cve_id='CVE-2021-41773')
        CVEEntry.objects.filter(pk=apache.pk).update(affected=[{'vendor': 'apache', 'product': 'http_server'}])
        self.run_scan([APACHE])
        call_command('recheck_openvas_generic_checks', apply=True, stdout=io.StringIO())
        self.assertEqual(CVEMatch.objects.get(cve_entry=apache, source='openvas').template_result, 'vulnerable')

    def test_it_is_an_upgrade_step_before_the_rerate(self):
        names = list(upgrade_backfills.BACKFILLS)
        self.assertLess(names.index('recheck_openvas_generic_checks'), names.index('rerate_findings'))
