"""A host runs one WordPress core, one Drupal core, one board: when its technologies state two versions of one, the evidence says which is wrong."""
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import cms, correlation
from cveFeed.models import ProbeObservation
from startScan.models import Subdomain, Technology
from tests.test_wordpress import WordPressFixture


def pairs(*names):
    return [correlation.split_name_version(n) for n in names]


class DisprovenTests(SimpleTestCase):
    def test_a_core_version_that_is_a_libraries_version_on_the_same_host_is_the_libraries_number(self):
        wrong = cms.disproven(pairs('WordPress:3.7.1', 'WordPress:7.1.4', 'jQuery:3.7.1', 'jQuery:3.4.1'))
        self.assertEqual(wrong, {('wordpress', '3.7.1')})

    def test_a_version_a_probe_states_settles_it_and_the_rest_are_dropped(self):
        wrong = cms.disproven(pairs('WordPress:6.4.2', 'WordPress:7.1.4'), attested={'wordpress': {'7.1.4'}})
        self.assertEqual(wrong, {('wordpress', '6.4.2')})

    def test_a_probe_wins_over_a_library_match(self):
        # the attested core happens to equal a library's version: it is still the core
        wrong = cms.disproven(pairs('WordPress:3.7.1', 'WordPress:7.1.4', 'jQuery:3.7.1'), attested={'wordpress': {'3.7.1'}})
        self.assertEqual(wrong, {('wordpress', '7.1.4')})

    def test_a_dispute_nothing_settles_keeps_every_version(self):
        self.assertEqual(cms.disproven(pairs('WordPress:6.4.2', 'WordPress:7.1.4', 'jQuery:3.7.1')), set())

    def test_a_single_version_is_never_dropped_even_when_it_matches_a_library(self):
        self.assertEqual(cms.disproven(pairs('WordPress:3.7.1', 'jQuery:3.7.1')), set())

    def test_every_version_that_is_a_library_number_is_left_when_no_other_remains(self):
        self.assertEqual(cms.disproven(pairs('WordPress:3.7.1', 'WordPress:3.4.1', 'jQuery:3.7.1', 'jQuery:3.4.1')), set())

    def test_libraries_with_several_versions_are_not_disputes(self):
        self.assertEqual(cms.disproven(pairs('jQuery:3.7.1', 'jQuery:1.2.1', 'Bootstrap:3.3.7', 'Bootstrap:5.3.0')), set())

    def test_the_rule_covers_every_product_with_one_instance_per_host(self):
        wrong = cms.disproven(pairs('Drupal:3.7.1', 'Drupal:10.2.3', 'jQuery:3.7.1', 'MyBB:1.8.38', 'MyBB:3.7.1'))
        self.assertEqual(wrong, {('drupal', '3.7.1'), ('mybb', '3.7.1')})

    def test_a_product_without_a_version_is_ignored(self):
        self.assertEqual(cms.disproven(pairs('WordPress', 'WordPress:7.1.4', 'jQuery:3.7.1')), set())


class SupersededTests(WordPressFixture, TestCase):
    def sub(self, *names):
        sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        for name in names:
            sub.technologies.add(Technology.objects.get_or_create(name=name)[0])
        return sub

    def test_the_library_number_is_dropped_with_no_probe_evidence(self):
        sub = self.sub('WordPress:3.7.1', 'WordPress:7.1.4', 'jQuery:3.7.1')
        self.assertEqual(cms.superseded(sub, list(sub.technologies.all())), {('wordpress', '3.7.1')})

    def test_a_trusted_probe_reading_settles_a_dispute_the_libraries_cannot(self):
        sub = self.sub('WordPress:6.4.2', 'WordPress:7.1.4')
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wpscan', port=0, kind='wordpress',
                                        product='WordPress', version='7.1.4', outcome='found', confidence=1.0, source='wpscan')
        self.assertEqual(cms.superseded(sub, list(sub.technologies.all())), {('wordpress', '6.4.2')})

    def test_a_guess_is_not_evidence(self):
        sub = self.sub('WordPress:6.4.2', 'WordPress:7.1.4')
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wordpress-signals', port=0, kind='wordpress',
                                        product='WordPress', version='7.1.4', outcome='found', confidence=0.5, source='page')
        self.assertEqual(cms.superseded(sub, list(sub.technologies.all())), set())

    def test_a_host_without_a_dispute_costs_no_query(self):
        sub = self.sub('WordPress:7.1.4', 'jQuery:3.7.1')
        technologies = list(sub.technologies.all())
        with self.assertNumQueries(0):
            self.assertEqual(cms.superseded(sub, technologies), set())

    def test_correlation_matches_only_the_version_that_survives(self):
        sub = self.sub('WordPress:3.7.1', 'WordPress:7.1.4', 'jQuery:3.7.1')
        seen = []
        with mock.patch.object(correlation, '_record_matches', lambda s, name, version, *a, **k: seen.append((name, version))):
            correlation.collect_subdomain_matches(sub, {}, {})
        self.assertIn(('WordPress', '7.1.4'), seen)
        self.assertNotIn(('WordPress', '3.7.1'), seen)
        self.assertIn(('jQuery', '3.7.1'), seen)  # the library's own version is still matched as the library's
