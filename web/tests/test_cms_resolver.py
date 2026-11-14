"""A host runs one WordPress core, one Drupal core, one board: when its technologies state two versions of one, the evidence says which is wrong."""
from unittest import mock

from django.test import TestCase

from cveFeed import cms_evidence, correlation
from cveFeed.models import ProbeObservation
from startScan.models import Subdomain, Technology
from tests.test_wordpress import WordPressFixture


def pairs(*names):
    return [correlation.split_name_version(n) for n in names]


class SupersededTests(WordPressFixture, TestCase):
    def sub(self, *names):
        sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        for name in names:
            sub.technologies.add(Technology.objects.get_or_create(name=name)[0])
        return sub

    def test_the_library_number_is_dropped_with_no_probe_evidence(self):
        sub = self.sub('WordPress:3.7.1', 'WordPress:7.1.4', 'jQuery:3.7.1')
        self.assertEqual(cms_evidence.superseded(sub, list(sub.technologies.all())), {('wordpress', '3.7.1')})

    def test_a_trusted_probe_reading_settles_a_dispute_the_libraries_cannot(self):
        sub = self.sub('WordPress:6.4.2', 'WordPress:7.1.4')
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wpscan', port=0, kind='wordpress',
                                        product='WordPress', version='7.1.4', outcome='found', confidence=1.0, source='wpscan')
        self.assertEqual(cms_evidence.superseded(sub, list(sub.technologies.all())), {('wordpress', '6.4.2')})

    def test_a_guess_is_not_evidence(self):
        sub = self.sub('WordPress:6.4.2', 'WordPress:7.1.4')
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wordpress-signals', port=0, kind='wordpress',
                                        product='WordPress', version='7.1.4', outcome='found', confidence=0.5, source='page')
        self.assertEqual(cms_evidence.superseded(sub, list(sub.technologies.all())), set())

    def test_a_host_without_a_dispute_costs_no_query(self):
        sub = self.sub('WordPress:7.1.4', 'jQuery:3.7.1')
        technologies = list(sub.technologies.all())
        with self.assertNumQueries(0):
            self.assertEqual(cms_evidence.superseded(sub, technologies), set())

    def test_correlation_matches_only_the_version_that_survives(self):
        sub = self.sub('WordPress:3.7.1', 'WordPress:7.1.4', 'jQuery:3.7.1')
        seen = []
        with mock.patch.object(correlation, '_record_matches', lambda s, name, version, *a, **k: seen.append((name, version))):
            correlation.collect_subdomain_matches(sub, {}, {})
        self.assertIn(('WordPress', '7.1.4'), seen)
        self.assertNotIn(('WordPress', '3.7.1'), seen)
        self.assertIn(('jQuery', '3.7.1'), seen)  # the library's own version is still matched as the library's
