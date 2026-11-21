"""Hot validation compares a finished job with the evidence the finding has NOW (the AI review coverage fixes, F1): a match whose version moved
after its row was last tracked is not taken for one already validated."""
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import hot_validation, triage
from cveFeed.models import CVEEntry, CVEMatch, OnDemandValidation, Triage
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.test_hot_validation import _LEGACY


def setUpModule():
    _LEGACY.start()


def tearDownModule():
    _LEGACY.stop()


class FreshSignatureTests(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='Sig', slug='sig')
        self.project = Project.objects.create(name='Sig', slug='sig', org=org, insert_date=now)
        domain = Domain.objects.create(name='sig.example', project=self.project, insert_date=now)
        sub = Subdomain.objects.create(name='www.sig.example', target_domain=domain)
        cve = CVEEntry.objects.create(cve_id='CVE-2099-81', cvss=9.8, affected=[{'product': 'nginx'}], published_at=now)
        self.match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0', version_in_range=True)
        self.row = triage.track(triage.with_cves([self.match]))[0][0]
        self.job = OnDemandValidation.objects.create(match=self.match, project=self.project, evidence_signature=self.row.signature, status='completed',
                                                     finished_at=now - timedelta(hours=1), result={'ai_state': 'completed'})

    def test_unchanged_evidence_keeps_the_job(self):
        self.assertEqual(hot_validation.enqueue(Triage.objects.get(pk=self.row.pk), 'fire'), 'fresh')

    def test_evidence_that_moved_without_a_track_is_validated_again(self):
        CVEMatch.objects.filter(pk=self.match.pk).update(matched_version='1.19.0', distro_status='vulnerable', updated_at=timezone.now())
        stale = Triage.objects.get(pk=self.row.pk)
        self.assertEqual(stale.signature, self.job.evidence_signature)  # what the old comparison read: "already validated"
        jobs = hot_validation._latest_jobs([stale])
        self.assertIsNone(hot_validation._settled(stale, 'fire', jobs, {}, timezone.now()))  # the fast path no longer turns it away
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as dispatch:
            self.assertEqual(hot_validation.enqueue(stale, 'fire'), 'queued')
        dispatch.assert_called_once()
        row = Triage.objects.get(pk=self.row.pk)
        self.assertNotEqual(row.signature, self.job.evidence_signature)  # the row was tracked: it describes the new evidence
        self.assertEqual(OnDemandValidation.objects.latest('id').evidence_signature, row.signature)
