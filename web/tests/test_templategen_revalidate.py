"""The update step for AI-written checks closed only because no scanner could check them (``revalidate_ai_drafts``), and the plain reasons of
rejections (``templategen.plain_reason``): the rows as the live install stores them."""
import io

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from cveFeed import templatevalidate
from cveFeed.models import CVEEntry, GeneratedTemplate as G
from tests.test_templategen import GOOD

NO_SCANNER = 'not validated: no scanner could take this work (nuclei_validate); the CVE is tried again later'
SONIC = ('WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not suitable '
         'and will fallback to encoding/json')


def cve(number):
    return CVEEntry.objects.create(cve_id=f'CVE-2024-{number}', title='t', published_at=timezone.now())


def stranded(entry, yaml_text=None, **fields):
    """A row as ``job_answer`` closed it before: invalid, no stage, the scanner message as both reason and output, the template id set."""
    text = yaml_text if yaml_text is not None else GOOD.replace('cve-2024-1234', entry.cve_id.lower())
    return G.objects.create(cve_entry=entry, yaml=text, template_id=entry.cve_id.lower(), status=G.STATUS_INVALID, validation_reason=NO_SCANNER,
                            validation_output=NO_SCANNER, validated_at=timezone.now(), ai_model='anthropic:m', **fields)


class RevalidateDraftsTests(TestCase):
    def run_command(self, apply=True):
        out = io.StringIO()
        call_command('revalidate_ai_drafts', **({'apply': True} if apply else {}), stdout=out)
        return out.getvalue()

    def test_a_check_closed_for_no_scanner_goes_back_to_validation(self):
        row = stranded(cve(1234))
        self.assertIn('1 AI-written check(s) would be given back', self.run_command(apply=False))
        self.assertEqual(G.objects.get(pk=row.pk).status, G.STATUS_INVALID)  # a dry run changes nothing
        self.run_command()
        row.refresh_from_db()
        self.assertEqual((row.status, row.validation_stage, row.validation_attempts, row.validated_at), (G.STATUS_DRAFT, 'syntax', 0, None))
        self.assertTrue(row.validation_reason.startswith('waiting:'))
        self.assertIsNotNone(row.validation_started_at)  # a fresh expiry window
        self.assertLessEqual(row.validation_next_at, timezone.now())  # due now
        self.assertEqual(row.path, '')  # never installed by this: only the gates promote it
        self.assertIn('0 AI-written check(s) given back', self.run_command())  # idempotent

    def test_only_the_newest_of_a_cve_and_never_beside_a_live_check(self):
        entry = cve(2000)
        older, newer = stranded(entry), stranded(entry)
        G.objects.filter(pk=older.pk).update(created_at=timezone.now() - timezone.timedelta(days=2))
        busy = cve(2001)
        held = stranded(busy)
        G.objects.create(cve_entry=busy, yaml=GOOD, template_id='cve-2024-2001', status=G.STATUS_VALID)
        self.run_command()
        self.assertEqual(G.objects.get(pk=newer.pk).status, G.STATUS_DRAFT)
        self.assertEqual(G.objects.get(pk=older.pk).status, G.STATUS_INVALID)
        self.assertEqual(G.objects.get(pk=held.pk).status, G.STATUS_INVALID)

    def test_a_text_that_no_longer_passes_the_static_check_stays_closed_with_that_reason(self):
        entry = cve(3000)
        row = stranded(entry, GOOD.replace('cve-2024-1234', 'cve-2024-3000').replace('    matchers:', '    redirects: true\n    matchers:'))
        self.run_command()
        row.refresh_from_db()
        self.assertEqual(row.status, G.STATUS_INVALID)
        self.assertTrue(row.validation_reason.startswith('static check:'))

    def test_a_rejection_with_no_reason_or_a_warning_for_one_is_named(self):
        # drafts 95 and 96 on the live install: a static-check rejection that wrote only the output
        static = G.objects.create(cve_entry=cve(4000), yaml='x', status=G.STATUS_INVALID, validation_output='static check: too many requests (10; the limit is 6)')
        failed = G.objects.create(cve_entry=cve(4001), yaml='', status=G.STATUS_INVALID,
                                  validation_output='the AI provider call failed (provider_network); no template was written')
        warned = G.objects.create(cve_entry=cve(4002), yaml='x', status=G.STATUS_INVALID,
                                  validation_output=SONIC + '\n[ERR] could not parse template', validation_reason='')
        nothing = G.objects.create(cve_entry=cve(4003), yaml='', status=G.STATUS_INVALID)
        self.run_command()
        self.assertEqual(G.objects.get(pk=static.pk).validation_reason, 'static check: too many requests (10; the limit is 6)')
        self.assertIn('provider_network', G.objects.get(pk=failed.pk).validation_reason)
        self.assertEqual(G.objects.get(pk=warned.pk).validation_reason, '[ERR] could not parse template')
        self.assertEqual(G.objects.get(pk=nothing.pk).validation_reason, '')

    def test_the_usage_page_names_a_rejection_without_the_warning(self):
        G.objects.create(cve_entry=cve(5000), yaml='x', status=G.STATUS_INVALID, validation_output=SONIC + '\nthe template has no matchers')
        reasons = [r['reason'] for r in templatevalidate.summary()['reasons']]
        self.assertEqual(reasons, ['the template has no matchers'])

    def test_it_runs_with_the_update(self):
        from cveFeed import upgrade_backfills
        self.assertIn('revalidate_ai_drafts', upgrade_backfills.BACKFILLS)
        self.assertLess(upgrade_backfills.BACKFILLS.index('revalidate_ai_drafts'), upgrade_backfills.BACKFILLS.index('rerate_findings'))
