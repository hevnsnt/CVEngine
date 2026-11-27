from django.core.management.base import BaseCommand

from cveFeed import tls_audit


class Command(BaseCommand):
    help = ('Say the open TLS audit findings (check names tlsa_*) the way a new test would: a plain description instead of testssl.sh\'s own result string, '
            'a title that states whether the result is confirmed, no more than Medium for a result that is only likely or potential (testssl.sh\'s own '
            'severity stays in the evidence), and the confidence recorded for the AI triage. It reads each finding\'s stored evidence and runs no test '
            '(cveFeed.tls_audit.rewrite_open). Resolved findings and a person\'s status, assignee and notes are left alone. Idempotent. '
            'A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='rewrite the findings (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = tls_audit.rewrite_open(apply=apply)
        self.stdout.write(f'Applied: {out["changed"]} of {out["rows"]} open TLS audit findings rewritten ({out["lowered"]} lowered in severity).' if apply
                          else f'Dry run: {out["changed"]} of {out["rows"]} open TLS audit findings would be rewritten ({out["lowered"]} lowered in severity).')
