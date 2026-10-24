"""Explicit maintainer approval of a generated detector with reviewed fixtures."""

from django.core.management.base import BaseCommand, CommandError

from cveFeed.models import GeneratedTemplate
from cveFeed.templategen import approve_reviewed_template


class Command(BaseCommand):
    help = ('Verify an AI draft against a checked-in positive and negative CVE '
            'response fixture before allowing targeted host execution.')

    def add_arguments(self, parser):
        parser.add_argument('template_id', type=int, help='GeneratedTemplate database ID')

    def handle(self, *args, **options):
        try:
            ok, reason = approve_reviewed_template(options['template_id'])
        except GeneratedTemplate.DoesNotExist as exc:
            raise CommandError('generated template not found') from exc
        if not ok:
            raise CommandError(reason)
        self.stdout.write(self.style.SUCCESS(reason))
