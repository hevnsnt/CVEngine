"""Enable again the accounts the old abuse guard disabled (cveFeed.guard_reenable has the rules). Nothing else is restored: the API tokens it
revoked stay revoked and are listed for an administrator to reissue. Run by every update and once as an update step
(cveFeed.upgrade_backfills); running it again finds nothing to change. A dry run by default.

    python3 manage.py reenable_guard_disabled_users
    python3 manage.py reenable_guard_disabled_users --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import guard_reenable


class Command(BaseCommand):
    help = 'Enable again the accounts the old abuse guard disabled, and only those (a dry run unless --apply).'

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='Enable the accounts. Without it the command only says what it would do.')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **opts):
        apply = bool(opts['apply']) and not opts['dry_run']
        guard_reenable.run(apply=apply, write=self.stdout.write)
