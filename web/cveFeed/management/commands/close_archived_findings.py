"""Close the open findings of the hosts that are archived now (cveFeed.archive_closure.backfill).

Archiving a host now closes every open CVE match, scanner finding and hygiene finding of it and of its other names in the project, as fixed
with a note that says when and by whom or why it was archived, and restoring it reopens them. Hosts archived before that kept theirs open: this
command closes them the same way. A finding a person closed is never touched, and running it again finds nothing to change. A dry run by default.

    python3 manage.py close_archived_findings
    python3 manage.py close_archived_findings --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import archive_closure


class Command(BaseCommand):
    help = 'Close the open findings of archived hosts, as archiving a host does now (a dry run unless --apply).'

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='Close the findings. Without it the command only counts.')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **opts):
        apply = bool(opts['apply']) and not opts['dry_run']
        out = archive_closure.backfill(apply=apply)
        total = out['match'] + out['vulnerability'] + out['hygiene']
        detail = f"{out['match']} CVE matches, {out['vulnerability']} scanner findings, {out['hygiene']} hygiene findings"
        if apply:
            self.stdout.write(f"Applied: {total} open findings on {out['hosts']} archived hosts closed ({detail}).")
        else:
            self.stdout.write(f"Dry run: {total} open findings on {out['hosts']} archived hosts would be closed ({detail}).")
