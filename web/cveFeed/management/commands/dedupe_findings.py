"""Merge the scanner and hygiene findings filed more than once for the same finding on the same host (cveFeed.finding_lifecycle).

Before 1.3.5 every scan filed a scanner finding it saw again as a new row and left the earlier scans' rows open, and a host covered by
two targets of one project had each hygiene finding twice. New scans update the existing row; this command merges what was filed
before. Per finding with more than one live copy (open, not closed by a person), the copy that stays is the scanner finding in the host's
current scan (else the oldest live copy) or the oldest hygiene finding; it takes the earliest first-seen date, every copy's comments and
audit trail and, when it has none of its own, a person's status, note and assignee. Every other live copy is closed with a note that names
the one that stays. A copy a person worked differently is left open and counted as a conflict. Closed copies are never touched. Projects
are never merged with each other. A dry run by default; safe to run again.

    python3 manage.py dedupe_findings
    python3 manage.py dedupe_findings --apply [--project slug]
"""
from django.core.management.base import BaseCommand

from cveFeed import finding_lifecycle

from ._finding_backfill import add_arguments, line, projects


class Command(BaseCommand):
    help = 'Merge duplicate scanner and hygiene findings (a dry run unless --apply).'

    def add_arguments(self, parser):
        add_arguments(parser)

    def handle(self, *args, **opts):
        total = {'scanner_closed': 0, 'hygiene_closed': 0, 'conflicts': 0}
        for project in projects(opts):
            v = finding_lifecycle.dedupe_vulnerabilities(project, apply=opts['apply'])
            h = finding_lifecycle.dedupe_hygiene(project, apply=opts['apply'])
            counts = {'scanner_groups': v['groups'], 'scanner_closed': v['closed'], 'hygiene_groups': h['groups'],
                      'hygiene_closed': h['closed'], 'conflicts': v['conflicts'] + h['conflicts']}
            for key in total:
                total[key] += counts[key]
            if any(counts.values()):
                self.stdout.write(line(project, counts))
        verb = 'closed' if opts['apply'] else 'would close'
        self.stdout.write(self.style.SUCCESS(
            f"{verb} {total['scanner_closed']} duplicate scanner finding(s) and {total['hygiene_closed']} duplicate hygiene finding(s); "
            f"{total['conflicts']} left open where people worked the copies differently"))
