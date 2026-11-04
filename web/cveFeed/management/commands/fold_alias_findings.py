"""Fold the findings of redirect aliases into their target hosts (cveFeed.finding_lifecycle.fold_aliases).

A host whose every web port's front page only redirects permanently (301 or 308) to another host the project inventories (www, blog or
careers to the apex) serves nothing of its own. An open finding it shares with that host (the same scanner template, or the same hygiene
check on the same port and, for a certificate, the same certificate) is closed with a note that names the target host's row. A finding
only the alias has stays open, and so does one a person set or was assigned. A copy folded earlier whose host now serves its own page is
reopened. Scans and the hygiene check do this as they run; this command does it for what is already stored. A dry run by default.

    python3 manage.py fold_alias_findings
    python3 manage.py fold_alias_findings --apply [--project slug]
"""
from django.core.management.base import BaseCommand

from cveFeed import finding_lifecycle

from ._finding_backfill import add_arguments, line, projects


class Command(BaseCommand):
    help = 'Fold the findings redirect aliases share with their target host (a dry run unless --apply).'

    def add_arguments(self, parser):
        add_arguments(parser)

    def handle(self, *args, **opts):
        total = {'vulnerability': 0, 'hygiene': 0, 'reopened': 0}
        for project in projects(opts):
            counts = finding_lifecycle.fold_aliases(project.pk, apply=opts['apply'])
            for key in total:
                total[key] += counts[key]
            if any(counts.values()):
                self.stdout.write(line(project, counts))
        verb = 'folded' if opts['apply'] else 'would fold'
        self.stdout.write(self.style.SUCCESS(
            f"{verb} {total['vulnerability']} scanner finding(s) and {total['hygiene']} hygiene finding(s) of redirect aliases into their "
            f"target hosts; {total['reopened']} {'reopened' if opts['apply'] else 'to reopen'} on hosts that serve their own page again"))
