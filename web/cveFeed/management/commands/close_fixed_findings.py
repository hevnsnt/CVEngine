"""Close the WordPress scan findings the version the scan last read on the same host is past the fix of (cveFeed.finding_lifecycle).

A later WordPress scan of a host now closes, as fixed and automatically, the open rows of an older version whose advisory states a fixed version at
or below the one it read (with the scan and the version in the note). This command does the same for what is already stored, from the
core, plugin and theme versions the scan last recorded for each host. A row a person set is never touched, a component the scan has no version
for proves nothing, and the "outdated" rows are left to the next scan (the stored versions do not say what the scan called outdated). A dry
run by default.

    python3 manage.py close_fixed_findings
    python3 manage.py close_fixed_findings --apply [--project slug]
"""
from django.core.management.base import BaseCommand

from cveFeed import finding_lifecycle

from ._finding_backfill import add_arguments, line, projects


class Command(BaseCommand):
    help = 'Close WordPress scan findings a later version read on the same host is past the fix of (a dry run unless --apply).'

    def add_arguments(self, parser):
        add_arguments(parser)

    def handle(self, *args, **opts):
        from cveFeed.models import ProbeObservation
        total = {'closed': 0, 'folded': 0}
        for project in projects(opts):
            counts = {'hosts': 0, 'closed': 0, 'folded': 0}
            stored = (ProbeObservation.objects.filter(project=project, source='wpscan', probe='wpscan-core').exclude(version='')
                      .select_related('domain').order_by('host'))
            for row in stored:
                report, when = finding_lifecycle.stored_wpscan_report(project.pk, row.host)
                read_in = f'as last stored on {when.date().isoformat()}' if when else ''
                done = finding_lifecycle.close_fixed_for_host(row.domain, row.host, report, read_in=read_in, apply=opts['apply'],
                                                              judge_outdated=False)
                counts['hosts'] += 1
                counts['closed'] += done['closed']
                counts['folded'] += done['folded']
            total['closed'] += counts['closed']
            total['folded'] += counts['folded']
            if counts['closed'] or counts['folded']:
                self.stdout.write(line(project, counts))
        verb = 'closed' if opts['apply'] else 'would close'
        self.stdout.write(self.style.SUCCESS(f"{verb} {total['closed']} WordPress scan finding(s) as fixed"))
