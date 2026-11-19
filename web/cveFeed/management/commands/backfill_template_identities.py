"""Read the stored template findings again for what their template says about the product (cveFeed.template_identity).

A technology template's finding gives the CPE its template names (tomcat-detect: cpe:2.3:a:apache:tomcat) to the host's technology of the same name, so
correlation matches it CPE first; a panel hit that extracted no version becomes an identity reading (vsrc:panel, no version) and a technology with no
version of its host. The hosts that changed are correlated again.

A dry run by default: it counts the findings it would read. With --apply it reads them in bounded passes (--limit findings each) from where the last
run stopped; safe to run again.

    python3 manage.py backfill_template_identities
    python3 manage.py backfill_template_identities --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import template_identity


class Command(BaseCommand):
    help = ('Give host technologies the CPE their technology template names, and read panel hits without a version as identity '
            'readings and technologies (cveFeed.template_identity), then correlate the hosts that changed. A dry run unless --apply.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the links, readings and matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')
        parser.add_argument('--limit', type=int, default=500, help='stored findings read per pass. Default 500.')
        parser.add_argument('--passes', type=int, default=1000, help='most passes in this run. Default 1000.')
        parser.add_argument('--reset', action='store_true', help='start from the first stored finding instead of where the last run stopped')

    def handle(self, *args, **opts):
        apply = bool(opts['apply']) and not opts['dry_run']
        if opts['reset'] and apply:
            template_identity.reset()
        if not apply:
            self.stdout.write(f'Dry run: {template_identity.pending()} stored technology and panel findings would be read for the product their '
                              'template names.')
            return
        total = {'findings': 0, 'links': 0, 'readings': 0, 'hosts': 0, 'matches': 0}
        for _ in range(max(1, opts['passes'])):
            out = template_identity.read_pass(limit=max(1, opts['limit']))
            for key in total:
                total[key] += out[key]
            if out['done']:
                break
        self.stdout.write(f'Applied: {total["findings"]} stored findings read; {total["links"]} technology links given their template\'s CPE, '
                          f'{total["readings"]} panel identity readings stored; {total["hosts"]} hosts correlated, {total["matches"]} CVE matches.')
