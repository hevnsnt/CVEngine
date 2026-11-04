"""Preview (and follow up) the heat re-rating of 1.3.5 (cveFeed.rerate).

A dry run by default: for each project, and overall, how many open CVE matches and scanner findings show another heat under the 1.3.5 rules
than under the rules before (from -> to), how many hosts that moves, how many fire page marks belong to matches that are not fire any more,
and how many Triage classifications sit above their CVE's max_remote_state. Nothing is written.

Heat is computed when it is read, so deploying 1.3.5 already changes it everywhere: this report is the preview. --apply writes only the
stored follow-ups: it rescores the hosts whose findings changed heat, clears the fire page mark of matches that are no longer fire (so real
proof later pages them; nothing is sent), and holds those classifications to the limit. Safe to run again.

    python3 manage.py rerate_findings
    python3 manage.py rerate_findings --project <slug> [--project <slug> ...]
    python3 manage.py rerate_findings --apply
"""
from collections import Counter

from django.core.management.base import BaseCommand

from cveFeed import rerate


class Command(BaseCommand):
    help = "Report how the 1.3.5 heat rules re-rate the open findings (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--project", action="append", default=[], help="Only this project (by slug); repeat for several.")
        parser.add_argument("--apply", action="store_true",
                            help="Rescore the hosts, clear stale fire page marks and hold classifications to the CVE's limit. Without it "
                                 "the command only counts.")

    def handle(self, *args, **opts):
        apply = opts["apply"]
        reports = rerate.run(opts["project"] or None, apply=apply)
        totals = {'cve': Counter(), 'scanner': Counter(), 'classification': 0, 'unmark': 0, 'hosts': 0}
        for slug, report in reports.items():
            self._lines(slug, report)
            for key in totals:
                totals[key] += report[key]
        self._lines("overall", totals, style=self.style.SUCCESS)
        if apply:
            self.stdout.write(self.style.SUCCESS("applied: hosts rescored, stale fire page marks cleared (nothing sent), classifications "
                                                 "held to the CVE's max_remote_state"))
        else:
            self.stdout.write("dry run: nothing written. Heat is computed when read, so these changes are live as soon as 1.3.5 runs; "
                              "--apply only rescores the hosts, clears stale fire page marks and holds the classifications.")

    def _lines(self, label, report, style=None):
        cve, scanner = sum(report['cve'].values()), sum(report['scanner'].values())
        text = (f"{label}: {cve} open CVE match(es) change heat ({rerate.transitions_text(report['cve'])}); "
                f"{scanner} open scanner finding(s) change heat ({rerate.transitions_text(report['scanner'])}); "
                f"{report['hosts']} host(s) to rescore; {report['unmark']} fire page mark(s) on matches no longer fire; "
                f"{report['classification']} classification(s) above the CVE's max_remote_state")
        self.stdout.write(style(text) if style else text)
