"""Read again the part of the cve.now feed a walk wrongly declared covered (CHANGELOG, 2026-11 feed paging fix).

cve.now renamed its list cursor (``nextCursor`` to ``next_cursor``) and started refusing anonymous list pages past the newest 400. The
backfill walk read the first page, saw no cursor, took the end of the listing for the floor of its window and moved the coverage
watermark (cveFeed.feed_watermark) to the head of the feed: every entry the scheduled sync missed since then stayed missing, and the
status said the feed was complete.

This moves the watermark back to ``--through`` (2026-11-06, the published seed's ``covers_through``) when it stands later, and queues
``recover_cve_feed_window``, which walks the window again (by date windows below the newest 400) until it is covered and matches every
CVE it reads against the inventory. A dry run unless --apply. Safe to run again: a second run reads the same window and finds nothing
missing.

    python3 manage.py recover_feed_gap
    python3 manage.py recover_feed_gap --apply
"""
import datetime

from django.core.management.base import BaseCommand, CommandError
from django.utils.dateparse import parse_datetime

RECOVER_THROUGH = '2026-11-06T00:00:00Z'


class Command(BaseCommand):
    help = "Move the cve.now coverage watermark back and read the window again (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Move the watermark and queue the walk. Without it the command only reports.")
        parser.add_argument("--through", default=RECOVER_THROUGH,
                            help=f"The time the feed is read back to (a margin before it is read too). Default {RECOVER_THROUGH}.")

    def handle(self, *args, **opts):
        from cveFeed import feed_watermark
        through = parse_datetime(opts["through"] or "")
        if through is None or through.tzinfo is None:
            raise CommandError(f"not a time with a zone: {opts['through']!r}")
        through = through.astimezone(datetime.timezone.utc)
        row = feed_watermark.current()
        before = row.covered_through
        moves = before is not None and before > through
        if not opts["apply"]:
            if moves:
                self.stdout.write(f"would move the feed watermark from {before.isoformat()} back to {through.isoformat()} and read the window again")
            else:
                self.stdout.write(f"the feed watermark ({before.isoformat() if before else 'none'}) already lies at or before "
                                  f"{through.isoformat()}; would read the window again")
            self.stdout.write(self.style.SUCCESS("dry run: nothing was written (run again with --apply)"))
            return
        if moves:
            row.covered_through = through
        row.resume_cursor, row.resume_head, row.checked_at = '', None, None  # a walk in progress started from the wrong place
        row.save()
        from cveFeed.tasks import recover_cve_feed_window
        recover_cve_feed_window.delay()
        self.stdout.write(self.style.SUCCESS(
            (f"feed watermark moved back from {before.isoformat()} to {through.isoformat()}" if moves
             else f"feed watermark kept at {before.isoformat() if before else 'none'}") + "; the window is read again and matched"))
