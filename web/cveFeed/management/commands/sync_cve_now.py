"""Sync recent vulnerabilities from the cve.now feed into the CVEEntry table.

Runs the sync synchronously (no celery/worker needed), so it is safe for cron,
first-time backfill, or testing:

    python3 manage.py sync_cve_now --max-new 500

Entries the incremental sync never reached (older than its first run, or beyond its stop rules) are read with --backfill-days,
--tech or --ids:

    python3 manage.py sync_cve_now --backfill-days 14
    python3 manage.py sync_cve_now --tech php
    python3 manage.py sync_cve_now --ids CVE-2026-109618 CVE-2026-109619
"""
from django.core.management.base import BaseCommand, CommandError

from cveFeed.tasks import backfill_cve_now_feed, sync_cve_now_feed


class Command(BaseCommand):
    help = "Sync recent vulnerabilities from the cve.now feed into the CVEEntry table."

    def add_arguments(self, parser):
        parser.add_argument(
            "--max-new", type=int, default=200,
            help="Stop after creating this many new entries. Default 200.")
        parser.add_argument(
            "--catch-up-after", type=int, default=40,
            help="Stop after this many consecutive already-known entries. Default 40.")
        parser.add_argument(
            "--max-scan", type=int, default=5000,
            help="Hard cap on summaries walked in one run. Default 5000.")
        parser.add_argument(
            "--backfill-days", type=int, default=None, metavar="DAYS",
            help="Read the last DAYS days of the feed, ignoring the known-in-a-row stop. Skipped when the store already reaches back that far.")
        parser.add_argument(
            "--tech", nargs="+", default=None, metavar="SLUG",
            help="Read the entries cve.now files under these technology slugs (for example php).")
        parser.add_argument(
            "--ids", nargs="+", default=None, metavar="ID",
            help="Read exactly these entries (CVE, GHSA or OSV ids).")
        parser.add_argument(
            "--force", action="store_true",
            help="With a backfill: walk even when the store already reaches back that far, and refresh entries already stored.")

    def handle(self, *args, **opts):
        if opts["backfill_days"] is not None or opts["tech"] or opts["ids"]:
            result = backfill_cve_now_feed(
                days=opts["backfill_days"], max_new=opts["max_new"], max_scan=opts["max_scan"],
                ids=opts["ids"], techs=opts["tech"], force=opts["force"])
            if result.get("invalid"):
                raise CommandError(f"not a valid id or technology slug: {', '.join(result['invalid'])}")
            if result.get("blocked"):
                raise CommandError(f"cve.now refused the request; stopped. {result}")
            self.stdout.write(self.style.SUCCESS(f"cve.now backfill: {result}"))
            return
        result = sync_cve_now_feed(
            max_new=opts["max_new"],
            catch_up_after=opts["catch_up_after"],
            max_scan=opts["max_scan"],
        )
        self.stdout.write(self.style.SUCCESS(f"cve.now sync: {result}"))
