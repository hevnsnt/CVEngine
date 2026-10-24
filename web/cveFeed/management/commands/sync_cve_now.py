"""Sync recent vulnerabilities from the cve.now feed into the CVEEntry table.

Runs the sync synchronously (no celery/worker needed), so it is safe for cron,
first-time backfill, or testing:

    python3 manage.py sync_cve_now --max-new 500
"""
from django.core.management.base import BaseCommand

from cveFeed.tasks import sync_cve_now_feed


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

    def handle(self, *args, **opts):
        result = sync_cve_now_feed(
            max_new=opts["max_new"],
            catch_up_after=opts["catch_up_after"],
            max_scan=opts["max_scan"],
        )
        self.stdout.write(self.style.SUCCESS(f"cve.now sync: {result}"))
