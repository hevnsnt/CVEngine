"""Correlate stored cve.now entries against discovered assets (creates CVEMatch rows).

Runs synchronously (no celery/worker needed):

    python3 manage.py correlate_cves --project acme --cve-limit 2000
"""
from django.core.management.base import BaseCommand

from cveFeed.tasks import correlate_cves


class Command(BaseCommand):
    help = "Correlate stored cve.now entries against discovered assets (creates CVEMatch rows)."

    def add_arguments(self, parser):
        parser.add_argument("--scan-id", type=int, default=None, help="Scope to one ScanHistory id.")
        parser.add_argument("--project", default=None, help="Scope to one project slug.")
        parser.add_argument("--min-confidence", type=float, default=0.4, help="Drop matches below this. Default 0.4.")
        parser.add_argument("--cve-limit", type=int, default=None, help="Cap the CVE pool to the newest N.")

    def handle(self, *args, **opts):
        result = correlate_cves(
            scan_history_id=opts["scan_id"],
            project_slug=opts["project"],
            min_confidence=opts["min_confidence"],
            cve_limit=opts["cve_limit"],
        )
        self.stdout.write(self.style.SUCCESS(f"correlation: {result}"))
