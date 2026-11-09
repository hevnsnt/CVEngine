"""Compute the per-project dashboard snapshots now (cveFeed.dashboard_snapshot).

    python manage.py refresh_dashboard_snapshots [--project SLUG]

The celery beat task does this every minute for the projects whose snapshot is older than 90 seconds; run this after an upgrade or a cache flush to
have the numbers ready before anyone opens the dashboard. Prints one line per project with the seconds it took.
"""
import time

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Compute the per-project dashboard snapshots now.'

    def add_arguments(self, parser):
        parser.add_argument('--project', help='only this project (slug)')

    def handle(self, *args, project=None, **opts):
        from cveFeed import dashboard_snapshot as snap
        from dashboard.models import Project
        qs = Project.objects.order_by('id')
        if project:
            qs = qs.filter(slug=project)
        for p in qs:
            started = time.monotonic()
            outcome = snap.refresh_project(p.id)
            self.stdout.write(f'{p.slug}: {outcome} in {time.monotonic() - started:.1f}s')
