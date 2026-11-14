"""Close the scans an update would otherwise wait for in vain (cveFeed.ghost_scans).

    python3 manage.py update_ghost_scans [--idle-minutes N]

Prints one line per scan closed, then ``ghosts N``. Run by scripts/apply-update.sh before it counts the scans that are still running.
"""
from django.core.management.base import BaseCommand

from cveFeed import ghost_scans


class Command(BaseCommand):
    help = "Mark running scans that no worker holds and that show no activity as failed (interrupted by an update)."

    def add_arguments(self, parser):
        parser.add_argument("--idle-minutes", type=int, default=ghost_scans.IDLE_MINUTES)

    def handle(self, *args, **opts):
        closed = ghost_scans.close(idle_minutes=max(1, opts["idle_minutes"]))
        for pk in closed:
            self.stdout.write(f"closed scan {pk}: {ghost_scans.MESSAGE}")
        self.stdout.write(f"ghosts {len(closed)}")
