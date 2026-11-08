from django.core.management.base import BaseCommand
from django.db import DatabaseError

from agentapi import sentinel_broker


class Command(BaseCommand):
    help = ("Print how many external Sentinels (not the built-in scanner) are live: 'EXTERNAL_SENTINELS_LIVE n'. Read only. scripts/update.sh runs it "
            "against the running server before an update, which can still be on a schema older than this code.")

    def handle(self, *args, **options):
        try:
            count = len(sentinel_broker.live_externals())
        except DatabaseError:
            # a database from before the built-in scanner (the columns this code reads are not there yet) can have no built-in scanner:
            # every live Sentinel on it is external
            from django.utils import timezone
            count = len(sentinel_broker._live_scanners(timezone.now()))
        self.stdout.write(f'EXTERNAL_SENTINELS_LIVE {count}')
