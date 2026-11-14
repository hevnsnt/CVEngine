from django.core.management.base import BaseCommand
from django.db import DatabaseError
from django.utils import timezone

from agentapi import sentinel_broker


class Command(BaseCommand):
    help = ("Print how many external Sentinels (not the built-in scanner) are live: 'EXTERNAL_SENTINELS_LIVE n'. Read only. scripts/update.sh and the Update "
            "button's host script run it against the running server before an update, when ./web already holds the new code but the database is still on the old "
            "schema.")

    def handle(self, *args, **options):
        try:
            count = len(sentinel_broker.live_externals())
        except DatabaseError:
            # The new code against a database that has not been migrated yet: a model query that names a column the old schema lacks fails. What the last-resort
            # rule counts (live_externals) is a live scanner Agent that is active, not revoked and heard from within LIVE_WINDOW, other than the built-in one; a
            # database from before the built-in scanner has none, so the same filter, read with a count (it names only the columns every schema has), is the answer.
            from agentapi.models import Agent
            count = Agent.objects.filter(kind='scanner', status='active', token__revoked=False,
                                         last_seen__gte=timezone.now() - sentinel_broker.LIVE_WINDOW).count()
        self.stdout.write(f'EXTERNAL_SENTINELS_LIVE {count}')
