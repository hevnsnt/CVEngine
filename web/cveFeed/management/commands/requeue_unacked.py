from django.core.management.base import BaseCommand

from cveFeed.broker_recovery import requeue_unacked


class Command(BaseCommand):
    help = ('Return the broker messages a killed worker took and never acknowledged to their queues. The worker container runs it '
            'before its workers start (see cveFeed.broker_recovery).')

    def handle(self, *args, **options):
        self.stdout.write(f'Returned {requeue_unacked()} unacknowledged message(s) to their queues')
