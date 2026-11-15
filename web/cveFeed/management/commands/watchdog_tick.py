import json
import os
import threading

from django.core.management.base import BaseCommand
from django.db import connection

from cveFeed import watchdog

HARD_SECONDS = watchdog.TICK_SECONDS + 8  # the tick ends itself at TICK_SECONDS; this is for a call blocked where Python cannot interrupt it


def self_destruct(seconds=HARD_SECONDS):
    """Kill this process after ``seconds`` whatever it is blocked in (a database or broker call stuck in C code ignores the tick's own alarm). The host
    script (``timeout``) is a third bound around both."""
    timer = threading.Timer(seconds, lambda: os._exit(3))
    timer.daemon = True
    timer.start()
    return timer


class Command(BaseCommand):
    help = ('One pass of the outer watchdog (docs/WATCHDOG.md): take a snapshot of the instance, apply the rules, record what it did. Run by '
            'scripts/watchdog.sh every 30 seconds in the web container; it never uses Celery and always ends within a bounded time.')

    def handle(self, *args, **options):
        age = watchdog.process_age_seconds()
        budget = watchdog.tick_budget(age)
        if budget is None:  # Django took nearly all of the command's time to load: a tick now would be killed half way and leave no word of why
            self.stdout.write(json.dumps({'ok': False, 'acted': [], 'startup_seconds': round(age, 1), 'seconds': 0,
                                          'skipped': f'the web container took {age:.0f} s to start this command (it must end within {watchdog.PROCESS_SECONDS} s), so this tick did nothing'}))
            return
        limit, hard = budget
        timer = self_destruct(hard)
        try:
            if connection.vendor == 'postgresql':
                with connection.cursor() as cur:
                    cur.execute('SET statement_timeout = 5000')
            out = watchdog.tick(limit=limit)
        finally:
            timer.cancel()
        out['startup_seconds'] = round(age, 1)
        self.stdout.write(json.dumps(out, default=str))
