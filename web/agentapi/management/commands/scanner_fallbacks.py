from django.core.management.base import BaseCommand, CommandError

from agentapi import scanner_fallback
from agentapi.models import SentinelTask


class Command(BaseCommand):
    help = ("Count the times a scan stage ran its tool on this server instead of a Sentinel (the telemetry that gates deleting a local scan path), "
            "by kind and reason over the last N days, with when each kind last did.")

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=scanner_fallback.STATUS_DAYS, help='how many days back to count (default %(default)s)')
        parser.add_argument('--kind', default='', help='only this task kind (one of the Sentinel task kinds)')

    def handle(self, *args, **options):
        days, kind = options['days'], (options['kind'] or '').strip()
        if days < 1:
            raise CommandError('--days must be at least 1')
        if kind and kind not in SentinelTask.KINDS:
            raise CommandError(f'unknown kind {kind!r}; valid kinds: {", ".join(SentinelTask.KINDS)}')
        found = scanner_fallback.counts(days, kind or None)
        last = scanner_fallback.last_at(kind or None)
        kinds = [kind] if kind else [k for k in SentinelTask.KINDS if k not in scanner_fallback.NO_STAGE]
        self.stdout.write(f'Local fallbacks in the last {days} day(s):')
        for k in kinds:
            row = found.get(k)
            when = last.get(k)
            seen = f', last {when.isoformat()}' if when else ', never recorded'
            self.stdout.write(f'  {k}: {row["count"] if row else 0}{seen}')
            if row:
                for reason in scanner_fallback.REASONS:
                    if reason in row['reasons']:
                        self.stdout.write(f'    {reason}: {row["reasons"][reason]}')
        total = sum(row['count'] for row in found.values())
        self.stdout.write(f'Total: {total}')
