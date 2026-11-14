"""Print how long each probe of the system status takes, from the web container: ``docker compose exec web python3 manage.py status_timings``.
Runs the same call as ``get_system_status`` as the first App Admin, prints seconds per probe (slowest first) and the problems it named, and exits."""
import time

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Print the seconds each probe of the system status took, and the problems it reported.'

    def handle(self, *args, **options):
        from agentapi import system_status
        from agentapi.services import Ctx
        admin = get_user_model().objects.filter(is_superuser=True, is_active=True).order_by('id').first()
        if admin is None:
            raise CommandError('there is no App Admin to run the status as')
        started = time.monotonic()
        out = system_status.system_status(Ctx(user=admin))
        timings = out['system']['timings']
        self.stdout.write(f"status answered in {time.monotonic() - started:.2f} s (budget {timings['budget_seconds']:g} s, {out['overall']})")
        for name, seconds in sorted(timings['probes'].items(), key=lambda item: -item[1]):
            self.stdout.write(f'  {seconds:8.3f} s  {name}' + ('  (did not finish)' if name in timings['not_finished'] else ''))
        for problem in out['problems']:
            self.stdout.write(f'problem: {problem}')
