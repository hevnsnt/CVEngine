import json

from django.core.management.base import BaseCommand, CommandError

from agentapi import fleet_token


class Command(BaseCommand):
    help = ("Hosted mode only (CVENGINE_HOSTED=1): create or rotate the least-privilege external Sentinel identity and token of the scanner fleet and print one "
            "JSON line on stdout; the token is in that line and is never shown again. --revoke, --disable and --enable end, suspend and resume it. "
            "Refuses to run when hosted mode is off. Nothing but that JSON line goes to stdout.")

    def add_arguments(self, parser):
        what = parser.add_mutually_exclusive_group()
        what.add_argument('--revoke', action='store_true', help='Revoke the token and the fleet Agent for good (a later run issues a new one).')
        what.add_argument('--disable', action='store_true', help='Suspend the fleet: its token stops working until --enable.')
        what.add_argument('--enable', action='store_true', help='Resume a fleet that --disable suspended.')
        parser.add_argument('--user', default='', help='The App Admin the token belongs to (default: the oldest active App Admin).')
        parser.add_argument('--max-concurrent', type=int, default=fleet_token.DEFAULT_CONCURRENCY, help='Tasks the fleet identity may hold at once (1 to 10).')

    def handle(self, *args, **opts):
        if not fleet_token.hosted_enabled():
            raise CommandError('hosted mode is off (CVENGINE_HOSTED is not set): ensure_fleet_token only runs on a hosted server')
        try:
            if opts['revoke']:
                out = fleet_token.revoke()
            elif opts['disable']:
                out = fleet_token.disable()
            elif opts['enable']:
                out = fleet_token.enable()
            else:
                out = fleet_token.ensure(username=opts['user'] or None, max_concurrent=opts['max_concurrent'])
        except fleet_token.FleetError as exc:
            raise CommandError(str(exc))
        self.stdout.write(json.dumps(out, separators=(',', ':')))
