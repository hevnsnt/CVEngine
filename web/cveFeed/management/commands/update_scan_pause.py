"""Request or release the drain pause scripts/apply-update.sh holds while an update is applied.

    python3 manage.py update_scan_pause --request [--reason "..."]
    python3 manage.py update_scan_pause --release

Exits 0 either way; prints "ok" so the calling shell script can tell the command ran without
needing to parse Django's own output.
"""
from django.core.management.base import BaseCommand, CommandError

from cveFeed.scan_control import release_update_pause, request_drain_pause


class Command(BaseCommand):
    help = "Request or release the drain pause an update applies while it is running."

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--request", action="store_true", help="Pause new scan dispatch for an update to drain into.")
        group.add_argument("--release", action="store_true", help="Release a pause this command previously requested.")
        parser.add_argument("--reason", default="An update is being applied", help="Shown in the admin's Scan control panel while paused.")

    def handle(self, *args, **opts):
        try:
            if opts["request"]:
                request_drain_pause(reason=opts["reason"])
            else:
                release_update_pause()
        except RuntimeError as exc:
            raise CommandError(str(exc))
        self.stdout.write(self.style.SUCCESS("ok"))
