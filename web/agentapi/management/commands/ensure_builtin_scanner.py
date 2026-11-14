from django.core.management.base import BaseCommand

from agentapi import builtin_scanner


class Command(BaseCommand):
    help = "Keep the built-in scanner's enrollment ready (CVENGINE_BUILTIN_SCANNER=1) and print where it stands."

    def handle(self, *args, **options):
        out = builtin_scanner.ensure()
        self.stdout.write(f"built-in scanner: {out['state']}")
