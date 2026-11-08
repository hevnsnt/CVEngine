from django.core.management.base import BaseCommand

from agentapi import builtin_reviewer


class Command(BaseCommand):
    help = "Keep the AI reviewer container's token ready (docs/AI-REVIEWER.md) and print where it stands."

    def handle(self, *args, **options):
        out = builtin_reviewer.ensure()
        self.stdout.write(f"AI reviewer token: {out['state']}")
