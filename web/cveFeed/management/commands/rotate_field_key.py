import base64
import os

from django.core.management.base import BaseCommand, CommandError

from reNgine import crypto_fields


class Command(BaseCommand):
    help = ('Re-encrypt every stored secret (API keys, webhook URLs, the update token, TOTP seeds) under the current dedicated key. '
            'Set CVENGINE_FIELD_KEY to the new key and put the old one in CVENGINE_FIELD_KEY_PREVIOUS first. '
            '--generate prints a new random key and does nothing else.')

    def add_arguments(self, parser):
        parser.add_argument('--generate', action='store_true', help='print a new key')

    def handle(self, *args, **options):
        if options['generate']:
            self.stdout.write(base64.urlsafe_b64encode(os.urandom(32)).decode())
            return
        if not crypto_fields.dedicated_keys():
            raise CommandError('CVENGINE_FIELD_KEY is not set: there is no dedicated key to re-encrypt under. '
                               'Run with --generate, put the result in .env as CVENGINE_FIELD_KEY, restart, then run this again.')
        rows = 0
        for model, names in crypto_fields.encrypted_fields():
            manager = getattr(model, '_base_manager')
            for row in manager.all().iterator():
                row.save(update_fields=names)  # read through the old key, written under the new one
                rows += 1
        self.stdout.write(f'{rows} row(s) re-encrypted. Once every container runs with the new key, remove CVENGINE_FIELD_KEY_PREVIOUS.')
