import base64
import os

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from cvengine import crypto_fields


class Command(BaseCommand):
    help = ('Re-encrypt every stored secret (API keys, webhook URLs, the update token, TOTP seeds) under the current dedicated key. '
            'Set CVENGINE_FIELD_KEY to the new key and put the old one in CVENGINE_FIELD_KEY_PREVIOUS first. '
            '--generate prints a new random key and does nothing else. '
            '--check changes nothing: it counts the stored secrets by the key that reads them and fails when one cannot be read.')

    def add_arguments(self, parser):
        parser.add_argument('--generate', action='store_true', help='print a new key')
        parser.add_argument('--check', action='store_true',
                            help='count stored secrets by the key that reads them; fail when one cannot be read')
        parser.add_argument('--strict', action='store_true',
                            help='with --check: also fail when a secret reads only with an older key (one that is about to be removed)')

    def handle(self, *args, **options):
        if options['generate']:
            self.stdout.write(base64.urlsafe_b64encode(os.urandom(32)).decode())
            return
        if options['check']:
            self._check(options['strict'])
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

    def _check(self, strict):
        """Reads the raw column values of every encrypted field (the plaintext is never printed) and sorts them by the key that decrypts them."""
        counts = {'current': 0, 'older': 0, 'unreadable': 0}
        where = {'older': set(), 'unreadable': set()}
        quote = connection.ops.quote_name
        for model, names in crypto_fields.encrypted_fields():
            for name in names:
                column, table = quote(model._meta.get_field(name).column), quote(model._meta.db_table)
                with connection.cursor() as cursor:
                    cursor.execute(f'SELECT {column} FROM {table} WHERE {column} IS NOT NULL')
                    for (raw,) in cursor.fetchall():
                        state = crypto_fields.stored_value_state(raw)
                        if state in counts:
                            counts[state] += 1
                        if state in where:
                            where[state].add(f'{model._meta.label}.{name}')
        self.stdout.write(f"Stored secrets: {counts['current']} under the current key, {counts['older']} under an older key, "
                          f"{counts['unreadable']} unreadable.")
        for state in ('unreadable', 'older'):
            if where[state]:
                self.stdout.write(f'{state.capitalize()} values in: {", ".join(sorted(where[state]))}')
        if counts['unreadable']:
            raise CommandError(f"{counts['unreadable']} stored secret(s) cannot be decrypted with any key this container has.")
        if strict and counts['older']:
            raise CommandError(f"{counts['older']} stored secret(s) still need an older key: run rotate_field_key before removing it.")
