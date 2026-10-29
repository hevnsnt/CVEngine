from django.core import serializers
from django.core.management.base import BaseCommand
from django.core.management.color import no_style
from django.db import IntegrityError, connection, transaction


class Command(BaseCommand):
    help = ('Adds the rows of the given fixture files that the database does not have yet (matched by primary key). A row that is already there '
            'is never touched, so an administrator\'s edit to a built-in scan engine survives every restart. loaddata, which this replaces in '
            'the celery entrypoint, overwrote every field of every row at every start.')

    def add_arguments(self, parser):
        parser.add_argument('fixtures', nargs='+', help='fixture files (the format is read from the content: they are YAML or JSON)')

    def handle(self, *args, **options):
        added, kept, skipped, models = 0, 0, 0, set()
        for path in options['fixtures']:
            with open(path, encoding='utf-8') as handle:
                rows = list(serializers.deserialize('yaml', handle))
            for row in rows:
                model, pk = row.object.__class__, row.object.pk
                if model._default_manager.filter(pk=pk).exists():
                    kept += 1
                    continue
                try:
                    with transaction.atomic():
                        row.save()
                except IntegrityError as exc:  # e.g. an administrator's own row already uses the name: leave it, and say so
                    skipped += 1
                    self.stderr.write(f'Not adding {model._meta.label} {pk} from {path}: {exc}')
                    continue
                added += 1
                models.add(model)
        if models:  # rows saved with explicit keys do not move the sequences, as loaddata does after it
            with connection.cursor() as cursor:
                for statement in connection.ops.sequence_reset_sql(no_style(), models):
                    cursor.execute(statement)
        self.stdout.write(f'Default fixtures: {added} added, {kept} already present and left as they are, {skipped} skipped.')
