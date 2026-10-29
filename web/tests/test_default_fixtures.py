from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase

from scanEngine.models import EngineType, InstalledExternalTool

FIXTURES = [str(Path(__file__).resolve().parent.parent / 'fixtures' / name)
            for name in ('default_scan_engines.yaml', 'external_tools.yaml')]


def load():
    out = StringIO()
    call_command('load_default_fixtures', *FIXTURES, stdout=out, stderr=StringIO())
    return out.getvalue()


class LoadDefaultFixturesTests(TestCase):
    """The celery entrypoint runs this at every start. loaddata, which it used to run, rewrote every field of every row each time, so an
    administrator's edit to a built-in scan engine came back as the fixture's text after any restart or update."""

    def setUp(self):
        EngineType.objects.all().delete()
        InstalledExternalTool.objects.all().delete()

    def test_an_empty_install_gets_the_defaults(self):
        self.assertIn('9 added', load())
        self.assertEqual(EngineType.objects.count(), 6)
        self.assertEqual(InstalledExternalTool.objects.count(), 3)
        self.assertTrue(EngineType.objects.filter(default_engine=True).exists())

    def test_an_edited_default_engine_survives_a_second_load(self):
        load()
        engine = EngineType.objects.order_by('id').first()
        engine.yaml_configuration = 'port_scan: {}\n# edited by an administrator\n'
        engine.engine_name = 'My own name'
        engine.save()
        load()
        engine.refresh_from_db()
        self.assertEqual(engine.engine_name, 'My own name')
        self.assertIn('edited by an administrator', engine.yaml_configuration)
        self.assertEqual(EngineType.objects.count(), 6)

    def test_a_default_the_install_does_not_have_yet_is_added_without_touching_the_others(self):
        load()
        gone = EngineType.objects.order_by('id').last()
        kept = EngineType.objects.order_by('id').first()
        kept.engine_name = 'Renamed'
        kept.save()
        gone.delete()
        output = load()
        self.assertIn('1 added', output)
        self.assertEqual(EngineType.objects.count(), 6)
        kept.refresh_from_db()
        self.assertEqual(kept.engine_name, 'Renamed')

    def test_rows_added_with_their_own_keys_do_not_leave_the_sequence_behind(self):
        load()
        fresh = EngineType.objects.create(engine_name='Created later', yaml_configuration='{}')
        self.assertGreater(fresh.pk, 6)
