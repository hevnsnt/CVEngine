"""One port row per port of an address (docs/UPGRADE.md, Duplicate rows merged before unique constraints).

* ``Port.ip_address`` names the address a port row belongs to, and ``uniq_port_ip_number_proto`` refuses a second row of the same
  (address, number, protocol).
* Two writers that find the same new port at the same moment store one row: the second insert waits for the first writer's commit, is
  refused, and the second writer uses the first one's row (``startScan.port_rows.create_ports``).
* Migration 0036 merges the duplicates stored before onto the oldest row of each group, and the address keeps its link to it."""
import importlib
import threading
import time
from types import SimpleNamespace
from unittest import mock

from django.apps import apps
from django.db import IntegrityError, connection, transaction
from django.test import TransactionTestCase

from cveFeed import port_inventory
from reNgine import discovery_events as bbot_lib
from reNgine.common_func import update_or_create_port
from reNgine.tasks import persist_bbot_result
from startScan.models import IpAddress, Port
from tests.test_bbot_batch_equivalence import Fixture as EquivalenceFixture

MIGRATION = 'startScan.migrations.0036_uniq_port_ip_number'
CONSTRAINT = 'uniq_port_ip_number_proto'
ADDRESS = '192.0.2.40'


def race(first, second):
    """Run ``first`` in a transaction that stays open while ``second`` runs: ``second`` reads before ``first`` commits (it finds no port),
    and its insert of the same port waits on ``first``'s row until ``first`` commits. Returns the errors either raised."""
    stored, release, errors = threading.Event(), threading.Event(), []

    def run_first():
        try:
            with transaction.atomic():
                first()
                stored.set()
                release.wait(10)
        except Exception as exc:  # noqa: BLE001 - reported to the test
            errors.append(exc)
        finally:
            stored.set()
            connection.close()

    def run_second():
        try:
            second()
        except Exception as exc:  # noqa: BLE001 - reported to the test
            errors.append(exc)
        finally:
            connection.close()

    a = threading.Thread(target=run_first)
    a.start()
    stored.wait(10)
    b = threading.Thread(target=run_second)
    b.start()
    time.sleep(0.5)  # the second writer has read and is waiting on the first one's uncommitted row
    release.set()
    a.join(20)
    b.join(20)
    return errors


def refused_inserts():
    """A spy on the insert of one port that ``create_ports`` falls back to when the database refused the batch (another writer stored the key)."""
    from startScan import port_rows
    return mock.patch.object(port_rows, '_create_one', wraps=port_rows._create_one)


def nmap(address=ADDRESS, number=443, **rec):
    return lambda: port_inventory.persist_inventory([{'ip': address, 'ports': [{'number': number, 'state': 'open', 'service_name': 'https', **rec}]}])


def bbot(address=ADDRESS, number=443):
    return lambda: persist_bbot_result(bbot_lib.BbotResult(ports={(address, number)}), ctx={})


class Base(TransactionTestCase):
    def setUp(self):
        self.ip = IpAddress.objects.create(address=ADDRESS)

    def rows(self, ip=None, number=443):
        return list((ip or self.ip).ports.filter(number=number).order_by('id'))


class ConstraintTests(Base):
    def test_the_constraint_exists_and_refuses_a_second_row_of_a_port(self):
        with connection.cursor() as cursor:
            cursor.execute('SELECT contype FROM pg_constraint WHERE conname = %s', [CONSTRAINT])
            self.assertEqual(cursor.fetchone(), ('u',))
        Port.objects.create(ip_address=self.ip, number=443, protocol='tcp')
        with self.assertRaises(IntegrityError), transaction.atomic():
            Port.objects.create(ip_address=self.ip, number=443, protocol='tcp')
        Port.objects.create(ip_address=self.ip, number=443, protocol='udp')  # UDP 443 is another service
        Port.objects.create(ip_address=IpAddress.objects.create(address='192.0.2.41'), number=443, protocol='tcp')  # another address
        Port.objects.create(number=443, protocol='tcp')
        Port.objects.create(number=443, protocol='tcp')  # rows with no address are not covered

    def test_every_writer_names_the_address(self):
        nmap()()
        bbot(number=80)()
        update_or_create_port(22, service_name='ssh', ip=self.ip)
        self.assertEqual(sorted(self.ip.ports.values_list('number', 'ip_address_id')), [(22, self.ip.pk), (80, self.ip.pk), (443, self.ip.pk)])


class RacingWriterTests(Base):
    def test_an_nmap_report_and_a_bbot_batch_racing_store_one_port(self):
        with refused_inserts() as one:
            errors = race(nmap(product='nginx', version='1.24.0'), bbot())
        self.assertEqual(errors, [])
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertTrue(one.called)  # the bbot insert was refused and it took the stored row
        self.assertEqual((rows[0].product, rows[0].version, rows[0].source), ('nginx', '1.24.0', 'nmap'))  # bbot wrote only the time it saw it
        self.assertEqual(rows[0].ip_address_id, self.ip.pk)

    def test_two_nmap_reports_racing_store_one_port_with_the_later_fingerprint(self):
        with refused_inserts() as one:
            errors = race(nmap(product='nginx', version='1.24.0', method='probed'), nmap(product='nginx', version='1.26.1', method='probed'))
        self.assertEqual(errors, [])
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertTrue(one.called)
        self.assertEqual(rows[0].version, '1.26.1')  # what a second report of a port it found would write

    def test_a_sweep_that_loses_the_race_keeps_the_fingerprint(self):
        errors = race(nmap(product='nginx', version='1.24.0', method='probed'), nmap(service_name='https'))
        self.assertEqual(errors, [])
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].product, rows[0].version), ('nginx', '1.24.0'))

    def test_update_or_create_port_that_loses_the_race_returns_the_stored_row(self):
        errors, out = [], {}

        def second():
            out['port'], out['created'] = update_or_create_port(443, service_name='https', ip=IpAddress.objects.get(pk=self.ip.pk))
        errors = race(bbot(), second)
        self.assertEqual(errors, [])
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual((out['port'].pk, out['created']), (rows[0].pk, False))


class RepeatedIngestTests(Base):
    def test_one_scan_batch_ingested_twice_at_once_and_again_stores_each_port_once(self):
        """A redelivered batch runs while the first delivery is still writing, and a resumed stage stores it a third time."""
        batch = lambda: persist_bbot_result(bbot_lib.BbotResult(ports={(ADDRESS, 80), (ADDRESS, 443), (ADDRESS, 8443)}), ctx={})  # noqa: E731
        self.assertEqual(race(batch, batch), [])
        batch()
        nmap(number=443)()
        counts = sorted((n, self.ip.ports.filter(number=n).count()) for n in (80, 443, 8443))
        self.assertEqual(counts, [(80, 1), (443, 1), (8443, 1)])
        self.assertEqual(Port.objects.count(), 3)


class SharedRowTests(Base):
    def test_an_address_that_leaves_a_shared_row_gets_its_own(self):
        other = IpAddress.objects.create(address='192.0.2.41')
        shared = Port.objects.create(ip_address=self.ip, number=443, protocol='tcp', product='apache')
        self.ip.ports.add(shared)
        other.ports.add(shared)
        nmap(product='nginx')()
        own = self.rows()
        self.assertEqual(len(own), 1)
        self.assertNotEqual(own[0].pk, shared.pk)
        self.assertEqual((own[0].product, own[0].ip_address_id), ('nginx', self.ip.pk))
        shared.refresh_from_db()
        self.assertEqual((shared.product, shared.ip_address_id), ('apache', None))
        self.assertEqual(list(other.ports.all()), [shared])


class MergeTests(TransactionTestCase):
    """The data step of startScan 0036, run on rows stored as before it: no address on the row, duplicates allowed."""

    def merged(self, build):
        model_constraint = next(c for c in Port._meta.constraints if c.name == CONSTRAINT)
        with connection.schema_editor() as editor:
            editor.remove_constraint(Port, model_constraint)
        try:
            out = build()
            Port.objects.update(ip_address=None)
            with transaction.atomic():
                importlib.import_module(MIGRATION).merge_duplicate_ports(apps, SimpleNamespace(connection=connection))
        finally:
            with connection.schema_editor() as editor:
                editor.add_constraint(Port, model_constraint)  # fails if a duplicate was left
        return out

    def test_the_oldest_row_stays_and_the_address_keeps_one_link_to_it(self):
        def build():
            a, b = IpAddress.objects.create(address='192.0.2.50'), IpAddress.objects.create(address='192.0.2.51')
            out = {'a': a, 'b': b}
            for name, ip, number, protocol, product in (('a80', a, 80, 'tcp', 'nginx'), ('a80copy', a, 80, 'tcp', 'Amazon CloudFront'),
                                                         ('a443', a, 443, '', ''), ('a443copy', a, 443, 'tcp', 'apache'),
                                                         ('a53udp', a, 53, 'udp', ''), ('a53tcp', a, 53, 'tcp', ''), ('b80', b, 80, 'tcp', 'caddy')):
                out[name] = Port.objects.create(number=number, protocol=protocol, product=product)
                ip.ports.add(out[name])
            out['shared'] = Port.objects.create(number=22, protocol='tcp', product='OpenSSH')
            a.ports.add(out['shared'])
            b.ports.add(out['shared'])
            return out
        out = self.merged(build)
        a, b = out['a'], out['b']
        self.assertEqual(sorted(a.ports.values_list('pk', flat=True)),
                         sorted(out[k].pk for k in ('a80', 'a443', 'a53udp', 'a53tcp', 'shared')))
        self.assertFalse(Port.objects.filter(pk__in=[out['a80copy'].pk, out['a443copy'].pk]).exists())
        kept = Port.objects.get(pk=out['a80'].pk)
        self.assertEqual(kept.product, 'nginx')  # a copy's columns are not taken over
        self.assertEqual(Port.objects.get(pk=out['a443'].pk).protocol, 'tcp')  # empty was TCP
        self.assertEqual(IpAddress.ports.through.objects.filter(ipaddress_id=a.pk, port_id=kept.pk).count(), 1)
        b_ports = {p.number: p for p in b.ports.all()}
        self.assertEqual(sorted(b_ports), [22, 80])
        self.assertEqual(b_ports[80].pk, out['b80'].pk)  # another address's row of the same number is its own
        self.assertNotEqual(b_ports[22].pk, out['shared'].pk)  # a shared row: the second address gets a copy
        self.assertEqual(b_ports[22].product, 'OpenSSH')
        self.assertEqual(set(Port.objects.filter(ports=a).values_list('ip_address_id', flat=True)), {a.pk})
        self.assertEqual(set(Port.objects.filter(ports=b).values_list('ip_address_id', flat=True)), {b.pk})

    def test_running_the_merge_again_changes_nothing(self):
        def build():
            a = IpAddress.objects.create(address='192.0.2.52')
            for product in ('one', 'two'):
                a.ports.add(Port.objects.create(number=80, protocol='tcp', product=product))
            return {'a': a}
        out = self.merged(build)
        before = list(Port.objects.order_by('id').values_list('id', 'ip_address_id', 'number', 'protocol', 'product'))
        with transaction.atomic():
            importlib.import_module(MIGRATION).merge_duplicate_ports(apps, SimpleNamespace(connection=connection))
        self.assertEqual(list(Port.objects.order_by('id').values_list('id', 'ip_address_id', 'number', 'protocol', 'product')), before)
        self.assertEqual(list(out['a'].ports.values_list('product', flat=True)), ['one'])

    def test_the_migration_builds_the_index_concurrently_outside_a_transaction(self):
        migration = importlib.import_module(MIGRATION).Migration
        self.assertFalse(migration.atomic)
        self.assertEqual(migration.dependencies, [('startScan', '0035_uniq_cweid_name')])
        sql = ' '.join(str(op.sql) for op in migration.operations[2].database_operations)
        self.assertIn('CREATE UNIQUE INDEX CONCURRENTLY', sql)
        self.assertIn('UNIQUE USING INDEX', sql)


class DiscoveryBatchTests(EquivalenceFixture):
    def test_every_port_a_discovery_batch_creates_names_its_address(self):
        """The batch fixture reaches both bbot port writers: listed ports, and ports only an HTTP answer revealed (8443, 9443, 8080)."""
        before = set(Port.objects.values_list('pk', flat=True))
        for batch in self.batches():
            persist_bbot_result(batch, ctx=dict(self.ctx))
        new = {link.port_id: link.ipaddress_id for link in IpAddress.ports.through.objects.exclude(port_id__in=before)}
        self.assertTrue({8443, 9443, 8080} <= set(Port.objects.filter(pk__in=new).values_list('number', flat=True)))
        self.assertEqual({pk: ip for pk, ip in Port.objects.filter(pk__in=new).values_list('pk', 'ip_address_id')}, new)
