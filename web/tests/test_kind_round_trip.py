"""Every Sentinel task kind, end to end through the real report path: the contract fixture of the kind is handed out by the real broker (claim, accept),
reported the way a Sentinel reports it, stored, and read back. One subtest per kind of ``sentinel_contract.KINDS``, so a kind added to the contract is in
this test the day it is added.

For each kind: the task ends ``done`` (not dropped by the address guard, not rejected by the schema), the stored result is still a valid result of the
contract, and a second delivery of the same report (a Sentinel whose answer was lost retries it) is a duplicate that writes no row anywhere. For a kind
that files its result itself when nothing waits for it any more (``sentinel_adopt``), filing the same result twice leaves the database as the first
filing left it: the natural keys hold (one host per name, one port per address and number, one technology per name, one finding per template and
place), and the first filing wrote the rows the result names.

Addresses are documentation ranges only (192.0.2.0/24, 2001:db8::/32) and the names are example names."""
import json
from pathlib import Path
from django.apps import apps
from django.core.cache import cache
from django.test import override_settings
from jsonschema import Draft202012Validator

from agentapi import address_guard, sentinel_adopt
from agentapi import sentinel_broker as broker
from agentapi import sentinel_contract as contract
from agentapi.models import SentinelTask
from cveFeed import exclusions
from startScan.models import IpAddress, Port, Subdomain
from tests.fake_scanner import SHARED_FIXTURE, FakeScanner, fixture
from tests.test_address_guard import World

TARGETS = Path(__file__).with_name('fixtures') / 'sentinel_targets'
PARTIAL = json.loads((Path(__file__).with_name('fixtures') / 'sentinel_partials' / 'bbot_discovery.json').read_text())
BUILTIN_DENIED = {'openvas'}  # the built-in scanner does not run OpenVAS until an administrator says so (sentinel_policy.SHIPPED_BUILTIN): an external Sentinel serves it
SERVER_KEYS = ('dropped',)  # what the server adds to a stored result itself: how many entries it held to the task's own targets
NAME_ADDRESS = '192.0.2.99'  # where every name a target names resolves: on no do-not-scan list
# rows that a duplicate report may still touch without filing anything (who asked, when)
VOLATILE = {'dashboard.auditlog', 'cvefeed.agentactivity', 'agentapi.agent', 'dashboard.apitoken'}
# kinds whose adopter must write rows from its contract fixture (``sentinel_adopt``)
FILES_ROWS = {'nmap': (Port, 1), 'naabu': (Port, 1)}


def target_of(kind):
    return json.loads((TARGETS / f'{SHARED_FIXTURE.get(kind, kind)}.json').read_text())


def snapshot():
    """``{model label: row count}`` of every table, the volatile ones left out, in a stable order."""
    out = {}
    for model in sorted(apps.get_models(include_auto_created=True), key=lambda m: m._meta.label_lower):
        label = model._meta.label_lower
        if label in VOLATILE or not model._meta.managed:
            continue
        out[label] = model._base_manager.count()
    return out


def changed(before, after):
    return {k: (before.get(k), after.get(k)) for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k)}


@override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})
class EveryKindRoundTrip(World):
    def setUp(self):
        super().setUp()
        exclusions._bump() if hasattr(exclusions, '_bump') else None
        builtin_kinds = [k for k in contract.KINDS if k not in BUILTIN_DENIED]
        self.fake = FakeScanner(kinds=builtin_kinds, responders={k: self.streamed for k in contract.STREAMED}).start_for(self)
        self.outside = FakeScanner(kinds=sorted(BUILTIN_DENIED), external=True, scope={'projects': [self.project.slug]}).start_for(self)

    def streamed(self, task):
        """A streamed kind posts its batches while it runs, then the result that closes it names how many it sent."""
        from agentapi import sentinel_stream
        result = fixture(task['kind'])
        for seq in range(1, result['partials'] + 1):
            answer = sentinel_stream.report_partial(self.fake._ctx(), task['id'], {**PARTIAL, 'seq': seq})
            self.assertTrue(answer.get('accepted') or answer.get('duplicate'), answer)
        return result

    def known(self, kind, target):
        """Give every name the task connects to a stored address, as discovery would have: a name with no known address waits at the claim."""
        for value in address_guard.task_values(kind, target):
            if exclusions.as_address(value) or '/' in value:
                continue
            name = exclusions.normalize(value)
            if name and not Subdomain.objects.filter(name=name).exists():
                sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=name)
                sub.ip_addresses.add(IpAddress.objects.get_or_create(address=NAME_ADDRESS, org=self.org)[0])  # addresses are per organization, as ingest keeps them

    def ips_of(self, target):
        listed = target.get('addresses') if isinstance(target.get('addresses'), list) else []
        single = [target['address']] if isinstance(target.get('address'), str) else []
        return [a for a in [*listed, *single] if exclusions.as_address(a)]

    def served(self, kind):
        target = target_of(kind)
        self.known(kind, target)
        cache.clear()  # the claim rate limit: one fake serves every kind in one test
        task = SentinelTask.objects.create(project=self.project, kind=kind, target=target, ips=self.ips_of(target), scan=self.scan)
        fake = self.outside if kind in BUILTIN_DENIED else self.fake
        entry = fake.serve_once()
        self.assertIsNotNone(entry, f'{kind}: the task was never handed out')
        self.served_by = fake
        self.assertEqual(entry['id'], task.pk)
        task.refresh_from_db()
        return task, entry

    def test_every_kind_is_stored_in_contract_and_a_second_delivery_writes_nothing(self):
        self.assertEqual(sorted(self.fake.kinds + self.outside.kinds), sorted(contract.KINDS))
        for kind in contract.KINDS:
            with self.subTest(kind=kind):
                task, entry = self.served(kind)
                self.assertEqual(task.status, 'done', f'{kind}: {task.error}')
                stored = {k: v for k, v in task.result.items() if k not in SERVER_KEYS}
                errors = sorted(Draft202012Validator(contract.result_schema(kind)).iter_errors(stored), key=lambda e: list(e.path))
                self.assertEqual([e.message for e in errors], [], f'{kind}: the stored result left the contract')
                before = snapshot()
                again = broker.report_result(self.served_by._ctx(), task.pk, entry['result'])
                self.assertTrue(again['duplicate'], kind)
                self.assertEqual(changed(before, snapshot()), {}, f'{kind}: a second delivery wrote rows')

    def test_a_result_filed_twice_by_its_adopter_lands_once(self):
        for kind in contract.KINDS:
            if not sentinel_adopt.has_adopter(kind):
                continue
            with self.subTest(kind=kind):
                task, _ = self.served(kind)
                self.assertEqual(task.status, 'done', f'{kind}: {task.error}')
                start = snapshot()
                first = sentinel_adopt.adopt(task, task.result, self.served_by.agent)
                self.assertTrue(first.get('adopted'), f'{kind}: {first}')
                after_first = snapshot()
                if kind in FILES_ROWS:
                    model, least = FILES_ROWS[kind]
                    grew = after_first[model._meta.label_lower] - start[model._meta.label_lower]
                    self.assertGreaterEqual(grew, least, f'{kind}: the adopter filed nothing of its fixture')
                second = sentinel_adopt.adopt(task, task.result, self.served_by.agent)
                self.assertTrue(second.get('adopted'), f'{kind}: {second}')
                self.assertEqual(changed(after_first, snapshot()), {}, f'{kind}: filing the same result again wrote rows')

    def test_the_natural_keys_hold_after_every_kind_was_filed(self):
        for kind in contract.KINDS:
            task, _ = self.served(kind)
            if task.status == 'done' and sentinel_adopt.has_adopter(kind):
                sentinel_adopt.adopt(task, task.result, self.served_by.agent)
                sentinel_adopt.adopt(task, task.result, self.served_by.agent)
        from django.db.models import Count
        from django.db.models.functions import Lower
        dup_hosts = (Subdomain.objects.annotate(n=Lower('name')).values('scan_history', 'target_domain', 'n').annotate(c=Count('id')).filter(c__gt=1))
        self.assertEqual(list(dup_hosts), [])
        dup_addresses = IpAddress.objects.values('address', 'org').annotate(c=Count('id')).filter(c__gt=1)
        self.assertEqual(list(dup_addresses), [])
        dup_ports = Port.objects.exclude(ip_address=None).values('ip_address', 'number', 'protocol').annotate(c=Count('id')).filter(c__gt=1)
        self.assertEqual(list(dup_ports), [])
        from startScan.models import Technology, Vulnerability
        self.assertEqual(list(Technology.objects.annotate(n=Lower('name')).values('n').annotate(c=Count('id')).filter(c__gt=1)), [])
        dup_findings = (Vulnerability.objects.values('subdomain', 'template_id', 'http_url', 'name').annotate(c=Count('id')).filter(c__gt=1))
        self.assertEqual(list(dup_findings), [])
