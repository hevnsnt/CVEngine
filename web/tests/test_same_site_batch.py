"""The same-site hosts of a library probe's policy (``probe_scope._same_site_hosts``) look their holders up in batches (``manual_only.holders``).

The old code asked ``manual_only.other_holder`` once per candidate name: up to 2,000 names per page, two statements each, and again for every
page of the same site in one task (about 266,000 statements in five hours on a live install). The batched lookup must give exactly the answers
``other_holder`` gives, ask the do-not-scan gate about exactly the same names, and cost a number of statements that does not grow with the
number of hosts a site has.
"""
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import js_libraries, manual_only, probe_scope
from cveFeed.models import HostExclusion, HostState
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain


def old_same_site_hosts(project_id, sub, gate):
    """``probe_scope._same_site_hosts`` as it was before the batch lookup: ``other_holder`` once per name."""
    from startScan.models import Subdomain
    target = getattr(sub, 'target_domain', None)
    if target is None or target.is_host_scoped() or js_libraries._held_back(target):
        return []
    site = js_libraries._site(sub.name)
    if not site:
        return []
    names = (Subdomain.objects.filter(target_domain__project_id=project_id, name__iendswith='.' + site)
             .exclude(target_domain__discovery_mode__in=(Domain.DISCOVERY_MANUAL, Domain.DISCOVERY_PASSIVE))
             .exclude(name__iexact=sub.name).values_list('name', flat=True).distinct()[:probe_scope.MAX_SAME_SITE * 2])
    out = []
    for name in dict.fromkeys(n.lower().rstrip('.') for n in names):
        if js_libraries._site(name) != site or gate.refusal(name):
            continue
        holder = manual_only.other_holder(project_id, name)
        if holder is None or js_libraries._held_back(holder):
            continue
        out.append(name)
        if len(out) >= probe_scope.MAX_SAME_SITE:
            break
    return out


class RecordingGate(probe_scope._Gate):
    """The real gate, recording every name it is asked about."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.asked = []

    def refusal(self, name):
        self.asked.append(name)
        return super().refusal(name)


class Fixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org = Org.objects.create(name='S', slug='ssb-org')
        cls.project = Project.objects.create(name='S', slug='ssb-proj', insert_date=now, org=cls.org)
        other = Project.objects.create(name='S2', slug='ssb-proj2', insert_date=now, org=Org.objects.create(name='S2', slug='ssb-org2'))
        mk = lambda name, mode=Domain.DISCOVERY_STANDARD, project=cls.project: Domain.objects.create(  # noqa: E731
            name=name, project=project, insert_date=now, discovery_mode=mode)
        cls.std = mk('example.test')
        cls.std2 = mk('two.example.test')
        cls.man = mk('man.example.test', Domain.DISCOVERY_MANUAL)
        cls.pas = mk('pas.example.test', Domain.DISCOVERY_PASSIVE)
        cls.own = mk('Own.Example.Test')  # a target's own name, mixed case, with no host row
        cls.man_own = mk('manown.example.test', Domain.DISCOVERY_MANUAL)  # a manual only target's own name, also a host row of a standard one
        cls.foreign = mk('example.test', project=other)  # another project's rows never answer
        rows = [
            ('www.example.test', cls.std), ('a.example.test', cls.std), ('B.Example.Test', cls.std),  # matches, one in mixed case
            ('m.example.test', cls.man),  # held only by a manual only target: a miss
            ('mx.example.test', cls.std), ('mx.example.test', cls.man),  # newest row manual only: the standard one answers
            ('p.example.test', cls.pas),  # held by a passive target only: found, then held back
            ('dup.example.test', cls.pas), ('dup.example.test', cls.std2),  # the newest non-manual row's target answers
            ('dup2.example.test', cls.std2), ('dup2.example.test', cls.pas),
            ('arch.example.test', cls.std), ('gone.example.test', cls.std),  # archived, excluded: the gate refuses them
            ('manown.example.test', cls.std),
            ('trail.example.test.', cls.std),  # stored with a trailing dot
            ('x.other.test', cls.std),  # another site
            ('f.example.test', cls.foreign),
        ]
        cls.subs = {}
        for name, domain in rows:
            cls.subs[(name, domain.pk)] = Subdomain.objects.create(name=name, target_domain=domain)
        HostState.objects.create(project=cls.project, domain=cls.std, host='arch.example.test', archived_at=now)
        HostExclusion.objects.create(org=cls.org, host='gone.example.test')

    def setUp(self):
        cache.clear()


class HoldersTests(Fixture):
    NAMES = ['www.example.test', 'A.EXAMPLE.TEST.', ' b.example.test ', 'm.example.test', 'mx.example.test', 'p.example.test', 'dup.example.test',
             'dup2.example.test', 'arch.example.test', 'gone.example.test', 'manown.example.test', 'own.example.test', 'OWN.example.test.',
             'man.example.test', 'pas.example.test', 'trail.example.test', 'trail.example.test.', 'x.other.test', 'f.example.test',
             'absent.example.test', 'example.test', '']

    def test_every_answer_is_the_one_other_holder_gives(self):
        want = {name.strip().lower().rstrip('.'): manual_only.other_holder(self.project.id, name) for name in self.NAMES}
        got = manual_only.holders(self.project.id, self.NAMES)
        self.assertEqual(got, want)
        self.assertEqual(got['mx.example.test'], self.std)
        self.assertEqual(got['dup.example.test'], self.std2)
        self.assertEqual(got['dup2.example.test'], self.pas)
        self.assertEqual(got['own.example.test'], self.own)
        self.assertEqual(got['manown.example.test'], self.std)
        self.assertIsNone(got['m.example.test'])
        self.assertIsNone(got['f.example.test'])
        self.assertIsNone(got['absent.example.test'])

    def test_answers_hold_across_chunks(self):
        want = manual_only.holders(self.project.id, self.NAMES)
        with mock.patch.object(manual_only, 'HOLDERS_CHUNK', 3):
            self.assertEqual(manual_only.holders(self.project.id, self.NAMES), want)

    def test_two_statements_per_chunk_whatever_the_number_of_names(self):
        with CaptureQueriesContext(connection) as few:
            manual_only.holders(self.project.id, self.NAMES[:3])
        with CaptureQueriesContext(connection) as many:
            manual_only.holders(self.project.id, self.NAMES + [f'n{i}.example.test' for i in range(900)])
        self.assertLessEqual(len(few), 2)
        self.assertEqual(len(many), 2)
        self.assertEqual(manual_only.holders(self.project.id, []), {})


class SameSiteEquivalenceTests(Fixture):
    def compare(self, sub):
        old_gate, new_gate = RecordingGate(self.project.id), RecordingGate(self.project.id)
        old = old_same_site_hosts(self.project.id, sub, old_gate)
        cache.clear()
        new = probe_scope._same_site_hosts(self.project.id, sub, new_gate)
        self.assertEqual(new, old, sub.name)
        self.assertEqual(new_gate.asked, old_gate.asked, sub.name)  # the gate is asked about the same names, in the same order
        return new

    def test_the_same_hosts_as_one_lookup_per_name(self):
        got = self.compare(self.subs[('www.example.test', self.std.pk)])
        self.assertEqual(set(got), {'a.example.test', 'b.example.test', 'mx.example.test', 'dup.example.test', 'manown.example.test'})
        for sub in self.subs.values():
            self.compare(sub)

    def test_the_same_hosts_when_the_cap_is_reached_part_way(self):
        for cap in (1, 2, 3, 4):
            with self.subTest(cap=cap), mock.patch.object(probe_scope, 'MAX_SAME_SITE', cap):
                self.assertEqual(len(self.compare(self.subs[('www.example.test', self.std.pk)])), cap)

    def test_a_shared_lookup_gives_the_same_hosts_for_every_page(self):
        known = {}
        gate = probe_scope._Gate(self.project.id)
        for sub in self.subs.values():
            want = old_same_site_hosts(self.project.id, sub, probe_scope._Gate(self.project.id))
            self.assertEqual(probe_scope._same_site_hosts(self.project.id, sub, gate, known), want, sub.name)

    def test_the_policies_are_unchanged(self):
        www = self.subs[('www.example.test', self.std.pk)]
        a = self.subs[('a.example.test', self.std.pk)]
        entry = {'probe': 'html-libraries', 'target': {'base': 'https://www.example.test'}}
        with mock.patch.object(probe_scope, '_same_site_hosts', side_effect=lambda pid, sub, gate, known=None: old_same_site_hosts(pid, sub, gate)):
            old = (probe_scope.for_probes(self.project.id, [(www, entry), (a, entry)]), probe_scope.for_page_read(self.project.id, www))
        cache.clear()
        new = (probe_scope.for_probes(self.project.id, [(www, entry), (a, entry)]), probe_scope.for_page_read(self.project.id, www))
        self.assertEqual(new, old)
        self.assertIn('dup.example.test', new[0]['hosts'])
        self.assertNotIn('p.example.test', new[0]['hosts'])
        self.assertNotIn('gone.example.test', new[0]['hosts'])
        self.assertNotIn('arch.example.test', new[1]['hosts'])


class QueryCeilingTests(TestCase):
    """One site of many hosts and a task of many library pages: the statements grow with the pages, never with the hosts of the site."""

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.project = Project.objects.create(name='Q', slug='ssbq-proj', insert_date=now, org=Org.objects.create(name='Q', slug='ssbq-org'))
        cls.domain = Domain.objects.create(name='site.test', project=cls.project, insert_date=now)
        Subdomain.objects.bulk_create([Subdomain(name=f'h{i}.site.test', target_domain=cls.domain) for i in range(300)])

    def setUp(self):
        cache.clear()

    def count(self, pages):
        subs = list(Subdomain.objects.filter(target_domain=self.domain).select_related('target_domain').order_by('id')[:pages])
        entry = {'probe': 'html-libraries', 'target': {'base': 'https://site.test'}}
        probe_scope.for_probes(self.project.id, [(subs[0], entry)])  # warm the per-project reads (exclusions) first
        statements = []

        def counted(execute, sql, params, many, context):
            statements.append(sql)
            return execute(sql, params, many, context)
        with connection.execute_wrapper(counted):  # a counter, not CaptureQueriesContext, whose log keeps the last 9,000 statements only
            scope = probe_scope.for_probes(self.project.id, [(sub, entry) for sub in subs])
        self.assertEqual({h for h in scope['hosts'] if h.startswith('h') and h.endswith('.site.test')}, {f'h{i}.site.test' for i in range(300)})
        return len(statements)

    def test_the_statements_do_not_grow_with_the_hosts_of_a_site(self):
        five, fifty = self.count(5), self.count(50)
        print(f'\nsame-site policy statements: 5 pages {five}, 50 pages {fifty}')
        # one statement per page (the site's names); the holders are looked up once for the whole task (12 and 57 when written)
        self.assertLessEqual(fifty - five, 45)
        self.assertLessEqual(five, 20)  # was 2,998: two statements per host of the site, per page
        self.assertLessEqual(fifty, 65)  # was 29,953
