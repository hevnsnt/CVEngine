"""Archiving a host closes what is open on it and keeps it out of searches and counts; restoring it reopens exactly that (cveFeed.archive_closure).

The scene: org A with projects a1 and a2, org B with b1. In a1 the host ``survey.example.test`` has an alias on the same address, CVE matches (open,
in progress with a person's note, and one a person already closed as a false positive), scanner findings (one on the alias, one filed against the
bare host's URL) and hygiene findings (one on the name, a certificate one on ``name:443``). A look-alike name and the same name in a2 and b1 have
findings of their own, which archiving the a1 host never touches.
"""
from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from agentapi import host_manage as hm
from agentapi import services as svc
from agentapi.services import ApiError, Ctx
from cveFeed import (
    archive_closure,
    closure,
    correlation,
    counts,
    finding_lifecycle,
    hygiene,
    inventory_counts,
    report_threats,
    situations,
)
from cveFeed.models import (
    CVEEntry,
    CVEMatch,
    FindingAuditEvent,
    HostState,
    HygieneFinding,
)
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import (
    IpAddress,
    ScanHistory,
    Subdomain,
    Technology,
    Vulnerability,
)
from targetApp.models import Domain

HOST, ALIAS, LOOKALIKE = 'survey.example.test', 'www.survey.example.test', 'notsurvey.example.test'
IP = '198.51.100.20'


class Base(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org_a, self.org_b = Org.objects.create(name='A', slug='arc-a'), Org.objects.create(name='B', slug='arc-b')
        self.a1 = Project.objects.create(name='A1', slug='arc-a1', insert_date=now, org=self.org_a)
        self.a2 = Project.objects.create(name='A2', slug='arc-a2', insert_date=now, org=self.org_a)
        self.b1 = Project.objects.create(name='B1', slug='arc-b1', insert_date=now, org=self.org_b)
        self.engine = EngineType.objects.create(engine_name='arc', yaml_configuration='x', default_engine=True)
        self.alice, self.bob, self.outsider = (User.objects.create_user(n, password='x') for n in ('alice', 'bob', 'outsider'))
        OrgMembership.objects.create(user=self.alice, org=self.org_a, role='admin')
        ProjectMembership.objects.create(user=self.bob, project=self.a1, role='user')
        OrgMembership.objects.create(user=self.outsider, org=self.org_b, role='admin')
        self.cve, _ = CVEEntry.objects.get_or_create(cve_id='CVE-2099-7001', defaults={'cvss': 9.8})
        self.domains, self.scans = {}, {}
        for p in (self.a1, self.a2, self.b1):
            self.domains[p.slug] = Domain.objects.create(name='example.test', project=p, insert_date=now) if p != self.a2 else \
                Domain.objects.create(name='a2.example.test', project=p, insert_date=now)
            self.scans[p.slug] = ScanHistory.objects.create(domain=self.domains[p.slug], scan_type=self.engine, start_scan_date=now, scan_status=2,
                                                            results_dir='/tmp')
        self.host = self.sub(self.a1, HOST, IP)
        self.alias = self.sub(self.a1, ALIAS, IP)
        self.lookalike = self.sub(self.a1, LOOKALIKE, '198.51.100.99')
        d = self.domains[self.a1.slug]
        self.m_open = self.match(self.host)
        self.m_progress = self.match(self.host, cve='CVE-2099-7002', remediation_status='in_progress', remediation_note='Ticket OPS-12', remediation_by=self.bob)
        self.m_fp = self.match(self.host, cve='CVE-2099-7003', remediation_status='false_positive', remediation_note='Not this product', remediation_by=self.bob)
        self.m_alias = self.match(self.alias, cve='CVE-2099-7004')
        self.m_lookalike = self.match(self.lookalike)
        self.v_alias = self.vuln(self.alias, 'Open admin')
        self.v_orphan = Vulnerability.objects.create(name='Exposed .git', severity=3, subdomain=None, target_domain=d, scan_history=self.scans[self.a1.slug],
                                                     http_url=f'https://{HOST}/.git/config', open_status=True)
        self.v_lookalike = self.vuln(self.lookalike, 'Other')
        self.h_name = HygieneFinding.objects.create(domain=d, host=HOST, check_name='dmarc_missing', severity=3, title='No DMARC')
        self.h_cert = HygieneFinding.objects.create(domain=d, host=f'{HOST}:443', check_name='tls_expiring', severity=3, title='Certificate expires soon')
        HostState.objects.create(project=self.a1, domain=d, host=HOST)
        # the same name in another project of the organization and in another organization
        self.twins = {}
        for p in (self.a2, self.b1):
            twin = self.sub(p, HOST, IP)
            self.twins[p.slug] = (self.match(twin), self.vuln(twin, 'Twin'),
                                  HygieneFinding.objects.create(domain=self.domains[p.slug], host=HOST, check_name='dmarc_missing', severity=3, title='No DMARC'))
            HostState.objects.create(project=p, domain=self.domains[p.slug], host=HOST)
        patcher = mock.patch('cveFeed.scoring.rescore_quietly')
        patcher.start()
        self.addCleanup(patcher.stop)

    def sub(self, project, name, ip=None):
        sub = Subdomain.objects.create(target_domain=self.domains[project.slug], scan_history=self.scans[project.slug], name=name)
        if ip:
            sub.ip_addresses.add(IpAddress.objects.get_or_create(address=ip)[0])
        return sub

    def match(self, sub, cve=None, **fields):
        entry = self.cve if cve is None else CVEEntry.objects.get_or_create(cve_id=cve, defaults={'cvss': 9.8})[0]
        return CVEMatch.objects.create(cve_entry=entry, subdomain=sub, scan_history=sub.scan_history, matched_product='nginx', matched_version='1.18.0',
                                       version_in_range=True, confidence=0.9, source='port', **fields)

    def vuln(self, sub, name):
        return Vulnerability.objects.create(name=name, severity=3, subdomain=sub, target_domain=sub.target_domain, scan_history=sub.scan_history,
                                            http_url=f'https://{sub.name}/admin', open_status=True)

    def ctx(self, user):
        return Ctx(user=user)

    def archive(self, user=None, project=None):
        with self.captureOnCommitCallbacks(execute=True):  # the snapshot revision bump runs, as in production
            return hm.host_archive(self.ctx(user or self.bob), (project or self.a1).slug, HOST, 'archive', reason='decommissioned')

    def restore(self, user=None, project=None):
        with self.captureOnCommitCallbacks(execute=True):
            return hm.host_archive(self.ctx(user or self.bob), (project or self.a1).slug, HOST, 'restore')

    def fresh(self, *rows):
        for row in rows:
            row.refresh_from_db()
        return rows


class ArchiveClosesTests(Base):
    def test_archive_closes_matches_scanner_and_hygiene_findings_of_the_host_and_its_alias(self):
        out = self.archive()
        self.assertEqual(out['findings_closed'], 7)  # 3 matches (open, in progress, alias), 2 scanner findings, 2 hygiene findings
        closed = self.fresh(self.m_open, self.m_progress, self.m_alias, self.v_alias, self.v_orphan, self.h_name, self.h_cert)
        for row in closed:
            self.assertEqual(row.remediation_status, 'fixed', row)
            self.assertIsNone(row.remediation_by_id)
            first = row.remediation_note.split('\n')[0]
            self.assertTrue(first.startswith(archive_closure.ARCHIVED), first)
            self.assertIn(f'by bob ({HOST}).', first)
            self.assertTrue(archive_closure.is_archive_closed(row, HOST))
        # a person's note stays below the closure line, and the closure reads back as automatic
        self.assertEqual(self.m_progress.remediation_note.split('\n', 1)[1], 'Ticket OPS-12')
        note, by, _when, automatic = closure.closure_of('match', self.m_open)
        self.assertTrue(automatic)
        self.assertIsNone(by)
        self.assertIn('the host was archived on', note)

    def test_the_other_names_on_its_addresses_are_archived_with_it_and_restored_with_it(self):
        out = self.archive()
        self.assertEqual(sorted(out['names']), [HOST, ALIAS])
        alias = HostState.objects.get(project=self.a1, host=ALIAS)
        self.assertIsNotNone(alias.archived_at)
        self.assertEqual((alias.archive_reason, alias.archived_by_user), (f'{archive_closure.WITH}{HOST}', True))
        # restoring by the alias's name restores the host it was archived with, and reopens what that archive closed
        with self.captureOnCommitCallbacks(execute=True):
            back = hm.host_archive(self.ctx(self.bob), self.a1.slug, ALIAS, 'restore')
        self.assertEqual((back['host'], back['findings_reopened']), (HOST, 7))
        self.assertFalse(HostState.objects.filter(project=self.a1, host__in=(HOST, ALIAS), archived_at__isnull=False).exists())

    def test_a_pinned_alias_is_not_archived_and_keeps_its_findings(self):
        HostState.objects.create(project=self.a1, domain=self.domains[self.a1.slug], host=ALIAS, pinned=True)
        out = self.archive()
        self.assertEqual(out['names'], [HOST])
        self.assertEqual(out['findings_closed'], 5)
        self.m_alias.refresh_from_db()
        self.assertEqual(self.m_alias.remediation_status, 'open')

    def test_the_closures_are_audited_and_marked(self):
        self.archive()
        events = FindingAuditEvent.objects.filter(project=self.a1, event='status', after__by=archive_closure.BY_ARCHIVE)
        self.assertEqual(events.count(), 7)
        progress = events.get(finding_kind='match', finding_id=self.m_progress.pk)
        self.assertEqual((progress.before, progress.after['status'], progress.actor), ({'status': 'in_progress'}, 'fixed', self.bob))
        log = AuditLog.objects.filter(action='host.archive').latest('id')
        self.assertEqual(log.detail['findings_closed'], 7)

    def test_what_a_person_closed_the_look_alike_and_other_projects_are_left_alone(self):
        self.archive()
        m_fp, m_look, v_look = self.fresh(self.m_fp, self.m_lookalike, self.v_lookalike)
        self.assertEqual((m_fp.remediation_status, m_fp.remediation_note, m_fp.remediation_by_id), ('false_positive', 'Not this product', self.bob.pk))
        self.assertEqual((m_look.remediation_status, v_look.remediation_status), ('open', 'open'))
        for rows in self.twins.values():
            for row in self.fresh(*rows):
                self.assertEqual(row.remediation_status, 'open')
        self.assertIsNone(HostState.objects.get(project=self.a2, host=HOST).archived_at)

    def test_archiving_again_finds_nothing_more_to_close(self):
        self.archive()
        again = self.archive()
        self.assertEqual(again['findings_closed'], 0)
        self.assertEqual(FindingAuditEvent.objects.filter(after__by=archive_closure.BY_ARCHIVE).count(), 7)

    def test_an_automatic_archive_says_why(self):
        state = HostState.objects.get(project=self.a1, host=HOST)
        state.archived_at = timezone.now()
        state.save(update_fields=['archived_at'])
        archive_closure.close_host(self.a1.pk, HOST, why=archive_closure.WHY_GONE)
        self.m_open.refresh_from_db()
        self.assertIn('archived automatically on', self.m_open.remediation_note)
        self.assertIn('because it was no longer found', self.m_open.remediation_note)

    def test_the_inactive_review_closes_what_is_open_when_it_archives(self):
        from cveFeed import inactive_archive
        now = timezone.now()
        state = HostState.objects.get(project=self.a1, host=HOST)
        old = now - timedelta(days=70)
        HostState.objects.filter(pk=state.pk).update(retired_at=old, last_seen=old, inactive_first_absent_at=now - timedelta(days=40), inactive_absent_checks=1)
        state.refresh_from_db()
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.archive_rediscovery.observe', return_value={'status': 'absent', 'addresses': []}):
            self.assertEqual(inactive_archive.check_one(state, now=now), 'archived')
        self.m_open.refresh_from_db()
        self.assertEqual(self.m_open.remediation_status, 'fixed')
        self.assertIn('because it was no longer found', self.m_open.remediation_note)

    def test_an_outsider_cannot_archive_and_closes_nothing(self):
        with self.assertRaises(ApiError):
            hm.host_archive(self.ctx(self.outsider), self.a1.slug, HOST, 'archive')
        self.m_open.refresh_from_db()
        self.assertEqual(self.m_open.remediation_status, 'open')


class RestoreReopensTests(Base):
    def test_restore_reopens_only_what_archiving_closed_with_its_earlier_status_and_note(self):
        self.archive()
        out = self.restore()
        self.assertEqual(out['findings_reopened'], 7)
        m_open, m_progress, m_alias, m_fp, v_orphan, h_cert = self.fresh(self.m_open, self.m_progress, self.m_alias, self.m_fp, self.v_orphan, self.h_cert)
        self.assertEqual((m_open.remediation_status, m_progress.remediation_status, m_alias.remediation_status), ('open', 'in_progress', 'open'))
        self.assertEqual((v_orphan.remediation_status, h_cert.remediation_status), ('open', 'open'))
        self.assertTrue(m_progress.remediation_note.startswith(archive_closure.REOPENED))
        self.assertEqual(m_progress.remediation_note.split('\n', 1)[1], 'Ticket OPS-12')
        self.assertEqual((m_fp.remediation_status, m_fp.remediation_note), ('false_positive', 'Not this product'))  # a person's earlier closure stays
        self.assertEqual(FindingAuditEvent.objects.filter(after__by=archive_closure.BY_RESTORE).count(), 7)

    def test_a_finding_a_person_changed_while_archived_is_theirs(self):
        self.archive()
        svc.update_finding_status(self.ctx(self.bob), self.a1.slug, 'match', self.m_open.pk, status='accepted_risk', note='Living with it')
        self.restore()
        self.m_open.refresh_from_db()
        self.assertEqual((self.m_open.remediation_status, self.m_open.remediation_note), ('accepted_risk', 'Living with it'))

    def test_restoring_one_project_never_reopens_another_projects_archive_closures(self):
        self.archive()
        hm.host_archive(self.ctx(self.alice), self.a2.slug, HOST, 'archive')
        self.restore()
        twin_match = self.twins[self.a2.slug][0]
        twin_match.refresh_from_db()
        self.assertEqual(twin_match.remediation_status, 'fixed')
        self.m_open.refresh_from_db()
        self.assertEqual(self.m_open.remediation_status, 'open')

    def test_rediscovery_reopens_what_an_automatic_archive_closed(self):
        from cveFeed import archive_rediscovery
        state = HostState.objects.get(project=self.a1, host=HOST)
        HostState.objects.filter(pk=state.pk).update(archived_at=timezone.now() - timedelta(days=31), archived_by_user=False)
        archive_closure.close_host(self.a1.pk, HOST, why=archive_closure.WHY_GONE)
        state.refresh_from_db()
        resolver = lambda name: ('absent', set()) if name.startswith('cvengine-nonexistent-') else ('resolved', {'8.8.8.8'})
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'back'
            self.assertEqual(archive_rediscovery.check_one(state, resolver=resolver), 'reactivated')
        m_open, m_progress, m_fp = self.fresh(self.m_open, self.m_progress, self.m_fp)
        self.assertEqual((m_open.remediation_status, m_progress.remediation_status, m_fp.remediation_status), ('open', 'in_progress', 'false_positive'))

    def test_a_scan_that_finds_the_host_again_reopens_it(self):
        from cveFeed import changes
        state = HostState.objects.get(project=self.a1, host=HOST)
        HostState.objects.filter(pk=state.pk).update(archived_at=timezone.now(), archived_by_user=False, state={'ips': {IP: {'ports': {}}}},
                                                     fingerprint='old')
        archive_closure.close_host(self.a1.pk, HOST, why=archive_closure.WHY_UNRESOLVED)
        changes._reopen_restored(self.a1.pk, [HOST])
        self.m_open.refresh_from_db()
        self.assertEqual(self.m_open.remediation_status, 'open')


    def test_close_and_reopen_cycles_never_cut_a_person_s_note(self):
        # each cycle used to add an engine line on top, and the note was cut from its end at 2000 characters: the person's note went first
        note = ('Ticket OPS-12: waiting on the vendor patch. ' * 40).strip()
        CVEMatch.objects.filter(pk=self.m_progress.pk).update(remediation_note=note)
        for day in range(30):
            when = timezone.now() + timedelta(days=day)
            archive_closure.close_host(self.a1.pk, HOST, why=archive_closure.WHY_GONE, when=when)
            self.m_progress.refresh_from_db()
            self.assertEqual(self.m_progress.remediation_status, 'fixed')
            self.assertTrue(self.m_progress.remediation_note.startswith(archive_closure.ARCHIVED))
            self.assertTrue(self.m_progress.remediation_note.endswith('\n' + note), day)
            self.assertLessEqual(len(self.m_progress.remediation_note), closure.NOTE_MAX)
            archive_closure.reopen_host(self.a1.pk, HOST, when=when)
            self.m_progress.refresh_from_db()
            self.assertEqual(self.m_progress.remediation_status, 'in_progress')
            self.assertTrue(self.m_progress.remediation_note.startswith(archive_closure.REOPENED))
            self.assertTrue(self.m_progress.remediation_note.endswith('\n' + note), day)
            self.assertLessEqual(len(self.m_progress.remediation_note), closure.NOTE_MAX)

    def test_a_scan_reopen_never_cuts_a_person_s_note_either(self):
        note = 'n' * (closure.NOTE_MAX - 20)
        history = '\n'.join([finding_lifecycle.REOPENED_NOTE] * 5)
        out = closure.prepend_note(finding_lifecycle.REOPENED_NOTE, f'{archive_closure.ARCHIVED} automatically on 2026-11-02 ({HOST}).\n{history}\n{note}')
        self.assertEqual(out, f'{finding_lifecycle.REOPENED_NOTE}\n{note}')  # the engine's lines go, oldest first, the person's text stays whole
        self.assertEqual(closure.prepend_note('Closed automatically: x.', 'short note'), 'Closed automatically: x.\nshort note')  # fits: as before
        self.assertEqual(closure.prepend_note('Closed automatically: x.', ''), 'Closed automatically: x.')
        long_ = 'p' * closure.NOTE_MAX  # a note longer than the room left keeps the person's text whole
        self.assertEqual(closure.prepend_note('Closed automatically: x.', long_), 'Closed automatically: x.\n' + long_)
        # a hygiene reopen appends its line at the end: that is the engine's too, and goes before the person's text
        tail = 'Reopened: the check found this again after it was marked fixed.'
        out = closure.prepend_note('Closed automatically: x.', f'{note}\n{tail}\n{tail}')
        self.assertEqual(out, f'Closed automatically: x.\n{note}')


class NextScanTests(Base):
    """The sticky-fixed rules keep a person's fixed status across scans; they keep an archive closure only while the host is archived."""

    def back_without_restore(self):
        """The host's archive lifted some way that did not reopen its findings (an older release, a write by hand)."""
        HostState.objects.filter(project=self.a1, host__in=(HOST, ALIAS)).update(archived_at=None, archive_reason='')

    def new_scan_matches(self):
        scan = ScanHistory.objects.create(domain=self.domains[self.a1.slug], scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, results_dir='/tmp')
        again = Subdomain.objects.create(target_domain=self.domains[self.a1.slug], scan_history=scan, name=HOST)
        fresh = CVEMatch(cve_entry=self.cve, subdomain=again, matched_product='nginx', source='port')
        person = CVEMatch(cve_entry=self.m_fp.cve_entry, subdomain=again, matched_product='nginx', source='port')
        correlation._carry_remediation([fresh, person])
        return fresh, person

    def test_a_new_scans_match_does_not_inherit_an_archive_closure_once_the_host_is_back(self):
        self.archive()
        self.back_without_restore()
        fresh, person = self.new_scan_matches()
        self.assertEqual((fresh.remediation_status, fresh.remediation_note), ('open', ''))
        self.assertEqual(person.remediation_status, 'false_positive')  # a person's decision is still carried

    def test_while_the_host_is_archived_a_new_scans_match_stays_closed(self):
        self.archive()
        fresh, _person = self.new_scan_matches()
        self.assertEqual(fresh.remediation_status, 'fixed')
        self.assertTrue(archive_closure.is_archive_closed(fresh, HOST))

    def test_a_scanner_finding_reported_again_reopens_once_the_host_is_back(self):
        self.archive()
        self.v_alias.refresh_from_db()
        self.assertNotIn('remediation_status', finding_lifecycle.seen_again(self.v_alias))  # still archived: it stays closed
        self.back_without_restore()
        self.v_alias.refresh_from_db()
        self.assertIn('remediation_status', finding_lifecycle.seen_again(self.v_alias))
        self.assertEqual(self.v_alias.remediation_status, 'open')

    def test_a_hygiene_check_that_finds_it_again_reopens_once_the_host_is_back(self):
        self.archive()
        found = [hygiene.Finding('dmarc_missing', 3, 'No DMARC', host=HOST)]
        hygiene.store_findings(self.domains[self.a1.slug], found, hosts=[HOST], owns=lambda check: check == 'dmarc_missing')
        self.h_name.refresh_from_db()
        self.assertEqual(self.h_name.remediation_status, 'fixed')
        self.back_without_restore()
        hygiene.store_findings(self.domains[self.a1.slug], found, hosts=[HOST], owns=lambda check: check == 'dmarc_missing')
        self.h_name.refresh_from_db()
        self.assertEqual(self.h_name.remediation_status, 'open')


class OutOfSearchAndCountsTests(Base):
    def names(self, user, slug, **params):
        return [(r.get('project') or slug, r['host']) for r in svc.search_hosts(self.ctx(user), slug, {'page_size': 100, **params})['results']]

    def test_search_leaves_an_archived_host_out_unless_asked(self):
        self.archive()
        self.assertNotIn((self.a1.slug, HOST), self.names(self.bob, self.a1.slug))
        self.assertNotIn((self.a1.slug, HOST), self.names(self.bob, self.a1.slug, q='cve:CVE-2099-7001'))
        self.assertIn((self.a1.slug, LOOKALIKE), self.names(self.bob, self.a1.slug, q='cve:CVE-2099-7001'))
        self.assertIn((self.a1.slug, HOST), self.names(self.bob, self.a1.slug, archived='1'))
        self.assertEqual(self.names(self.bob, self.a1.slug, archived='only'), [(self.a1.slug, HOST)])
        count = svc.search_hosts(self.ctx(self.bob), self.a1.slug, {'page_size': 0})['count']
        self.assertEqual(count, svc.search_hosts(self.ctx(self.bob), self.a1.slug, {'page_size': 0, 'archived': '1'})['count'] - 1)

    def test_the_all_projects_search_leaves_it_out_and_keeps_the_other_projects_host(self):
        self.archive()
        everywhere = self.names(self.alice, '_all', q='cve:CVE-2099-7001')
        self.assertNotIn((self.a1.slug, HOST), everywhere)
        self.assertIn((self.a2.slug, HOST), everywhere)
        self.assertNotIn((self.b1.slug, HOST), everywhere)  # another organization: never
        self.assertIn((self.a1.slug, HOST), self.names(self.alice, '_all', q='cve:CVE-2099-7001', archived='1'))

    def test_the_facets_and_the_host_list_leave_it_out(self):
        before = svc.search_hosts(self.ctx(self.bob), self.a1.slug, {'page_size': 10})['facets']['heat']
        self.archive()
        after = svc.search_hosts(self.ctx(self.bob), self.a1.slug, {'page_size': 10})['facets']['heat']
        self.assertEqual(sum(after.values()), sum(before.values()) - 1)
        listed = [r['host'] for r in svc.list_hosts(self.ctx(self.bob), self.a1.slug, {'page_size': 100})['results']]
        self.assertNotIn(HOST, listed)
        self.assertIn(HOST, [r['host'] for r in svc.list_hosts(self.ctx(self.bob), self.a1.slug, {'page_size': 100, 'archived': 'only'})['results']])

    def test_a_bad_archived_value_is_a_400(self):
        with self.assertRaises(ApiError) as caught:
            svc.search_hosts(self.ctx(self.bob), self.a1.slug, {'archived': 'maybe'})
        self.assertEqual(caught.exception.status, 400)

    def test_the_host_counts_leave_it_out(self):
        def a1_hosts():
            return sum(1 for s in counts.reps_of(counts.rep_ids()) if s.target_domain.project_id == self.a1.pk)
        before = a1_hosts()
        shared_before = inventory_counts.shared_host_counts()['hosts'][self.a1.pk]
        self.archive()
        self.assertEqual(a1_hosts(), before - 1)
        self.assertEqual(inventory_counts.shared_host_counts()['hosts'][self.a1.pk], shared_before - 1)
        self.assertEqual(counts.host_reps().filter(target_domain__project=self.a1, name=HOST).count(), 0)

    def test_the_threat_cards_leave_it_out(self):
        tech = Technology.objects.get_or_create(name='nginx')[0]
        self.host.technologies.add(tech)
        self.alias.technologies.add(tech)
        before = report_threats.impact([self.a1.pk], [self.cve])[self.cve.id]
        self.assertTrue(before['matched'])
        self.archive()
        after = report_threats.impact([self.a1.pk], [self.cve])[self.cve.id]
        keys = set(counts.with_host_key(Subdomain.objects.filter(pk__in=(self.host.pk, self.alias.pk))).values_list('host_key', flat=True))
        self.assertFalse((after['matched'] | after['product_only']) & keys)
        self.assertFalse(keys & {k for k, _s in report_threats._sightings([self.a1.pk])})

    def test_situations_leave_it_out_even_with_something_left_open_on_it(self):
        listed = lambda: {g['host'] for g in situations.listing([self.a1.pk], size=100)['results']}
        self.assertIn(HOST, listed())
        self.archive()
        # a finding a scan already under way filed after the archive: the host is still out of the ranking
        self.vuln(self.host, 'Late finding')
        self.assertNotIn(HOST, listed())
        self.assertIn(LOOKALIKE, listed())

    def test_rest_and_mcp_take_the_archived_parameter(self):
        from agentapi.auth import create_token
        from tests.test_agentapi import call, tool_call
        self.archive()
        _, token = create_token(self.bob, 'arc')
        status, data = call(token, 'GET', f'/api/v1/projects/{self.a1.slug}/search?archived=only')
        self.assertEqual((status, [r['host'] for r in data['results']]), (200, [HOST]))
        status, data = call(token, 'GET', f'/api/v1/projects/{self.a1.slug}/hosts')
        self.assertNotIn(HOST, [r['host'] for r in data['results']])
        is_error, data = tool_call(token, 'search_hosts', {'project': self.a1.slug, 'archived': True})
        self.assertFalse(is_error)
        self.assertIn(HOST, [r['host'] for r in data['results']])
        is_error, data = tool_call(token, 'list_hosts', {'project': self.a1.slug})
        self.assertNotIn(HOST, [r['host'] for r in data['results']])
        status, _ = call(token, 'GET', f'/api/v1/projects/{self.a1.slug}/search?archived=sometimes')
        self.assertEqual(status, 400)

    def test_the_hosts_own_record_still_opens(self):
        self.archive()
        self.assertEqual(svc.search_hosts(self.ctx(self.bob), self.a1.slug, {'names': HOST})['results'], [])  # named, but archived: left out
        everywhere = svc.search_hosts(self.ctx(self.alice), '_all', {'names': f'{self.a1.slug}/{HOST},{self.a2.slug}/{HOST}'})['results']
        self.assertEqual([(r['project'], r['host']) for r in everywhere], [(self.a2.slug, HOST)])
        rows = svc.search_hosts(self.ctx(self.bob), self.a1.slug, {'names': HOST, 'archived': '1'})['results']
        self.assertEqual([r['host'] for r in rows], [HOST])
        self.assertTrue(rows[0]['archived'])


class BackfillTests(Base):
    def archived_earlier(self, by_user=True):
        when = timezone.now() - timedelta(days=12)
        HostState.objects.filter(project=self.a1, host=HOST).update(archived_at=when, archived_by_user=by_user,
                                                                   archive_reason='Manually archived' if by_user else
                                                                   'Automatically archived after 3 days without once resolving to a scannable IP')
        if by_user:
            AuditLog.objects.create(actor=self.bob, actor_name='bob', action='host.archive', target=f'{HOST} in {self.a1.slug}', org=self.org_a,
                                    detail={'project': self.a1.slug, 'host': HOST})
        return when

    def test_the_backfill_closes_what_hosts_archived_earlier_kept_open_and_is_idempotent(self):
        when = self.archived_earlier()
        dry = archive_closure.backfill(apply=False)
        # each archived name on its own: the alias was not archived, so its match and finding stay open
        self.assertEqual((dry['hosts'], dry['match'], dry['vulnerability'], dry['hygiene']), (1, 2, 1, 2))
        self.m_open.refresh_from_db()
        self.assertEqual(self.m_open.remediation_status, 'open')  # a dry run writes nothing
        done = archive_closure.backfill(apply=True)
        self.assertEqual(done, dry)
        self.m_open.refresh_from_db()
        self.assertEqual(self.m_open.remediation_status, 'fixed')
        self.assertIn(f'archived on {timezone.localtime(when).date().isoformat()} by bob ({HOST})', self.m_open.remediation_note)
        self.assertEqual(archive_closure.backfill(apply=True), {'hosts': 0, 'match': 0, 'vulnerability': 0, 'hygiene': 0})
        twin = self.twins[self.a2.slug][0]
        twin.refresh_from_db()
        self.assertEqual(twin.remediation_status, 'open')  # the same name in another project was not archived

    def test_an_automatic_archive_is_backfilled_with_its_reason_and_restores_cleanly(self):
        self.archived_earlier(by_user=False)
        out = StringIO()
        call_command('close_archived_findings', '--apply', stdout=out)
        self.assertIn('Applied: 5 open findings on 1 archived hosts closed', out.getvalue())
        self.m_open.refresh_from_db()
        self.assertIn('because it did not resolve to a scannable address', self.m_open.remediation_note)
        self.restore()
        self.m_progress.refresh_from_db()
        self.assertEqual(self.m_progress.remediation_status, 'in_progress')

    def test_the_command_is_a_dry_run_by_default(self):
        self.archived_earlier()
        out = StringIO()
        call_command('close_archived_findings', stdout=out)
        self.assertIn('Dry run: 5 open findings on 1 archived hosts would be closed', out.getvalue())
        self.m_open.refresh_from_db()
        self.assertEqual(self.m_open.remediation_status, 'open')
