"""The approved Nuclei template bundle a Sentinel fetches (``GET sentinel/template-policy`` and ``.../bundle``), the ``bundle_sha256`` a nuclei task
target carries, and the heartbeat's optional ``running`` list."""
import hashlib
import io
import os
import re
import shutil
import tarfile
import tempfile
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as dispatch
from agentapi import template_bundle
from agentapi.auth import create_token, hash_token
from agentapi.models import Agent, SentinelTask
from cveFeed import nuclei_scan, templategen
from dashboard.models import ApiToken, Project, ScanPolicy
from tests.test_agentapi import call
from tests.test_sentinel_hardening import enroll
from tests.test_sentinels import SentinelBase, register_sentinel, reset_rates
from tests.test_validation import GET_TEMPLATE

POLICY = '/api/v1/sentinel/template-policy'
BUNDLE = POLICY + '/bundle'
WRITE_TEMPLATE = GET_TEMPLATE.replace('method: GET', 'method: POST')


def get(token, path, **headers):
    return Client().get(path, HTTP_AUTHORIZATION=f'Bearer {token}', **headers)


def body_of(response):
    return b''.join(response.streaming_content)


def members_of(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        return {m.name: (m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()}


class LibraryMixin:
    """A throwaway template library as the installed one, a fresh snapshot cache and bundle cache, and cleanup of every file they leave."""

    def setUp(self):
        super().setUp()
        self.library = tempfile.mkdtemp(prefix='cvengine-test-library-')
        self.addCleanup(shutil.rmtree, self.library, ignore_errors=True)
        self.write_template('http/safe.yaml', GET_TEMPLATE)
        self.write_template('http/write.yaml', WRITE_TEMPLATE)
        ScanPolicy.objects.all().delete()
        ScanPolicy.objects.create(nuclei_all_templates=False)
        for patcher in (mock.patch.object(templategen, 'TEMPLATES_ROOT', self.library),
                        mock.patch.dict(nuclei_scan._APPROVED, {'root': None, 'at': 0, 'value': None, 'retained': []}),
                        mock.patch.dict(template_bundle._BUILT, clear=True), mock.patch.dict(template_bundle._TOO_BIG, clear=True),
                        mock.patch.object(nuclei_scan, '_report_policy')):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self.remove_snapshots)

    def write_template(self, relative, text):
        path = os.path.join(self.library, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as output:
            output.write(text)

    def remove_snapshots(self):
        paths = [nuclei_scan._APPROVED['value'][0]] if nuclei_scan._APPROVED['value'] else []
        paths += [path for path, _ in nuclei_scan._APPROVED.get('retained', [])]
        for path in paths:
            shutil.rmtree(path, ignore_errors=True)
            try:
                os.unlink(path.rstrip('/') + template_bundle.SUFFIX)
            except OSError:
                pass

    def drop_caches(self):
        """As if the web process had just started: no snapshot and no bundle known (the old snapshot is kept for cleanup)."""
        old = nuclei_scan._APPROVED['value']
        nuclei_scan._APPROVED.update(root=None, at=0, value=None)
        nuclei_scan._APPROVED['retained'].append((old[0], 0))
        template_bundle._BUILT.clear()


class BundleBase(LibraryMixin, SentinelBase):
    def setUp(self):
        super().setUp()
        self.sentinel = enroll(self.t['dana'])['token']
        reset_rates({'sentinel': self.sentinel})


class TemplatePolicyRouteTests(BundleBase):
    def test_the_policy_has_exactly_the_documented_shape(self):
        status, out = call(self.sentinel, 'GET', POLICY)
        self.assertEqual(status, 200)
        self.assertEqual(set(out), {'rev', 'read_only', 'bundle'})
        self.assertEqual((out['rev'], out['read_only']), (nuclei_scan.TEMPLATE_POLICY_REV, True))
        self.assertEqual(set(out['bundle']), {'sha256', 'bytes', 'templates', 'path'})
        self.assertRegex(out['bundle']['sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(out['bundle']['templates'], 1)  # the POST template fails the read-only policy
        self.assertEqual(out['bundle']['path'], BUNDLE)

    def test_the_bundle_is_the_approved_snapshot_as_a_gzip_tarball(self):
        _, policy = call(self.sentinel, 'GET', POLICY)
        response = get(self.sentinel, BUNDLE)
        data = body_of(response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/gzip')
        self.assertEqual(int(response['Content-Length']), len(data))
        self.assertEqual(len(data), policy['bundle']['bytes'])
        self.assertEqual(response['ETag'], f'"{policy["bundle"]["sha256"]}"')
        self.assertEqual(hashlib.sha256(data).hexdigest(), policy['bundle']['sha256'])
        members = members_of(data)
        self.assertEqual(list(members), ['http/safe.yaml'])
        member, content = members['http/safe.yaml']
        self.assertTrue(member.isreg())
        self.assertEqual(content.decode(), GET_TEMPLATE)
        self.assertEqual((member.mtime, member.uid, member.gid), (0, 0, 0))

    def test_if_none_match_gets_a_304_without_a_body(self):
        _, policy = call(self.sentinel, 'GET', POLICY)
        sha = policy['bundle']['sha256']
        for value in (f'"{sha}"', sha, f'W/"{sha}"', f'"other", "{sha}"', '*'):
            response = get(self.sentinel, BUNDLE, HTTP_IF_NONE_MATCH=value)
            self.assertEqual(response.status_code, 304, value)
            self.assertEqual(response.content, b'')
            self.assertEqual(response['ETag'], f'"{sha}"')
        response = get(self.sentinel, BUNDLE, HTTP_IF_NONE_MATCH='"0000"')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(hashlib.sha256(body_of(response)).hexdigest(), sha)

    def test_the_archive_is_built_once_and_never_per_request(self):
        with mock.patch.object(template_bundle, '_pack', wraps=template_bundle._pack) as pack:
            call(self.sentinel, 'GET', POLICY)
            for _ in range(3):
                body_of(get(self.sentinel, BUNDLE))
            call(self.sentinel, 'GET', POLICY)
        self.assertEqual(pack.call_count, 1)

    def test_the_sha_is_stable_for_the_same_content_across_a_rebuild_of_the_snapshot(self):
        _, first = call(self.sentinel, 'GET', POLICY)
        self.drop_caches()
        _, second = call(self.sentinel, 'GET', POLICY)
        self.assertEqual(first['bundle'], second['bundle'])

    def test_a_changed_template_changes_the_sha(self):
        _, first = call(self.sentinel, 'GET', POLICY)
        self.write_template('http/more.yaml', GET_TEMPLATE + '\n# one more\n')
        self.drop_caches()
        _, second = call(self.sentinel, 'GET', POLICY)
        self.assertEqual(second['bundle']['templates'], 2)
        self.assertNotEqual(first['bundle']['sha256'], second['bundle']['sha256'])

    def test_allowing_every_template_changes_the_rev_and_the_sha(self):
        _, restricted = call(self.sentinel, 'GET', POLICY)
        ScanPolicy.objects.update(nuclei_all_templates=True)
        _, everything = call(self.sentinel, 'GET', POLICY)
        self.assertEqual((restricted['rev'], restricted['read_only']), (nuclei_scan.TEMPLATE_POLICY_REV, True))
        self.assertEqual((everything['rev'], everything['read_only']), (nuclei_scan.ALL_TEMPLATES_REV, False))
        self.assertEqual(everything['bundle']['templates'], 2)
        self.assertNotEqual(restricted['bundle']['sha256'], everything['bundle']['sha256'])
        ScanPolicy.objects.update(nuclei_all_templates=False)
        _, back = call(self.sentinel, 'GET', POLICY)
        self.assertEqual(back['bundle']['sha256'], restricted['bundle']['sha256'])

    def test_a_missing_library_or_an_oversized_set_is_a_clear_503(self):
        shutil.rmtree(self.library)
        status, out = call(self.sentinel, 'GET', POLICY)
        self.assertEqual(status, 503)
        self.assertIn('template', out['error'])

    def test_an_oversized_set_is_a_503_that_is_not_retried_for_every_request(self):
        with mock.patch.object(template_bundle, 'MAX_FILES', 0), mock.patch.object(template_bundle, '_collect', wraps=template_bundle._collect) as walk:
            for path in (POLICY, BUNDLE, POLICY):
                response = get(self.sentinel, path)
                self.assertEqual(response.status_code, 503)
                self.assertIn('more than 0 files', response.json()['error'])
        self.assertEqual(walk.call_count, 1)

    def test_an_archive_over_the_size_cap_is_a_503_and_leaves_no_file(self):
        with mock.patch.object(template_bundle, 'MAX_PACKED_BYTES', 10):
            status, out = call(self.sentinel, 'GET', POLICY)
        self.assertEqual(status, 503)
        self.assertIn('larger than', out['error'])
        snapshot = nuclei_scan._APPROVED['value'][0]
        self.assertFalse(os.path.exists(snapshot + template_bundle.SUFFIX))
        self.assertEqual([n for n in os.listdir(os.path.dirname(snapshot)) if n.startswith(os.path.basename(snapshot)) and n.endswith('.part')], [])

    def test_the_bundle_sits_next_to_its_snapshot_and_is_swept_when_the_snapshot_is_gone(self):
        call(self.sentinel, 'GET', POLICY)
        snapshot = nuclei_scan._APPROVED['value'][0]
        stray = tempfile.mkdtemp(prefix='cvengine-approved-nuclei-')
        orphan = stray + template_bundle.SUFFIX
        with open(orphan, 'wb') as output:
            output.write(b'x')
        shutil.rmtree(stray)
        self.assertTrue(os.path.isfile(snapshot + template_bundle.SUFFIX))
        self.drop_caches()
        call(self.sentinel, 'GET', POLICY)
        self.assertFalse(os.path.exists(orphan))

    def test_the_routes_are_rate_limited(self):
        with mock.patch.dict(sb.RATES, {'bundle': (2, 60), 'policy': (2, 60)}):
            for path, ok in ((BUNDLE, 200), (BUNDLE, 200), (BUNDLE, 429), (POLICY, 200), (POLICY, 200), (POLICY, 429)):
                response = get(self.sentinel, path)
                body_of(response) if response.streaming else None
                self.assertEqual(response.status_code, ok, path)

    def test_nothing_is_audited_for_a_fetch(self):
        from dashboard.models import AuditLog as AuditEvent
        before = AuditEvent.objects.count()
        call(self.sentinel, 'GET', POLICY)
        body_of(get(self.sentinel, BUNDLE))
        self.assertEqual(AuditEvent.objects.count(), before)


class TemplatePolicyAccessTests(BundleBase):
    def test_a_token_that_is_not_a_sentinels_is_refused(self):
        for raw in (self.t['dana'], self.t['root']):  # a full token, an App Admin's too
            for path in (POLICY, BUNDLE):
                self.assertEqual(get(raw, path).status_code, 403, path)

    def test_an_inventory_token_is_refused(self):
        _, raw = create_token(self.dana, 'inv', scope='inventory', project=Project.objects.get(slug='sen-a'))
        for path in (POLICY, BUNDLE):
            self.assertEqual(get(raw, path).status_code, 403, path)

    def test_no_token_is_a_401(self):
        for path in (POLICY, BUNDLE):
            self.assertEqual(Client().get(path).status_code, 401, path)

    def test_a_revoked_token_is_a_401(self):
        ApiToken.objects.filter(key_hash=hash_token(self.sentinel)).update(revoked=True)
        for path in (POLICY, BUNDLE):
            self.assertEqual(get(self.sentinel, path).status_code, 401, path)

    def test_an_expired_token_is_a_401(self):
        ApiToken.objects.filter(key_hash=hash_token(self.sentinel)).update(
            expires_at=timezone.now() - timedelta(minutes=1))
        for path in (POLICY, BUNDLE):
            self.assertEqual(get(self.sentinel, path).status_code, 401, path)

    def test_a_revoked_sentinel_agent_is_refused(self):
        Agent.objects.filter(token__key_hash=hash_token(self.sentinel)).update(status='revoked')
        self.assertEqual(get(self.sentinel, POLICY).status_code, 403)

    def test_other_methods_and_paths_are_not_open(self):
        self.assertEqual(Client().post(POLICY, HTTP_AUTHORIZATION=f'Bearer {self.sentinel}').status_code, 405)
        self.assertEqual(get(self.sentinel, POLICY + '/other').status_code, 403)  # not a Sentinel route: the token scope refuses it


class DocsAndRouteTableTests(SimpleTestCase):
    def test_the_routes_are_in_the_openapi_table_and_the_doc(self):
        from agentapi import rest
        paths = rest.openapi_spec()['paths']
        self.assertIn('get', paths[POLICY])
        self.assertIn('get', paths[BUNDLE])
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, '..', '..', 'docs', 'AGENT-API.md'), encoding='utf-8') as handle:
            doc = handle.read()
        for needle in ('sentinel/template-policy', 'sentinel/template-policy/bundle', 'bundle_sha256', '"running"'):
            self.assertIn(needle, doc)


class BundleContentTests(SimpleTestCase):
    """The packer on its own: what goes in the archive, and what never does."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='cvengine-test-pack-')
        self.outside = tempfile.mkdtemp(prefix='cvengine-test-outside-')
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.outside, ignore_errors=True)

    def put(self, base, relative, text='id: x\n'):
        path = os.path.join(base, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as output:
            output.write(text)
        return path

    def pack(self):
        final = self.root.rstrip('/') + '.packed.tar.gz'
        self.addCleanup(lambda: os.path.exists(final) and os.unlink(final))
        bundle = template_bundle._pack(self.root, final, 'readonly-2', 'rev')
        with open(final, 'rb') as handle:
            data = handle.read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), bundle.sha256)
        self.assertEqual(len(data), bundle.bytes)
        return bundle, members_of(data)

    def test_a_symlink_to_a_file_inside_is_read_through_and_one_to_the_outside_is_left_out(self):
        real = self.put(self.root, 'real/a.yaml', 'id: a\n')
        os.symlink(real, os.path.join(self.root, 'link.yaml'))
        secret = self.put(self.outside, 'secret.yaml', 'id: secret\n')
        os.symlink(secret, os.path.join(self.root, 'escape.yaml'))
        os.symlink(self.outside, os.path.join(self.root, 'dirlink'))
        bundle, members = self.pack()
        self.assertEqual(sorted(members), ['link.yaml', 'real/a.yaml'])
        self.assertTrue(all(m.isreg() and not m.issym() for m, _ in members.values()))
        self.assertEqual(members['link.yaml'][1], b'id: a\n')
        self.assertEqual(bundle.templates, 2)

    def test_names_are_relative_sorted_and_only_templates(self):
        for relative in ('z.yaml', 'a/b.yml', 'a/a.yaml', 'readme.md', '.hidden/x.yaml'):
            self.put(self.root, relative)
        _, members = self.pack()
        names = list(members)
        self.assertEqual(names, sorted(names))
        self.assertEqual(sorted(names), ['.hidden/x.yaml', 'a/a.yaml', 'a/b.yml', 'z.yaml'])
        for name in names:
            self.assertFalse(name.startswith('/') or '..' in name.split('/'), name)

    def test_a_path_traversal_name_is_never_included(self):
        for name in ('../evil.yaml', '/etc/evil.yaml', 'a/../../evil.yaml', 'a//b.yaml', './a.yaml', 'a\\b.yaml', 'a\x00.yaml'):
            self.assertIsNone(template_bundle._safe_name(name), name)
        self.assertEqual(template_bundle._safe_name('a/b..c.yaml'), 'a/b..c.yaml')  # two dots inside a file name are no traversal
        self.put(self.root, 'a/..b.yaml')
        self.put(self.outside, 'evil.yaml')
        _, members = self.pack()
        self.assertEqual(list(members), ['a/..b.yaml'])

    def test_identical_content_gives_identical_bytes_whatever_the_times_and_order(self):
        for relative in ('b.yaml', 'a.yaml'):
            self.put(self.root, relative)
        first, _ = self.pack()
        os.utime(os.path.join(self.root, 'a.yaml'), (1_000_000, 1_000_000))
        second, _ = self.pack()
        self.assertEqual(first.sha256, second.sha256)
        self.put(self.root, 'a.yaml', 'id: changed\n')
        third, _ = self.pack()
        self.assertNotEqual(first.sha256, third.sha256)

    def test_an_empty_set_is_refused(self):
        with self.assertRaises(template_bundle.BundleError):
            template_bundle._collect(self.root)


class TaskTargetCarriesTheShaTests(LibraryMixin, TestCase):
    def target(self):
        with mock.patch('cveFeed.validation.all_templates_allowed', side_effect=lambda: bool(ScanPolicy.current().nuclei_all_templates)):
            return dispatch._nuclei_target('nuclei_targeted', ['www.example.test'], {})

    def test_the_field_is_null_until_the_snapshot_is_cached_and_never_builds_one(self):
        target = self.target()
        self.assertEqual(target['template_policy'], {'rev': nuclei_scan.TEMPLATE_POLICY_REV, 'read_only': True, 'bundle_sha256': None})
        self.assertIsNone(nuclei_scan._APPROVED['value'])  # a dispatch did not walk the template library

    def test_the_field_is_the_bundles_sha_once_the_snapshot_is_cached(self):
        nuclei_scan.approved_templates()
        target = self.target()
        expected = template_bundle.current().sha256
        self.assertEqual(target['template_policy'], {'rev': nuclei_scan.TEMPLATE_POLICY_REV, 'read_only': True, 'bundle_sha256': expected})
        self.assertEqual(target['etags'], ['dos'])
        self.assertEqual(target['targets'], ['www.example.test'])

    def test_the_field_follows_the_policy(self):
        nuclei_scan.approved_templates()
        restricted = self.target()['template_policy']
        ScanPolicy.objects.update(nuclei_all_templates=True)
        nuclei_scan.approved_templates()
        everything = self.target()['template_policy']
        self.assertEqual(everything['rev'], nuclei_scan.ALL_TEMPLATES_REV)
        self.assertNotEqual(restricted['bundle_sha256'], everything['bundle_sha256'])

    def test_a_bundle_that_cannot_be_built_never_fails_the_dispatch(self):
        nuclei_scan.approved_templates()
        with mock.patch.object(template_bundle, '_pack', side_effect=template_bundle.BundleError('no')):
            self.assertIsNone(self.target()['template_policy']['bundle_sha256'])


class HeartbeatRunningTests(SentinelBase):
    def setUp(self):
        super().setUp()
        self.project = Project.objects.get(slug='sen-a')

    def running_task(self, token, accepted_ago=300, host='www.a.example'):
        """A task leased to this Sentinel and accepted ``accepted_ago`` seconds ago."""
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind='naabu', target={'addresses': ['192.0.2.50']},
                                           host=host, ips=['192.0.2.50'])
        status, out = call(token, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(out['task']['id'], task.pk)
        self.assertEqual(call(token, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')[0], 200)
        SentinelTask.objects.filter(pk=task.pk).update(accepted_at=timezone.now() - timedelta(seconds=accepted_ago))
        return task

    def heartbeat(self, token, body=None):
        reset_rates({'t': token})
        return call(token, 'POST', '/api/v1/sentinel/heartbeat', body)

    def test_a_task_missing_from_the_list_is_ended_as_expired(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        status, out = self.heartbeat(self.t['dana'], {'running': []})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual((task.status, task.error), ('expired', 'the Sentinel no longer reports this task'))
        self.assertIsNone(task.agent_id)
        self.assertEqual(out['leases'], [])  # and the reply does not offer a lease on it

    def test_a_task_in_the_list_is_kept_and_its_lease_extended(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        status, out = self.heartbeat(self.t['dana'], {'running': [task.pk, 999999]})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'running')
        self.assertEqual([lease['task_id'] for lease in out['leases']], [task.pk])

    def test_a_task_accepted_less_than_two_minutes_ago_is_left_alone(self):
        register_sentinel(self.t['dana'])
        fresh = self.running_task(self.t['dana'], accepted_ago=60)
        self.heartbeat(self.t['dana'], {'running': []})
        fresh.refresh_from_db()
        self.assertEqual(fresh.status, 'running')
        SentinelTask.objects.filter(pk=fresh.pk).update(accepted_at=timezone.now() - timedelta(seconds=121))
        self.heartbeat(self.t['dana'], {'running': []})
        fresh.refresh_from_db()
        self.assertEqual(fresh.status, 'expired')

    def test_another_sentinels_tasks_are_never_touched(self):
        register_sentinel(self.t['dana'], name='sentinel-dana')
        register_sentinel(self.t['alice'], name='sentinel-alice')
        mine = self.running_task(self.t['dana'])
        theirs = self.running_task(self.t['alice'], host='www2.a.example')
        self.assertNotEqual(mine.pk, theirs.pk)
        self.heartbeat(self.t['dana'], {'running': []})
        mine.refresh_from_db()
        theirs.refresh_from_db()
        self.assertEqual((mine.status, theirs.status), ('expired', 'running'))
        self.assertIsNotNone(theirs.agent_id)
        self.heartbeat(self.t['dana'], {'running': [theirs.pk]})  # naming another Sentinel's task changes nothing either
        theirs.refresh_from_db()
        self.assertEqual(theirs.status, 'running')

    def test_without_the_field_nothing_is_ended(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        for body in (None, {}, {'running': None}, {'info': None}):
            self.assertEqual(self.heartbeat(self.t['dana'], body)[0], 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'running')

    def test_a_claimed_task_that_was_never_accepted_is_judged_by_its_claim_time(self):
        register_sentinel(self.t['dana'])
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind='naabu', target={'addresses': ['192.0.2.50']},
                                           host='www.a.example', ips=['192.0.2.50'])
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.heartbeat(self.t['dana'], {'running': []})
        task.refresh_from_db()
        self.assertEqual(task.status, 'claimed')  # just offered
        SentinelTask.objects.filter(pk=task.pk).update(claimed_at=timezone.now() - timedelta(seconds=200), lease_expires_at=timezone.now() + timedelta(seconds=60))
        self.heartbeat(self.t['dana'], {'running': []})
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')

    def test_a_bad_value_is_a_400_naming_the_field_and_ends_nothing(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        for bad in ('1', 5, {'a': 1}, [0], [-1], [1.5], ['1'], [True], [None], [[1]], list(range(1, 102))):
            status, out = self.heartbeat(self.t['dana'], {'running': bad})
            self.assertEqual(status, 400, bad)
            self.assertIn('running', out['error'])
        task.refresh_from_db()
        self.assertEqual(task.status, 'running')
        self.assertEqual(self.heartbeat(self.t['dana'], {'running': list(range(1, 101))})[0], 200)  # exactly 100 is fine

    def test_the_expired_task_frees_the_slot_for_the_dispatcher(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        self.heartbeat(self.t['dana'], {'running': []})
        self.assertFalse(SentinelTask.objects.filter(pk=task.pk, status__in=('claimed', 'running')).exists())
        agent_id = Agent.objects.get(token__key_hash=hash_token(self.t['dana'])).pk
        self.assertEqual(sb.slot_usage([agent_id]).get(agent_id, {}), {})
