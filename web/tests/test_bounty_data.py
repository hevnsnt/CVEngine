import json
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import bounty_data as bd
from cveFeed.models import BountyAsset, BountyProgram, BountyScopeChange, BountySource


class NormalizeAssetTests(SimpleTestCase):
    def one(self, raw_type, ident):
        return bd.normalize_asset(raw_type, ident)

    def test_domain_url_and_wildcard(self):
        self.assertEqual(self.one('URL', 'API.Example.com'), [('domain', 'api.example.com')])
        self.assertEqual(self.one('URL', 'https://www.example.com/app/login?x=1'), [('url', 'www.example.com/app/login')])
        self.assertEqual(self.one('URL', 'https://*.example.com/'), [('wildcard', '*.example.com')])
        self.assertEqual(self.one('WILDCARD', '*.EXAMPLE.com.'), [('wildcard', '*.example.com')])

    def test_credentials_and_port_are_dropped(self):
        self.assertEqual(self.one('URL', 'user:pw@host.example.org:8443/x'), [('url', 'host.example.org/x')])

    def test_one_entry_may_name_several_hosts(self):
        self.assertEqual(self.one('URL', 'a.com, b.com'), [('domain', 'a.com'), ('domain', 'b.com')])

    def test_ip_cidr_and_range(self):
        self.assertEqual(self.one('IP_ADDRESS', '203.0.113.7'), [('ip', '203.0.113.7')])
        self.assertEqual(self.one('CIDR', '198.51.100.0/24'), [('cidr', '198.51.100.0/24')])
        self.assertEqual(self.one('URL', '194.9.120.0 - 194.9.123.255'), [('cidr', '194.9.120.0/22')])
        self.assertEqual(self.one('URL', '[2001:db8::1]'), [('ip', '2001:db8::1')])

    def test_a_block_too_wide_to_be_a_scope_is_not_read_as_one(self):
        self.assertEqual(self.one('CIDR', '10.0.0.0/7')[0][0], 'other')
        self.assertEqual(self.one('URL', '0.0.0.0 - 255.255.255.255')[0][0], 'other')

    def test_bad_network_values_are_other_not_hosts(self):
        self.assertEqual(self.one('URL', '10.0.0.0/33')[0][0], 'other')
        self.assertEqual(self.one('URL', '10.0.0.9 - 10.0.0.1')[0][0], 'other')

    def test_patterns_and_prose_stay_other(self):
        for value in ('api-*.example.com', '*.*.example.com', 'all', 'exa mple.com', 'javascript:alert(1)'):
            self.assertEqual(self.one('URL', value)[0][0], 'other', value)

    def test_redacted_and_empty_rows_name_nothing(self):
        self.assertEqual(self.one('URL', '\u2588' * 12), [])
        self.assertEqual(self.one('URL', ''), [])
        self.assertEqual(self.one('URL', None), [])
        self.assertEqual(self.one('URL', 'x' * 2001), [])

    def test_mobile_and_code_types(self):
        self.assertEqual(self.one('google_play_app_id', 'com.example.app'), [('mobile', 'com.example.app')])
        self.assertEqual(self.one('SOURCE_CODE', 'https://github.com/example/repo'), [('code', 'https://github.com/example/repo')])

    def test_control_characters_are_removed(self):
        self.assertEqual(self.one('URL', 'a.example.com\x00\n'), [('domain', 'a.example.com')])


H1 = [{'handle': 'acme', 'name': 'Acme', 'url': 'https://hackerone.com/acme', 'offers_bounties': True, 'submission_state': 'open',
       'managed_program': False, 'response_efficiency_percentage': 98, 'average_time_to_first_program_response': 12.5,
       'average_time_to_report_resolved': 300,
       'targets': {'in_scope': [{'asset_type': 'URL', 'asset_identifier': '*.acme.test', 'eligible_for_bounty': True, 'eligible_for_submission': True,
                                 'max_severity': 'critical', 'instruction': 'be nice'},
                                {'asset_type': 'URL', 'asset_identifier': 'www.acme.test', 'eligible_for_bounty': False}],
                   'out_of_scope': [{'asset_type': 'URL', 'asset_identifier': 'status.acme.test'}]}}]
BC = [{'name': 'Beta', 'url': 'https://bugcrowd.com/engagements/beta', 'max_payout': 5000, 'safe_harbor': 'full',
       'targets': {'in_scope': [{'type': 'website', 'name': 'Beta site', 'uri': 'https://beta.test'}], 'out_of_scope': []}}]
IG = [{'handle': 'gamma', 'company_handle': 'gco', 'name': 'Gamma', 'url': 'https://app.intigriti.com/x', 'status': 'open',
       'min_bounty': {'value': 100, 'currency': 'EUR'}, 'max_bounty': {'value': 2000, 'currency': 'EUR'},
       'targets': {'in_scope': [{'type': 'url', 'endpoint': 'gamma.test', 'impact': 'Tier 1', 'description': ''}], 'out_of_scope': []}}]
YW = [{'id': 'delta', 'name': 'Delta', 'public': True, 'disabled': False, 'min_bounty': 50, 'max_bounty': 0,
       'targets': {'in_scope': [{'type': 'web-application', 'target': 'delta.test'}], 'out_of_scope': []}}]


class NormalizePayloadTests(SimpleTestCase):
    def test_hackerone(self):
        [p] = bd.normalize_payload('hackerone', H1)
        self.assertEqual((p['handle'], p['offers_bounties'], p['response_efficiency'], p['first_response_hours']), ('acme', True, 98, 12.5))
        by = {(a['identifier'], a['in_scope']): a for a in p['assets']}
        self.assertTrue(by[('*.acme.test', True)]['eligible_for_bounty'])
        self.assertEqual(by[('*.acme.test', True)]['max_severity'], 'critical')
        self.assertIs(by[('www.acme.test', True)]['eligible_for_bounty'], False)
        self.assertIn(('status.acme.test', False), by)

    def test_bugcrowd(self):
        [p] = bd.normalize_payload('bugcrowd', BC)
        self.assertEqual((p['handle'], p['safe_harbor'], p['max_bounty'], p['offers_bounties']), ('beta', 'full', 5000, True))
        self.assertEqual(p['assets'][0]['identifier'], 'beta.test')

    def test_intigriti_and_yeswehack(self):
        [g] = bd.normalize_payload('intigriti', IG)
        self.assertEqual((g['handle'], g['currency'], g['min_bounty'], g['max_bounty']), ('gco/gamma', 'EUR', 100, 2000))
        [y] = bd.normalize_payload('yeswehack', YW)
        self.assertEqual((y['handle'], y['offers_bounties']), ('delta', False))

    def test_rows_without_a_handle_or_not_objects_are_skipped(self):
        self.assertEqual(bd.normalize_payload('hackerone', [1, 'x', None, {'name': 'no handle'}]), [])

    def test_a_non_list_file_is_refused(self):
        with self.assertRaises(ValueError):
            bd.normalize_payload('hackerone', {'a': 1})

    def test_text_is_cut_to_length_and_cleaned(self):
        row = {**H1[0], 'handle': 'h' * 500, 'name': 'N\x00' + 'x' * 900}
        [p] = bd.normalize_payload('hackerone', [row])
        self.assertEqual(len(p['handle']), 200)
        self.assertLessEqual(len(p['name']), 300)
        self.assertNotIn('\x00', p['name'])

    def test_duplicate_entries_are_collapsed(self):
        row = {**H1[0], 'targets': {'in_scope': [{'asset_type': 'URL', 'asset_identifier': 'a.test'}] * 3, 'out_of_scope': []}}
        [p] = bd.normalize_payload('hackerone', [row])
        self.assertEqual(len(p['assets']), 1)

    def test_hash_changes_with_scope_and_not_with_order(self):
        [a] = bd.normalize_payload('hackerone', H1)
        reorder = {**H1[0], 'targets': {'in_scope': list(reversed(H1[0]['targets']['in_scope'])), 'out_of_scope': H1[0]['targets']['out_of_scope']}}
        [b] = bd.normalize_payload('hackerone', [reorder])
        self.assertEqual(bd.content_hash(a), bd.content_hash(b))
        more = {**H1[0], 'targets': {'in_scope': H1[0]['targets']['in_scope'] + [{'asset_type': 'URL', 'asset_identifier': 'new.acme.test'}],
                                     'out_of_scope': H1[0]['targets']['out_of_scope']}}
        [c] = bd.normalize_payload('hackerone', [more])
        self.assertNotEqual(bd.content_hash(a), bd.content_hash(c))


class FetchTests(SimpleTestCase):
    def test_only_the_fixed_addresses_are_fetched(self):
        with self.assertRaises(ValueError):
            bd.fetch('https://evil.example/data.json')

    def _resp(self, status=200, chunks=(b'[]',), etag='"e1"'):
        r = mock.Mock(status_code=status, headers={'ETag': etag})
        r.iter_content.return_value = iter(chunks)
        return r

    def test_not_modified_returns_none(self):
        get = mock.Mock(return_value=self._resp(304))
        self.assertEqual(bd.fetch(bd.SOURCES['hackerone'], '"e1"', get=get), (None, '"e1"'))
        self.assertEqual(get.call_args.kwargs['headers']['If-None-Match'], '"e1"')

    def test_redirects_are_not_followed_and_a_bad_status_raises(self):
        get = mock.Mock(return_value=self._resp(302))
        with self.assertRaises(ValueError):
            bd.fetch(bd.SOURCES['hackerone'], get=get)
        self.assertIs(get.call_args.kwargs['allow_redirects'], False)

    def test_oversize_is_refused(self):
        with mock.patch.object(bd, 'MAX_BYTES', 10):
            with self.assertRaises(ValueError):
                bd.fetch(bd.SOURCES['hackerone'], get=mock.Mock(return_value=self._resp(chunks=(b'x' * 11,))))

    def test_body_and_etag_are_returned(self):
        self.assertEqual(bd.fetch(bd.SOURCES['hackerone'], get=mock.Mock(return_value=self._resp(chunks=(b'[{"a":', b'1}]')))), ([{'a': 1}], '"e1"'))


def fetcher(payload, etag='"v1"'):
    return lambda url, old: ((None, old) if old == etag else (payload, etag))


class SyncTests(TestCase):
    def sync(self, payload, etag='"v1"', **kw):
        return bd.sync_platform('hackerone', fetcher=fetcher(payload, etag), **kw)

    def test_first_load_stores_programs_and_assets_without_a_radar(self):
        out = self.sync(H1)
        self.assertEqual((out['status'], out['programs'], out['first_run']), ('updated', 1, True))
        p = BountyProgram.objects.get(handle='acme')
        self.assertEqual((p.in_scope_count, p.bounty_scope_count), (2, 1))
        self.assertEqual(BountyAsset.objects.filter(program=p).count(), 3)
        self.assertFalse(BountyScopeChange.objects.exists())
        src = BountySource.objects.get(platform='hackerone')
        self.assertEqual((src.etag, src.programs, src.last_error), ('"v1"', 1, ''))

    def test_unchanged_etag_costs_nothing(self):
        self.sync(H1)
        self.assertEqual(self.sync(H1)['status'], 'unchanged')

    def test_added_removed_and_flipped_scope_land_on_the_radar(self):
        self.sync(H1)
        changed = json.loads(json.dumps(H1))
        t = changed[0]['targets']
        t['in_scope'].append({'asset_type': 'URL', 'asset_identifier': 'new.acme.test'})
        t['in_scope'] = [a for a in t['in_scope'] if a['asset_identifier'] != 'www.acme.test']
        t['out_of_scope'].append({'asset_type': 'URL', 'asset_identifier': '*.acme.test'})
        t['in_scope'] = [a for a in t['in_scope'] if a['asset_identifier'] != '*.acme.test']
        self.sync(changed, etag='"v2"')
        kinds = {(c.kind, c.identifier) for c in BountyScopeChange.objects.all()}
        self.assertIn(('asset_added', 'new.acme.test'), kinds)
        self.assertIn(('asset_removed', 'www.acme.test'), kinds)
        self.assertIn(('asset_flipped', '*.acme.test'), kinds)
        p = BountyProgram.objects.get(handle='acme')
        self.assertIsNotNone(p.last_scope_change_at)
        self.assertEqual(p.in_scope_count, 1)
        self.assertEqual(BountyAsset.objects.filter(program=p, removed_at__isnull=False).count(), 2)

    def test_a_new_and_a_vanished_program(self):
        self.sync(H1)
        extra = json.loads(json.dumps(H1[0])); extra['handle'] = 'other'
        self.sync([H1[0], extra], etag='"v2"')
        self.assertTrue(BountyScopeChange.objects.filter(kind='program_added', program__handle='other').exists())
        self.sync([H1[0], extra, json.loads(json.dumps(H1[0])) | {'handle': 'third'}], etag='"v3"')
        self.sync([extra, json.loads(json.dumps(H1[0])) | {'handle': 'third'}, json.loads(json.dumps(H1[0])) | {'handle': 'fourth'}], etag='"v4"')
        gone = BountyProgram.objects.get(handle='acme')
        self.assertIsNotNone(gone.removed_at)
        self.assertTrue(BountyScopeChange.objects.filter(kind='program_removed', program=gone).exists())

    def test_a_truncated_file_is_ignored(self):
        many = [json.loads(json.dumps(H1[0])) | {'handle': f'p{i}'} for i in range(10)]
        self.sync(many)
        out = self.sync(many[:2], etag='"v2"')
        self.assertEqual(out['status'], 'error')
        self.assertEqual(BountyProgram.objects.filter(removed_at__isnull=True).count(), 10)
        self.assertIn('truncated', BountySource.objects.get(platform='hackerone').last_error)

    def test_an_empty_file_does_not_wipe_the_catalogue(self):
        self.sync(H1)
        self.assertEqual(self.sync([], etag='"v2"')['status'], 'error')
        self.assertEqual(BountyProgram.objects.filter(removed_at__isnull=True).count(), 1)

    def test_a_failed_fetch_is_recorded_and_changes_nothing(self):
        self.sync(H1)
        boom = mock.Mock(side_effect=RuntimeError('network down'))
        out = bd.sync_platform('hackerone', fetcher=boom)
        self.assertEqual(out['status'], 'error')
        self.assertIn('network down', BountySource.objects.get(platform='hackerone').last_error)
        self.assertEqual(BountyProgram.objects.count(), 1)

    def test_garbage_json_is_an_error_not_an_exception(self):
        self.assertEqual(self.sync({'not': 'a list'})['status'], 'error')

    def test_old_radar_rows_are_pruned(self):
        self.sync(H1)
        p = BountyProgram.objects.get(handle='acme')
        old = BountyScopeChange.objects.create(program=p, kind='asset_added', detected_at=timezone.now() - timedelta(days=bd.CHANGE_RETENTION_DAYS + 5))
        self.sync(H1[:1] + [json.loads(json.dumps(H1[0])) | {'handle': 'n'}], etag='"v2"')
        self.assertFalse(BountyScopeChange.objects.filter(pk=old.pk).exists())


class OverlongIdentifierTests(SimpleTestCase):
    def test_a_host_or_url_longer_than_the_column_is_kept_as_text_not_cut_into_another_host(self):
        long_path = 'https://www.example.com/' + 'a' * 900
        rows = bd._asset('URL', long_path, True, None, '', '')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['kind'], 'other')
        self.assertEqual(len(rows[0]['identifier']), 500)
        rows = bd._asset('URL', 'https://www.example.com/short', True, None, '', '')
        self.assertEqual((rows[0]['kind'], rows[0]['identifier']), ('url', 'www.example.com/short'))
