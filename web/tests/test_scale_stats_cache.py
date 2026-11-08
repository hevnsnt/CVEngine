"""The dashboard's headline numbers are a cached snapshot (``cveFeed.snapshot_cache``). They must equal a direct recount of the same definitions
(``views.stats_payload``, built on ``cveFeed.counts``) after any sequence of writes once the writing path has told the cache (``bump_stats_revision``), and
after at most STATS_CACHE_SECONDS when a path writes without telling it (a scan storing a finding straight through the ORM). This runs a seeded random sequence
of 80 writes of every kind the numbers count (a host, a finding of any severity, a CVE match, a closed finding, a deleted one, a hygiene finding, a certificate,
a scan starting and ending, a target) and compares the cached payload with the recount after each; the stampede and scoping are in tests/test_live_cache.py.
"""
import random
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from cveFeed import snapshot_cache, views
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, TlsCertificate
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_live_cache import World, steady_caches

NUMBERS = ('targets', 'certs_expiring', 'certs_total', 'hygiene_open', 'hosts', 'hosts_live', 'tiers', 'cves', 'matches', 'match_groups', 'scanner_findings',
           'exposed_hosts', 'oldest_open_days', 'oldest_open_kind', 'scans_running', 'autofire_runs', 'templates')


def picked(payload):
    return {k: payload[k] for k in NUMBERS if k in payload}


class CachedNumbersEqualARecountTests(World):
    def setUp(self):
        super().setUp()
        self.rng = random.Random(20261107)
        self.domain, self.scan, _running, _host = self.hosts['alpha']
        self.live_scan = self.scan
        self.n = 0

    # --- the writes -------------------------------------------------------------------------------------------------------------------------------

    def host(self):
        self.n += 1
        h = Subdomain.objects.create(name=f'h{self.n}.alpha.lcexample.test', target_domain=self.domain, scan_history=self.scan, http_status=self.rng.choice((0, 200, 403)))
        if self.rng.random() < .7:
            h.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{self.n % 250 + 1}'))
        return h

    def some_host(self):
        return Subdomain.objects.filter(target_domain=self.domain).order_by('?').first() or self.host()

    def finding(self):
        self.n += 1
        return Vulnerability.objects.create(name=f'f{self.n}', severity=self.rng.randint(0, 4), subdomain=self.some_host(), target_domain=self.domain, scan_history=self.scan,
                                            open_status=self.rng.random() < .9, template_id=f't{self.n}', http_url='https://x.example.test/', discovered_date=timezone.now())

    def match(self):
        self.n += 1
        cve = CVEEntry.objects.create(cve_id=f'CVE-2099-8{self.n:03d}', kev=self.rng.random() < .3, cvss=self.rng.choice((5.0, 7.5, 9.8)), published_at=timezone.now(), affected=[])
        return CVEMatch.objects.create(cve_entry=cve, subdomain=self.some_host(), matched_product=f'p{self.n}', confidence=.8,
                                       ai_verdict=self.rng.choice(('', 'affected', 'not_affected')))

    def close_one(self):
        row = Vulnerability.objects.filter(target_domain=self.domain).order_by('?').first()
        if row:
            row.remediation_status = self.rng.choice(('fixed', 'accepted_risk', 'false_positive', 'open'))
            row.save()

    def delete_one(self):
        row = Vulnerability.objects.filter(target_domain=self.domain).order_by('?').first()
        if row:
            row.delete()

    def hygiene(self):
        HygieneFinding.objects.create(domain=self.domain, host=self.some_host().name, check_name=f'c{self.n}', severity=self.rng.randint(0, 3), title='t',
                                      status=self.rng.choice(('open', 'open', 'fixed')))

    def cert(self):
        self.n += 1
        TlsCertificate.objects.create(domain=self.domain, host=self.some_host().name, port=1000 + self.n, subject='s', issuer='i',
                                      not_after=timezone.now() + timedelta(days=self.rng.randint(-5, 120)))

    def scan_cycle(self):
        s = ScanHistory.objects.create(domain=self.domain, scan_type=EngineType.objects.first(), scan_status=self.rng.choice((1, 2, -1)), start_scan_date=timezone.now())
        if s.scan_status == 2:
            self.scan = s

    def target(self):
        self.n += 1
        Domain.objects.create(name=f'extra{self.n}.lcexample.test', project=self.alpha, insert_date=timezone.now())

    def writes(self):
        return [self.host, self.finding, self.finding, self.match, self.close_one, self.delete_one, self.hygiene, self.cert, self.scan_cycle, self.target]

    # --- the comparison ---------------------------------------------------------------------------------------------------------------------------

    def test_after_every_write_that_tells_the_cache_the_numbers_equal_a_recount(self):
        with steady_caches():
            for step in range(80):
                self.rng.choice(self.writes())()
                views.bump_stats_revision()  # what every path that closes, rates or stores a finding does (cveFeed.views.bump_stats_revision callers)
                cached = views.cached_stats_snapshot()['payload']
                direct = views.stats_payload()
                self.assertEqual(picked(cached), picked(direct), f'after write {step}')

    def test_a_write_that_does_not_tell_the_cache_is_stale_for_at_most_the_freshness_window(self):
        with steady_caches():
            first = views.cached_stats_snapshot()['payload']
            self.host()
            self.finding()
            within = views.cached_stats_snapshot()['payload']
            self.assertEqual(picked(within), picked(first), 'inside the window the snapshot is served as it was (bounded staleness, by design)')
            later = snapshot_cache._now() + views.STATS_CACHE_SECONDS + 1
            with mock.patch.object(snapshot_cache, '_now', return_value=later):
                after = views.cached_stats_snapshot()['payload']
            self.assertEqual(picked(after), picked(views.stats_payload()))
            self.assertNotEqual(picked(after), picked(first), 'the recount saw the two writes')

    def test_the_window_is_ten_seconds_and_a_snapshot_is_kept_longer_than_that_to_serve_while_one_request_recomputes(self):
        self.assertEqual(views.STATS_CACHE_SECONDS, 10)
        self.assertGreaterEqual(snapshot_cache.store_seconds(views.STATS_CACHE_SECONDS), snapshot_cache.STALE_KEEP_SECONDS)
