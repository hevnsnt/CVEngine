"""Situations in one pass (cveFeed.situations, perf/situations-queries-and-list).

The ranking reads each source once, row by row, and the same rows give every host's counts and the first items its list row shows; the tier of a CVE
match and a scanner finding is worked out in Python (``tier_of``) instead of a CASE that repeated the heat expression; the AI reviewer's demotions are
read in one small query (``disputed_ids``) instead of a dozen correlated subqueries per finding. These tests hold each piece to the path it replaced
(the SQL tier, the per-finding review subqueries, the grouped queries, the windowed item read) on the same rows, and pin the query counts.
"""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.db.models import Count, IntegerField, Max, Min, Q, Value
from django.test.utils import CaptureQueriesContext

from cveFeed import reviewer, situations
from cveFeed.models import CVEEntry, CVEMatch, FindingReview, HygieneFinding, Triage
from startScan.models import Vulnerability
from tests.test_situations import Seeded


def old_group_rows(qs, kev=None, manual=None, distinct=None):
	"""The grouped query the ranking used before the one pass (``situations._group_rows`` on develop), kept here as the reference."""
	aggregates = {'n': Count(distinct or 'pk', distinct=bool(distinct)), 'worst': Max('sev'), 'oldest': Min('first')}
	aggregates['kev_n'] = Count('pk', filter=Q(**{kev: True})) if kev else Value(0, output_field=IntegerField())
	aggregates['manual_n'] = Count('pk', filter=manual) if manual is not None else Value(0, output_field=IntegerField())
	return sorted((r['pid'], r['lname'], r['tier'], r['n'], r['worst'] or 0, r['oldest'], r['kev_n'], r['manual_n'])
				  for r in qs.values('pid', 'lname', 'tier').annotate(**aggregates))


def old_read_items(groups, cap):
	"""The windowed item read the list used before the one pass (``situations._read_items`` on develop, with the per-finding review subqueries), kept
	here as the reference."""
	from collections import defaultdict
	from cveFeed.models import Triage as T
	S = situations
	wanted = S._wanted(groups)
	items = defaultdict(list)

	def full(qs):  # the demotion as it was: the newest review read per finding
		return qs.annotate(**reviewer.newest_review_q('triage__')).annotate(disputed=S._disputed())
	qs = full(S._match_rows(list(wanted)))
	qs = qs.annotate(tier=S._tier_case(Q(triage__validation_status=S.VALIDATION_HIT), Q(triage__heat_override=S.ICE), Q(triage__heat_override__in=(S.FIRE, S.SMOKE)),
									   Q(disputed=False, heat__gte=S.HEAT_RANK[S.SMOKE])))
	for r in S._windowed(qs, wanted, cap).values('pk', 'pid', 'lname', 'tier', 'sev', 'heat', 'first', 'cve_entry__cve_id', 'cve_entry__kev', 'matched_product',
												'triage__heat_override', 'triage__id'):
		items[(r['pid'], r['lname'])].append(S._item('match', r['pk'], r['cve_entry__cve_id'], r['tier'], r['sev'], r['heat'], r['first'], 'cve',
													 kev=bool(r['cve_entry__kev']), product=S.product(r['matched_product']), manual=bool(r['triage__heat_override']),
													 triage=r['triage__id']))
	qs = full(S._vuln_rows(list(wanted)))
	qs = qs.annotate(tier=S._tier_case(Q(triage__validation_status=S.VALIDATION_HIT), Q(triage__heat_override=S.ICE), Q(triage__heat_override__in=(S.FIRE, S.SMOKE)),
									   Q(disputed=False, heat__gte=S.HEAT_RANK[S.SMOKE]), exposure=S._exposure_q(), hygiene=S._takeover_q()))
	for r in S._windowed(qs, wanted, cap).values('pk', 'pid', 'lname', 'tier', 'sev', 'heat', 'first', 'name', 'source', 'triage__heat_override', 'triage__id'):
		what = 'database' if r['source'] == S.SOURCE_DB else 'dns' if r['tier'] in (S.EXPOSURE, S.HYGIENE) else 'finding'
		items[(r['pid'], r['lname'])].append(S._item('vulnerability', r['pk'], r['name'], r['tier'], r['sev'], r['heat'], r['first'], what,
													 manual=bool(r['triage__heat_override']), triage=r['triage__id']))
	for r in S._windowed(S._hygiene(list(wanted)), wanted, cap).values('pk', 'pid', 'lname', 'tier', 'sev', 'first', 'title', 'check_name'):
		what = S.HYGIENE_WHAT.get(r['check_name'], 'hygiene') if r['tier'] == S.HYGIENE else 'admin' if r['tier'] == S.EXPOSURE else 'hygiene'
		items[(r['pid'], r['lname'])].append(S._item('hygiene', r['pk'], r['title'], r['tier'], r['sev'], 0, r['first'], what, check=r['check_name']))
	qs = S._secrets(list(wanted)).filter(S._host_filter(wanted)).order_by('pid', 'lname', '-finding__severity', 'finding_id').values(
		'pid', 'lname', 'finding_id', 'finding__masked', 'finding__provider', 'finding__kind', 'sev', 'first').distinct()
	seen, per_host = set(), defaultdict(int)
	for r in qs:
		key = (r['pid'], r['lname'])
		if (key, r['finding_id']) in seen or per_host[key] >= cap:
			continue
		seen.add((key, r['finding_id']))
		per_host[key] += 1
		label = ' '.join(filter(None, [S.clean(r['finding__provider'], 40) or S.clean(r['finding__kind'], 40), 'secret', S.clean(r['finding__masked'], 40)]))
		items[key].append(S._item('secret', r['finding_id'], label, S.HYGIENE, r['sev'], 0, r['first'], 'secret'))
	proven = [i['triage'] for rows_ in items.values() for i in rows_ if i['tier'] == S.PROVEN and i.get('triage')]
	steps = dict(T.objects.filter(pk__in=proven).values_list('pk', 'validation_steps')) if proven else {}
	for rows_ in items.values():
		for i in rows_:
			i['proof'] = S._proof(steps.get(i.get('triage'))) if i['tier'] == S.PROVEN else None
	for rows_ in items.values():
		rows_.sort(key=S._item_key)
	return items


class Rich(Seeded):
	"""The seeded project plus a host with more items than a list row shows, every tier, heats a person set, a takeover-able dangling record, a name
	with a port, an alias on the same address, and AI reviews that demote and that do not."""

	@classmethod
	def setUpTestData(cls):
		super().setUpTestData()
		cls.many = cls.host('many.sa.test', http=200, webserver='Apache')
		cls.alias = cls.host('alias.sa.test', address='192.0.2.250')
		cls.many.ip_addresses.set(cls.alias.ip_addresses.all())  # the same address: one host, the alias folded into it
		cves = [CVEEntry.objects.create(cve_id=f'CVE-2098-{i}', cvss=(3.0, 5.0, 7.5, 9.8)[i % 4], kev=i % 5 == 0, exploit_db=i % 3 == 0, affected=[])
				for i in range(16)]
		heats = {2: 'fire', 3: 'ice', 4: 'smoke'}
		cls.matches = [cls.match(cls.many, cve, heat=heats.get(i, ''), validation='hit' if i in (1, 3) else 'none', steps=cls.hit(f'probe {i}') if i in (1, 3) else None)
					   for i, cve in enumerate(cves)]
		cls.match(cls.alias, cves[0])
		for i in range(14):
			cls.finding(cls.many, (1, 2, 3, 4)[i % 4], f'Finding {i:02d}', source='nuclei')
		cls.finding(cls.many, 4, 'Dangling NS record', source='bbot')  # high: someone can take it over (high hygiene)
		cls.finding(cls.many, 2, 'Dangling CNAME record', source='bbot')  # exposure
		cls.finding(cls.many, 4, 'Open Redis', source='db_exposure')
		for check, sev in (('tls_expired', 3), ('dmarc_missing', 2), ('spf_allow_all', 2), ('cleartext_telnet', 3), ('hsts_missing', 1)):
			HygieneFinding.objects.create(domain=cls.da, host='many.sa.test:443' if check == 'tls_expired' else 'many.sa.test', check_name=check, severity=sev, title=check)
		# the AI reviewer: a high-confidence false positive demotes a likely match, unless the server refused it, a newer verdict replaced it, or a retest reproduced it
		likely = [m for m in cls.matches if Triage.objects.get(match=m).heat_override == '' and Triage.objects.get(match=m).validation_status != 'hit']
		cls.demoted, refused, replaced, retested, after_refusal = likely[:5]
		cls.review(cls.demoted, 'false_positive', 'high', 'recorded')
		cls.review(refused, 'false_positive', 'high', 'disputed')
		cls.review(replaced, 'false_positive', 'high', 'recorded')
		cls.review(replaced, 'true_open', 'high', 'recorded')
		cls.review(retested, 'false_positive', 'high', 'held')
		Triage.objects.filter(match=retested).update(retest_state='still_reproduces')
		cls.review(after_refusal, 'false_positive', 'high', 'held')
		cls.review(after_refusal, '', 'low', 'refused')
		finding = Vulnerability.objects.get(subdomain=cls.many, name='Finding 03')
		triage = Triage.objects.create(project=cls.pa, domain=cls.da, host=cls.many.name, kind='nuclei', vulnerability=finding, status='triaged', classification='likely')
		FindingReview.objects.create(triage=triage, project=cls.pa, review_key='v' * 40, verdict='false_positive', confidence='high', outcome='recorded')

	@classmethod
	def review(cls, match, verdict, confidence, outcome):
		triage = Triage.objects.get(match=match)
		return FindingReview.objects.create(triage=triage, project=cls.pa, review_key=f'{triage.pk:040d}'[-40:], verdict=verdict, confidence=confidence, outcome=outcome)

	def ids(self):
		return [self.pa.pk, self.pb.pk]


class EquivalenceTests(Rich):
	def test_the_demotions_are_the_per_finding_rule(self):
		old = set()
		for qs in (CVEMatch.objects.all(), Vulnerability.objects.all()):
			old |= set(qs.annotate(**reviewer.newest_review_q('triage__')).annotate(disputed=situations._disputed()).filter(disputed=True)
					   .values_list('triage__id', flat=True))
		self.assertEqual(set(situations.disputed_ids()), old)
		self.assertEqual(len(old), 3)  # the recorded one, the one after a refusal, the scanner finding
		self.assertIn(Triage.objects.get(match=self.demoted).pk, old)

	def test_the_tier_worked_out_in_python_is_the_sql_tier(self):
		disputed = situations.disputed_ids()
		for kind, full in (('match', situations._matches), ('vulnerability', situations._vulns)):
			sql = dict(full(self.ids())[0].values_list('pk', 'tier'))
			rows = situations._ranking_values(kind, situations._sources(self.ids(), disputed, tiers=False)[kind], disputed)
			self.assertEqual({r['pk']: r['tier'] for r in rows}, sql, kind)
		tiers = {r['tier'] for kind in ('match', 'vulnerability') for r in situations._ranking_values(kind, situations._sources(self.ids(), disputed, tiers=False)[kind], disputed)}
		self.assertEqual(tiers, {situations.PROVEN, situations.LIKELY, situations.HYGIENE, situations.EXPOSURE, situations.MINOR})

	def test_the_host_counts_are_the_grouped_queries(self):
		ids, disputed = self.ids(), situations.disputed_ids()
		qs, manual = situations._matches(ids)
		old = {'match': old_group_rows(qs, kev='cve_entry__kev', manual=manual)}
		qs, manual = situations._vulns(ids)
		old['vulnerability'] = old_group_rows(qs, manual=manual)
		old['hygiene'] = old_group_rows(situations._hygiene(ids))
		old['secret'] = old_group_rows(situations._secrets(ids), distinct='finding_id')
		for kind, qs in situations._sources(ids, disputed, tiers=False).items():
			self.assertEqual(sorted(situations._aggregate(situations._ranking_values(kind, qs, disputed))), old[kind], kind)

	def test_the_items_a_list_row_carries_are_the_windowed_read(self):
		groups, _hosts = situations._rank(self.ids())
		self.assertTrue(groups)
		old = old_read_items(groups, situations.LIST_ITEMS)
		for g in groups:
			self.assertEqual(g['items'], situations._items_of(g, old)[:situations.LIST_ITEMS], g['name'])
		many = next(g for g in groups if g['name'] == 'many.sa.test')
		self.assertEqual(len(many['items']), situations.LIST_ITEMS)
		self.assertGreater(sum(many['n'].values()), 2 * situations.LIST_ITEMS)  # more than one source was cut
		self.assertIn('many.sa.test:443', many['names'])
		self.assertIn('alias.sa.test', many['all'])

	def test_a_ranking_cached_without_items_lists_the_same(self):
		# a ranking stored by the previous release carries no items: its page reads them as before, and says the same
		groups, hosts = situations._rank(self.ids())
		bare = [{k: v for k, v in g.items() if k != 'items'} for g in groups]
		for kwargs in ({}, {'size': 2, 'page': 2}, {'tier': 'likely'}, {'q': 'many'}):
			with mock.patch.object(situations, 'ranked', return_value=(groups, hosts)):
				new = situations.listing(self.ids(), **kwargs)
			with mock.patch.object(situations, 'ranked', return_value=(bare, hosts)):
				old = situations.listing(self.ids(), **kwargs)
			self.assertEqual(new, old, kwargs)
			self.assertTrue(new['results'] or kwargs.get('page'))

	def test_the_detail_reads_the_items_as_before(self):
		groups, _hosts = situations._rank(self.ids())
		for cap in (situations.LIST_ITEMS, situations.DETAIL_ITEMS):
			self.assertEqual(situations._read_items(groups, cap), old_read_items(groups, cap), cap)
		row = situations.one(self.ids(), 'many.sa.test')
		self.assertEqual(row['findings_total'], len(row['findings']))


class QueryCeilingTests(Rich):
	def setUp(self):
		super().setUp()
		cache.clear()

	def test_a_list_page_reads_no_items_of_its_own(self):
		ids = self.ids()
		situations.ranked(ids)  # the shared ranking, built once
		info = situations._scope_info(ids)
		with CaptureQueriesContext(connection) as ctx:
			out = situations.listing(ids, size=50, info=info)
		self.assertTrue(out['results'])
		sources = ('cveFeed_cvematch', 'startScan_vulnerability', 'cveFeed_hygienefinding', 'cveFeed_secretoccurrence', 'cveFeed_triage', 'cveFeed_findingreview')
		self.assertFalse([q['sql'][:120] for q in ctx if any(t in q['sql'] for t in sources)])
		self.assertLessEqual(len(ctx), 1, [q['sql'][:120] for q in ctx])  # at most the project ids of the snapshot key (snapshot_cache.scope_hash)

	def test_the_ranking_reads_a_fixed_number_of_queries(self):
		from cveFeed import current_scans
		ids = self.ids()

		def count():
			cache.clear()
			with current_scans.shared_sets(), CaptureQueriesContext(connection) as ctx:
				situations._rank(ids)
			return len(ctx)
		count()  # the process-level caches a first ranking fills (the internal ranges, the policies) are not the ranking's own work
		few = count()
		for i in range(10):
			sub = self.host(f'bulk{i}.sa.test')
			self.match(sub, self.kev, validation='hit', steps=self.hit())
			self.finding(sub, 4, 'Dangling NS record', source='bbot')
		self.assertEqual(count(), few, 'the number of queries must not grow with the number of hosts')
		# the current scans, 2 inventory queries, the demotions, one per source, the proofs, the gone check at most
		self.assertLessEqual(few, 10)

	def test_new_worth_a_look_reads_the_demotions_once(self):
		now = self.now
		with CaptureQueriesContext(connection) as ctx:
			situations.new_worth_a_look(self.ids(), now - timedelta(days=30), now + timedelta(days=1))
		self.assertEqual(sum('cveFeed_findingreview' in q['sql'] for q in ctx), 1)
