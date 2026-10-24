from django.db import connection
from django.test import TestCase


def _index_names(model):
	with connection.cursor() as cursor:
		constraints = connection.introspection.get_constraints(cursor, model._meta.db_table)
	return {name: info for name, info in constraints.items() if info['index']}


class PerfIndexTests(TestCase):
	def _assert_cols(self, model, name, columns):
		indexes = _index_names(model)
		self.assertIn(name, indexes)
		self.assertEqual(indexes[name]['columns'], columns)

	def test_startscan_indexes(self):
		from startScan.models import ScanHistory, Subdomain, Technology, Vulnerability
		self._assert_cols(Subdomain, 'sub_domain_name_idx', ['target_domain_id', 'name'])
		self._assert_cols(Subdomain, 'sub_scan_name_idx', ['scan_history_id', 'name'])
		self._assert_cols(Subdomain, 'sub_domain_score_idx', ['target_domain_id', 'score'])
		self._assert_cols(ScanHistory, 'scan_status_id_idx', ['scan_status', 'id'])
		self._assert_cols(ScanHistory, 'scan_domain_status_idx', ['domain_id', 'scan_status'])
		self._assert_cols(Vulnerability, 'vuln_sub_open_sev_idx', ['subdomain_id', 'open_status', 'severity'])
		self._assert_cols(Vulnerability, 'vuln_scan_name_idx', ['scan_history_id', 'name'])
		self.assertTrue(any(info['columns'] == ['name'] for info in _index_names(Technology).values()))

	def test_cvefeed_indexes(self):
		from cveFeed.models import CVEMatch, ServiceRun
		self._assert_cols(CVEMatch, 'cvematch_sub_verdict_idx', ['subdomain_id', 'ai_verdict'])
		self._assert_cols(ServiceRun, 'servicerun_svc_asset_proj_idx', ['service', 'asset', 'project_id'])
		self._assert_cols(ServiceRun, 'servicerun_svc_proj_fin_idx', ['service', 'project_id', 'finished_at'])

	def test_asset_change_indexes(self):
		from cveFeed.models import AssetChange, HostState
		self._assert_cols(AssetChange, 'assetchange_proj_at_idx', ['project_id', 'detected_at'])
		self._assert_cols(AssetChange, 'assetchange_proj_kind_at_idx', ['project_id', 'kind', 'detected_at'])
		self._assert_cols(AssetChange, 'assetchange_proj_host_at_idx', ['project_id', 'host', 'detected_at'])
		with connection.cursor() as cursor:
			constraints = connection.introspection.get_constraints(cursor, HostState._meta.db_table)
		self.assertEqual(constraints['uniq_hoststate_project_host']['columns'], ['project_id', 'host'])
		self._assert_cols(HostState, 'hoststate_domain_retired_idx', ['domain_id', 'retired_at'])
		self._assert_cols(HostState, 'hoststate_proj_zombie_idx', ['project_id', 'zombie_since'])

	def test_route_auth_indexes(self):
		from cveFeed.models import RouteAuth
		self._assert_cols(RouteAuth, 'routeauth_proj_state_idx', ['project_id', 'auth_state'])
		self._assert_cols(RouteAuth, 'routeauth_proj_host_idx', ['project_id', 'host'])
		self._assert_cols(RouteAuth, 'routeauth_proj_sens_idx', ['project_id', 'sensitive_score'])
		with connection.cursor() as cursor:
			constraints = connection.introspection.get_constraints(cursor, RouteAuth._meta.db_table)
		self.assertEqual(constraints['uniq_routeauth_project_url']['columns'], ['project_id', 'url'])
