"""cvengine.definitions, roles and utilities after their clean-room rewrite: the values the database and other modules rely on are unchanged,
and the helpers behave as their specification says."""
import datetime
import logging
from unittest import mock

from django.test import SimpleTestCase

from cvengine import definitions as d
from cvengine import roles, utilities


class DefinitionValueTests(SimpleTestCase):
    def test_stored_and_compared_values_are_unchanged(self):
        expected = {
            'ALL': 'all', 'EXTENSIONS': 'extensions', 'OSINT': 'osint', 'PORT': 'port', 'RATE_LIMIT': 'rate_limit', 'RETRIES': 'retries',
            'TIMEOUT': 'timeout', 'NUCLEI': 'nuclei', 'NMAP': 'nmap', 'USER_AGENT': 'user_agent', 'PROVIDERS': 'providers',
            'NUCLEI_SEVERITY_MAP': {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4, 'unknown': -1},
            'NUCLEI_REVERSE_SEVERITY_MAP': {0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical', -1: 'unknown'},
            'DISCORD_INFO_COLOR': '0xfbbc00', 'DISCORD_WARNING_COLOR': '0xf75b00', 'DISCORD_ERROR_COLOR': '0xf70000',
            'DISCORD_SUCCESS_COLOR': '0x00ff78',
            'DISCORD_SEVERITY_COLORS': {'info': '0xfbbc00', 'warning': '0xf75b00', 'error': '0xf70000', 'aborted': '0xf70000',
                                        'success': '0x00ff78'},
            'STATUS_TO_SEVERITIES': {'RUNNING': 'info', 'SUCCESS': 'success', 'FAILED': 'error', 'ABORTED': 'error'},
            'INITIATED_TASK': -1, 'FAILED_TASK': 0, 'RUNNING_TASK': 1, 'SUCCESS_TASK': 2, 'ABORTED_TASK': 3,
            'CELERY_TASK_STATUS_MAP': {-1: 'INITITATED', 0: 'FAILED', 1: 'RUNNING', 2: 'SUCCESS', 3: 'ABORTED'},
            'CELERY_TASK_STATUSES': ((-1, -1), (0, 0), (1, 1), (2, 2), (3, 3)),
            'PERM_MODIFY_SYSTEM_CONFIGURATIONS': 'modify_system_configurations', 'PERM_MODIFY_SCAN_CONFIGURATIONS': 'modify_scan_configurations',
            'PERM_MODIFY_TARGETS': 'modify_targets', 'PERM_MODIFY_SCAN_RESULTS': 'modify_scan_results', 'PERM_MODIFY_WORDLISTS': 'modify_wordlists',
            'PERM_MODIFY_INTERESTING_LOOKUP': 'modify_interesting_lookup', 'PERM_MODIFY_SCAN_REPORT': 'modify_scan_report',
            'PERM_INITATE_SCANS_SUBSCANS': 'initiate_scans_subscans', 'FOUR_OH_FOUR_URL': '/404/',
            'SYSTEM_LEVEL_NOTIFICATION': 'system', 'PROJECT_LEVEL_NOTIFICATION': 'project',
            'NOTIFICATION_TYPES': (('system', 'system'), ('project', 'project')),
            'NOTIFICATION_STATUS_TYPES': (('success', 'Success'), ('info', 'Informational'), ('warning', 'Warning'), ('error', 'Error')),
        }
        for name, value in expected.items():
            self.assertEqual(getattr(d, name), value, name)
        self.assertFalse(hasattr(d, '__all__'))  # star importers get every name
        self.assertIsInstance(d.logger, logging.Logger)
        self.assertEqual(d.logger.name, 'django')


class RoleTests(SimpleTestCase):
    def test_role_names_and_permission_grants(self):
        perms = [d.PERM_MODIFY_SYSTEM_CONFIGURATIONS, d.PERM_MODIFY_SCAN_CONFIGURATIONS, d.PERM_MODIFY_SCAN_RESULTS, d.PERM_MODIFY_WORDLISTS,
                 d.PERM_MODIFY_INTERESTING_LOOKUP, d.PERM_MODIFY_SCAN_REPORT, d.PERM_INITATE_SCANS_SUBSCANS, d.PERM_MODIFY_TARGETS]
        grants = {
            roles.SysAdmin: [True] * 8,
            roles.PenetrationTester: [False, True, True, True, True, True, True, True],
            roles.Auditor: [False, False, True, False, True, True, False, False],
        }
        for role, row in grants.items():
            self.assertEqual(role.available_permissions, dict(zip(perms, row)), role.__name__)
        self.assertEqual([r.get_name() for r in grants], ['sys_admin', 'penetration_tester', 'auditor'])  # stored role names


class UtilityTests(SimpleTestCase):
    def test_time_taken_text(self):
        t0 = datetime.datetime(2026, 1, 1, 0, 0, 0)
        cases = {0: '0 seconds', 42: '42 seconds', 60: '1 minutes', 119: '1 minutes', 3599: '59 minutes', 3600: '1 hours',
                 3660: '1 hours 1 minutes', 3 * 86400 + 125: '72 hours 2 minutes', 7200 + 59: '2 hours'}
        for seconds, text in cases.items():
            self.assertEqual(utilities.get_time_taken(t0 + datetime.timedelta(seconds=seconds, microseconds=999), t0), text, seconds)

    def test_replace_nulls_recurses_into_lists_and_dict_values_only(self):
        data = {'a\x00': ['x\x00y', {'k': 'v\x00'}, 3], 'b': ('t\x00',), 'c': None}
        self.assertEqual(utilities.replace_nulls(data), {'a\x00': ['xy', {'k': 'v'}, 3], 'b': ('t\x00',), 'c': None})

    def test_scope_checker_regex_and_plain_patterns(self):
        checker = utilities.SubdomainScopeChecker(['^dev\\.', 'Staging', '', None, 'bad[pattern'])
        self.assertTrue(checker.is_out_of_scope('DEV.example.test'))
        self.assertTrue(checker.is_out_of_scope('app.staging.example.test'))
        self.assertTrue(checker.is_out_of_scope('BAD[PATTERN'))
        self.assertFalse(checker.is_out_of_scope('bad[pattern.example.test'))  # a plain pattern is the whole name
        self.assertFalse(checker.is_out_of_scope('www.example.test'))
        self.assertEqual(checker.plain_patterns, {'bad[pattern'})
        self.assertEqual(len(checker.regex_patterns), 2)

    def test_task_formatter_names_the_task_or_the_function(self):
        fmt = utilities.CVEngineTaskFormatter('%(task_name)s|%(task_id)s|%(message)s')
        record = logging.LogRecord('x', logging.INFO, '/p/mod.py', 1, 'hello', None, None, func='fn')
        with mock.patch.object(utilities, 'get_current_task', return_value=None):
            self.assertEqual(fmt.format(record), 'mod.fn||hello')
        task = mock.Mock()
        task.name = 'cvengine.tasks.port_scan'
        task.request.id = 'abc'
        record = logging.LogRecord('x', logging.INFO, '/p/mod.py', 1, 'hi', None, None, func='fn')
        with mock.patch.object(utilities, 'get_current_task', return_value=task):
            self.assertEqual(fmt.format(record), 'cvengine/port_scan|abc|hi')

    def test_secret_alphabet_and_length(self):
        from cvengine.init import get_random
        allowed = set('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)')
        values = {get_random() for _ in range(20)}
        self.assertEqual(len(values), 20)
        for value in values:
            self.assertEqual(len(value), 64)
            self.assertLessEqual(set(value), allowed)
