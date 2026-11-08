"""Fixes from the second fresh install: the Sentinel claim limiter scales with the Sentinel's slots and says when to come back (D2); the scanner bar says a
kind paused by the failure cool-off is paused, not offline (D12)."""
import json

from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import agent_broker as broker
from agentapi import sentinel_broker as sentinels
from agentapi import scanner_state
from agentapi.models import SentinelTask
from tests.test_scanner_waiting_state import SentinelWorld
from tests.test_sentinels import SentinelBase, register_sentinel, reset_rates


class ClaimLimitTests(SentinelBase):
    def poll(self, token, n):
        c = Client()
        out = []
        for _ in range(n):
            r = c.post('/api/v1/sentinel/tasks/next', json.dumps({'wait': 0}), content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {token}')
            out.append(r)
        return out

    def test_the_limit_grows_with_the_sentinels_slots_and_never_falls_below_the_old_sixty(self):
        self.assertEqual(sentinels.claim_limit(1), 60)
        self.assertEqual(sentinels.claim_limit(2), 60)
        self.assertEqual(sentinels.claim_limit(10), 300)
        self.assertEqual(sentinels.claim_limit('x'), 60)

    def test_a_sentinel_with_ten_slots_is_not_refused_at_the_old_sixty(self):
        status, out = register_sentinel(self.t['alice'], max_concurrent=10)
        self.assertEqual(status, 201, out)
        reset_rates(self.t)
        codes = [r.status_code for r in self.poll(self.t['alice'], 100)]
        self.assertNotIn(429, codes)  # 100 calls in a minute: two per task for fifty short tasks

    def test_a_one_slot_sentinel_still_hits_sixty_and_is_told_when_to_come_back(self):
        status, out = register_sentinel(self.t['alice'], max_concurrent=1)
        self.assertEqual(status, 201, out)
        reset_rates(self.t)
        responses = self.poll(self.t['alice'], 62)
        self.assertEqual([r.status_code for r in responses].count(429), 2)
        refused = responses[-1]
        self.assertIn('Retry-After', refused)
        self.assertTrue(1 <= int(refused['Retry-After']) <= broker.RATES['claim'][1])
        self.assertEqual(refused.json()['retry_after_seconds'], int(refused['Retry-After']))
        self.assertIn('too many claim calls', refused.json()['error'])


class PausedKindTests(SentinelWorld, TestCase):
    """D12: a kind a live Sentinel withholds after three failures in a row is paused, not offline, and never described as nothing having failed."""
    FAIL = 'TypeError: bbot deep scan crashed in module xyz ' + 'x' * 250

    def fail_tasks(self, agent, kind, n=3):
        for i in range(n):
            SentinelTask.objects.create(project=self.project, kind=kind, target={}, agent=agent, status='failed', error=self.FAIL,
                                        finished_at=timezone.now() - timedelta(minutes=i))

    def test_a_live_sentinel_with_a_withheld_kind_is_paused_with_its_retry_time_and_error(self):
        agent = self.sentinel(['bbot_discovery', 'web_screenshot', 'nmap'])
        self.fail_tasks(agent, 'bbot_discovery')
        self.fail_tasks(agent, 'web_screenshot')
        out = scanner_state.status()
        self.assertEqual(sorted(out['cooling']), ['bbot_discovery', 'web_screenshot'])
        text = out['cooling_message']
        self.assertTrue(text.startswith('Paused after repeated failures: bbot_discovery, web_screenshot. The scanner is online; it retries at '), text)
        self.assertRegex(text, r'retries at \d\d:\d\d UTC and the last error is on the Sentinels page\.')
        self.assertIn('Last error, bbot_discovery: TypeError: bbot deep scan crashed', text)
        self.assertLess(len(text), 400)  # the error is shortened
        for other in (out['message'], out['never_seen_message'], out['disabled_message']):  # the sentences about offline and never-seen kinds do not name them
            for kind in ('bbot_discovery', 'web_screenshot'):
                self.assertNotIn(kind, other or '')
        self.assertNotIn('Nothing has failed', out['cooling_message'])
        self.assertIn('bbot_discovery', out['kinds'])  # still waiting for the sweeps: they stay due

    def test_the_retry_time_is_the_cool_offs_end(self):
        agent = self.sentinel(['web_screenshot'])
        self.fail_tasks(agent, 'web_screenshot')
        row = scanner_state.state()['cooling']['web_screenshot']
        newest = SentinelTask.objects.filter(agent=agent).order_by('-finished_at').first().finished_at
        self.assertEqual(row['retry_at'], (newest + timedelta(minutes=sentinel_broker_cooldown())).isoformat())
        self.assertEqual(row['sentinel'], agent.name)

    def test_a_truly_absent_sentinel_is_still_offline(self):
        self.sentinel(['bbot_discovery'], seen='old')
        out = scanner_state.status()
        self.assertNotIn('cooling', out)
        self.assertTrue(out['message'].startswith('Scanner offline: '))
        self.assertIn('Nothing has failed', out['message'])

    def test_a_healthy_kind_is_not_paused(self):
        self.sentinel(['bbot_discovery'])
        out = scanner_state.state()
        self.assertNotIn('cooling', out)
        self.assertNotIn('bbot_discovery', out['kinds'])


class ExplainErrorTests(SimpleTestCase):
    def test_chromiums_apparmor_refusal_is_named_not_quoted(self):
        raw = ('browserType.launch: Target page, context or browser has been closed\nBrowser logs:\n'
               '[0107/101010:FATAL:credentials.cc(131)] Check failed: . : Permission denied (13)')
        out = sentinels.explain_error(raw)
        self.assertIn("AppArmor profile blocks Chromium's sandbox", out)
        self.assertIn('docs/DEPLOYMENT.md', out)
        self.assertNotIn('credentials.cc', out)

    def test_a_cut_off_browser_log_still_points_at_the_launch_failure(self):
        out = sentinels.explain_error('browserType.launch: Target page, context or browser has been closed')
        self.assertIn('exited at launch', out)
        self.assertIn('AppArmor', out)

    def test_the_scanners_out_of_memory_words_pass_through_unchanged(self):
        text = 'out of memory, retry later (nuclei was killed by the system)'
        self.assertEqual(sentinels.explain_error(text), text)


class BannerPortTests(TestCase):
    def banner(self, port):
        import re
        from tests.test_create_admin import run
        out = run('--reset', env={'CVENGINE_HTTPS_PORT': port}) if User.objects.filter(username='admin').exists() else run(env={'CVENGINE_HTTPS_PORT': port})
        return re.search(r'Address\s+: (\S+)', out).group(1)

    def test_a_moved_https_port_is_in_the_printed_address(self):
        self.assertEqual(self.banner('18443'), 'https://scanner.example:18443/')

    def test_the_default_port_is_not_printed(self):
        self.assertEqual(self.banner(''), 'https://scanner.example/')
        self.assertEqual(self.banner('443'), 'https://scanner.example/')
        self.assertEqual(self.banner('junk'), 'https://scanner.example/')


class UninstallUpdaterTests(SimpleTestCase):
    """D8: install.sh adds a root crontab line; scripts/uninstall-updater.sh (and make uninstall-updater) removes exactly that line."""

    def run_script(self, crontab_text):
        import os
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / 'cron').write_text(crontab_text)
        stub = tmp / 'bin'
        stub.mkdir()
        (stub / 'crontab').write_text('#!/bin/sh\ncase "$1" in -l) [ -s "$STUB_CRON" ] && cat "$STUB_CRON"; exit 0;; -r) : > "$STUB_CRON"; exit 0;; *) cat > "$STUB_CRON";; esac\n')
        (stub / 'crontab').chmod(0o755)
        env = {**os.environ, 'PATH': f'{stub}:{os.environ["PATH"]}', 'STUB_CRON': str(tmp / 'cron')}
        result = subprocess.run(['bash', str(root / 'scripts' / 'uninstall-updater.sh')], env=env, capture_output=True, text=True)
        return result, (tmp / 'cron').read_text()

    def test_only_the_updater_line_goes(self):
        line = '* * * * * /opt/cvengine/scripts/update-watch.sh >/dev/null 2>&1 # cvengine-auto-update'
        result, left = self.run_script(f'0 3 * * * /usr/bin/backup\n{line}\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(left, '0 3 * * * /usr/bin/backup\n')
        self.assertIn('Removed', result.stdout)

    def test_it_is_not_an_error_when_nothing_is_installed_and_it_leaves_the_crontab_alone(self):
        result, left = self.run_script('0 3 * * * /usr/bin/backup\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(left, '0 3 * * * /usr/bin/backup\n')
        self.assertIn('nothing to remove', result.stdout)

    def test_the_only_line_leaves_no_empty_crontab_and_the_make_target_and_docs_exist(self):
        from pathlib import Path
        result, left = self.run_script('* * * * * /x/update-watch.sh >/dev/null 2>&1 # cvengine-auto-update\n')
        self.assertEqual((result.returncode, left), (0, ''))
        root = Path(__file__).resolve().parents[2]
        self.assertIn('uninstall-updater:', (root / 'Makefile').read_text())
        for doc in ('UPDATES.md', 'DEPLOYMENT.md'):
            self.assertIn('uninstall-updater', (root / 'docs' / doc).read_text())


class ComposeProjectTests(SimpleTestCase):
    """D6: a second stack on the same host must not share the first one's project (volumes, network) or the scanner's container name."""

    def setUp(self):
        import shutil
        import tempfile
        from pathlib import Path
        self.root = Path(__file__).resolve().parents[2]
        self.tmp = Path(tempfile.mkdtemp()) / 'my-second_stack'
        (self.tmp / 'scripts').mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.tmp.parent, ignore_errors=True)
        shutil.copy(self.root / 'scripts' / 'init-env.sh', self.tmp / 'scripts' / 'init-env.sh')
        shutil.copy(self.root / '.env.example', self.tmp / '.env.example')
        (self.tmp / 'bin').mkdir()

    def init_env(self, docker_prints='', env=None, keep_env=None):
        import os
        import subprocess
        (self.tmp / 'bin' / 'docker').write_text(f'#!/bin/sh\ncase "$*" in *project=rengine*) printf %s "{docker_prints}";; esac\nexit 0\n')
        (self.tmp / 'bin' / 'docker').chmod(0o755)
        if keep_env is not None:
            (self.tmp / '.env').write_text(keep_env)
        full = {**{k: v for k, v in os.environ.items() if k != 'COMPOSE_PROJECT_NAME'}, 'PATH': f'{self.tmp / "bin"}:{os.environ["PATH"]}',
                'CVENGINE_DETECT_IP': '10.1.2.3', **(env or {})}
        result = subprocess.run(['bash', 'scripts/init-env.sh'], cwd=self.tmp, env=full, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return [line.split('=', 1)[1] for line in (self.tmp / '.env').read_text().splitlines() if line.startswith('COMPOSE_PROJECT_NAME=')][-1]

    def test_a_host_with_no_other_stack_keeps_the_default_name(self):
        self.assertEqual(self.init_env(), 'rengine')

    def test_a_host_that_already_runs_rengine_elsewhere_gives_the_new_checkout_a_name_of_its_own(self):
        self.assertEqual(self.init_env(docker_prints='/opt/cvengine\\n'), 'rengine-my-second_stack'.replace('_', '-'))

    def test_a_name_given_for_the_run_is_used(self):
        self.assertEqual(self.init_env(env={'COMPOSE_PROJECT_NAME': 'staging'}), 'staging')
        self.tmp.joinpath('.env').unlink()
        self.assertEqual(self.init_env(env={'COMPOSE_PROJECT_NAME': 'Not Valid!'}), 'rengine')

    def test_an_existing_env_keeps_its_name_whatever_runs_on_the_host(self):
        self.assertEqual(self.init_env(docker_prints='/opt/cvengine\\n', keep_env='COMPOSE_PROJECT_NAME=rengine\nDOMAIN_NAME=x.test\n'), 'rengine')

    def test_the_scanner_has_no_fixed_container_name_and_nothing_reaches_it_by_one(self):
        import re
        compose = (self.root / 'docker-compose.yml').read_text()
        self.assertNotRegex(compose, r'(?m)^\s*container_name:\s*cvengine-scanner')
        for path in [*(self.root / 'scripts').glob('*'), self.root / 'Makefile', self.root / 'install.sh']:
            if path.is_file():
                self.assertFalse(re.search(r'(docker|compose)[^\n]*\bcvengine-scanner\b', path.read_text(errors='replace')), path.name)


def sentinel_broker_cooldown():
    from agentapi import sentinel_broker
    return sentinel_broker.FAIL_COOLDOWN_DEFAULT_MINUTES


if __name__ == '__main__':
    import unittest
    unittest.main()
