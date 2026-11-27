"""cvengine/lane_stacks.py and the stack request of scripts/watchdog.sh: a gevent worker whose hub is held inside C code (the state the watchdog's rule R1
restarts) still prints the Python stack of every thread when it gets SIGUSR2, and the script's signal reaches the Celery workers and nothing else."""
import re
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path

WEB = Path(__file__).resolve().parents[1]
MODULE = WEB / 'cvengine' / 'lane_stacks.py'
WATCHDOG = WEB.parent / 'scripts' / 'watchdog.sh'

# a gevent worker in miniature: lane_stacks loaded from its file (no Django), then one greenlet that never yields, inside a C call that runs for seconds
FROZEN_WORKER = f'''
from gevent import monkey
monkey.patch_all()
import importlib.util, sys, re
spec = importlib.util.spec_from_file_location('lane_stacks', {str(MODULE)!r})
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print('installed', mod.install(), flush=True)
import gevent

def stuck_in_c():
    # one regular expression with catastrophic backtracking: a single C call that holds the hub, as a frozen lane does
    re.match(r'(a+)+$', 'a' * 34 + 'b')

gevent.spawn(stuck_in_c).join()
'''


def stacks_script():
    text = WATCHDOG.read_text()
    match = re.search(r"STACKS_PY='(.*?)'\n", text, re.S)
    return match.group(1) if match else None


class LaneStacksTests(unittest.TestCase):
    def test_not_a_gevent_worker_registers_nothing(self):
        out = subprocess.run([sys.executable, '-c', f'''
import importlib.util
spec = importlib.util.spec_from_file_location('lane_stacks', {str(MODULE)!r})
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.install())
'''], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.strip(), 'False', out.stderr)

    @unittest.skipUnless(hasattr(signal, 'SIGUSR2'), 'needs SIGUSR2')
    def test_a_worker_frozen_in_c_code_prints_where_it_is_on_sigusr2(self):
        proc = subprocess.Popen([sys.executable, '-c', FROZEN_WORKER], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), 'installed True')
            time.sleep(1)  # inside the regular expression by now
            proc.send_signal(signal.SIGUSR2)
            time.sleep(1)
            self.assertIsNone(proc.poll(), 'the signal must not end the worker')
        finally:
            proc.kill()
            _out, err = proc.communicate(timeout=30)
        self.assertIn('most recent call first', err)
        self.assertIn('in stuck_in_c', err)  # the greenlet that holds the hub is named, with its line

    @unittest.skipUnless(hasattr(signal, 'SIGUSR2') and Path('/proc/self/cmdline').exists(), 'needs SIGUSR2 and /proc')
    def test_the_watchdogs_signal_reaches_celery_workers_and_nothing_else(self):
        code = stacks_script()
        self.assertIsNotNone(code, 'STACKS_PY is not in scripts/watchdog.sh')
        catch = 'import signal, sys, time\nsignal.signal(signal.SIGUSR2, lambda *a: (print("got it", flush=True), sys.exit(0)))\nprint("ready", flush=True)\ntime.sleep(30)\n'
        worker = subprocess.Popen([sys.executable, '-c', catch, '-A', 'cvengine.tasks', 'worker', '-n', 'classic_worker'], stdout=subprocess.PIPE, text=True)
        bystander = subprocess.Popen([sys.executable, '-c', catch, 'cvengine.tasks'], stdout=subprocess.PIPE, text=True)  # not a worker
        try:
            self.assertEqual(worker.stdout.readline().strip(), 'ready')
            self.assertEqual(bystander.stdout.readline().strip(), 'ready')
            run = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(worker.stdout.readline().strip(), 'got it')
            self.assertEqual(worker.wait(timeout=10), 0)
            time.sleep(0.5)
            self.assertIsNone(bystander.poll())
        finally:
            for p in (worker, bystander):
                p.kill()
                p.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
