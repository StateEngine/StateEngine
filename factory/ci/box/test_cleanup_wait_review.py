"""Real kernel lease contention at the cleanup-hook boundary; no live CI state."""
from contextlib import redirect_stderr
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import runner_slot

HERE = Path(__file__).resolve().parent
previous = sys.path[:]
try:
    # Resolve candidate dependencies before the installed hook adds its fixed path.
    for name in ('custody', 'dispatch', 'engine', 'github_binding', 'transport', 'workload'):
        __import__(name)
    spec = importlib.util.spec_from_file_location('cleanup_hook_review',
                                                HERE.parent / 'self-hosted/hook.py')
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
finally:
    sys.path[:] = previous

ARGV_MARKER = 'SYNTHETIC_ARGV_MUST_NOT_APPEAR_IN_HOLDER_REPORT'
HOLDER = """import fcntl,sys
with open(sys.argv[1]) as lease:
    fcntl.flock(lease, fcntl.LOCK_EX)
    print('held', flush=True)
    sys.stdin.readline()
"""


class Announcements(io.StringIO):
    def __init__(self, event):
        super().__init__()
        self.event = event

    def write(self, value):
        count = super().write(value)
        if 'cleanup waiting for lease' in value:
            self.event.set()
        return count


class CleanupWait(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cleanup-wait-',
                                                 dir=os.environ.get('TMPDIR'))
        self.root = Path(self.temp.name)
        self.config = dict(ci_lock=str(self.root / 'maintenance.lock'),
                           slot_lock=str(self.root / 'primary.lock'),
                           slot='primary', parallel=True)
        for key in ('ci_lock', 'slot_lock'):
            Path(self.config[key]).touch(mode=0o600)
        self.children = []

    def tearDown(self):
        for child in self.children:
            self.release(child)
        self.temp.cleanup()

    def holder(self, key):
        child = subprocess.Popen([sys.executable, '-c', HOLDER, self.config[key], ARGV_MARKER],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        self.children.append(child)
        self.assertEqual(child.stdout.readline(), 'held\n')
        self.assertIn(ARGV_MARKER.encode(), Path('/proc', str(child.pid), 'cmdline').read_bytes())
        return child

    def release(self, child):
        if child.poll() is None:
            child.stdin.write('release\n')
            child.stdin.flush()
        child.wait(timeout=5)
        self.assertEqual(child.returncode, 0)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()

    def cleanup(self, reconciled):
        request = SimpleNamespace(buffer=io.BytesIO(b'{"command":"cleanup_job"}'))
        journal = SimpleNamespace(reconcile=lambda: reconciled.append(True))
        handlers = {kind: signal.getsignal(kind) for kind in (signal.SIGINT, signal.SIGTERM)}
        try:
            with patch.object(sys, 'stdin', request), patch.object(sys, 'argv', ['hook']), \
                    patch.object(hook, 'config_at', return_value=(self.config, {})), \
                    patch.object(hook, 'journal_at', return_value=journal):
                return hook.main()
        finally:
            for kind, handler in handlers.items():
                signal.signal(kind, handler)

    def waits_then_reconciles(self, key, parallel):
        self.config['parallel'] = parallel
        child = self.holder(key)
        waiting = threading.Event()
        finished = threading.Event()
        errors = []

        def unlock():
            if waiting.wait(5):
                try:
                    self.release(child)
                except Exception as error:
                    errors.append(error)
                finally:
                    finished.set()

        worker = threading.Thread(target=unlock)
        worker.start()
        reconciled, capture = [], Announcements(waiting)
        result = error = None
        try:
            with redirect_stderr(capture):
                try:
                    result = self.cleanup(reconciled)
                except Exception as caught:
                    error = caught
        finally:
            waiting.set()
            worker.join(6)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertIsNone(error, f'cleanup refused a transient image/slot lease: {error!r}')
        self.assertEqual(result, {'exit_code': 0})
        self.assertEqual(reconciled, [True])
        self.assertTrue(finished.is_set())
        # /proc/locks is a best-effort kernel enumeration, separate from the
        # successful exclusive lease and the eventual cleanup acquisition.
        self.assertIn('cleanup waiting for lease', capture.getvalue())
        self.assertNotIn(ARGV_MARKER, capture.getvalue())

    def test_serial_cleanup_waits_for_image_builder_maintenance_lease(self):
        self.waits_then_reconciles('ci_lock', False)

    def test_parallel_cleanup_waits_for_image_builder_maintenance_lease(self):
        self.waits_then_reconciles('ci_lock', True)

    def test_parallel_cleanup_waits_for_selected_slot_lease(self):
        self.waits_then_reconciles('slot_lock', True)

    def test_workload_maintenance_admission_stays_immediate(self):
        self.holder('ci_lock')
        started = time.monotonic()
        with self.assertRaises(BlockingIOError):
            with runner_slot.venue(self.config):
                self.fail('workload entered a held maintenance lease')
        self.assertLess(time.monotonic() - started, 0.5)

    def test_workload_slot_admission_stays_immediate(self):
        self.holder('slot_lock')
        started = time.monotonic()
        with self.assertRaises(BlockingIOError):
            with runner_slot.venue(self.config):
                self.fail('workload entered a held slot lease')
        self.assertLess(time.monotonic() - started, 0.5)

    def test_real_timeout_reports_holder_without_argv_and_preserves_its_lease(self):
        child = self.holder('ci_lock')
        capture = io.StringIO()
        started = time.monotonic()
        with redirect_stderr(capture), self.assertRaises(TimeoutError) as raised:
            with runner_slot.venue(self.config, wait_seconds=1):
                self.fail('cleanup entered the held lease')
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.9)
        self.assertLess(elapsed, 2.5)
        diagnostic = capture.getvalue() + str(raised.exception)
        self.assertIn(f'pid={child.pid}', diagnostic)
        self.assertIn('name=', diagnostic)
        self.assertIn('mode=WRITE', diagnostic)
        self.assertNotIn(ARGV_MARKER, diagnostic)
        self.assertIsNone(child.poll())
        with open(self.config['ci_lock']) as lease:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_one_wait_budget_covers_maintenance_then_slot_and_releases_maintenance(self):
        maintenance = self.holder('ci_lock')
        self.holder('slot_lock')
        clock = [0.0]

        def sleep(delay):
            clock[0] += delay
            if maintenance.poll() is None:
                self.release(maintenance)

        # Kernel locks stay real; the clock advances deterministically instead of
        # waiting ten minutes to exercise the shared deadline policy.
        clock_api = SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep)
        with patch.object(runner_slot, 'time', clock_api), redirect_stderr(io.StringIO()):
            with self.assertRaises(TimeoutError):
                with runner_slot.venue(self.config, wait_seconds=1):
                    self.fail('cleanup entered a held slot')
        self.assertEqual(clock[0], 1.0)
        with open(self.config['ci_lock']) as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_canceled_wait_propagates_without_reconciling_or_retaining_maintenance(self):
        self.holder('slot_lock')
        clock_api = SimpleNamespace(monotonic=time.monotonic, sleep=lambda _: hook.canceled())
        reconciled = []
        with patch.object(runner_slot, 'time', clock_api), redirect_stderr(io.StringIO()):
            with self.assertRaises(InterruptedError):
                self.cleanup(reconciled)
        self.assertEqual(reconciled, [])
        with open(self.config['ci_lock']) as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_holder_report_is_inode_scoped_and_distinguishes_unreadable(self):
        child = self.holder('slot_lock')
        unrelated = self.holder('ci_lock')
        with open(self.config['slot_lock']) as lease:
            report = runner_slot.holders(lease.fileno())
            self.assertIn(f'pid={child.pid}', report)
            self.assertNotIn(f'pid={unrelated.pid}', report)
            self.assertNotIn(ARGV_MARKER, report)
            with patch('builtins.open', side_effect=PermissionError('synthetic procfs denial')):
                self.assertIn('holder unreadable: PermissionError', runner_slot.holders(lease.fileno()))

    def test_wait_range_is_fixed_and_invalid_values_refuse_before_open(self):
        for value in (-1, 601, True, '600', 0.5, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                with runner_slot.venue({'ci_lock': '/synthetic-absent'}, wait_seconds=value):
                    self.fail('invalid wait was accepted')


if __name__ == '__main__':
    unittest.main(verbosity=2)
