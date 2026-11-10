"""Review fixed orchestration with real children and independent outside outcomes."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import controller
import engine
from github_binding import Binding
import transport
import workload

STAGES = ("fmt", "clippy", "archive", "test-1", "test-2", "windows-clippy")
TEXT = {"fmt": "\nRan 1 test in 0.01s\n\nOK\n",
        "archive": "test result: ok. 1 passed; 0 failed;\n",
        "test-1": "Summary [ 1s] 2 tests run: 2 passed\nCustom harnesses: 9 passed, 0 failed\n",
        "test-2": "Summary [ 1s] 2 tests run: 2 passed\n"}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    previous = sys.path[:]
    try:
        spec.loader.exec_module(value)
    finally:
        sys.path[:] = previous
    return value


class Worker:
    """Replace only engine admission/exec; transport still drains actual pipes."""
    def __init__(self, failure=None, overflow=False):
        self.failure, self.overflow = failure, overflow
        self.boxes, self.commands, self.children = [], [], []
        self.closed = 0

    def create(self, image, **limits):
        self.boxes.append((image, limits))
        return SimpleNamespace(id="f" * 64, started=time.monotonic(), deadline=30,
                               proof={"seccomp_profile_sha256": "d" * 64}, close=self.close)

    def close(self):
        self.closed += 1
        for child in self.children:
            child.wait(timeout=5)

    def command(self, *argv):
        self.commands.append(argv)
        name = argv[-1] if argv[-1] in (*STAGES, "source") else "cache"
        text = "x" * 1024 if self.overflow and name == self.failure else TEXT.get(name, "")
        code = 7 if name == self.failure and not self.overflow else 0
        program = ("import sys;sys.stdin.buffer.read();sys.stdout.write(" + repr(text) +
                   ");sys.stderr.write('worker diagnostic\\n');raise SystemExit(" + str(code) + ")")
        return [sys.executable, "-c", program]

    def popen(self, *args, **kwargs):
        child = self.original_popen(*args, **kwargs)
        self.children.append(child)
        return child

    def cohort(self, root):
        source, cache = root / "source", root / "cache"
        source.write_bytes(b"opaque candidate source")
        cache.write_bytes(b"opaque public dependencies")
        cohort = workload.Cohort({"image": "sha256:" + "c" * 64,
                                  "seccomp_sha256": "d" * 64}, None, source, cache, root,
                                 threading.Event())
        return cohort

    @contextmanager
    def patches(self):
        self.original_popen = subprocess.Popen
        with patch("workload.Tracked", side_effect=self.create), \
                patch("transport.engine_args", side_effect=self.command), \
                patch("transport.subprocess.Popen", side_effect=self.popen):
            yield


class SingleContainerReview(unittest.TestCase):
    def test_all_stages_share_one_bound_and_source_transfer(self):
        worker = Worker()
        with tempfile.TemporaryDirectory() as temporary, worker.patches():
            cohort = worker.cohort(Path(temporary))
            status, outcomes = cohort.run()
            self.assertEqual(status, "passed")
            self.assertEqual(tuple(outcomes), STAGES)
            self.assertEqual(len(worker.boxes), 1)
            limits = worker.boxes[0][1]
            self.assertEqual((limits['memory'], limits['cpus'], limits['deadline']),
                             (18 * 1024**3, 8, 1800))
            self.assertEqual(sum(c[-1] == 'source' for c in worker.commands), 1)
            self.assertEqual([c[-1] for c in worker.commands if c[-1] in STAGES], list(STAGES))
            self.assertEqual(len({c[2] for c in worker.commands}), 1)
            self.assertEqual(worker.closed, 1)
            self.assertEqual(outcomes['windows-clippy']['checks'], 1)
            self.assertEqual(list(cohort.active), [])
        self.assertTrue(worker.children and all(p.poll() == 0 for p in worker.children))

    def test_native_compiler_test_windows_and_output_limit_failures_stay_red(self):
        for name, overflow in [('clippy', False), ('test-1', False),
                               ('windows-clippy', False), ('clippy', True)]:
            with self.subTest(stage=name, overflow=overflow):
                worker = Worker(name, overflow)
                with tempfile.TemporaryDirectory() as temporary, worker.patches():
                    cohort = worker.cohort(Path(temporary))
                    original = transport.execute
                    def bounded(*args, **kwargs):
                        return original(*args, limit=512, **kwargs)
                    with patch('workload.execute', side_effect=bounded):
                        with self.assertRaises(transport.WorkloadFailure):
                            cohort.run()
                    self.assertEqual(cohort.outcomes[name]['exit'], 1)
                    self.assertGreaterEqual(worker.closed, 1)
                self.assertTrue(all(p.poll() is not None for p in worker.children))

    def test_account_exec_drops_ambient_credentials(self):
        account = SimpleNamespace(pw_uid=os.getuid(), pw_dir='/var/lib/stateengine-ci')
        with patch.dict(os.environ, {'REVIEW_EVERYDAY_TOKEN': 'synthetic-never-forward'}, clear=False), \
                patch('engine.pwd.getpwnam', return_value=account):
            argv = engine.account_args(sys.executable, '-c',
                "import os;assert 'REVIEW_EVERYDAY_TOKEN' not in os.environ;print('isolated')")
            result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'isolated\n')

    def shadow(self, root, cleanup_error, canceled_at_release=False):
        image = root / 'image.json'
        image.write_text(json.dumps({'policy': {}}))
        output = root / 'output'
        journal = Mock()
        journal.reconcile.side_effect = [None, cleanup_error] if cleanup_error else [None, None]
        outcomes = {name: dict(exit=0, tests=1, custom=9, docs=1, checks=1) for name in STAGES}
        cohort = Mock(outcomes=outcomes)
        cohort.run.return_value = ('passed', outcomes)
        api = Mock(); api.get.return_value = b'opaque source'
        @contextmanager
        def venue():
            yield
            if canceled_at_release:
                controller.stop()
        args = SimpleNamespace(output=output, image_report=image, token_helper=root/'unused',
                               run=1, attempt=1, pr=1, checkout='a'*40, cache=root/'unused')
        with patch('controller.GitHub', return_value=api), \
                patch('controller.bind', return_value=Binding('StateEngine/StateEngine', 1, 1, 1,
                                                              'a'*40, 'b'*40, 1)), \
                patch('controller.exclusive', side_effect=venue), \
                patch('controller.Journal', return_value=journal), \
                patch('controller.Cohort', return_value=cohort):
            code = controller.run(args)
        return code, json.loads((output/'result.json').read_text())

    def test_shadow_success_requires_final_outside_custody_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, result = self.shadow(Path(temporary), None)
            self.assertEqual(code, 0)
            self.assertTrue(result['success'])
        with tempfile.TemporaryDirectory() as temporary:
            code, result = self.shadow(Path(temporary), RuntimeError('outside inventory unreadable'))
            self.assertNotEqual(code, 0)
            self.assertFalse(result['success'])
            self.assertEqual(set(result['jobs']), set(STAGES))
            self.assertIn('outside inventory unreadable', result['error'])


    def test_shadow_cancellation_at_venue_release_cannot_publish_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, result = self.shadow(Path(temporary), None, canceled_at_release=True)
            self.assertNotEqual(code, 0)
            self.assertFalse(result['success'])
            self.assertEqual(set(result['jobs']), set(STAGES))
            self.assertIn('controller canceled', result['error'])

if __name__ == '__main__':
    unittest.main()
