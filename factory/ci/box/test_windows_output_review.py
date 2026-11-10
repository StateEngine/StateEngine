"""Exercise native runner outputs and the required-status reader independently."""
from contextlib import nullcontext
import copy
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_single_container_review import module, Worker
import transport
import workload

ROOT = Path(__file__).resolve().parents[3]
hook = module('review_box_hook', ROOT/'factory/ci/self-hosted/hook.py')
check = module('review_required_status', ROOT/'scripts/ci/check.py')


class WindowsOutputReview(unittest.TestCase):
    def jobs(self):
        return {'changes': {'result': 'success', 'outputs': {'rust': 'true', 'windows': 'true'}},
                'linux-route': {'result': 'success', 'outputs': {'route': 'box'}},
                'linux-box': {'result': 'success', 'outputs': {'status': 'passed', 'windows': 'passed'}},
                **{n: {'result': 'skipped'} for n in ['fmt', 'clippy', 'archive', 'test', 'windows-clippy']}}

    def observe(self, root, worker, cancel=False, cleanup=False):
        source, cache = root/'source.tar.gz', root/'cache'
        source.write_bytes(b'opaque candidate source'); cache.write_bytes(b'opaque public dependencies')
        journal = Mock()
        if cleanup:
            journal.reconcile.side_effect = [None, RuntimeError('outside custody unavailable')]
        handlers = {}
        original = transport.execute
        def execute(*args, **kwargs):
            result = original(*args, **kwargs)
            if cancel and args[1][-1] == 'fmt':
                handlers[signal.SIGTERM](signal.SIGTERM, None)
            return result
        with worker.patches(), patch.object(hook, 'capacity'), \
                patch.object(hook, 'venue', side_effect=lambda _: nullcontext()), \
                patch.object(hook, 'Journal', return_value=journal), \
                patch.object(hook.signal, 'signal', side_effect=lambda n, h: handlers.update({n: h})), \
                patch('workload.execute', side_effect=execute):
            return hook.linux_step({'cache': str(cache)},
                {'image': 'sha256:'+'c'*64, 'seccomp_sha256': 'd'*64}, root)

    def test_windows_native_success_is_required_and_reaches_the_final_reader(self):
        worker = Worker()
        with tempfile.TemporaryDirectory() as temporary:
            result = self.observe(Path(temporary), worker)
        self.assertEqual(result, {'exit_code': 0, 'outputs': {'status': 'passed', 'windows': 'passed'}})
        self.assertTrue(check.accepted(self.jobs()))
        self.assertTrue(worker.children and all(p.poll() == 0 for p in worker.children))

    def test_windows_compiler_failure_remains_red_with_hosted_linux_success(self):
        worker = Worker('windows-clippy')
        with tempfile.TemporaryDirectory() as temporary:
            result = self.observe(Path(temporary), worker)
        self.assertEqual(result, {'exit_code': 1, 'outputs': {'status': 'failed', 'windows': 'failed'}})
        jobs = self.jobs(); jobs['linux-box']['outputs'] = result['outputs']
        for name in ['fmt', 'clippy', 'archive', 'test', 'windows-clippy']:
            jobs[name]['result'] = 'success'
        self.assertFalse(check.accepted(jobs))
        self.assertTrue(all(p.poll() is not None for p in worker.children))

    def test_final_custody_refusal_never_supplies_a_passing_box(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = self.observe(Path(temporary), Worker(), cleanup=True)
        self.assertEqual(result['outputs']['status'], 'unavailable')
        jobs = self.jobs(); jobs['linux-box']['outputs'] = result['outputs']
        self.assertFalse(check.accepted(jobs))

    def test_signal_cancellation_joins_and_never_returns_success_or_fallback(self):
        worker = Worker()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(InterruptedError):
                self.observe(Path(temporary), worker, cancel=True)
        self.assertTrue(worker.children and all(p.poll() is not None for p in worker.children))

    def test_missing_failed_or_canceled_windows_proof_cannot_borrow_box_success(self):
        for proof in [None, '', 'unavailable', 'failed']:
            jobs = self.jobs()
            if proof is None:
                del jobs['linux-box']['outputs']['windows']
            else:
                jobs['linux-box']['outputs']['windows'] = proof
            self.assertFalse(check.accepted(jobs))
        for result in ['failure', 'cancelled']:
            jobs = self.jobs(); jobs['windows-clippy']['result'] = result
            self.assertFalse(check.accepted(jobs))

    def test_fallback_requires_both_complete_platform_chains(self):
        jobs = self.jobs(); jobs['linux-box']['outputs'] = {'status': 'unavailable', 'windows': 'unavailable'}
        for name in ['fmt', 'clippy', 'archive', 'test', 'windows-clippy']:
            jobs[name]['result'] = 'success'
        self.assertTrue(check.accepted(jobs))
        for name in ['fmt', 'clippy', 'archive', 'test', 'windows-clippy']:
            for state in ['failure', 'cancelled', 'skipped']:
                changed = copy.deepcopy(jobs); changed[name]['result'] = state
                self.assertFalse(check.accepted(changed))


if __name__ == '__main__':
    unittest.main()
