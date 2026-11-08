"""Independent required-CI checks at slow API and native output/cleanup boundaries."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import dispatch
from dispatch_binding import Request
import transport
import workload
from box_result import external_id, report, STAGES


BINDING = dict(repository=1, run=2, attempt=3, checkout='a'*40, head='b'*40)


class OutcomeReview(unittest.TestCase):
    def test_slow_api_does_not_admit_after_the_original_reservation_deadline(self):
        clock = [0]
        def slow_live(*_):
            clock[0] += 31
            return True
        rows = [{'name': 'linux-route', 'conclusion': 'success'},
                {'name': 'linux-box', 'status': 'in_progress'}]
        with patch('dispatch.live', side_effect=slow_live), patch('dispatch.jobs', return_value=rows):
            admitted = dispatch.handshake(Mock(), Request(BINDING, 4, 5), seconds=30,
                clock=lambda: clock[0], sleep=lambda n: clock.__setitem__(0, clock[0]+n))
        self.assertFalse(admitted, 'slow API response admitted work after reservation expiry')

    def output_failure(self, cleanup_fails):
        children = []
        popen = subprocess.Popen
        def child(*args, **kwargs):
            value = popen(*args, **kwargs)
            children.append(value)
            return value

        class Container:
            def __init__(self, *args, **kwargs):
                self.started, self.deadline, self.id = time.monotonic(), 30, 'fixture'
                self.proof = {'seccomp_profile_sha256': 'd'*64}
            def close(self):
                # Observe child exit before simulating an unavailable engine read.
                for process in children:
                    process.wait(timeout=5)
                if cleanup_fails:
                    raise RuntimeError('owned engine cleanup unavailable')

        class Cohort(workload.Cohort):
            def run(self):
                return ('passed' if self.stage('clippy') else 'failed'), self.outcomes

        def execute(box, argv, output, **kwargs):
            if argv[-1] == 'source':
                return {'success': True}
            return transport.execute(box, argv, output, limit=8)

        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            api = Mock()
            api.get.side_effect = lambda path, **kwargs: (b'isolated source fixture'
                if path.startswith('tarball/') else dict(app={'id': 9}, head_sha=BINDING['checkout'],
                    external_id=external_id(BINDING)))
            image = dict(image='sha256:'+'c'*64, policy_digest='d'*64, seccomp_sha256='d'*64)
            native_command = [sys.executable, '-c', 'import sys;sys.stdout.write("x"*32);sys.stdout.flush()']
            try:
                with patch('dispatch.Cohort', Cohort), patch('workload.Tracked', Container), \
                        patch('workload.execute', execute), \
                        patch('transport.engine_args', return_value=native_command), \
                        patch('transport.subprocess.Popen', side_effect=child):
                    dispatch.execute(api, Request(BINDING, 4, 5), 7,
                                     dict(cache=str(folder/'unused'), app_id=9), image, folder, None)
                self.assertEqual((folder/'clippy/job.log').read_bytes(), b'x'*8)
                self.assertTrue(children and all(p.poll() == 0 for p in children))
                return json.loads((folder/'terminal.json').read_text())['report']['status']
            finally:
                for process in children:
                    process.wait(timeout=5)
                    process.stdout.close()
                    process.stderr.close()

    def test_observed_output_failure_remains_red_when_cleanup_is_unavailable(self):
        self.assertEqual(self.output_failure(False), 'failed', 'positive control did not reach byte limit')
        self.assertEqual(self.output_failure(True), 'failed',
                         'observed output overflow was erased into infrastructure fallback')

    def test_terminal_success_is_not_published_after_cancellation_or_a_new_attempt(self):
        stages = {name: dict(exit=0, tests=1, custom=9, docs=1, checks=1) for name in STAGES}
        value = {'app_id': 9, 'request': {'identity': BINDING, 'number': 4, 'changes_job': 5},
                 'report': report(BINDING, 7, 'sha256:'+'c'*64, 'd'*64, 'passed', stages)}
        for attempt, status, conclusion in [(3, 'completed', 'cancelled'), (4, 'in_progress', None)]:
            with self.subTest(attempt=attempt):
                api = Mock()
                def read(path):
                    if path == 'check-runs/7':
                        return dict(app={'id': 9}, head_sha=BINDING['checkout'], external_id=external_id(BINDING))
                    if path == 'actions/runs/2':
                        return dict(run_attempt=attempt, status=status, conclusion=conclusion)
                    raise AssertionError('unexpected API request: '+path)
                api.get.side_effect = read
                try:
                    dispatch.publish(api, value)
                except (RuntimeError, ValueError):
                    pass  # An explicit stale/canceled refusal also preserves this contract.
                published = [call for call in api.write.call_args_list
                             if call.args[1].get('conclusion') == 'success']
                self.assertFalse(published, 'persisted success published after cancellation/supersession')


if __name__ == '__main__':
    unittest.main()
