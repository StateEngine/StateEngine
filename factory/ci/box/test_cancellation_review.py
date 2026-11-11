"""A witnessed nonzero workload exit cannot disappear behind later cancellation."""
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
from box_result import external_id
import transport
import workload

BINDING = dict(repository=1, run=2, attempt=3, checkout='a'*40, head='b'*40)


class CancellationReview(unittest.TestCase):
    def observe(self, cancel_after_observation):
        children = []
        popen = subprocess.Popen
        def child(*args, **kwargs):
            process = popen(*args, **kwargs)
            children.append(process)
            return process
        class Container:
            def __init__(self, *args, **kwargs):
                self.started, self.deadline, self.id = time.monotonic(), 30, 'fixture'
                self.proof = {'seccomp_profile_sha256': 'd'*64}
            def close(self):
                for process in children:
                    process.wait(timeout=5)
        class Cohort(workload.Cohort):
            def run(self):
                return ('passed' if self.stage('clippy') else 'failed'), self.outcomes

        canceled = []
        def execute(box, argv, output, **kwargs):
            if argv[-1] == 'source':
                return dict(success=True, exit_code=0, reason=None)
            result = transport.execute(box, argv, output)
            assert result['exit_code'] == 7 and result['reason'] is None
            assert not result['success'], 'native failed workload precondition was not reached'
            if cancel_after_observation:
                canceled[0].set()
            return result

        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            api = Mock()
            api.get.side_effect = lambda path, **kwargs: (b'isolated source fixture'
                if path.startswith('tarball/') else dict(app={'id': 9}, head_sha=BINDING['checkout'],
                    external_id=external_id(BINDING)))
            image = dict(image='sha256:'+'c'*64, policy_digest='d'*64, seccomp_sha256='d'*64)
            def cohort(*args, **kwargs):
                value = Cohort(*args, **kwargs)
                canceled.append(value.canceled)
                return value
            native_command = [sys.executable, '-c', 'print("owned workload failed");raise SystemExit(7)']
            try:
                with patch('dispatch.Cohort', side_effect=cohort), patch('workload.Tracked', Container), \
                        patch('workload.execute', execute), \
                        patch('transport.engine_args', return_value=native_command), \
                        patch('transport.subprocess.Popen', side_effect=child):
                    dispatch.execute(api, Request(BINDING, 4, 5), 7,
                                     dict(cache=str(folder/'unused'), app_id=9), image, folder, None)
                self.assertTrue(children and all(p.poll() == 7 for p in children))
                return json.loads((folder/'terminal.json').read_text())['report']['status']
            finally:
                for process in children:
                    process.wait(timeout=5)
                    process.stdout.close()
                    process.stderr.close()

    def test_natural_failed_exit_remains_red_after_concurrent_cancellation(self):
        self.assertEqual(self.observe(False), 'failed', 'positive control did not observe the failed workload')
        self.assertEqual(self.observe(True), 'failed',
                         'a witnessed native failure became unavailable after cancellation')


if __name__ == '__main__':
    unittest.main()
