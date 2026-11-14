"""Exercise resource selection through both trusted CI entry points."""
from contextlib import nullcontext
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import dispatch
from dispatch_binding import Request
import workload

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('resource_hook_review',
                                            HERE.parent / 'self-hosted/hook.py')
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)
GIB = 1024 ** 3


class ResourceProfileReview(unittest.TestCase):
    def observe(self, entry, parallel):
        seen = {'cohorts': [], 'containers': [], 'workers': []}
        real_cohort = workload.Cohort

        class Box:
            def __init__(self, image, **limits):
                seen['containers'].append(limits)
                self.proof = {'seccomp_profile_sha256': 'approved'}

            def close(self):
                pass

        def cohort(*args, **kwargs):
            value = real_cohort(*args, **kwargs)
            seen['cohorts'].append(dict(memory=value.memory, cpus=value.cpus,
                                       workers=value.workers))
            return value

        def execute(box, argv, output, **kwargs):
            if argv[-2:] == ['run', 'fmt']:
                seen['workers'].append(int(argv[argv.index('--jobs') + 1]))
                output.write_text('Ran 1 test in 0.001s\n\nOK\n')
            return dict(success=True, exit_code=0)

        def run(cohort):
            passed = cohort.stage('fmt')
            return ('passed' if passed else 'failed'), cohort.outcomes

        with tempfile.TemporaryDirectory(prefix='ci-profile-review-') as temporary:
            root = Path(temporary)
            (root / 'source.tar.gz').write_bytes(b'opaque source')
            # The dispatcher creates its own exclusive source archive.
            if entry == 'app':
                (root / 'source.tar.gz').unlink()
            config = {'cache': str(root / 'cache'), 'app_id': 9}
            if parallel is not None:
                config['parallel'] = parallel
            report = {'image': 'fixed-image', 'seccomp_sha256': 'approved'}
            journal = Mock()
            with patch('workload.Tracked', Box), patch('workload.execute', execute), \
                    patch.object(real_cohort, 'run', run):
                if entry == 'hook':
                    with patch.object(hook, 'Cohort', side_effect=cohort), \
                            patch.object(hook, 'admits'), \
                            patch.object(hook, 'venue', side_effect=lambda _: nullcontext()), \
                            patch.object(hook, 'journal_at', return_value=journal), \
                            patch.object(hook.signal, 'signal'), patch.object(hook, 'JOBS', ('fmt',)):
                        result = hook.linux_step(config, report, root)
                    seen['status'] = result['outputs']['status']
                else:
                    api = Mock()
                    api.get.return_value = b'opaque source'
                    binding = dict(repository=1, run=2, attempt=3, checkout='a' * 40, head='b' * 40)
                    with patch.object(dispatch, 'Cohort', side_effect=cohort), \
                            patch.object(dispatch, 'finish') as finish:
                        dispatch.execute(api, Request(binding, 4, 5), 7, config,
                                         report, root, journal)
                    seen['status'] = finish.call_args.args[4]
        return seen

    def check_profile(self, observed, memory, cpus, workers):
        self.assertEqual(observed['status'], 'passed', 'real CI entry refused its resource profile')
        self.assertEqual(observed['cohorts'][0]['memory'], memory)
        self.assertEqual(observed['cohorts'][0]['cpus'], cpus)
        self.assertEqual(observed['cohorts'][0]['workers'], workers)
        self.assertEqual(observed['containers'][0]['memory'], memory)
        self.assertEqual(observed['containers'][0]['cpus'], cpus)
        self.assertEqual(observed['workers'], [workers])

    def test_paired_self_hosted_hook_forwards_sixteen_gib_to_the_actual_cohort(self):
        # The archive stage writes ~10.4 GiB into the RAM-backed /work tmpfs,
        # which counts against this same cap, so 12 GiB left too little room.
        self.check_profile(self.observe('hook', True), 16 * GIB, 4, 4)

    def test_paired_app_dispatch_forwards_sixteen_gib_to_container_and_worker(self):
        self.check_profile(self.observe('app', True), 16 * GIB, 4, 4)

    def test_explicit_serial_entry_points_keep_their_original_profile(self):
        for entry in ('hook', 'app'):
            with self.subTest(entry=entry):
                self.check_profile(self.observe(entry, False), 18 * GIB, 8, 8)

    def test_legacy_serial_entry_points_keep_their_original_profile(self):
        for entry in ('hook', 'app'):
            with self.subTest(entry=entry):
                self.check_profile(self.observe(entry, None), 18 * GIB, 8, 8)


if __name__ == '__main__':
    unittest.main(verbosity=2)
