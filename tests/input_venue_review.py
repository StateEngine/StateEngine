"""Independent controls for CI venue selection and native limit flags."""
import ast
import contextlib
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
import input_judges as subject
import custom

EXPECTED = {
    ('agent_allocation_routes', 'direct_agent_allocations_remain_distinct_and_replay_without_new_events'),
    ('agent_allocation_routes', 'hosted_agent_allocations_remain_distinct_and_replay_without_new_events'),
    ('breakaway_refusal', 'eligible_broker_runtime_outlives_strict_job_and_public_down_closes_it'),
    *(('hook_session_independent', 'hook_session_' + case) for case in
      ('active', 'deadline', 'expired', 'prepared', 'purpose', 'revoked', 'stop_unproved', 'superseded')),
    ('http_admission', 'public_http_admission_precedes_anonymous_and_private_routes'),
    ('runtime_image_remedy', 'multilink_image_names_the_launch_precondition_and_a_single_link_copy_starts'),
    ('runtime_refusals', 'live_host_init_refuses_with_down_then_retry_succeeds'),
    ('runtime_refusals', 'uninstall_verifies_live_host_shutdown_before_removing_files'),
}

class Function:
    def __init__(self, function): self.function = function
    def __call__(self, *args): return self.function(*args)

class Controls(unittest.TestCase):
    def test_limit_flags_not_membership(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        scripts = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                   and isinstance(node.value, str) and 'QueryInformationJobObject' in node.value]
        self.assertEqual(len(scripts), 1)
        cases = [(True, 0, False, True, 0), (True, 0x800, False, True, 1),
                 (True, 0x1000, False, True, 1), (True, 0x1800, False, True, 1),
                 (True, 0x2000, False, True, 0), (False, 0, False, True, 1),
                 (True, 0, True, True, 0), (True, 0x800, True, True, 1),
                 (True, 0, True, False, 1)]
        for member, flags, fallback, readable, expected in cases:
            with self.subTest(member=member, flags=flags, fallback=fallback, readable=readable):
                def membership(_process, _job, out):
                    out._obj.value = int(member)
                    return 1
                def query(_job, level, out, _size, _got):
                    if not readable or (fallback and level == 9): return 0
                    info = out._obj
                    basic = info.BasicLimitInformation if level == 9 else info
                    basic.LimitFlags = flags
                    return 1
                fake = type('Kernel', (), {})()
                fake.IsProcessInJob = Function(membership)
                fake.QueryInformationJobObject = Function(query)
                with mock.patch.object(ctypes, 'WinDLL', return_value=fake, create=True):
                    with self.assertRaises(SystemExit) as exit:
                        exec(compile(scripts[0], '<native-limit-control>', 'exec'), {})
                self.assertEqual(exit.exception.code, expected)

    def test_denied_venue_names_exactly_fifteen_without_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(subject, 'breakaway_venue_required', return_value=True), \
                 contextlib.redirect_stderr(io.StringIO()) as stream:
                selectors = subject.unavailable(root)
            report = json.loads((root / 'target/nextest/input-judges.json').read_text())
            rows = [row for row in report['not_run'] if 'needs a breakaway-capable venue' in row['missing_inputs']]
            self.assertEqual({tuple(row['judge'].split('::')[1:]) for row in rows}, EXPECTED)
            self.assertEqual(len(rows), 15)
            self.assertTrue(all(row['status'] == 'not_run' for row in rows))
            for binary, name in EXPECTED:
                self.assertIn(f'(package(=se) & binary(={binary}) & test(={name}))', selectors)
                self.assertIn(f'NOT RUN se::{binary}::{name}:', stream.getvalue())

    def test_real_filter_reports_the_fifteen_in_both_modes(self):
        for all_features in (False, True):
            with self.subTest(all_features=all_features), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                summary = root / 'summary.md'
                with mock.patch.object(custom, 'ROOT', root), \
                     mock.patch.object(subject, 'breakaway_venue_required', return_value=True), \
                     mock.patch.object(custom, 'custom_targets', return_value={'se::other': root}), \
                     mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}), \
                     contextlib.redirect_stderr(io.StringIO()) as stream:
                    selection = custom.filterset(all_features=all_features)
                report = json.loads((root / 'target/nextest/input-judges.json').read_text())
                venue = [row for row in report['not_run'] if 'needs a breakaway-capable venue' in row['missing_inputs']]
                self.assertEqual(len(venue), 15)
                self.assertTrue(all(row['status'] == 'not_run' for row in venue))
                text = summary.read_text()
                for binary, name in EXPECTED:
                    self.assertIn(f'(package(=se) & binary(={binary}) & test(={name}))', selection)
                    self.assertIn(f'NOT RUN se::{binary}::{name}:', text)
                    self.assertIn(f'NOT RUN se::{binary}::{name}:', stream.getvalue())

    def test_linux_does_not_probe_windows_or_add_venue_exclusions(self):
        with mock.patch.object(subject.sys, 'platform', 'linux'), \
             mock.patch.object(subject.subprocess, 'run', side_effect=AssertionError('native probe on Linux')):
            self.assertFalse(subject.breakaway_venue_required())
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(subject.sys, 'platform', 'linux'), \
             contextlib.redirect_stderr(io.StringIO()):
            subject.unavailable(Path(temporary))
            report = json.loads((Path(temporary) / 'target/nextest/input-judges.json').read_text())
            self.assertFalse(any('needs a breakaway-capable venue' in row['missing_inputs'] for row in report['not_run']))

if __name__ == '__main__':
    unittest.main(verbosity=2)
