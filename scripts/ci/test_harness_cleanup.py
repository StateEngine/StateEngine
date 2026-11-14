"""Smoke cleanup consumes both public stop closure contracts without hiding gaps."""
import copy
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_matrix.flow import Smoke


def stopped(launched):
    return dict(result='already-stopped', population='empty', remaining=[],
                enumeration='complete' if launched else 'not-applicable',
                witness=dict(state='witnessed', observed_at='2000-01-01T00:00:00Z',
                             method='job-empty' if launched else 'not-applicable',
                             detail='Complete admitted control snapshot has no managed lifecycle or live session.'))


class Cleanup(unittest.TestCase):
    def cleanup(self, result):
        with tempfile.TemporaryDirectory() as directory:
            smoke = Smoke.__new__(Smoke)
            smoke.home = Path(directory) / 'home'
            smoke.home.mkdir()
            smoke.binary = smoke.home / 'se'
            smoke.binary.write_bytes(b'synthetic executable')
            smoke.state = smoke.home / 'state'
            smoke.initialization_attempted = True
            smoke.record = {}
            smoke.commands = mock.Mock()
            smoke.commands.observer.observe.return_value = []
            smoke.call = mock.Mock(side_effect=[result, {},
                dict(complete=True, witness=dict(state='witnessed'), stops=[])])
            smoke.cleanup()
            self.assertEqual([c.args[0][0] for c in smoke.call.call_args_list],
                             ['stop', 'remove', 'down'])
            smoke.commands.run.assert_called_once()
            self.assertEqual(smoke.commands.run.call_args.args[0][1], 'uninstall')
            self.assertEqual(smoke.commands.observer.observe.call_count, 2)
            self.assertEqual(smoke.record['process_closure'], [])
            self.assertEqual(smoke.record['fixture_retained'], smoke.home.exists())
            return smoke.record

    def test_never_launched_and_previously_launched_cleanup(self):
        for launched in [False, True]:
            with self.subTest(launched=launched):
                record = self.cleanup(dict(complete=True, stops=[stopped(launched)]))
                self.assertEqual(record['cleanup'], [])
                self.assertFalse(record['fixture_retained'])

    def test_nonempty_unwitnessed_or_incomplete_stop_retains_fixture(self):
        changes = [dict(remaining=[dict(pid=123)]), dict(remaining=None),
                   dict(population='unknown'), dict(population='nonempty'),
                   dict(result='unwitnessed'), dict(result='capture-incomplete'),
                   dict(enumeration='best-effort'), dict(enumeration='unavailable')]
        witness_changes = [dict(state='unwitnessed'), dict(method=None),
                           dict(observed_at=None), dict(detail=None)]
        for launched in [False, True]:
            variants = [dict(stopped(launched), **change) for change in changes]
            for change in witness_changes:
                row = stopped(launched)
                row['witness'].update(change)
                # A real native exit does not require the empty-snapshot detail
                # or its not-applicable method, but it always needs a witness.
                if not launched or 'state' in change or 'observed_at' in change:
                    variants.append(row)
            for index, row in enumerate(variants):
                with self.subTest(launched=launched, variant=index):
                    result = dict(complete=True, stops=[stopped(launched), row])
                    record = self.cleanup(result)
                    self.assertEqual(record['cleanup'], ['stop: Stop closure is incomplete'])
                    self.assertTrue(record['fixture_retained'])

    def test_empty_exception_requires_its_exact_discriminants(self):
        for change in [dict(result='stopped'), dict(population=None), dict(witness=None)]:
            with self.subTest(change=change):
                result = dict(complete=True, stops=[dict(stopped(False), **change)])
                self.assertTrue(self.cleanup(result)['fixture_retained'])

    def test_incomplete_or_unreadable_top_level_stop_is_not_empty_success(self):
        valid = dict(complete=True, stops=[stopped(False)])
        for changes in [dict(complete=False), dict(complete=None), dict(stops=None),
                        dict(stops=[None])]:
            with self.subTest(changes=changes):
                result = copy.deepcopy(valid)
                result.update(changes)
                record = self.cleanup(result)
                self.assertEqual(record['cleanup'], ['stop: Stop closure is incomplete'])
                self.assertTrue(record['fixture_retained'])


if __name__ == '__main__':
    unittest.main()
