"""Exercise the retained report and finalizer without activating a service."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, required=True)
args, remaining = parser.parse_known_args()
sys.path.insert(0, str(args.source.resolve()))
sys.dont_write_bytecode = True
import report
import lifecycle
import nightly


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def fixture(root, code=1, measurements=None, surface='claude', selection='wave-2'):
    selected = [1, 2, 3, 5] if selection == 'wave-2' else [1, 2, 3, 4, 5]
    invocation = {'platform': 'linux', 'surface': surface, 'selection': selection,
                  'output': 'probe', 'exit': code, 'state': 'finished'}
    measurements = measurements if measurements is not None else [
        {'label': 'CLI contextual read verbs', 'passed': False,
         'reads': {'p95_ms': {'status': 23.5}, 'samples': [12, 23.5]}}]
    receipt = {'platform': 'linux', 'implementation': 'rust', 'surface': surface,
               'scope': {'mode': 'rust-wave-2' if selection == 'wave-2' else 'first-hour', 'selected': selected},
               'results': [{'journey': n, 'result': 'PASS', 'cleanup': []} for n in selected],
               'cleanup': [], 'qualification': 'see journey scope and required budgets' if selection == 'wave-2'
               else 'Five behavior checks only; synthetic controls',
               'budgets': {'passed': all(m['passed'] for m in measurements),
                           'required': [m['label'] for m in measurements]}}
    budgets = {'profile': 'rust', 'measurements': measurements, 'limits': {'contextual_reads_ms': 20}}
    write(root / 'probe/results.json', receipt)
    write(root / 'probe/budgets.json', budgets)
    run = {'started_at': '2026-01-01T00:00:00+00:00', 'state': 'finished', 'errors': [], 'invocations': [invocation]}
    write(root / 'run.json', run)
    return run, receipt, budgets


def linux_cells(value):
    return {row['journey']: row['platforms']['linux']['state'] for row in value['tables'][0]['rows']}


def budget(value, name):
    return next(row for row in value['budgets'] if row['id'] == name)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='nightly-verdict-')
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_completed_exit_one_keeps_journeys_and_budget_miss_separate(self):
        run, _, _ = fixture(self.root)
        value = report.publish(self.root)
        self.assertEqual(linux_cells(value), {1: 'PASS', 2: 'PASS', 3: 'PASS', 4: 'NOT RUN', 5: 'PASS'})
        self.assertEqual(value['status']['outcome'], 'FAIL')
        self.assertTrue(value['status']['complete'])
        measured = budget(value, 'B7')
        self.assertEqual(measured['state'], 'MISS')
        self.assertEqual(measured['probes'][0]['numbers'], {'reads.p95_ms.status': 23.5})
        self.assertEqual(measured['probes'][0]['limits']['contextual_reads_ms'], 20)
        self.assertEqual(json.loads((self.root / 'run.json').read_text()), run)

    def test_missing_budget_does_not_change_completed_behavior(self):
        run, _, _ = fixture(self.root)
        (self.root / 'probe/budgets.json').unlink()
        value = report.publish(self.root)
        self.assertEqual(linux_cells(value)[1], 'PASS')
        self.assertFalse(value['status']['complete'])
        self.assertTrue(all(row['state'] == 'NOT MEASURED' for row in value['budgets']))

    def test_zero_is_observed_but_boolean_missing_and_nonfinite_are_not(self):
        samples = [{'label': label, 'passed': True, 'idle': {'cpu_percent_one_core': 0, 'wakeups': 0}}
                   for label in ['idle no session', 'idle one session']]
        fixture(self.root, 0, samples)
        value = report.publish(self.root)
        self.assertEqual(budget(value, 'B5')['state'], 'PASS')
        self.assertEqual(budget(value, 'B6')['state'], 'PASS')
        self.assertEqual(list(budget(value, 'B5')['probes'][0]['numbers'].values()), [0])
        for bad in [True, None, float('nan')]:
            for row in samples:
                row['idle']['cpu_percent_one_core'] = bad
            fixture(self.root, 0, samples)
            value = report.publish(self.root)
            self.assertEqual(budget(value, 'B5')['state'], 'NOT MEASURED')
            self.assertEqual(budget(value, 'B6')['state'], 'PASS')

    def test_cleanup_failure_changes_its_own_journey(self):
        run, receipt, _ = fixture(self.root)
        receipt['results'][1]['cleanup'] = ['synthetic retained owner']
        write(self.root / 'probe/results.json', receipt)
        value = report.publish(self.root)
        self.assertEqual(linux_cells(value), {1: 'PASS', 2: 'FAIL', 3: 'PASS', 4: 'NOT RUN', 5: 'PASS'})

    def test_identity_and_scope_mismatch_cannot_qualify_rows(self):
        for field, bad in [('surface', 'codex'), ('implementation', 'node'), ('platform', 'darwin')]:
            fixture(self.root)
            path = self.root / 'probe/results.json'
            receipt = json.loads(path.read_text()); receipt[field] = bad; write(path, receipt)
            self.assertEqual(linux_cells(report.publish(self.root))[1], 'UNKNOWN')
        for selected in [[1], [1, 2, 3, 5, 5], [True, 2, 3, 5]]:
            _, receipt, _ = fixture(self.root)
            receipt['scope']['selected'] = selected; write(self.root / 'probe/results.json', receipt)
            self.assertEqual(linux_cells(report.publish(self.root))[1], 'UNKNOWN')

    def test_interruption_keeps_completed_rows_and_labels_unfinished_work(self):
        run, _, _ = fixture(self.root)
        run['state'] = 'interrupted'
        value = report.summarize(run, self.root)
        self.assertEqual(value['status']['outcome'], 'INTERRUPTED')
        self.assertEqual(linux_cells(value)[1], 'PASS')
        run['invocations'][0].update(state='timed-out', exit=None)
        value = report.summarize(run, self.root)
        self.assertEqual(linux_cells(value)[1], 'INTERRUPTED')
        self.assertEqual(value['tables'][0]['rows'][0]['platforms']['win32']['state'], 'NOT RUN')

    def service(self, code, result, status, expected_interrupted, judge_exit=1):
        state = self.root / (code + '-' + result + '-' + status)
        config = {'state': str(state), 'probes': [['claude', 'wave-2']]}
        identity = 'a' * 32
        with unittest.mock.patch.dict(os.environ, {'INVOCATION_ID': identity, 'SERVICE_RESULT': result,
                                                 'EXIT_CODE': code, 'EXIT_STATUS': status}):
            _, directory, _ = lifecycle.begin(config)
            run, _, _ = fixture(directory, judge_exit)
            run['service_invocation_id'] = identity
            write(directory / 'run.json', run)
            lifecycle.service_exit(config)
            record = json.loads((directory / 'run.json').read_text())
            self.assertEqual(record['state'] == 'interrupted', expected_interrupted)
            self.assertEqual(record['service_exit'], {'result': result, 'code': code, 'status': status})
            if expected_interrupted:
                self.assertEqual(json.loads((directory / 'report.json').read_text())['status']['outcome'], 'INTERRUPTED')

    def test_expected_completed_verdict_exit_one_is_not_an_interruption(self):
        self.service('exited', 'exit-code', '1', False)

    def test_unexpected_exit_signal_and_manager_failure_are_interruptions(self):
        for code, result, status in [('exited', 'exit-code', '2'), ('killed', 'signal', 'TERM'),
                                     ('exited', 'success', '1'), ('exited', 'timeout', '1')]:
            self.service(code, result, status, True)

    def test_successful_producer_exit_zero_is_preserved(self):
        state = self.root / 'success'
        config = {'state': str(state), 'probes': [['codex', 'first-hour']]}
        with unittest.mock.patch.dict(os.environ, {'INVOCATION_ID': 'b'*32, 'SERVICE_RESULT': 'success',
                                                 'EXIT_CODE': 'exited', 'EXIT_STATUS': '0'}):
            _, directory, _ = lifecycle.begin(config)
            run, _, _ = fixture(directory, 0, [], 'codex', 'first-hour')
            run['service_invocation_id'] = 'b'*32; write(directory / 'run.json', run)
            lifecycle.service_exit(config)
            self.assertEqual(json.loads((directory / 'run.json').read_text())['state'], 'finished')

    def test_late_corrupt_finalizer_does_not_replace_newer_pointer(self):
        config = {'state': str(self.root / 'spool'), 'probes': [['claude', 'wave-2']]}
        with unittest.mock.patch.dict(os.environ, {'INVOCATION_ID': 'c'*32}):
            state, old, _ = lifecycle.begin(config)
            time.sleep(.002)
            os.environ['INVOCATION_ID'] = 'd'*32
            lifecycle.begin(config)
            before = (state / 'latest.json').read_bytes()
            (old / 'run.json').write_text('{broken')
            os.environ.update(INVOCATION_ID='c'*32, SERVICE_RESULT='signal', EXIT_CODE='killed', EXIT_STATUS='TERM')
            lifecycle.service_exit(config)
            self.assertEqual((state / 'latest.json').read_bytes(), before)

    def test_build_context_deduplicates_driver_ancestors_and_retains_unreadable(self):
        proc = self.root/'proc'; proc.mkdir()
        for pid, name, parent in [(101,'cargo',1),(102,'cargo-clippy',101),(103,'rustc',102),
                                  (201,'cargo-nextest',1),(301,'rustc',1)]:
            folder=proc/str(pid);folder.mkdir()
            (folder/'stat').write_text(f'{pid} ({name}) S {parent} ' + '0 '*48)
        for pid, state in [(501,'Z'),(502,'X'),(503,'x')]:
            folder=proc/str(pid);folder.mkdir();(folder/'stat').write_text(f'{pid} (cargo) {state} 1 '+'0 '*48)
        (proc/'401').mkdir();(proc/'401/stat').write_text('unreadable stat fields')
        with unittest.mock.patch.object(nightly,'Path',side_effect=lambda value:proc if value=='/proc' else Path(value)), unittest.mock.patch.object(nightly.os,'getloadavg',return_value=(1.,2.,3.)):
            context=nightly.box_load()
        self.assertEqual(context['driver_pids'],[101,201,301])
        self.assertEqual(context['concurrent_builds_observed'],3)
        self.assertEqual(context['unreadable_pids'],[401])
        self.assertEqual(context['load_average'],[1.,2.,3.])

    def test_exited_unreaped_driver_is_not_a_concurrent_build(self):
        child=subprocess.Popen([sys.executable,'-c',
            'import ctypes,os; ctypes.CDLL(None).prctl(15,b"cargo",0,0,0); os._exit(0)'])
        try:
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                observed=Path(f'/proc/{child.pid}/stat').read_text()
                fields=observed.rsplit(')',1)[1].split()
                if fields[0]=='Z': break
                time.sleep(.001)
            self.assertEqual(fields[0],'Z','owned fixture did not reach its exited state')
            self.assertEqual(observed.split('(',1)[1].rsplit(')',1)[0],'cargo','owned driver name was not witnessed')
            context=nightly.box_load()
            self.assertNotIn(child.pid,context['driver_pids'],'an exited zombie cannot be an active concurrent build')
        finally:
            child.wait(timeout=2)

    def test_cli_report_replays_actual_reader_and_credential_option_is_forwarded(self):
        fixture(self.root)
        completed = subprocess.run([sys.executable, '-B', str(args.source/'nightly.py'), '--report', str(self.root)],
                                   capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(linux_cells(json.loads((self.root/'report.json').read_text()))[1], 'PASS')
        judge = self.root/'judge'; (judge/'journeys').mkdir(parents=True)
        (judge/'journeys/run.mjs').write_text('import json,sys\nfrom pathlib import Path\nPath(sys.argv[sys.argv.index("--out")+1]+".argv").write_text(json.dumps(sys.argv))\n')
        config = {'state': str(self.root/'invoke'), 'probes': [['codex','first-hour']],
                  'node': sys.executable, 'auth_home': str(self.root/'synthetic-normal'),
                  'credential_sources': {'codex': str(self.root/'synthetic-profile/auth.json')}}
        _, directory, run = lifecycle.begin(config)
        nightly.invoke(config, run, directory, judge, self.root/'descriptor', self.root/'archive', {},
                       run['invocations'][0], time.monotonic()+10)
        argv = json.loads((directory/'1-codex-first-hour.argv').read_text())
        self.assertEqual(argv[argv.index('--credential-source')+1], config['credential_sources']['codex'])
        self.assertEqual(set(run['invocations'][0]['box_load']), {'before','after'})
        self.assertEqual(len(run['invocations'][0]['box_load']['before']['load_average']),3)


if __name__ == '__main__':
    import unittest.mock
    unittest.main(argv=[sys.argv[0], *remaining])
