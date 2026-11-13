"""Optional pinned harness-matrix observation alongside the existing journeys."""
import hashlib
import json
import os
import re
import signal
from pathlib import Path
import subprocess
import sys
import time

STATES = ('PASS', 'FAIL', 'ABSENT', 'SKIPPED', 'UNREADABLE', 'NOT RUN')
PLATFORMS = ('linux', 'win32', 'darwin')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def plan(config):
    if 'harness_matrix' not in config:
        return None
    stage = dict(state='planned', result='NOT RUN', exit=None, output='harness-matrix',
                 expected=[], manifest_sha256=None, report_sha256=None)
    try:
        manifest = Path(config['harness_matrix']['manifest'])
        if not manifest.is_absolute() or manifest.is_symlink() or manifest.stat().st_size > 1024 * 1024:
            raise ValueError('matrix manifest must be a bounded absolute plain file')
        raw = manifest.read_bytes()
        value = json.loads(raw)
        expected = [row['id'] for row in value['harnesses']]
        if value.get('schema') != 'se.harness-matrix-input/v1' or not 1 <= len(expected) <= 64 or any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name) for name in expected) or len(set(expected)) != len(expected):
            raise ValueError('invalid matrix coverage plan')
        stage.update(expected=expected, manifest_sha256=hashlib.sha256(raw).hexdigest())
    except (OSError, ValueError, KeyError, TypeError) as error:
        stage['error'] = str(error)
    return stage


def run(config, record, directory, source, bundle, env, deadline, checkpoint):
    stage = record['harness_matrix']
    stage.update(state='running')
    checkpoint()
    selected = config['harness_matrix']
    manifest = Path(selected['manifest'])
    if not manifest.is_absolute() or manifest.is_symlink() or manifest.stat().st_size > 1024 * 1024:
        raise ValueError('matrix manifest must be a bounded absolute plain file')
    raw = manifest.read_bytes()
    value = json.loads(raw)
    if value.get('schema') != 'se.harness-matrix-input/v1':
        raise ValueError('unsupported harness matrix input')
    expected = [entry['id'] for entry in value['harnesses']]
    if not expected or len(set(expected)) != len(expected):
        raise ValueError('empty or duplicate harness matrix plan')
    copied = directory / 'harness-matrix-input.json'
    if stage.get('error') or expected != stage['expected'] or hashlib.sha256(raw).hexdigest() != stage['manifest_sha256']:
        raise ValueError('matrix input changed after tonight’s plan was recorded')
    copied.write_bytes(raw)
    stage.update(expected=expected, manifest_sha256=digest(copied),
                 source_commit=record['product']['commit'])
    checkpoint()
    matrix_env = dict(env)
    # Only names enter configuration and receipts; credential values are not retained.
    for entry in value['harnesses']:
        for name in entry.get('platforms', {}).get('linux', {}).get('environment', []):
            if name.upper() == 'SE_SESSION' or name.upper().startswith(('STATEENGINE_', 'SECODE_')):
                raise ValueError('matrix environment carries runtime authority')
            if name in os.environ:
                matrix_env[name] = os.environ[name]
    names = ['harness-matrix.py', 'harness-matrix-report.py', 'ci/installation_account.py',
             *['harness_matrix/' + name for name in
               ('flow.py', 'inputs.py', 'io.py', 'report.py', 'native_processes.ps1')]]
    stage['runner_sha256'] = {name: digest(source / 'scripts' / name) for name in names}
    checkpoint()
    output = directory / stage['output']
    seconds = min(3600, deadline - time.monotonic())
    if seconds <= 1:
        raise RuntimeError('matrix deadline reached before execution')
    argv = [sys.executable, '-B', str(source / 'scripts/harness-matrix.py'),
            '--package', str(bundle), '--source-commit', stage['source_commit'],
            '--manifest', str(copied), '--out', str(output)]
    with (directory / 'harness-matrix.log').open('xb') as log:
        child = subprocess.Popen(argv, env=matrix_env, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT)
        process = Path('/proc') / str(child.pid)
        identity = None
        if child.poll() is None:
            try:
                identity = ((process / 'stat').read_text().rsplit(') ', 1)[1].split()[19],
                            (process / 'cmdline').read_bytes())
            except FileNotFoundError:
                pass
        try:
            stage['exit'] = child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            stage.update(state='timed-out', error='matrix deadline; native closure requires observation')
            checkpoint()
            if child.poll() is None:
                current = ((process / 'stat').read_text().rsplit(') ', 1)[1].split()[19],
                           (process / 'cmdline').read_bytes())
                if not identity or not identity[1] or current != identity:
                    raise RuntimeError('matrix child identity changed; native custody is unknown') from None
                # The runner catches termination and closes its active fixture.
                # The scheduler reserves a separate hour for finalization.
                child.send_signal(signal.SIGTERM)
            try:
                stage['exit'] = child.wait(timeout=600)
            except subprocess.TimeoutExpired:
                raise RuntimeError('matrix did not close after termination; native custody is unknown') from None
            checkpoint()
            stage['timed_out'] = True
    stage.update(state='observed')
    checkpoint()
    inputs = [output, *[Path(path) for path in selected.get('native_results', [])]]
    argv = [sys.executable, '-B', str(source / 'scripts/harness-matrix-report.py'),
            '--source-commit', stage['source_commit'], '--manifest-sha256', stage['manifest_sha256'],
            '--expected', *expected, '--out', str(directory / 'harness-matrix-report')]
    for path in inputs:
        argv += ['--input', str(path)]
    with (directory / 'harness-matrix-report.log').open('xb') as log:
        stage['report_exit'] = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT, timeout=60).returncode
    report = directory / 'harness-matrix-report/matrix.json'
    stage['report_sha256'] = digest(report)
    stage.update(state='finished', result=json.loads(report.read_text())['result'])
    checkpoint()


def observation(record, directory):
    stage = record.get('harness_matrix')
    if stage is None:
        return None
    planned = [dict(harness=name, platforms={platform: dict(result='NOT RUN',
                reason='planned matrix has no complete observation') for platform in PLATFORMS})
               for name in stage.get('expected', [])]
    result = dict(state='partial', complete=False, outcome='UNKNOWN', errors=[], rows=planned)
    try:
        path = directory / 'harness-matrix-report/matrix.json'
        if stage.get('state') != 'finished':
            raise ValueError('planned harness matrix has no complete observation')
        if digest(path) != stage.get('report_sha256'):
            raise ValueError('harness matrix report digest differs')
        value = json.loads(path.read_text())
        if (value.get('schema') != 'se.harness-matrix-summary/v1'
                or value.get('source_commit') != (record.get('product') or {}).get('commit')
                or value.get('manifest_sha256') != stage.get('manifest_sha256')
                or value.get('runner_sha256') != stage.get('runner_sha256')
                or not isinstance(value.get('rows'), list)
                or [row.get('harness') for row in value['rows']] != stage.get('expected')
                or not isinstance(value.get('errors'), list)):
            raise ValueError('harness matrix report identity or coverage differs')
        result.update(rows=value['rows'], errors=value['errors'], qualification=value.get('qualification'))
        states = [row['platforms'][platform]['result'] for row in value['rows']
                  for platform in ('linux', 'win32', 'darwin')]
        if not states or any(state not in STATES for state in states):
            raise ValueError('invalid harness matrix native results')
        passed = not value['errors'] and all(state == 'PASS' for state in states)
        if passed != (value.get('result') == 'PASS') or stage.get('report_exit') != (0 if passed else 1):
            raise ValueError('harness matrix report exit or aggregate differs')
        if passed and stage.get('exit') != 0:
            raise ValueError('passing harness matrix has a failing local producer')
        result.update(state='complete' if all(state in ('PASS', 'FAIL') for state in states) else 'partial',
                      complete=all(state in ('PASS', 'FAIL') for state in states),
                      outcome='PASS' if passed else 'FAIL' if value['errors'] or any(state in ('FAIL', 'UNREADABLE') for state in states) else 'UNKNOWN')
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['errors'].append(str(error))
    return result
