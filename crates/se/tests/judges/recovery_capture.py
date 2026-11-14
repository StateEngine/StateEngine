"""Public Linux recovery consumer. Only exact owned host/provider births are killed.

python3 recovery_capture.py --se RELEASE_SE --output NEW_DIRECTORY
Uses the production transcript reader and an owned Claude protocol fixture.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import tempfile
import time
from mail_cli import Fixture


def wait(predicate, detail, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        result = predicate()
        if result:
            return result
        time.sleep(.03)
    raise AssertionError(detail)


def native(pid):
    try:
        directory = Path('/proc') / str(pid)
        fields = (directory / 'stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'birth': fields[19], 'state': fields[0],
                'command': (directory / 'cmdline').read_bytes().replace(b'\0', b' ').decode()}
    except (FileNotFoundError, ProcessLookupError):
        return None


def gone(original):
    row = native(original['pid'])
    return not row or row['birth'] != original['birth'] or row['state'] in ('Z', 'X', 'x')


def replies(f):
    history = f.ok('--project', f.project, 'history', '--agent', f.agent, '--limit', '100')
    assert history['window']['complete'], 'history page is incomplete'
    return [item['payload']['body']['text'] for item in history['items']
            if item['kind'] == 'session.turn' and item['payload']['role'] == 'assistant']


def status(f):
    return f.ok('--project', f.project, 'status')


def run_case(options, case):
    f = Fixture(options.se, options.output / case,
                provider_helper=Path(__file__).with_name('recovery_capture_provider.py'), log_directory='calls')
    runtime = Path(tempfile.mkdtemp(prefix='se-recovery-capture-'))
    print("fixture root (retained on failed or interrupted closure):", runtime, flush=True)
    f.env['XDG_RUNTIME_DIR'] = str(runtime)
    f.env['TMPDIR'] = '/tmp'
    (f.root / 'routing.json').write_text(json.dumps({key: f.env[key] for key in
        ['HOME', 'USERPROFILE', 'XDG_RUNTIME_DIR', 'TMPDIR']}, indent=2))
    checks = []
    try:
        if case == 'partial':
            (f.repo / 'partial-tail').touch()
        launch = f.ok('--project', f.project, 'launch', f.agent, '--detach', '--task', 'Finish original work')
        f.session = launch['session_id']
        ready = wait(lambda: (f.repo / 'recovery-ready.json').exists(), 'provider did not start')
        assert ready
        wait(lambda: 'BEFORE_HOST_CRASH_REPLY' in replies(f), 'initial reply did not capture')
        before = status(f)
        host = native(before['runtime']['process']['pid'])
        provider = native(launch['process']['pid'])
        helper = native(json.loads((f.repo / 'recovery-ready.json').read_text())['helper_pid'])
        assert host and str(f.se) in host['command']
        assert provider and str(f.root / 'provider') in provider['command']
        assert helper and 'recovery_capture_provider.py' in helper['command']
        f.processes.extend((row['pid'], row['birth']) for row in [host, provider, helper])
        os.kill(host['pid'], signal.SIGKILL)
        killed_ns = time.time_ns()
        wait(lambda: gone(host), 'exact host did not exit')
        (f.repo / 'work-release').touch()
        wait(lambda: gone(provider) and gone(helper), 'original provider did not finish after host exit')
        transcript, = (f.root / 'owner/.claude/projects').glob('*/*.jsonl')
        assert 'AFTER_HOST_CRASH_REPLY' in transcript.read_text()
        assert (f.repo / 'notes.md').stat().st_mtime_ns >= killed_ns
        checks.append('original work and native reply completed after the exact host exited')
        retained = transcript.with_suffix('.retained')
        if case == 'missing':
            transcript.rename(retained)
        f.ok('up')
        if case != 'complete':
            agent = wait(lambda: (row if row['session']['state'] == 'recovery-pending' else None)
                         if (row := next(row for row in status(f)['agents']['items'] if row['id'] == f.agent))
                         else None, 'capture debt is not visible')
            assert ' stop ' in agent['resume']['reason'], agent
            assert agent['session']['recorded_state'] == 'activated', agent
            refusal = f.call('--project', f.project, 'stop', f.agent)
            assert refusal.returncode != 0, 'incomplete capture falsely returned exit zero'
            refused = json.loads(refusal.stdout)
            assert not refused['complete'], 'failed capture silently retired the session'
            checks.append('unavailable final capture stays pending with an exact public stop remedy')
            if case == 'missing':
                transcript.write_bytes(retained.read_bytes())
                replacement = f.call('--project', f.project, 'stop', f.agent)
                assert replacement.returncode != 0 and b'incarnation changed' in replacement.stdout
                assert not json.loads(replacement.stdout)['complete']
                transcript.unlink()
                checks.append('a replacement file with identical bytes cannot replace the original native incarnation')
                retained.rename(transcript)
            else:
                with transcript.open('a') as stream:
                    stream.write('\n')
            stop = f.ok('--project', f.project, 'stop', f.agent)
            assert stop['complete'] and stop['capture']['flushed'], stop
            assert not [row for row in status(f)['pending'] if 'recovered final capture' in row['detail']]
            checks.append('repairing the original source and retrying stop completes capture and clears pending debt')
        else:
            wait(lambda: 'AFTER_HOST_CRASH_REPLY' in replies(f), 'automatic recovery omitted the completed reply')
            wait(lambda: next(row for row in status(f)['agents']['items'] if row['id'] == f.agent)
                 ['session']['recorded_state'] == 'ended', 'automatic capture did not retire the completed session')
            checks.append('up automatically captures and retires the completed session without another launch')
        captured = replies(f)
        assert captured.count('BEFORE_HOST_CRASH_REPLY') == 1
        assert captured.count('AFTER_HOST_CRASH_REPLY') == 1
        f.ok('up')
        assert replies(f) == captured
        checks.append('history and repeated up preserve both replies exactly once')
    finally:
        (f.repo / 'work-release').touch()
        try:
            # A failing assertion must not leave an injected unavailable source.
            if 'transcript' in locals():
                if 'retained' in locals() and retained.exists():
                    if transcript.exists():
                        transcript.unlink()
                    retained.rename(transcript)
                if transcript.exists() and not transcript.read_bytes().endswith(b'\n'):
                    with transcript.open('ab') as stream:
                        stream.write(b'\n')
        finally:
            f.close()
        directory = runtime / 'stateengine'
        if directory.exists():
            directory.rmdir()
        runtime.rmdir()
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=['complete', 'missing', 'partial'], action='append')
    options = parser.parse_args()
    os.umask(0o077)
    options.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for case in options.case or ['complete', 'missing', 'partial']:
        for check in run_case(options, case):
            rows.append(case + ': ' + check)
            print('ok', len(rows), '-', rows[-1], flush=True)
    (options.output / 'results.json').write_text(json.dumps({'pass': len(rows), 'checks': rows}, indent=2))
    print('passed', len(rows), 'failed 0', flush=True)


if __name__ == '__main__':
    main()
