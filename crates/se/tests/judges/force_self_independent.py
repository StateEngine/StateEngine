"""Actual in-scope MCP self-relaunch and successor-authenticated replay (Linux)."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode = True
from judge_records import read_json, wait_json
from force_relaunch_independent import Fixture, wait_for
from launch_startup import pin, exited


def provider_readiness():
    import force_self_provider as provider

    observed, finished = threading.Event(), threading.Event()
    admissions, failures = [], []

    class Readiness(threading.Event):
        def wait(self, timeout=None):
            observed.set()
            assert super().wait(5), 'provider readiness was never signalled'
            return True

    class ChildBoundary(Exception):
        pass

    ready = Readiness()

    def run_worker():
        try:
            provider.worker()
        except ChildBoundary:
            pass
        except BaseException as error:
            failures.append(error)
        finally:
            finished.set()
            observed.set()

    cwd = Path.cwd()
    with tempfile.TemporaryDirectory(prefix='se-self-ready-') as directory:
        repo = Path(directory)
        ready_file = repo / 'provider-ready.json'
        ready_file.touch()

        def admit_child(*args, **kwargs):
            assert ready.is_set(), 'child admitted before provider readiness'
            assert json.loads(ready_file.read_text())['helper_pid'] == os.getpid()
            admissions.append(args[0])
            raise ChildBoundary()

        try:
            os.chdir(repo)
            with patch.dict(os.environ, {'SE_SESSION': 'synthetic-ready-session'}), \
                    patch.object(provider, 'provider_ready', ready, create=True), \
                    patch.object(provider.subprocess, 'Popen', admit_child):
                thread = threading.Thread(target=run_worker)
                thread.start()
                try:
                    assert observed.wait(5), 'worker never reached its readiness barrier'
                    if failures:
                        raise failures[0]
                    assert not finished.is_set(), 'worker stopped before readiness'
                    assert ready_file.read_bytes() == b''
                    assert not admissions, 'empty readiness file admitted a child'
                    assert not list((repo / 'self-admissions').iterdir())
                    ready_file.write_text(json.dumps({'conversation': 'synthetic-conversation',
                        'session_discovery': True, 'http_discovery': True,
                        'native_root_pid': os.getppid(), 'helper_pid': os.getpid()}))
                    ready.set()
                    assert finished.wait(5), 'worker did not advance after readiness'
                    if failures:
                        raise failures[0]
                    assert len(admissions) == 1, admissions
                finally:
                    ready.set()
                    thread.join(5)
                    assert not thread.is_alive(), 'readiness worker did not join'
        finally:
            os.chdir(cwd)
    print('PASS self-force worker waits for complete provider readiness before child admission', flush=True)


def self_relaunch(binary, root):
    f = Fixture(binary, root, provider_helper=Path(__file__).with_name('force_self_provider.py'), log_directory='calls')
    identities, rows = [], {}
    failure = None
    try:
        up = f.ok('up')
        identities.append(pin(up['process']['pid']))
        f.launch()
        old = f.session
        records = f.repo / 'self-admissions'
        original = wait_json(records / (old + '.json'))
        old_pins = [pin(pid) for pid in original['pids']]
        identities.extend(old_pins)
        rows.update(original=original, original_native=old_pins)
        (f.repo / 'self-force-go').write_text('run the one admitted self-force request')

        def successor():
            files = list(records.glob('*.json'))
            errors = list(f.repo.glob('self-error-*.txt'))
            assert not errors, {p.name: p.read_text() for p in errors}
            rejection = f.repo / 'self-original-launch.response.json'
            value = read_json(rejection)
            if value is not None:
                assert not value.get('result', {}).get('isError') and 'error' not in value, value
            assert len(files) <= 2, 'self force started more than one successor'
            return next((value for path in files if path.stem != old
                         if (value := read_json(path)) is not None), None)

        fresh = wait_for(successor, 'successor created by the old scope actual MCP call', 35)
        new_pins = [pin(pid) for pid in fresh['pids']]
        identities.extend(new_pins)
        rows.update(successor=fresh, successor_native=new_pins)
        assert all(exited(native) for native in old_pins), 'self-force left original managed work live'
        f.session = fresh['session']
        def running():
            current = f.ok('--project', f.project, 'agent', 'show', f.agent)['agent']['value']
            return current if current['session']['session_id'] == f.session and current['session']['state'] == 'running' else None
        current = wait_for(running, 'successor running commit')
        rows['before_replay'] = current
        (f.repo / 'self-replay-go').write_text('retry the exact same operation under the successor admission')
        replay_path = f.repo / 'self-successor-launch.response.json'
        def replay():
            successor()
            return read_json(replay_path)
        reply = wait_for(replay, 'successor authenticated same-key replay', 35)
        rows['replay'] = reply
        assert 'error' not in reply and not reply['result'].get('isError'), reply
        result = reply['result']['structuredContent']
        assert result['session_id'] == f.session and result['state'] == 'running', result
        assert result['takeover']['previous_session'] == old, result
        assert all(not exited(native) for native in new_pins), 'same-key self retry stopped its successor'
        time.sleep(.3)
        assert len(list(records.glob('*.json'))) == 2, 'same-key self retry launched another scope'
        initial = f.repo / ('self-input-' + f.session + '.jsonl')
        inputs = [json.loads(line) for line in initial.read_text().splitlines()]
        assert len(inputs) == 1 and 'Owned self-force replacement input.' in inputs[0], inputs
        rows['successor_inputs'] = inputs
        after = f.ok('--project', f.project, 'agent', 'show', f.agent)['agent']['value']
        assert after['session']['session_id'] == f.session and after['session']['state'] == 'running', after
        assert after['session']['process']['pid'] == current['session']['process']['pid'], after
        rows['after_replay'] = after
        print('PASS actual in-scope MCP self force: old scope closed; one running successor; fresh-admission same-key replay sends no new initial input', flush=True)
    except BaseException:
        failure = traceback.format_exc()
        rows['failure'] = failure
    finally:
        try:
            f.close()
            closure = [{'pid': native[0], 'birth': native[1], 'exited': exited(native)} for native in identities]
            rows['closure'] = closure
            assert all(item['exited'] for item in closure), closure
        except BaseException:
            rows['cleanup_failure'] = traceback.format_exc()
        (root / 'observations.json').write_text(json.dumps(rows, indent=2))
    if failure or 'cleanup_failure' in rows:
        raise AssertionError(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    provider_readiness()
    self_relaunch(args.se.resolve(), args.output)


if __name__ == '__main__':
    main()
