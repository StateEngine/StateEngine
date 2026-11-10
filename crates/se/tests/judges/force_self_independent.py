"""Actual in-scope MCP self-relaunch and successor-authenticated replay (Linux)."""
import argparse
import json
import subprocess
import sys
import time
import traceback
from pathlib import Path
sys.dont_write_bytecode = True
from force_relaunch_independent import Fixture, wait_for
from launch_startup import pin, exited


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
        wait_for(lambda: (records / (old + '.json')).exists(), 'original scope identity')
        original = json.loads((records / (old + '.json')).read_text())
        old_pins = [pin(pid) for pid in original['pids']]
        identities.extend(old_pins)
        rows.update(original=original, original_native=old_pins)
        (f.repo / 'self-force-go').write_text('run the one admitted self-force request')

        def successor():
            files = list(records.glob('*.json'))
            errors = list(f.repo.glob('self-error-*.txt'))
            assert not errors, {p.name: p.read_text() for p in errors}
            rejection = f.repo / 'self-original-launch.response.json'
            if rejection.exists():
                value = json.loads(rejection.read_text())
                assert not value.get('result', {}).get('isError') and 'error' not in value, value
            assert len(files) <= 2, 'self force started more than one successor'
            return next((json.loads(path.read_text()) for path in files if path.stem != old), None)

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
            return json.loads(replay_path.read_text()) if replay_path.exists() else None
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
    self_relaunch(args.se.resolve(), args.output)


if __name__ == '__main__':
    main()
