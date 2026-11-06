"""Bug: 9596e4d1 — busy stop stranded capture at 128 commits and leaked source pins.

Linux installed CLI consumer; owned Claude protocol double, no provider account.
Run with --se ABSOLUTE_BINARY --output NEW_DIRECTORY --runtime NEW_SHORT_DIRECTORY.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.dont_write_bytecode = True
from mail_cli import Fixture
from recovery_capture import gone, native, wait


def run(options):
    f = Fixture(options.se, options.output,
                provider_helper=Path(__file__).with_name('soak_capture_provider.py'), log_directory='calls')
    options.runtime.mkdir(mode=0o700, parents=True, exist_ok=False)
    f.env.update(TMPDIR=str(options.runtime), XDG_RUNTIME_DIR=str(options.runtime))
    checks, pins, path, repair, complete = [], [], None, None, False
    def check(value, detail):
        assert value, detail
        checks.append(detail)
        print('ok', len(checks), '-', detail, flush=True)
    def status():
        return f.ok('--project', f.project, 'status')
    def stop(required=True):
        key = str(uuid.uuid4())
        for _ in range(5):
            response = f.call('--project', f.project, '--key', key, 'stop', f.agent)
            value = json.loads(response.stdout)
            if value.get('code') != 'commit-outcome-unknown':
                break
            assert value['detail']['key'] == key, 'stop changed its uncertain request identity'
        else:
            raise AssertionError('same-key stop outcome remained unknown')
        if required:
            assert response.returncode == 0, value
        return response, value
    def agent():
        return next(row for row in status()['agents']['items'] if row['id'] == f.agent)
    def history():
        rows, cursor = [], None
        while True:
            args = ['--project', f.project, 'history', '--agent', f.agent, '--kind', 'session.turn', '--limit', '100']
            if cursor:
                args += ['--cursor', cursor]
            page = f.ok(*args)
            rows.extend(page['items'])
            cursor = page['next']
            if not cursor:
                assert page['window']['complete'], page['window']
                # read_at describes this inspection; all committed provenance is stable.
                return [{key: value for key, value in row.items() if key != 'read_at'} for row in rows]
    def terminal_pins(host):
        found = []
        for fd in (Path('/proc') / str(host['pid']) / 'fd').iterdir():
            try:
                target = os.readlink(fd)
            except FileNotFoundError:
                continue
            if str(f.root / 'owner/.claude/projects') in target:
                found.append(target)
        return found
    try:
        conversation = None
        expected = []
        ready = f.repo / 'provider-ready.json'
        for cycle in range(0 if options.case == 'eof' else 3):
            turns = 259 if cycle == 0 and options.case == 'combined' else 1
            ready = f.repo / 'provider-ready.json'
            ready.unlink(missing_ok=True)
            launch = f.ok('--project', f.project, 'launch', f.agent, '--detach', '--task', 'Continue retained work')
            wait(ready.exists, 'provider discovery did not finish')
            provider = json.loads(ready.read_text())
            pins.extend(native(pid) for pid in [provider['native_root_pid'], provider['helper_pid']])
            assert all(pins), 'missing native provider identity'
            if conversation is None:
                conversation = launch['conversation_id']
            check(launch['conversation_id'] == conversation, f'cycle {cycle}: normal reopen preserves conversation')
            path = Path(provider['path'])
            host = native(status()['runtime']['process']['pid'])
            assert host and str(f.se) in host['command'], 'unidentified fixture host'
            if not any(pin['pid'] == host['pid'] and pin['birth'] == host['birth'] for pin in pins):
                pins.append(host)
            with path.open('ab') as stream:
                for turn in range(turns):
                    stream.write((json.dumps({'type': 'assistant', 'sessionId': conversation,
                        'uuid': f'cycle-{cycle}-turn-{turn}', 'message': {'role': 'assistant',
                        'content': f'BUSY_CAPTURE_{cycle}_{turn}'}}) + '\n').encode())
                stream.flush()
                os.fsync(stream.fileno())
            _, stopped = stop()
            check(stopped['complete'] and stopped['capture']['flushed'] and agent()['resume']['ready'],
                  f'cycle {cycle}: one stop drains {turns} replies and allows resume')
            check(not terminal_pins(host), f'cycle {cycle}: terminal transcript file and directory pins are zero')
            saved = history()
            texts = [row['payload']['body']['text'] for row in saved if row['payload']['role'] == 'assistant']
            expected.extend(f'BUSY_CAPTURE_{cycle}_{t}' for t in range(turns))
            check(sorted(texts) == sorted(expected), f'cycle {cycle}: all public replies are retained exactly once')
        if options.case == 'pins':
            complete = True
            return
        # Failed EOF followed by no-new-turn repair must clear the latest failure.
        ready.unlink(missing_ok=True)
        f.ok('--project', f.project, 'launch', f.agent, '--detach', '--task', 'Check repair')
        wait(ready.exists, 'repair provider did not start')
        provider = json.loads(ready.read_text())
        pins.extend(native(pid) for pid in [provider['native_root_pid'], provider['helper_pid']])
        path = Path(provider['path'])
        host = native(status()['runtime']['process']['pid'])
        assert host, 'missing repair host identity'
        if not any(pin['pid'] == host['pid'] and pin['birth'] == host['birth'] for pin in pins):
            pins.append(host)
        stable = history()
        repair = path.read_bytes()
        with path.open('ab') as stream:
            stream.write(b'{"type":')
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(2):
            refused, value = stop(required=False)
            check(refused.returncode != 0 and not value['complete'] and not value['capture']['flushed']
                  and not agent()['resume']['ready'], f'EOF attempt {attempt}: incomplete source refuses with resume debt')
        check(not terminal_pins(host), 'failed terminal capture releases native pins while retaining repair debt')
        with path.open('r+b') as stream:
            stream.truncate(len(repair))
            stream.flush()
            os.fsync(stream.fileno())
        _, repaired = stop()
        check(repaired['complete'] and repaired['capture']['flushed'] and agent()['resume']['ready'],
              'same-file EOF repair with no new turn clears the latest durable failure')
        repair = None
        check(history() == stable, 'EOF verification invents no turn or changed public provenance')
        f.ok('down')
        f.ok('up')
        host = native(status()['runtime']['process']['pid'])
        pins.append(host)
        check(agent()['resume']['ready'] and history() == stable and not terminal_pins(host),
              'cold readback preserves readiness, exact history and zero historical transcript pins')
        complete = True
    finally:
        if repair is not None and path and path.exists():
            with path.open('r+b') as stream:
                stream.truncate(len(repair))
        # Repeated stops are cleanup only; they cannot rescue a failed one-stop assertion.
        for _ in range(8):
            result = f.call('--project', f.project, 'stop', f.agent)
            if result.returncode == 0:
                break
        f.close()
        outside = [{'before': pin, 'after': native(pin['pid'])} for pin in pins if pin]
        assert all(gone(pin) for pin in pins if pin), outside
        (f.root / 'outside.json').write_text(json.dumps(outside, indent=2))
        (f.root / 'results.json').write_text(json.dumps({'complete': complete, 'pass': len(checks), 'checks': checks}, indent=2))
    print('passed', len(checks), 'failed 0; all fixture births and endpoints closed', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--case', choices=['combined', 'pins', 'eof'], default='combined')
    options = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('this native handle consumer qualifies Linux only')
    os.umask(0o077)
    run(options)
