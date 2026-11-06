"""Bug: 880576ec — mail maintenance overtakes a stop queued during capture.

Uses only the installed Linux CLI, a provider protocol double, native IO and
outside process/file observations. No database edits or private host calls.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import uuid

sys.dont_write_bytecode = True
from mail_cli import Fixture
from recovery_capture import gone, native, wait


def run(args):
    os.umask(0o077)
    args.runtime.mkdir(mode=0o700, parents=True, exist_ok=False)
    library = args.runtime / 'barrier.so'
    source = Path(__file__).with_name('capture_stop_barrier.c')
    build = subprocess.run(['cc', '-std=c11', '-shared', '-fPIC', '-Wall', '-Wextra',
                            '-Werror', '-O2', str(source), '-o', str(library)],
                           capture_output=True, timeout=30)
    assert build.returncode == 0, build.stderr.decode()
    fixture = Fixture(args.se, args.output,
        provider_helper=Path(__file__).with_name('capture_stop_provider.py'),
        log_directory='calls')
    gate = args.runtime / 'gate'
    gate.mkdir(mode=0o700)
    token = 'capture-order-' + uuid.uuid4().hex
    key = 'queued-stop-' + uuid.uuid4().hex
    fixture.env.update(TMPDIR=str(args.runtime), XDG_RUNTIME_DIR=str(args.runtime),
        LD_PRELOAD=str(library), CAPTURE_ORDER_GATE=str(gate),
        CAPTURE_ORDER_HOME=str(fixture.home), CAPTURE_ORDER_TURN=token,
        CAPTURE_ORDER_STOP_KEY=key)
    pins, checks, stop = [], [], None
    result = {'binary_sha256': hashlib.sha256(args.se.read_bytes()).hexdigest(),
              'checks': checks, 'stop_key': key}
    foreground_log = (fixture.root / 'host.log').open('wb')
    foreground = subprocess.Popen([str(args.se), '--home', str(fixture.home),
        'up', '--foreground', '--json'], env=fixture.env, stdin=subprocess.DEVNULL,
        stdout=foreground_log, stderr=foreground_log)

    def check(value, name):
        checks.append({'name': name, 'passed': bool(value)})
        print(('ok' if value else 'not ok'), len(checks), '-', name, flush=True)

    try:
        wait(lambda: (fixture.home / 'endpoint.json').exists(), 'foreground runtime did not publish')
        status = fixture.ok('--project', fixture.project, 'status')
        host = native(status['runtime']['process']['pid'])
        assert host and host['pid'] == foreground.pid, 'foreground runtime identity differs'
        pins.append(host)
        assert str(library) in Path('/proc', str(host['pid']), 'maps').read_text(), (
            'the native barrier is not mapped in the foreground host')
        (gate / 'host-pid').write_text(str(host['pid']))
        launch = fixture.ok('--project', fixture.project, 'launch', fixture.agent,
                            '--detach', '--task', 'Retain capture before a queued stop')
        ready = fixture.repo / 'provider-ready.json'
        wait(ready.exists, 'provider startup did not complete')
        binding = json.loads(ready.read_text())
        pins.extend([native(binding['native_root_pid']), native(binding['helper_pid'])])
        assert all(pins), 'provider identity absent'
        fixture.mail('send', fixture.agent, 'Pending mail must not overtake the queued stop')
        (fixture.repo / 'complete-task').write_text(token)
        wait(lambda: (gate / 'capture-write-accepted').exists(),
             'native capture write barrier was not reached')
        stop = subprocess.Popen([str(args.se), '--json', '--home', str(fixture.home),
            '--project', fixture.project, '--key', key, 'stop', fixture.agent],
            env=fixture.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        wait(lambda: (gate / 'stop-arrived').exists(),
             'public stop request was not observed at the host IO boundary')
        time.sleep(.25)
        check(stop.poll() is None and not (gate / 'capture-write-returned').exists(),
              'queued stop waits for the accepted capture write to finish')
        (gate / 'release').touch()
        stdout, stderr = stop.communicate(timeout=45)
        (fixture.root / 'stop.stdout').write_bytes(stdout)
        (fixture.root / 'stop.stderr').write_bytes(stderr)
        stopped = json.loads(stdout)
        check(stop.returncode == 0 and stopped.get('complete')
              and stopped.get('capture', {}).get('flushed'),
              'one queued stop completes after capture publication')
        check(not (gate / 'mail-offered').exists(),
              'mail transport does not overtake the queued stop')
        page = fixture.ok('--project', fixture.project, 'history', '--agent', fixture.agent,
                          '--kind', 'session.turn', '--limit', '100')
        assert page['window']['complete'] and not page['next'], 'history page incomplete'
        saved = [row for row in page['items']
                 if row['payload'].get('role') == 'assistant'
                 and row['payload'].get('body', {}).get('text') == token]
        check(len(saved) == 1, 'accepted capture is independently readable exactly once')
        rows = fixture.ok('--project', fixture.project, 'status')['agents']['items']
        check(next(row for row in rows if row['id'] == fixture.agent)['resume']['ready'],
              'terminal capture leaves the stopped agent ready to resume')
        check(not (gate / 'barrier-expired').exists(),
              'the native IO barrier was explicitly released')
        result['conversation'] = launch['conversation_id']
    except Exception:
        result['setup_or_consumer_failure'] = traceback.format_exc()
    finally:
        (gate / 'release').touch()
        try:
            if stop and stop.poll() is None:
                stdout, stderr = stop.communicate(timeout=45)
                (fixture.root / 'cleanup-stop.stdout').write_bytes(stdout)
                (fixture.root / 'cleanup-stop.stderr').write_bytes(stderr)
            fixture.close()
            foreground.wait(timeout=10)
        except Exception:
            result['cleanup_failure'] = traceback.format_exc()
        foreground_log.close()
        outside = [{'before': pin, 'after': native(pin['pid'])} for pin in pins]
        result['outside'] = outside
        check(all(gone(pin) for pin in pins)
              and not (fixture.home / 'endpoint.json').exists(),
              'all saved process identities and the fixture endpoint are closed')
        result['pass'] = sum(row['passed'] for row in checks)
        result['fail'] = len(checks) - result['pass'] + int(
            'setup_or_consumer_failure' in result) + int('cleanup_failure' in result)
        result['markers'] = {p.name: p.read_text() for p in gate.iterdir() if p.is_file()}
        (fixture.root / 'result.json').write_text(json.dumps(result, indent=2))
        assert hashlib.sha256(args.se.read_bytes()).hexdigest() == result['binary_sha256']
    print('passed', result['pass'], 'failed', result['fail'], flush=True)
    return int(result['fail'] > 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['se', 'output', 'runtime']:
        parser.add_argument('--' + name, type=lambda p: Path(p).resolve(), required=True)
    options = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('the native IO barrier qualifies Linux only')
    raise SystemExit(run(options))
