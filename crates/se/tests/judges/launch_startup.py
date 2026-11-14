"""Public startup recovery journey; real native processes, no model/account calls.
Run with --se RELEASE_SE --output NEW_OWNED_DIRECTORY (Linux).
"""
import argparse
import json
from pathlib import Path
import subprocess
import fcntl
import os
import traceback
import time

from judge_records import read_json, wait_json
from mail_cli import Fixture


def pin(pid):
    row = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
    return pid, row[19]


def exited(identity):
    pid, birth = identity
    try:
        row = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        return row[19] != birth or row[0] in ('Z', 'X', 'x')
    except FileNotFoundError:
        return True


def run(binary, root, mode, control):
    f = Fixture(binary, root, provider_helper=Path(__file__).with_name('launch_startup_provider.py'), log_directory='calls')
    (f.repo / 'startup-mode').write_text(mode)
    up = f.ok('up')
    all_identities = [pin(up['process']['pid'])]
    argv = ['--project', f.project, '--key', 'original-startup', 'launch', f.agent, '--detach', '--task', 'Startup recovery']
    started = time.monotonic()
    launch = subprocess.Popen([str(f.se), '--json', '--home', str(f.home), *argv],
                              env=f.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    failure = None
    try:
        until = time.monotonic() + 20
        marker = f.repo / 'startup-pids.json'
        published = read_json(marker)
        while published is None:
            assert launch.poll() is None, 'launch ended before the startup barrier'
            assert time.monotonic() < until, 'provider never entered startup'
            time.sleep(.05)
            published = read_json(marker)
        identities = [pin(pid) for pid in published]
        all_identities.extend(identities)
        # The helper runs only after exec. Permit the host one short publication
        # turn; this wait is not provider readiness and must not last its budget.
        status = None
        for _ in range(30):
            result = f.call('--project', f.project, 'status')
            if result.returncode == 0:
                status = json.loads(result.stdout)
                break
            time.sleep(.1)
        assert status is not None, (result.stdout, result.stderr)
        assert 'starting' in json.dumps(status), status
        diagnosis = f.ok('doctor')
        pending = [row for row in diagnosis['checks'] if row['id'].startswith('runtime.launch.')]
        assert len(pending) == 1 and pending[0]['state'] == 'warning', diagnosis
        remedy = pending[0]['fix']['argv']
        assert remedy == ['se', '--home', str(f.home), '--project', f.project, 'stop', f.agent], remedy
        assert diagnosis['outcome'] != 'healthy'
        probe = wait_json(f.repo / 'startup-owner-probe.json', seconds=10)
        assert probe['exit'] != 0
        print(f'ok - {mode}/{control}: owner status and scoped startup diagnosis before readiness', flush=True)
        control_started = time.monotonic()
        if control == 'stop':
            if mode == 'idle':
                # Unix SQLite WAL_WRITE_LOCK is byte 0 at UNIX_SHM_BASE=120.
                # Hold its real interprocess writer lock without opening another
                # SQLite connection that can checkpoint or truncate this WAL.
                lock = os.open(f.home / 'state.db-shm', os.O_RDWR)
                blocked = None
                try:
                    fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 120)
                    blocked = subprocess.Popen([str(f.se), '--json', '--key', 'blocked-startup-stop', *remedy[1:]],
                                               env=f.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    time.sleep(1)
                    alive = [not exited(identity) for identity in identities]
                    observation = {'writer_locked': True, 'provider_alive': alive,
                                   'stdin_closed': (f.repo / 'startup-saw-eof').exists()}
                    (f.root / 'stop-before-commit.json').write_text(json.dumps(observation))
                    assert all(alive), 'stop took native effect before its FULL intent'
                    assert not observation['stdin_closed'], 'handshake cancellation closed stdin before its FULL intent'
                finally:
                    try:
                        if blocked:
                            # A busy writer may refuse promptly; preserve its
                            # reply even when the native-effect assertion fails.
                            output, error = blocked.communicate(timeout=10)
                            (f.root / 'blocked-stop.stdout').write_bytes(output)
                            (f.root / 'blocked-stop.stderr').write_bytes(error)
                    finally:
                        fcntl.lockf(lock, fcntl.LOCK_UN, 1, 120)
                        os.close(lock)
                assert blocked.returncode != 0, (output, error)
            stopping = subprocess.Popen([str(f.se), '--json', *remedy[1:]], env=f.env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stop_output, stop_error = stopping.communicate(timeout=35)
            (f.root / 'printed-stop.stdout').write_bytes(stop_output)
            (f.root / 'printed-stop.stderr').write_bytes(stop_error)
            assert stopping.returncode == 0, (stop_output, stop_error)
            stopped = json.loads(stop_output)
            assert stopped['complete'] and stopped['witness']['state'] == 'witnessed', stopped
        elif control == 'down':
            stopped = f.ok('down')
            assert stopped['complete'] and stopped['witness']['state'] == 'witnessed', stopped
        if control in ('stop', 'down'):
            assert time.monotonic() - control_started < 20, 'control waited for the whole readiness budget'
        output, error = launch.communicate(timeout=35)
        (f.root / 'launch.stdout').write_bytes(output)
        (f.root / 'launch.stderr').write_bytes(error)
        assert launch.returncode != 0 and b'commit-outcome-unknown' not in output + error, (output, error)
        assert time.monotonic() - started < 30, 'startup cleanup escaped the original call budget'
        assert all(exited(identity) for identity in identities), identities
        print(f'ok - {mode}/{control}: readiness failure remains recoverable and native exit is witnessed', flush=True)
        if control != 'down':
            count = (f.repo / 'startup-count').read_bytes()
            retry = f.call(*argv)
            assert retry.returncode == launch.returncode and retry.stdout == output and retry.stderr == error, (retry.stdout, retry.stderr, output, error)
            assert (f.repo / 'startup-count').read_bytes() == count, 'same key spawned another provider'
            assert f.call(*[word if word != 'Startup recovery' else 'Different intent' for word in argv]).returncode != 0
            assert (f.repo / 'startup-count').read_bytes() == count
            print(f'ok - {mode}/{control}: original-key failure replay and changed-intent refusal', flush=True)
            f.ok('--project', f.project, 'status')
            (f.repo / 'startup-mode').write_text('ready')
            launched = f.ok('--project', f.project, '--key', 'fresh-after-failure', 'launch', f.agent, '--detach', '--new')
            assert launched['state'] == 'running', launched
            ready = wait_json(f.repo / 'provider-ready.json')
            assert ready['session_discovery'] and ready['http_discovery']
            all_identities.extend(pin(pid) for pid in wait_json(marker))
            assert (f.repo / 'startup-count').read_text().count('started') == 2
            print(f'ok - {mode}/{control}: explicit fresh launch succeeds with both credential proofs', flush=True)
    except BaseException as error:
        failure = error
        (f.root / 'failure.txt').write_text(traceback.format_exc())
    finally:
        try:
            f.close()
        except BaseException:
            (f.root / 'cleanup-failure.txt').write_text(traceback.format_exc())
            if failure is None:
                raise
        output, error = launch.communicate(timeout=35)
        (f.root / 'launch.stdout').write_bytes(output)
        (f.root / 'launch.stderr').write_bytes(error)
        until = time.monotonic() + 2
        while not all(exited(identity) for identity in all_identities) and time.monotonic() < until:
            time.sleep(.05)
        closure = [{'pid': pid, 'birth': birth, 'exited': exited((pid, birth))} for pid, birth in all_identities]
        (f.root / 'outside-closure.json').write_text(json.dumps(closure, indent=2))
        if failure is None:
            assert all(row['exited'] for row in closure), closure
    if failure:
        raise failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=False)
    for mode, control in [('idle', 'timeout'), ('http-only', 'stop'), ('idle', 'stop'), ('idle', 'down')]:
        run(options.se, options.output / (mode + '-' + control), mode, control)
    print('PASS 14 startup recovery checks', flush=True)


if __name__ == '__main__':
    main()
