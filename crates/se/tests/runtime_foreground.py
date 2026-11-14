#!/usr/bin/env python3
"""Protects: B3/B5 — foreground up is the actual host until down or terminal Ctrl-C.

Linux public-CLI judge. --setup-se may pin a compatible setup binary separately
when the baseline's account-wide init claim is held by another install. No
installer, provider, account claim or product-internal API is used here.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import signal
import shutil
import subprocess
import sys
import tempfile
import termios
import time


def identity(pid):
    try:
        root = Path('/proc') / str(pid)
        stat = root.joinpath('stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'birth': stat[19], 'state': stat[0],
                'argv': root.joinpath('cmdline').read_bytes().split(b'\0')[:-1]}
    except FileNotFoundError:
        return None


def same(old):
    new = identity(old['pid'])
    return new is not None and new['birth'] == old['birth'] and new['argv'] == old['argv']


def terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def inventory(home):
    rows, unreadable, empty = [], 0, 0
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            row = identity(int(path.name))
            if row is None:
                continue
            if not row['argv']:
                empty += 1
            elif str(home).encode() in b' '.join(row['argv']) and row['state'] != 'Z':
                rows.append({'pid': row['pid'], 'birth': row['birth'],
                             'argv_hex': [x.hex() for x in row['argv']]})
        except PermissionError:
            unreadable += 1
    return {'matches': rows, 'unreadable': unreadable, 'empty_argv': empty}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--setup-se', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('native Linux /proc and controlling-PTY observer required; not reached')
    args.se = args.se.resolve(strict=True)
    setup = (args.setup_se or args.se).resolve(strict=True)
    args.out.mkdir(mode=0o700)
    # Adopt detached baseline children for exact wait/reap after public down.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    root = Path(tempfile.mkdtemp(prefix='se-fg-', dir=Path.home()))
    print("fixture root (retained on failed or interrupted closure):", root, flush=True)
    results = []
    for ending in ('down', 'ctrl-c'):
        home = root / ending
        home.mkdir(mode=0o700)
        repo = home / 'repo'
        repo.mkdir()
        user_file = repo / 'user.txt'
        user_file.write_text('Keep this user work.\n')
        state = home / 'state'
        binary = home / 'se'
        shutil.copy2(args.se, binary)
        env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
               'XDG_STATE_HOME': str(home / 'xdg'), 'XDG_RUNTIME_DIR': '/run/user/1000'}
        calls = []

        def call(binary, label, *argv):
            command = [str(binary), '--home', str(state), *argv, '--json']
            value = subprocess.run(command, cwd=repo, env=env, capture_output=True, timeout=30)
            stem = f'{ending}-{len(calls):03d}-{label}'
            (args.out / f'{stem}.stdout').write_bytes(value.stdout)
            (args.out / f'{stem}.stderr').write_bytes(value.stderr)
            calls.append({'argv': command, 'exit': value.returncode})
            return value

        seeded = call(setup, 'init', 'init', '--repo', str(repo), '--name', ending,
                      '--agent', 'judge', '--provider', 'claude')
        if seeded.returncode != 0:
            raise RuntimeError('public setup failed; retained raw output, no host started')
        master, slave = pty.openpty()
        attributes = termios.tcgetattr(slave)
        attributes[3] |= termios.ISIG
        attributes[6][termios.VINTR] = b'\x03'
        termios.tcsetattr(slave, termios.TCSANOW, attributes)
        log = (args.out / f'{ending}-foreground.log').open('wb')
        child = subprocess.Popen([str(binary), '--home', str(state), 'up', '--foreground', '--json'],
                                 cwd=repo, env=env, stdin=slave, stdout=log, stderr=log,
                                 preexec_fn=terminal)
        os.close(slave)
        initial = identity(child.pid)
        observed = None
        failure = None
        cleanup = []
        census = None
        try:
            until = time.monotonic() + 20
            while time.monotonic() < until:
                # A direct status takes a shared lease: polling it during the
                # initial exclusive claim changes the race we mean to observe.
                if not (state / 'endpoint.json').exists():
                    if child.poll() not in (None, 0):
                        raise AssertionError(f'up failed before readiness: {child.returncode}')
                    time.sleep(.05)
                    continue
                value = call(binary, 'status', 'status')
                if value.returncode == 0:
                    status = json.loads(value.stdout)
                    if status['runtime']['state'] == 'running':
                        observed = status['runtime']['process']['pid']
                        break
                time.sleep(.05)
            if observed is None:
                raise AssertionError('foreground host never became publicly running')
            host = identity(observed)
            if host is None or str(home).encode() not in b' '.join(host['argv']):
                raise AssertionError('public host PID has no exact private-home command line')
            # A sibling under the subreaper is the original regression.
            if observed != child.pid or child.poll() is not None:
                raise AssertionError(f'foreground root {child.pid} exited/detached; public host is {observed}')
            census = inventory(home)
            if any(row['pid'] != child.pid for row in census['matches']):
                raise AssertionError('another live private-home process accompanies the foreground host')
            time.sleep(.15)
            if not same(initial) or child.poll() is not None:
                raise AssertionError('up did not retain the same native host for its lifetime')
            if ending == 'ctrl-c':
                # Exercise terminal input, not an artificial process-name signal.
                os.write(master, b'\x03')
            else:
                stopped = call(binary, 'down', 'down')
                if stopped.returncode != 0:
                    raise AssertionError('public down failed')
            code = child.wait(timeout=15)
            if ending == 'down' and code != 0:
                raise AssertionError(f'normal host shutdown exit was {code}, expected 0')
            if ending == 'ctrl-c' and code not in (0, 130, -signal.SIGINT):
                raise AssertionError(f'Ctrl-C host exit was {code}')
        except Exception as error:
            failure = str(error)
        finally:
            # Public cleanup first even when the baseline detached a sibling.
            remaining_host = identity(observed) if observed is not None else None
            if ((state / 'endpoint.json').exists()
                    or (remaining_host is not None and remaining_host['state'] != 'Z')):
                stopped = call(binary, 'cleanup-down', 'down')
                if stopped.returncode != 0:
                    cleanup.append('public cleanup down failed')
            if child.poll() is None:
                if initial and same(initial):
                    child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    cleanup.append('foreground child still alive after exact-instance TERM')
            if observed is not None and observed != child.pid:
                until = time.monotonic() + 10
                while time.monotonic() < until:
                    try:
                        reaped, _ = os.waitpid(observed, os.WNOHANG)
                        if reaped == observed:
                            break
                    except ChildProcessError:
                        break
                    time.sleep(.02)
            os.close(master)
            log.close()
            if observed is not None and identity(observed) is not None:
                cleanup.append(f'observed host PID {observed} remains; no pattern kill attempted')
            if (state / 'endpoint.json').exists():
                cleanup.append('endpoint remains')
            with (state / 'runtime.lock').open('rb') as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    cleanup.append('home runtime lease still held')
            if user_file.read_text() != 'Keep this user work.\n':
                cleanup.append('user work changed')
            final_census = inventory(home)
            if final_census['matches']:
                cleanup.append('private-home processes remain; see bounded outside census')
        row = {'case': ending, 'passed': failure is None and not cleanup,
               'failure': failure, 'cleanup_errors': cleanup,
               'foreground_pid': child.pid, 'public_host_pid': observed,
               'foreground_birth': initial['birth'] if initial else None,
               'foreground_exit': child.returncode, 'calls': calls,
               'live_census': census, 'closed_census': final_census}
        results.append(row)
        (args.out / 'results.json').write_text(json.dumps({
            'binary_sha256': hashlib.sha256(args.se.read_bytes()).hexdigest(),
            'setup_binary_sha256': hashlib.sha256(setup.read_bytes()).hexdigest(),
            'fixture_root': str(root), 'cases': results}, indent=2))
        print(('PASS' if row['passed'] else 'FAIL') + ': ' + ending + ': ' + str(failure), flush=True)
    if all(row['passed'] for row in results):
        try:
            shutil.rmtree(root)
        except OSError as error:
            results[-1]['cleanup_errors'].append('fixture removal: ' + str(error))
            results[-1]['passed'] = False
            (args.out / 'results.json').write_text(json.dumps({
                'binary_sha256': hashlib.sha256(args.se.read_bytes()).hexdigest(),
                'setup_binary_sha256': hashlib.sha256(setup.read_bytes()).hexdigest(),
                'fixture_root': str(root), 'cases': results}, indent=2))
    return 0 if all(r['passed'] for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
