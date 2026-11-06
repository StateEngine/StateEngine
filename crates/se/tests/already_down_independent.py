#!/usr/bin/env python3
"""Protects: G6 — already-down succeeds honestly, but endpoint absence cannot hide a held lease.

Linux public CLI judge for an initialized home, first without a host and then
after a real public up/down. The negative case holds the real OS lease while
no endpoint exists. No state/endpoint bytes are fabricated or edited.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def native(pid):
    try:
        row = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'birth': row[19], 'state': row[0]}
    except FileNotFoundError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--setup-se', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('native Linux lease/process observer required; other OS not reached')
    image = args.se.resolve(strict=True)
    setup = (args.setup_se or args.se).resolve(strict=True)
    args.out.mkdir(mode=0o700)
    root = Path(tempfile.mkdtemp(prefix='se-already-down-', dir=Path.home()))
    binary = root / 'se'
    shutil.copy2(image, binary)
    env = {'HOME': str(root), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
           'XDG_STATE_HOME': str(root / 'xdg')}
    repo, state = root / 'repo', root / 'state'
    repo.mkdir()
    user = repo / 'user.txt'
    user.write_bytes(b'Keep user work.\n')
    subprocess.run(['/usr/bin/git', 'init', '--quiet'], cwd=repo, env=env, check=True)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    calls, failures, known = [], [], None

    def call(label, *argv, human=False, executable=binary):
        cmd = [str(executable), '--home', str(state), *argv]
        if not human:
            cmd.append('--json')
        child = subprocess.Popen(cmd, cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            child.kill()  # Popen retains the exact unreaped child.
            out, err = child.communicate()
            (args.out / (label + '.timeout')).write_bytes(out + err)
            raise
        (args.out / (label + '.stdout')).write_bytes(out)
        (args.out / (label + '.stderr')).write_bytes(err)
        calls.append({'label': label, 'argv': cmd, 'pid': child.pid, 'exit': child.returncode})
        return child.returncode, out, err

    def already(label):
        code, out, err = call(label + '-json', 'down')
        try:
            value = json.loads(out)
            if (code != 0 or value.get('schema') != 'se.runtime-stop/v1'
                    or value.get('already_down') is not True or value.get('complete') is not True
                    or value.get('stops') != []):
                failures.append(label + ' did not honestly report an already-down success')
        except (ValueError, TypeError):
            failures.append(label + ' had no public JSON stop response')
        code, out, err = call(label + '-human', 'down', human=True)
        text = (out + err).decode(errors='replace').lower()
        if code != 0 or 'already down' not in text or 'no host was running' not in text:
            failures.append(label + ' human output did not explain that no host was running')
        if (state / 'endpoint.json').exists():
            failures.append(label + ' created an endpoint')
        with (state / 'runtime.lock').open('rb') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    seeded = call('init', 'init', '--repo', str(repo), '--name', 'down-judge',
                  '--agent', 'judge', '--provider', 'claude', executable=setup)
    if seeded[0] != 0:
        raise RuntimeError('public setup not reached; raw output retained')
    try:
        already('never-started')
        # A live lease with absent endpoint is uncertainty, never already down.
        with (state / 'runtime.lock').open('rb') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, out, err = call('held-lease', 'down')
            try:
                value = json.loads(out)
                if code == 0 or value.get('schema') != 'se.error/v1' or not value.get('remedy'):
                    failures.append('held lease was mistaken for already down')
            except ValueError:
                failures.append('held lease did not give a named refusal')
        code, out, err = call('up', 'up')
        if code != 0:
            raise RuntimeError('public host startup not reached; raw output retained')
        pid = json.loads(out)['process']['pid']
        known = native(pid)
        if known is None or known['state'] == 'Z':
            raise AssertionError('public up did not identify a live native host')
        code, out, err = call('first-down', 'down')
        if code != 0 or json.loads(out).get('complete') is not True:
            failures.append('first real shutdown did not complete')
        until = time.monotonic() + 10
        while time.monotonic() < until:
            try:
                reaped, _ = os.waitpid(pid, os.WNOHANG)
                if reaped == pid:
                    break
            except ChildProcessError:
                break
            time.sleep(.02)
        current = native(pid)
        if current is not None and current['birth'] == known['birth']:
            failures.append('first shutdown left the exact known host instance')
        already('after-shutdown')
    except BaseException as error:
        failures.append(f'consumer did not complete: {type(error).__name__}: {error}')
        raise
    finally:
        if (state / 'endpoint.json').exists():
            code, out, err = call('cleanup-down', 'down')
            if code != 0:
                failures.append('public fixture cleanup failed; endpoint retained')
        if user.read_bytes() != b'Keep user work.\n':
            failures.append('user work changed')
        report = {'passed': not failures, 'failures': failures, 'calls': calls,
                  'fixture_root': str(root), 'known_host': known,
                  'binary_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                  'setup_sha256': hashlib.sha256(setup.read_bytes()).hexdigest(),
                  'bounds': 'Known exact host PID/birth plus endpoint and free home lease; no provider launched.'}
        (args.out / 'results.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'passed': not failures, 'failures': failures}))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
