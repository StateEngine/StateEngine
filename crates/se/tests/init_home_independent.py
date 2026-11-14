#!/usr/bin/env python3
"""Protects: G6 — refused same-home init preserves bytes; unrelated homes initialize concurrently.

Public Linux CLI and actual nonblocking OS file locks only. The held empty home
models a setup already owning its runtime lease, before it publishes any state.
No provider, host, installer or account claim is started by the judge.
"""
import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('native Linux flock required; other operating systems not reached')
    image = args.se.resolve(strict=True)
    args.out.mkdir(mode=0o700)
    root = Path(tempfile.mkdtemp(prefix='se-init-homes-', dir=Path.home()))
    print("fixture root (retained on failed or interrupted closure):", root, flush=True)
    binary = root / 'se'
    shutil.copy2(image, binary)
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    fixtures, calls = [], []
    failures = []

    def fixture(name):
        home = root / name
        home.mkdir(mode=0o700)
        repo = home / 'repo'
        repo.mkdir()
        (repo / 'user.txt').write_bytes(b'Keep user work.\n')
        env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
               'XDG_STATE_HOME': str(home / 'xdg')}
        subprocess.run(['/usr/bin/git', 'init', '--quiet'], cwd=repo, env=env, check=True)
        value = (name, home, repo, home / 'state', env)
        fixtures.append(value)
        return value

    def run(fix, label, *argv):
        name, home, repo, state, env = fix
        cmd = [str(binary), '--home', str(state), *argv, '--json']
        child = subprocess.Popen(cmd, cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            # Popen still owns this unreaped exact child. No name-matched kill.
            child.kill()
            stdout, stderr = child.communicate()
            (args.out / (label + '.timeout')).write_bytes(stdout + stderr)
            raise
        (args.out / (label + '.stdout')).write_bytes(stdout)
        (args.out / (label + '.stderr')).write_bytes(stderr)
        calls.append({'label': label, 'pid': child.pid, 'argv': cmd, 'exit': child.returncode})
        return child.returncode, stdout, stderr

    def init(fix, label):
        return run(fix, label, 'init', '--repo', str(fix[2]), '--name', fix[0],
                   '--agent', 'judge', '--provider', 'claude')

    def snapshot(state):
        return {str(p.relative_to(state)): digest(p) for p in state.rglob('*') if p.is_file()}

    first = fixture('locked')
    state = first[3]
    state.mkdir(mode=0o700)
    # This is an OS fixture lease, not a fabricated database or credential.
    lock = state / 'runtime.lock'
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = snapshot(state)
        code, stdout, stderr = init(first, 'same-home-refusal')
        if code == 0 or not any(word in stdout + stderr for word in (b'lease', b'writer', b'lock')):
            failures.append('same-home init did not give a named lease refusal')
        after = snapshot(state)
        if after != before:
            failures.append('refused init changed or published protected files')
        others = [fixture('independent-a'), fixture('independent-b')]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda f: init(f, f[0]), others))
        if any(result[0] != 0 for result in results):
            failures.append('an unrelated concurrent init was refused')
        if snapshot(state) != after:
            failures.append('unrelated init mutated the held home')
    finally:
        os.close(fd)
    # Resume through the same public command after releasing the lease.
    if init(first, 'after-release')[0] != 0:
        failures.append('same-home init did not succeed after lease release')
    ids = []
    for fix in fixtures:
        name, home, repo, state, env = fix
        code, stdout, stderr = run(fix, name + '-readback', 'agent', 'list')
        try:
            value = json.loads(stdout)
            rows = value['items']
            if code != 0 or len(rows) != 1:
                raise ValueError('one independently readable agent required')
            ids.append(rows[0]['id'])
        except (ValueError, KeyError, TypeError) as error:
            failures.append(f'{name} public readback failed: {error}')
        if (repo / 'user.txt').read_bytes() != b'Keep user work.\n':
            failures.append(name + ' user work changed')
        if (state / 'endpoint.json').exists():
            failures.append(name + ' unexpectedly left a host endpoint')
        if not (state / 'runtime.lock').exists():
            failures.append(name + ' has no runtime lease file after setup')
            continue
        with (state / 'runtime.lock').open('rb') as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                failures.append(name + ' retained a runtime lease')
    if len(set(ids)) != 3:
        failures.append('three independent homes did not retain distinct agents')
    if not failures:
        try:
            shutil.rmtree(root)
        except OSError as error:
            failures.append('fixture removal: ' + str(error))
    report = {'passed': not failures, 'binary_sha256': digest(image), 'fixture_root': str(root),
              'held_before': before, 'held_after_refusal': after, 'calls': calls, 'failures': failures,
              'bounds': 'Three private homes; every CLI child waited; no runtime/provider/installer started.'}
    (args.out / 'results.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'passed': not failures, 'failures': failures}))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
