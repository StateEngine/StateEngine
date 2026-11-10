#!/usr/bin/env python3
"""Protects: direct-init uninstall stops owned work, retains history/identity and refuses unsafe artifacts.

Linux public CLI consumer. Human-only uninstall runs in a PTY under the user's
OS scheduler, outside the agent ancestry. No installer manifest, paid account or
manual deletion is used.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import re
import socket
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).with_name('judges')))
from mail_cli import Fixture


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def terminal(f, label, json_output=True):
    argv = [str(f.se), '--home', str(f.home)]
    if json_output:
        argv.append('--json')
    argv += ['uninstall', '--key', str(uuid.uuid4())]
    public = {'HOME', 'USERPROFILE', 'PATH', 'LANG', 'LC_ALL', 'TERM', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'CODEX_HOME'}
    clean = {key: value for key, value in f.env.items() if key in public}
    command = ['/usr/bin/systemd-run', '--user', '--quiet', '--wait', '--collect', '--pipe',
               '--unit', 'se-home-cleanup-' + uuid.uuid4().hex,
               '/usr/bin/env', '-i', *[f'{key}={value}' for key, value in clean.items()],
               '/usr/bin/script', '-q', '-e', '-c', shlex.join(argv), '/dev/null']
    result = subprocess.run(command, input=b'', capture_output=True, timeout=100)
    (f.root / (label + '.stdout')).write_bytes(result.stdout)
    (f.root / (label + '.stderr')).write_bytes(result.stderr)
    (f.root / (label + '.invocation.json')).write_text(json.dumps({'argv': argv,
        'executor': 'user systemd manager + script PTY; cleared fleet/session environment',
        'exit': result.returncode}, indent=2))
    return result


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--se', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expect-record-refusal', action='store_true')
    p.add_argument('--port', type=int, default=28755)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    checks = []

    def passed(text):
        checks.append(text)
        print(f'ok {len(checks)} - {text}', flush=True)

    for running in [False, True]:
        f = Fixture(a.se, a.output / ('running' if running else 'never-started'))
        runtime = Path(tempfile.mkdtemp(prefix='se5b-home-', dir='/tmp'))
        for name, suffix in [('CODEX_HOME', 'codex'), ('XDG_CONFIG_HOME', 'config'), ('XDG_CACHE_HOME', 'cache'), ('XDG_DATA_HOME', 'data'), ('XDG_STATE_HOME', 'state')]:
            location = f.root / ('private-' + suffix)
            location.mkdir(mode=0o700)
            f.env[name] = str(location)
        f.env['XDG_RUNTIME_DIR'] = str(runtime)
        config = f.home / 'config.toml'
        with socket.socket() as available:
            available.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            available.bind(('127.0.0.1', a.port))
        configured, replaced = re.subn(r'(?m)^listen_port = [0-9]+$', 'listen_port = ' + str(a.port), config.read_text(), count=1)
        assert replaced == 1, 'listener port anchor unavailable'
        config.write_text(configured)
        try:
            extra = f.home / 'user-file.txt'
            extra.write_text('Unrelated user bytes must survive.\n')
            protected = {str(path): digest(path) for path in [extra, f.home / 'credential',
                f.home / 'machine.json', f.home / 'config.toml']}
            lock = f.home / 'runtime.lock'
            lock_identity = (lock.stat().st_dev, lock.stat().st_ino)
            history = f.mail('send', f.agent, 'Retain this message through direct-init cleanup.')['message_id']
            if running:
                f.launch()
                status = f.ok('--project', f.project, 'status')
                host = status['runtime']['process']['pid']
                birth = Path(f'/proc/{host}/stat').read_text().rsplit(') ', 1)[1].split()[19]
                f.processes.append((host, birth))
            result = terminal(f, 'first-uninstall')
            if a.expect_record_refusal:
                expected = b'uninstall unresolved process custody' if running else b'owned installation record is absent'
                assert result.returncode and expected in result.stdout + result.stderr, (result.returncode, result.stdout, result.stderr)
                passed('base direct-init uninstall refuses ' + ('unresolved live custody' if running else 'the absent installation record'))
                continue
            assert result.returncode == 0, (result.stdout, result.stderr)
            frames = [line for line in result.stdout.splitlines() if line.startswith(b'{')]
            assert len(frames) == 1, (result.stdout, result.stderr)
            output = json.loads(frames[0])
            assert output['complete'] and output['home_cleanup']['runtime']['state'] == 'present', output
            assert output['install_files'] == [] and output['path']['before_entries'] == output['path']['after_entries'] == [], output
            files = output['home_cleanup']['runtime_files']
            assert any(row['path'] == str(f.home / 'runtime-info.json') for row in files), files
            assert all(row['outcome'] in ['removed', 'already-absent'] and row['witness']['state'] == 'witnessed' for row in files), files
            assert not (f.home / 'endpoint.json').exists() and not (f.home / 'runtime-info.json').exists()
            assert 'manually' in output['home_cleanup']['manual_data_removal'] and str(f.home) in output['home_cleanup']['manual_data_removal']
            passed(('running' if running else 'never-started') + ': runtime-only cleanup succeeds with exact paths and no installation claims')
            for path, expected in protected.items():
                assert digest(Path(path)) == expected, path
            assert (lock.stat().st_dev, lock.stat().st_ino) == lock_identity
            read = f.mail('read', history)
            assert 'Retain this message' in json.dumps(read), read
            assert f.ok('--project', f.project, 'agent', 'list')['items'], 'retained agents disappeared'
            passed('history, credentials, machine identity, configuration, user bytes and coordination inode survive')
            repeat = terminal(f, 'repeat-uninstall', json_output=False)
            assert repeat.returncode == 0 and b'Uninstall complete' in repeat.stdout, (repeat.stdout, repeat.stderr)
            for path in [f.home / name for name in ['state.db', 'credential', 'machine.json', 'config.toml', 'runtime.lock']]:
                assert str(path).encode() in repeat.stdout, path
            passed('repeated cleanup prints kept paths and the separate manual data-removal step')
            # A link at a known artifact path must not grant authority over its target.
            target = f.home / 'unrelated-observation.json'
            target.write_text('Keep this unrelated object.\n')
            info = f.home / 'runtime-info.json'
            info.symlink_to(target)
            unsafe = terminal(f, 'unsafe-observation')
            assert unsafe.returncode != 0, (unsafe.stdout, unsafe.stderr)
            assert info.is_symlink() and target.read_text() == 'Keep this unrelated object.\n'
            passed('unsafe runtime artifact is refused with its unrelated target preserved')
            info.unlink()  # Only this consumer-created link, never the target.
            with lock.open('rb') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                busy = terminal(f, 'held-lease')
                assert busy.returncode != 0, (busy.stdout, busy.stderr)
                assert (lock.stat().st_dev, lock.stat().st_ino) == lock_identity
            passed('held native lease refuses cleanup and preserves the same coordination inode')
        finally:
            f.close()
            if (runtime / 'stateengine').exists():
                (runtime / 'stateengine').rmdir()
            runtime.rmdir()
        (f.root / 'outside-closure.json').write_text(json.dumps({'exact_births': f.processes,
            'all_rechecked_gone': True, 'endpoint_absent': not (f.home / 'endpoint.json').exists()}, indent=2))
        passed('public down and outside exact-birth closure complete')
    (a.output / 'results.json').write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))
    print(f'1..{len(checks)}', flush=True)


if __name__ == '__main__':
    main()
