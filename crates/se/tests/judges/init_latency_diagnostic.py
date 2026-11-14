"""Observe native fresh init without recording credential or random-buffer bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
from directory_owner import DirectoryOwner


def read_metadata(path):
    try:
        return {'state': 'present', 'text': path.read_text()}
    except OSError as error:
        return {'state': 'unreadable', 'reason': str(error)}


def birth(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return raw[19]
    except FileNotFoundError:
        return None


def metadata(home):
    if not home.exists():
        return {'state': 'absent', 'entries': []}
    try:
        return {'state': 'present', 'entries': [
            {'name': path.name, 'bytes': path.lstat().st_size,
             'mtime_ns': path.lstat().st_mtime_ns}
            for path in sorted(home.iterdir())]}
    except OSError as error:
        return {'state': 'unreadable', 'reason': str(error)}


def snapshot(pid):
    root = Path(f'/proc/{pid}')
    result = {name: read_metadata(root / name)
              for name in ['status', 'syscall', 'wchan', 'schedstat', 'io']}
    try:
        result['argv'] = (root / 'cmdline').read_bytes().decode(errors='replace').split('\0')
        result['fd_paths'] = {path.name: os.readlink(path) for path in (root / 'fd').iterdir()}
    except OSError as error:
        result['descriptor_observation'] = {'state': 'unreadable', 'reason': str(error)}
    return result


def verify_exact(pid, expected, initial_birth):
    if initial_birth is None or birth(pid) != initial_birth:
        raise RuntimeError('owned process identity is absent or changed')
    actual = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[:-1]
    if actual != [os.fsencode(arg) for arg in expected]:
        raise RuntimeError('owned process argv changed')


def terminate_exact(process, expected, initial_birth):
    if process.poll() is not None:
        return
    verify_exact(process.pid, expected, initial_birth)
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        verify_exact(process.pid, expected, initial_birth)
        process.kill()
        process.wait(timeout=2)


def stop_traced_child(supervisor, command, row):
    children = Path(f'/proc/{supervisor.pid}/task/{supervisor.pid}/children').read_text().split()
    row['traced_children'] = {}
    for text in children:
        pid = int(text)
        initial_birth = birth(pid)
        if initial_birth is None:
            row['traced_children'][text] = {'state': 'already exited'}
            continue
        verify_exact(pid, command, initial_birth)
        row['traced_children'][text] = snapshot(pid)
        verify_exact(pid, command, initial_birth)
        os.kill(pid, signal.SIGTERM)
        try:
            supervisor.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if birth(pid) == initial_birth:
                verify_exact(pid, command, initial_birth)
                os.kill(pid, signal.SIGKILL)
                supervisor.wait(timeout=2)
        if birth(pid) == initial_birth:
            raise RuntimeError('traced CLI exit was not confirmed; retaining its fixture')
    if supervisor.poll() is None:
        supervisor.wait(timeout=2)


def run_case(image, output, case, traced):
    case.mkdir(mode=0o700)
    owner = DirectoryOwner(case)
    home, repo, native = case / 'state', case / 'repo', case / 'bin'
    repo.mkdir(); native.mkdir()
    (repo / 'keep.txt').write_text('Synthetic user work.\n')
    shutil.copy2('/bin/true', native / 'goose')
    (native / 'goose').chmod(0o700)
    environment = {'HOME': str(case), 'USERPROFILE': str(case), 'PATH': str(native),
                   'LANG': 'C.UTF-8', 'XDG_STATE_HOME': str(case / 'xdg'), 'TMPDIR': str(case)}
    command = [str(image), '--home', str(home), 'init', '--repo', str(repo),
               '--harness', 'goose', '--json']
    invocation = command
    if traced:
        invocation = ['/usr/bin/strace', '-ff', '-ttt', '-T', '-yy', '-e',
                      'trace=process,file,fsync,fdatasync,fcntl,futex,poll,ppoll',
                      '-o', str(output / 'syscalls'), *command]
    began = time.monotonic()
    row = {'case': case.name, 'traced': traced, 'command': command,
           'observer_seconds': 5, 'timeout': False}
    with (output / 'stdout').open('wb') as stdout, (output / 'stderr').open('wb') as stderr:
        process = subprocess.Popen(invocation, cwd=repo, env=environment, stdout=stdout, stderr=stderr)
        initial_birth = birth(process.pid)
        try:
            row['exit'] = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            row['timeout'] = True
            row['at_deadline'] = snapshot(process.pid)
            row['state_at_deadline'] = metadata(home)
            if traced:
                stop_traced_child(process, command, row)
            else:
                terminate_exact(process, invocation, initial_birth)
            row['exit'] = process.returncode
            row['closure_confirmed'] = True
    row.update(seconds=time.monotonic() - began, state_after=metadata(home),
               configuration_present=(home / 'config.toml').exists(),
               stdout_bytes=(output / 'stdout').stat().st_size,
               stderr_bytes=(output / 'stderr').stat().st_size,
               endpoint_present=(home / 'endpoint.json').exists())
    row['passed'] = (not row['timeout'] and row['exit'] == 0 and row['configuration_present']
                     and not row['endpoint_present']
                     and (repo / 'keep.txt').read_text() == 'Synthetic user work.\n')
    (output / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
    if row['passed']:
        owner.remove()
    else:
        owner.close()
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    image = args.se.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    scratch = Path(tempfile.mkdtemp(prefix='init-latency-'))
    owner = DirectoryOwner(scratch)
    report = {'kind': 'native setup diagnostic; no historical cause or provider qualification',
              'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
              'observer_seconds': 5, 'fixture': str(scratch), 'rows': [],
              'trace_available': Path('/usr/bin/strace').is_file(),
              'pressure_before': {name: read_metadata(Path('/proc/pressure') / name)
                                  for name in ['cpu', 'io', 'memory']}}
    try:
        for index in range(6):
            traced = index % 2 == 1
            if traced and not report['trace_available']:
                raise RuntimeError('strace is absent; trace controls were not exercised')
            label = f'{index:02}-' + ('traced' if traced else 'plain')
            output = args.output / label
            output.mkdir(mode=0o700)
            report['rows'].append(run_case(image, output, scratch / label, traced))
            (args.output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    except BaseException as error:
        report['observer_error'] = {'kind': type(error).__name__, 'reason': str(error)}
        raise
    finally:
        report['pressure_after'] = {name: read_metadata(Path('/proc/pressure') / name)
                                    for name in ['cpu', 'io', 'memory']}
        report['passed'] = len(report['rows']) == 6 and all(row['passed'] for row in report['rows'])
        (args.output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        if report['passed']:
            owner.remove()
        else:
            owner.close()
        print(json.dumps(report), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
