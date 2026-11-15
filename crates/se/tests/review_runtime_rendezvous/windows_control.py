"""Real Windows route/authentication crash window and held-owner consumers.

The native peer helper reads the real suspended owner's handle table. It closes
all duplicated handles before returning. No product hooks or endpoint edits are
used. Run under the admitted VM owner with a native compiler on PATH.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def wait(predicate, seconds=10):
    end = time.monotonic() + seconds
    while True:
        result = predicate()
        if result:
            return result
        if time.monotonic() >= end:
            raise TimeoutError('Bounded native reviewer condition was not witnessed')
        time.sleep(.01)


def path_value(value):
    assert value['encoding'] == 'windows_utf16', value
    units = value['units']
    return Path(b''.join(int(x).to_bytes(2, 'little') for x in units).decode('utf-16-le'))


def trial(args, label, held, Fixture, Native, PausedParent, Process):
    root = args.out / label
    root.mkdir()
    image = root / 'se.exe'
    shutil.copyfile(args.se, image)
    report = {'case': label, 'qualified': False, 'held': held,
              'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
              'not_exercised': ['Exact failed bootstrap count', 'Deadline after retention',
                                'First and retry bootstrap refusal']}
    f = None
    host = pause = caller = None
    owned = []
    try:
        # Keep public cleanup available if construction fails after init.
        f = Fixture.__new__(Fixture)
        Fixture.__init__(f, image, root / 'fixture')
        f.launch()
        ready = json.loads((f.repo / 'provider-ready.json').read_text())
        providers = []
        for pid, executable in [(ready['native_root_pid'], f.root / 'provider.exe'),
                                (ready['helper_pid'], Path(sys.executable))]:
            process = Process(pid, executable, str(f.root))
            providers.append(process)
            owned.append(process)
        report['providers_before'] = [p.initial for p in providers]
        before = f.ok('up')
        host = Process(before['process']['pid'], image)
        owned.append(host)
        report['host_before'] = host.initial
        endpoint_bytes = (f.home / 'endpoint.json').read_bytes()
        endpoint = json.loads(endpoint_bytes)
        assert endpoint['epoch']['owner']['pid'] == host.pid
        assert endpoint['address']['kind'] == 'windows_pipe'
        pipe_name = endpoint['address']['name']
        assert pipe_name.startswith('\\\\.\\pipe\\'), 'Expected a local native pipe'
        native_pipe_name = '\\Device\\NamedPipe\\' + pipe_name[len('\\\\.\\pipe\\'):]
        native = Native()
        assert native.writer_present(f.home / 'runtime.lock')
        pause = PausedParent(native, host)
        report['owner_threads_suspended'] = len(pause.handles)
        assert report['owner_threads_suspended'] > 0
        stdout, stderr = root / 'up.stdout', root / 'up.stderr'
        with stdout.open('wb') as out, stderr.open('wb') as err:
            caller = subprocess.Popen([str(image), '--json', '--home', str(f.home), 'up'],
                                      env=f.env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        client = Process(caller.pid, image, str(f.home))
        owned.append(client)
        report['caller'] = client.initial
        observations = []

        def connected():
            assert caller.poll() is None, 'CLI exited before its connection was witnessed'
            result = subprocess.run([str(args.peer), str(host.pid), str(caller.pid),
                                     str(host.initial['creation_filetime']), host.initial['image'],
                                     native_pipe_name],
                                    capture_output=True, timeout=10)
            row = {'exit': result.returncode, 'stdout': result.stdout.decode(),
                   'stderr': result.stderr.decode()}
            observations.append(row)
            if result.returncode == 2:
                raise RuntimeError('Native pipe observation was unreadable: ' + repr(row))
            assert result.returncode in (0, 1), row
            if result.returncode == 0:
                value = json.loads(result.stdout)
                assert value['owner'] == host.pid and value['client'] == caller.pid
                assert value['matches'] > 0
                return value
            return None

        try:
            report['real_pipe_connection_before_auth'] = wait(connected)
        finally:
            report['connection_observations'] = observations
        assert (f.home / 'endpoint.json').read_bytes() == endpoint_bytes
        assert native.writer_present(f.home / 'runtime.lock')
        if not held:
            report['crashed_exact_owner'] = host.crash()
            # Thread handles retain the dead threads until resume closes them.
            # Their suspend counts no longer affect a live process.
            for handle in list(pause.handles.values()):
                native.close(handle)
            pause.handles.clear()
            pause = None
            wait(lambda: not native.writer_present(f.home / 'runtime.lock'))
            report['owner_exit_and_lease_release_witnessed'] = True
        caller.wait(timeout=45)
        report['up_exit'] = caller.returncode
        report['up_reply'] = json.loads(stdout.read_bytes())
        report['providers_survive'] = [not p.exited() for p in providers]
        assert all(report['providers_survive']), 'Recovery stopped a preserved provider'
        if held:
            assert caller.returncode != 0 and b'state-conflict' in stdout.read_bytes()
            assert not host.exited() and native.writer_present(f.home / 'runtime.lock')
            assert (f.home / 'endpoint.json').read_bytes() == endpoint_bytes
            report['held_owner_and_endpoint_unchanged'] = True
            # The paused owner has no running accept loop. The native witness
            # establishes a real connection, not an exact attempt count.
            report['connection_attempt_count'] = 'not measured'
            pause.resume()
            pause = None
        elif args.expect == 'recovered':
            assert caller.returncode == 0, report['up_reply']
            replacement = Process(report['up_reply']['process']['pid'], image)
            owned.append(replacement)
            assert replacement.initial['creation_filetime'] != host.initial['creation_filetime']
            report['replacement'] = replacement.initial
            retained = path_value(report['up_reply']['endpoint_recovery']['retained'])
            assert retained.resolve().is_relative_to(f.home.resolve())
            assert retained.read_bytes() == endpoint_bytes
            report['retained_endpoint_bytes_verified'] = True
        else:
            assert caller.returncode != 0 and b'state-conflict' in stdout.read_bytes()
        recovered = f.ok('up')
        if not any(p.pid == recovered['process']['pid'] for p in owned):
            owned.append(Process(recovered['process']['pid'], image))
        assert all(not p.exited() for p in providers)
        report['behavior_witnessed'] = True
    except BaseException as error:
        report['failure'] = f'{type(error).__name__}: {error}'
    finally:
        errors = []
        if pause:
            try:
                pause.resume()
            except BaseException as error:
                errors.append('Resume: ' + repr(error))
        if caller and caller.poll() is None:
            try:
                caller.wait(timeout=45)
            except subprocess.TimeoutExpired:
                errors.append('Exact CLI remains live; no overlapping cleanup issued')
        if f and (not caller or caller.poll() is not None):
            try:
                f.close()
                wait(lambda: all(p.exited() for p in owned))
                assert not (f.home / 'endpoint.json').exists()
                assert not Native().writer_present(f.home / 'runtime.lock')
                report['public_cleanup_and_native_exits_witnessed'] = True
            except BaseException as error:
                errors.append('Public/native closure: ' + repr(error))
        report['remaining'] = [p.initial for p in owned if not p.exited()]
        if errors:
            report['cleanup_failures'] = errors
        report['qualified'] = bool(report.get('behavior_witnessed') and
                                   report.get('public_cleanup_and_native_exits_witnessed') and
                                   not report['remaining'] and not errors and not report.get('failure'))
        for process in owned:
            process.close()
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'se', 'peer', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expect', choices=('refused', 'recovered'), required=True)
    args = parser.parse_args()
    assert os.name == 'nt', 'Native Windows is required'
    args.se, args.peer = args.se.resolve(strict=True), args.peer.resolve(strict=True)
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(args.source / 'crates/se/tests/judges'))
    from mail_cli import Fixture as PublicFixture
    from windows_startup_native import Native, PausedParent
    from windows_process import Process

    class Fixture(PublicFixture):
        def call(self, *arguments, **options):
            for key in list(self.env):
                if key.startswith(('SECODE_', 'OPENAI_', 'ANTHROPIC_', 'GH_', 'GITHUB_')):
                    self.env.pop(key)
            for key in ('APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
                        'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'CODEX_HOME'):
                private = self.root / key.lower()
                private.mkdir(exist_ok=True)
                self.env[key] = str(private)
            return super().call(*arguments, **options)

    reports = []
    for label, held in [('crash-window-1', False), ('crash-window-2', False), ('held-owner', True)]:
        reports.append(trial(args, label, held, Fixture, Native, PausedParent, Process))
        (args.out / 'summary.json').write_text(json.dumps(reports, indent=2) + '\n')
        if reports[-1].get('remaining') or reports[-1].get('cleanup_failures'):
            break
    return 0 if len(reports) == 3 and all(r['qualified'] for r in reports) else 1


if __name__ == '__main__':
    raise SystemExit(main())
