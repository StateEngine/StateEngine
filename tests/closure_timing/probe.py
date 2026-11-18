"""Exercise exact spawner ownership, reclaim and automatic cleanup on native Windows."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'support'))
from harness_matrix.io import spawner_argument
from judge_records import write_json
from mail_cli import Fixture
from windows_journeys.credentials import protect

SOURCE = 'be88441c63dce7dda3ac912e7e50d1eb9760ab59'
BUNDLE_FILES = {
    'README.txt', 'probe.py', 'se.exe', 'LICENSE', 'NOTICE.txt', 'notices.tar', 'provenance/build.json',
    'provenance/native-payload.json', 'provenance/payload-pin.json',
    'support/mail_cli.py', 'support/mail_provider.py', 'support/judge_records.py',
    'support/harness_matrix/__init__.py', 'support/harness_matrix/io.py',
    'support/windows_journeys/__init__.py', 'support/windows_journeys/credentials.py',
}


def check(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_bundle():
    manifest = json.loads((ROOT / 'bundle.json').read_bytes())
    check(manifest['source_commit'] == SOURCE and manifest['target'] == 'x86_64-pc-windows-msvc'
          and manifest['build_run_id'] == '44248850199' and set(manifest['files']) == BUNDLE_FILES,
          'Bundle source, build, target or inventory differs')
    for name, expected in manifest['files'].items():
        path = ROOT / name
        check(path.is_file() and not path.is_symlink() and digest(path) == expected,
              'Bundle bytes differ from the pin for ' + name)
    return manifest


def copy_single_link(image, destination, expected):
    destination.parent.mkdir()
    shutil.copy2(image, destination)
    check(destination.stat().st_nlink == 1 and digest(destination) == expected,
          'Runtime copy did not preserve the pinned binary as a single-link file')
    return destination


def native_handles():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [
        wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def borrow_process(kernel, pid):
    synchronize_and_query = 0x00100000 | 0x1000
    handle = kernel.OpenProcess(synchronize_and_query, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        check(kernel.WaitForSingleObject(handle, 0) == 258,
              'An owned native process was not live before expiry')
        stamps = (wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME())
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(stamp) for stamp in stamps)):
            raise ctypes.WinError(ctypes.get_last_error())
        birth = (stamps[0].dwHighDateTime << 32) | stamps[0].dwLowDateTime
        check(birth > 0, 'Native creation time is unavailable')
        return handle, birth
    except BaseException:
        kernel.CloseHandle(handle)
        raise


def owner(se, home, repository):
    run = subprocess.run([se, '--home', home, '--json', 'up', *spawner_argument()],
                         cwd=repository, stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    print(json.dumps(dict(exit=run.returncode, stdout=json.loads(run.stdout) if run.returncode == 0
                          else run.stdout.decode('utf-8', errors='replace'),
                          stderr=run.stderr.decode('utf-8', errors='replace'))), flush=True)
    sys.stdin.buffer.read()


def start_spawner(binary, fixture):
    args = [sys.executable, '-B', str(Path(__file__).resolve()), '--owner',
            str(binary), str(fixture.home), str(fixture.repo)]
    child = subprocess.Popen(args, env=fixture.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        with child.stdout:
            line = child.stdout.readline(1024**2 + 1)
        check(0 < len(line) <= 1024**2, 'Spawner transferred no bounded readiness reply')
        result = json.loads(line)
        check(result['exit'] == 0,
              'Spawner start refused: ' + str(result['stdout']) + result['stderr'])
        return child, result['stdout']
    except BaseException:
        stop_spawner(child)
        raise


def stop_spawner(child):
    child.stdin.close()
    check(child.wait(timeout=100) == 0, 'Exact spawner did not exit cleanly')


def wait_for(probe, seconds, reason):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(.5)
    raise RuntimeError(reason)


def run(out, receipt, manifest):
    binary = copy_single_link(ROOT / 'se.exe', out / 'image' / 'se.exe', manifest['files']['se.exe'])
    for key, name in (('APPDATA', 'Roaming'), ('LOCALAPPDATA', 'Local')):
        directory = out / 'profile' / 'AppData' / name
        directory.mkdir(parents=True)
        os.environ[key] = str(directory)
    fixture = Fixture(binary, out / 'fixture')
    kernel = native_handles()
    endpoint = fixture.home / 'endpoint.json'
    report = fixture.home / 'runtime-spawner-close.json'
    spawner, handles = None, {}
    try:
        receipt['stage'] = 'start'
        spawner, first = start_spawner(binary, fixture)
        host = first['process']['pid']
        view = fixture.ok('status')['runtime']['spawner']
        check(view['pid'] == spawner.pid and view['state'] == 'watching', 'Initial binding is missing')
        refused = fixture.call('up', *spawner_argument())
        check(refused.returncode != 0 and b'reclaim window' in refused.stderr, 'A live spawner was displaced')
        fixture.launch()
        provider = json.loads((fixture.repo / 'provider-ready.json').read_text(encoding='utf-8'))
        pids = {host, provider['native_root_pid'], provider['helper_pid']}
        check(len(pids) == 3, 'The three expected native process roles did not have distinct PIDs')
        for pid in pids:
            handles[pid] = borrow_process(kernel, pid)
        receipt['initial'] = dict(spawner_pid=spawner.pid, host_pid=host, session=fixture.session)
        receipt['stage'] = 'reclaim'
        stop_spawner(spawner)
        spawner = None
        wait_for(lambda: fixture.ok('status')['runtime']['spawner']['state'] == 'reclaim-window',
                 25, 'Original spawner exit was not witnessed')
        spawner, second = start_spawner(binary, fixture)
        view = fixture.ok('status')['runtime']['spawner']
        check(second['process']['pid'] == host and view['pid'] == spawner.pid and view['state'] == 'watching',
              'Reclaim changed the host or failed to renew the binding')
        receipt['reclaim'] = dict(state='witnessed', spawner_pid=spawner.pid, host_pid=host)
        receipt['stage'] = 'expiry'
        stop_spawner(spawner)
        spawner = None
        started = time.monotonic()
        write_json(out / 'receipt.json', receipt)
        wait_for(lambda: report.is_file() and not endpoint.exists(), 690, 'Expiry never retired the endpoint')
        for handle, _ in handles.values():
            check(kernel.WaitForSingleObject(handle, 20000) == 0, 'An original native process remained live')
        elapsed = time.monotonic() - started
        check(590 <= elapsed <= 710, 'Closure fell outside the production grace window')
        closed = json.loads(report.read_bytes())
        stops = [row for row in closed['stops'] if row['session'] == fixture.session]
        check(closed['resources_closed'] and not closed['pending'] and len(stops) == 1
              and stops[0]['witness'] is not None and stops[0]['reason'] is None,
              'The native cleanup record did not witness the provider exit')
        visible = fixture.ok('status')['runtime']['spawner_cleanup']
        check(visible['complete'] and any(row['session'] == fixture.session and row['stopped']
              for row in visible['sessions']), 'Owner status did not report the stopped session')
        refused = fixture.call('up', *spawner_argument())
        reply = refused.stdout + refused.stderr
        check(refused.returncode != 0 and fixture.session.encode() in reply and b'--home' in reply
              and b'without --spawner' in reply and not endpoint.exists(), 'Saved-home refusal is incomplete')
        receipt['expiry'] = dict(state='witnessed', elapsed_seconds=round(elapsed, 1),
                                 report_sha256=digest(report), session=fixture.session,
                                 processes=[dict(pid=pid, birth=str(birth), state='exited')
                                            for pid, (_, birth) in sorted(handles.items())],
                                 owner_status_reported=True, saved_home_refused=True)
    finally:
        cleanup_errors = []
        for operation in ((lambda: fixture.close() if endpoint.exists() else None),
                          (lambda: stop_spawner(spawner) if spawner is not None else None)):
            try:
                operation()
            except Exception as error:
                cleanup_errors.append(str(error))
        for handle, _ in handles.values():
            if not kernel.CloseHandle(handle):
                cleanup_errors.append('A process observation handle did not close')
        receipt['cleanup_errors'] = cleanup_errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New private output directory')
    args = parser.parse_args()
    check(os.name == 'nt', 'Native Windows is required')
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() != 'PSMODULEPATH' and not key.upper().startswith(
                       ('STATEENGINE_', 'SE_', 'CODEX_', 'CLAUDE', 'ANTHROPIC_', 'OPENAI_', 'CI_ANTHROPIC_', 'CI_OPENAI_'))}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    os.environ.clear()
    os.environ.update(environment)
    out = args.output.resolve()
    out.mkdir(mode=0o700)
    receipt = dict(schema='se.spawner-native-probe/v1', source_commit=SOURCE,
                   result='FAIL', stage='protect-output')
    try:
        protect(out)
        receipt['stage'] = 'verify-bundle'
        manifest = load_bundle()
        receipt.update(build_run_id=manifest['build_run_id'], binary_sha256=manifest['files']['se.exe'])
        receipt['stage'] = 'fixture'
        run(out, receipt, manifest)
        check(not receipt.get('cleanup_errors'), 'Fixture cleanup is incomplete')
        receipt.update(stage='finished', result='PASS')
    except BaseException as error:
        receipt['failure'] = str(error) or type(error).__name__
    finally:
        write_json(out / 'receipt.json', receipt)
        print(json.dumps(receipt), flush=True)
    return 0 if receipt['result'] == 'PASS' else 1


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--owner':
        owner(*sys.argv[2:])
    else:
        raise SystemExit(main())
