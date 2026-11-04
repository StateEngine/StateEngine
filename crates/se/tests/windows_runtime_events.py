#!/usr/bin/env python3
"""Protects: G6 — real Windows console close/Ctrl-Break drain a foreground host.

Run on native Windows with Python 3 and rustc on PATH:
  python windows_runtime_events.py --se C:\\owned\\se.exe --out C:\\owned\\new-results
Uses the existing recorded Claude fixture; no provider account is required.
The host has a real separate console; managed root/helper have no console.
"""
import argparse
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def api():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    declarations = {
        'OpenProcess': ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        'CloseHandle': ([w.HANDLE], w.BOOL),
        'GetProcessTimes': ([w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4, w.BOOL),
        'QueryFullProcessImageNameW': ([w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)], w.BOOL),
        'WaitForSingleObject': ([w.HANDLE, w.DWORD], w.DWORD),
        'GetConsoleWindow': ([], w.HWND),
        'GetConsoleProcessList': ([ctypes.POINTER(w.DWORD), w.DWORD], w.DWORD),
        'AttachConsole': ([w.DWORD], w.BOOL),
        'FreeConsole': ([], w.BOOL),
        'GenerateConsoleCtrlEvent': ([w.DWORD, w.DWORD], w.BOOL),
        'CreateFileW': ([w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
    }
    for name, (arguments, result) in declarations.items():
        getattr(kernel, name).argtypes, getattr(kernel, name).restype = arguments, result
    return kernel


def require(value, operation):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error(), operation)
    return value


def wait_for(check, description, seconds=25):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if value := check():
            return value
        time.sleep(.05)
    raise TimeoutError(description)


class Pin:
    def __init__(self, kernel, pid):
        self.kernel = kernel
        self.handle = require(kernel.OpenProcess(0x1000 | 0x100000, False, pid), 'pin exact process')
        times = [w.FILETIME() for _ in range(4)]
        require(kernel.GetProcessTimes(self.handle, *(ctypes.byref(t) for t in times)), 'process birth')
        image, size = ctypes.create_unicode_buffer(32768), w.DWORD(32768)
        require(kernel.QueryFullProcessImageNameW(self.handle, 0, image, ctypes.byref(size)), 'process image')
        self.record = {'pid': pid, 'birth': times[0].dwLowDateTime | (times[0].dwHighDateTime << 32),
                       'image': image.value}
        if self.exited():
            raise AssertionError('native process precondition already exited')

    def exited(self):
        value = self.kernel.WaitForSingleObject(self.handle, 0)
        if value not in (0, 258):
            raise ctypes.WinError(ctypes.get_last_error(), 'process exit observation')
        return value == 0

    def close(self):
        require(self.kernel.CloseHandle(self.handle), 'close owned observer handle')


def worker(args):
    """Protects: console stimulus reaches the actual host with real terminal input."""
    import msvcrt
    kernel = api()
    callback_type = ctypes.WINFUNCTYPE(w.BOOL, w.DWORD)
    callback = callback_type(lambda event: True)
    kernel.SetConsoleCtrlHandler.argtypes = [callback_type, w.BOOL]
    kernel.SetConsoleCtrlHandler.restype = w.BOOL
    require(kernel.SetConsoleCtrlHandler(callback, True), 'worker console handler')
    console = kernel.CreateFileW('CONIN$', 0x80000000, 3, None, 3, 0, None)
    if console == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error(), 'real console input')
    with os.fdopen(msvcrt.open_osfhandle(console, os.O_RDONLY), 'rb', buffering=0) as input_stream:
        with args.out.joinpath('foreground.log').open('wb') as log:
            child = subprocess.Popen([str(args.se), '--home', str(args.home), 'up', '--foreground', '--json'],
                                     stdin=input_stream, stdout=log, stderr=log)
            args.out.joinpath('worker-ready.json').write_text(json.dumps({
                'host_pid': child.pid, 'worker_pid': os.getpid(),
                'console_window': int(require(kernel.GetConsoleWindow(), 'native console window'))}))
            return child.wait()


def stimulus(kernel, ready, pins, selected):
    kernel.FreeConsole()  # Detach only this observer; never another process.
    require(kernel.AttachConsole(ready['worker_pid']), 'attach exact owned console')
    try:
        entries = (w.DWORD * 64)()
        count = kernel.GetConsoleProcessList(entries, len(entries))
        if not count or count > len(entries):
            raise AssertionError('console membership observation incomplete')
        members = list(entries[:count])
        if ready['host_pid'] not in members:
            raise AssertionError('foreground host is not attached to the stimulus console')
        if any(pin.record['pid'] in members for pin in pins[1:]):
            raise AssertionError('managed fixture children would receive the console event directly')
        if selected == 'break':
            callback_type = ctypes.WINFUNCTYPE(w.BOOL, w.DWORD)
            callback = callback_type(lambda event: True)
            kernel.SetConsoleCtrlHandler.argtypes = [callback_type, w.BOOL]
            kernel.SetConsoleCtrlHandler.restype = w.BOOL
            require(kernel.SetConsoleCtrlHandler(callback, True), 'observer console handler')
            require(kernel.GenerateConsoleCtrlEvent(1, 0), 'real CTRL_BREAK_EVENT')
    finally:
        require(kernel.FreeConsole(), 'detach owned console observer')
    if selected == 'close':
        user = ctypes.WinDLL('user32', use_last_error=True)
        user.PostMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
        user.PostMessageW.restype = w.BOOL
        require(user.PostMessageW(ready['console_window'], 0x10, 0, 0), 'close actual console window')
    return members


def run_case(args, kernel, root, selected):
    from mail_cli import Fixture
    import msvcrt
    fixture = Fixture(args.se, root / selected)
    # Retain the existing provider protocol, but detach its real native root
    # and helper from the host console before reporting readiness.
    source = fixture.root / 'provider.rs'
    source.write_text('''use std::os::windows::process::CommandExt;
#[link(name="kernel32")] unsafe extern "system" { fn FreeConsole()->i32; }
fn main(){let a:Vec<String>=std::env::args().collect();
if a.get(1).map(String::as_str)==Some("--version"){println!("2.1.287 (Claude Code)");return;}
unsafe{FreeConsole();}
let s=std::process::Command::new(PYTHON).creation_flags(0x08000000)
.args([HELPER,SE,HOME]).args(&a[1..]).status().unwrap();
std::process::exit(s.code().unwrap_or(1));}'''
        .replace('PYTHON', json.dumps(sys.executable))
        .replace('HELPER,SE,HOME', ','.join(json.dumps(str(p)) for p in [
            Path(__file__).parent / 'judges/mail_provider.py', fixture.se, fixture.home])))
    subprocess.run(['rustc', '--edition=2024', str(source), '-o', str(fixture.root / 'provider.exe')],
                   capture_output=True, check=True, timeout=60)
    user_file = fixture.repo / 'user.txt'
    user_file.write_bytes(b'Keep Windows user work.\r\n')
    pins, failures, cleanup, members = [], [], [], []
    launcher = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--worker',
        '--se', str(fixture.se), '--home', str(fixture.home), '--out', str(fixture.root)],
        cwd=fixture.repo, env=fixture.env, creationflags=subprocess.CREATE_NEW_CONSOLE)
    try:
        ready_path = fixture.root / 'worker-ready.json'
        wait_for(ready_path.exists, 'console worker readiness')
        ready = json.loads(ready_path.read_text())
        wait_for((fixture.home / 'endpoint.json').exists, 'foreground endpoint readiness')
        endpoint = json.loads((fixture.home / 'endpoint.json').read_text())
        if endpoint['epoch']['owner']['pid'] != ready['host_pid']:
            raise AssertionError('foreground launch detached to another native process')
        pins.append(Pin(kernel, ready['host_pid']))
        fixture.launch()
        provider = json.loads((fixture.repo / 'provider-ready.json').read_text())
        pins.extend(Pin(kernel, provider[key]) for key in ('native_root_pid', 'helper_pid'))
        members = stimulus(kernel, ready, pins, selected)
        try:
            wait_for(lambda: all(pin.exited() for pin in pins), 'host or managed root/helper survived event', 15)
        except TimeoutError as error:
            failures.append(str(error))
        if (fixture.home / 'endpoint.json').exists():
            failures.append('termination retained the protected endpoint')
        try:
            with (fixture.home / 'runtime.lock').open('r+b') as lease:
                msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
                msvcrt.locking(lease.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError as error:
            failures.append('runtime lease unavailable: ' + str(error))
    except Exception as error:
        failures.append(type(error).__name__ + ': ' + str(error))
    finally:
        fixture.se = args.cleanup_se
        try:
            if (fixture.home / 'endpoint.json').exists() or any(not pin.exited() for pin in pins):
                fixture.ok('up')
                if fixture.session:
                    fixture.ok('--project', fixture.project, 'stop', fixture.agent)
                fixture.ok('down')
            wait_for(lambda: all(pin.exited() for pin in pins), 'owned instances remain after public cleanup')
            launcher.wait(timeout=10)
            if (fixture.home / 'endpoint.json').exists():
                cleanup.append('endpoint retained after public cleanup')
            if user_file.read_bytes() != b'Keep Windows user work.\r\n':
                cleanup.append('user work changed')
        except Exception as error:
            cleanup.append(type(error).__name__ + ': ' + str(error))
        records = [pin.record for pin in pins]
        for pin in pins:
            pin.close()
    return {'case': selected, 'passed': not failures and not cleanup, 'failures': failures,
            'cleanup_errors': cleanup, 'known_instances': records, 'console_members': members,
            'fixture': str(fixture.root)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--cleanup-se', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--home', type=Path)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('native Windows required')
    if args.worker:
        return worker(args)
    sys.path.insert(0, str(Path(__file__).parent / 'judges'))
    args.se = args.se.resolve(strict=True)
    args.cleanup_se = (args.cleanup_se or args.se).resolve(strict=True)
    args.out.mkdir(mode=0o700)
    root = Path(tempfile.mkdtemp(prefix='5d-console-events-'))
    image = root / 'se.exe'
    shutil.copy2(args.se, image)
    digest = hashlib.sha256(args.se.read_bytes()).hexdigest()
    args.se = image
    rows = []
    for selected in ('break', 'close'):
        row = run_case(args, api(), root, selected)
        rows.append(row)
        print(('PASS: ' if row['passed'] else 'FAIL: ') + selected, flush=True)
        report = {'binary_sha256': digest, 'cases': rows,
                  'passed': sum(row['passed'] for row in rows),
                  'failed': sum(not row['passed'] for row in rows),
                  'bounds': 'Native Windows console events and managed processes; synthetic provider, no paid account.'}
        (args.out / 'results.json').write_text(json.dumps(report, indent=2))
    print(f"Windows console events: {report['passed']} passed, {report['failed']} failed", flush=True)
    return 1 if report['failed'] else 0


if __name__ == '__main__':
    sys.exit(main())
