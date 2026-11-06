#!/usr/bin/env python3
"""Protects: G1/G6 — explicit and automatic Windows hosts publish fresh local pipe names and authenticate them.

Native Windows: python -I windows_ipc_rotation_independent.py --se IMAGE --out NEW_DIRECTORY
Stage this file beside tests/judges. Synthetic provider, no paid account.
"""
import argparse
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent / 'judges'))
from mail_cli import Fixture


def wait_for(check, description):
    end = time.monotonic() + 25
    while time.monotonic() < end:
        if value := check():
            return value
        time.sleep(.05)
    raise TimeoutError(description)


class Pin:
    def __init__(self, pid):
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        for name, arguments, result in [
            ('OpenProcess', [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            ('GetProcessTimes', [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4, w.BOOL),
            ('QueryFullProcessImageNameW', [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)], w.BOOL),
            ('WaitForSingleObject', [w.HANDLE, w.DWORD], w.DWORD),
            ('CloseHandle', [w.HANDLE], w.BOOL),
        ]:
            getattr(self.kernel, name).argtypes, getattr(self.kernel, name).restype = arguments, result
        self.handle = self.kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        times = [w.FILETIME() for _ in range(4)]
        image, size = ctypes.create_unicode_buffer(32768), w.DWORD(32768)
        if (not self.kernel.GetProcessTimes(self.handle, *(ctypes.byref(t) for t in times))
                or not self.kernel.QueryFullProcessImageNameW(self.handle, 0, image, ctypes.byref(size))):
            raise ctypes.WinError(ctypes.get_last_error())
        self.record = {'pid': pid, 'birth': times[0].dwLowDateTime | times[0].dwHighDateTime << 32,
                       'image': image.value}
        if self.exited():
            raise AssertionError('native instance already exited at its precondition')

    def exited(self):
        result = self.kernel.WaitForSingleObject(self.handle, 0)
        if result not in (0, 258):
            raise ctypes.WinError(ctypes.get_last_error())
        return result == 0

    def close(self):
        if not self.kernel.CloseHandle(self.handle):
            raise ctypes.WinError(ctypes.get_last_error())


def endpoint(fixture):
    record = json.loads((fixture.home / 'endpoint.json').read_text())
    name = record['address']['name']
    prefix = r'\\.\pipe\stateengine-'
    tail = name.removeprefix(prefix)
    if not name.startswith(prefix) or len(tail) != 64 or any(c not in '0123456789abcdef' for c in tail):
        raise AssertionError('endpoint does not advertise a single local 256-bit pipe name')
    return record


def run(args):
    root = Path(tempfile.mkdtemp(prefix='se-windows-ipc-rotation-'))
    image = root / 'se.exe'
    shutil.copy2(args.se, image)
    report = {'binary_sha256': hashlib.sha256(image.read_bytes()).hexdigest(), 'fixture': str(root),
              'failures': [], 'cleanup_errors': [], 'names': [], 'stage': 'setup'}
    fixtures, pins = [], []
    try:
        for label in ('first', 'second'):
            fixture = Fixture(image, root / label)
            fixtures.append(fixture)
            (fixture.repo / 'user.txt').write_bytes(b'Preserve independent Windows work.\r\n')
            report['stage'] = 'explicit startup: ' + label
            fixture.ok('up')
            record = endpoint(fixture)
            report['names'].append(record['address']['name'])
            pin = Pin(record['epoch']['owner']['pid'])
            pins.append(pin)
            repeated = fixture.ok('up')
            if repeated['process']['pid'] != pin.record['pid'] or pin.exited():
                raise AssertionError('protected-name discovery did not authenticate the existing host')
        if len(set(report['names'])) != 2:
            raise AssertionError('two simultaneous homes collided on one pipe')
        second = endpoint(fixtures[1])
        first = fixtures[0]
        report['stage'] = 'close first exact host before automatic launch'
        first.ok('down')
        wait_for(pins[0].exited, 'first explicit host survived public down')
        if (first.home / 'endpoint.json').exists():
            raise AssertionError('down retained the original rendezvous record')
        report['stage'] = 'automatic provider/hook startup discovers a fresh name'
        first.launch()
        record = endpoint(first)
        pins.append(Pin(record['epoch']['owner']['pid']))
        ready = json.loads((first.repo / 'provider-ready.json').read_text())
        pins.extend(Pin(ready[key]) for key in ('native_root_pid', 'helper_pid'))
        if record['address']['name'] in report['names']:
            raise AssertionError('automatic startup reused a prior per-home or other-home pipe')
        report['names'].append(record['address']['name'])
        if first.ok('up')['process']['pid'] != pins[2].record['pid']:
            raise AssertionError('explicit discovery could not authenticate the automatically started host')
        report['stage'] = 'stop provider and close automatic host'
        first.ok('--project', first.project, 'stop', first.agent)
        first.ok('down')
        wait_for(lambda: all(pin.exited() for pin in pins[2:]), 'automatic host/provider/helper survived public cleanup')
        report['stage'] = 'a third explicit start rotates the protected name again'
        first.ok('up')
        record = endpoint(first)
        pins.append(Pin(record['epoch']['owner']['pid']))
        if record['address']['name'] in report['names']:
            raise AssertionError('explicit restart reused a prior pipe name')
        report['names'].append(record['address']['name'])
        if endpoint(fixtures[1]) != second or pins[1].exited():
            raise AssertionError('first-home restart changed the unrelated second host')
        if fixtures[1].ok('up')['process']['pid'] != pins[1].record['pid']:
            raise AssertionError('unrelated home no longer authenticates its exact host')
    except Exception as error:
        report['failures'].append(type(error).__name__ + ': ' + str(error))
        report['traceback'] = traceback.format_exc()
    finally:
        for fixture in fixtures:
            try:
                if (fixture.home / 'endpoint.json').exists():
                    result = fixture.ok('down')
                    if not result['complete'] or result['witness']['state'] != 'witnessed':
                        raise AssertionError('public down did not witness complete cleanup')
                if (fixture.home / 'endpoint.json').exists():
                    raise AssertionError('protected endpoint remains after cleanup')
                if (fixture.repo / 'user.txt').read_bytes() != b'Preserve independent Windows work.\r\n':
                    raise AssertionError('user file changed')
            except Exception as error:
                report['cleanup_errors'].append(str(error))
        try:
            wait_for(lambda: all(pin.exited() for pin in pins), 'known native instances remain after cleanup')
        except Exception as error:
            report['cleanup_errors'].append(str(error))
        report['known_instances'] = [pin.record for pin in pins]
        for pin in pins:
            pin.close()
    report['passed'] = int(not report['failures'] and not report['cleanup_errors'])
    report['failed'] = 1 - report['passed']
    report['bounds'] = 'Real Windows host/provider and public CLI/hook discovery; synthetic provider; no paid-provider or entropy-quality claim.'
    (args.out / 'results.json').write_text(json.dumps(report, indent=2))
    print(f"Windows pipe rotation: {report['passed']} passed, {report['failed']} failed", flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('native Windows required')
    args.se = args.se.resolve(strict=True)
    args.out.mkdir()
    sys.exit(run(args))
