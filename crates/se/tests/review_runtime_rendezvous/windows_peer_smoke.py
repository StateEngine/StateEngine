"""Exercise the caller-side native witness with real named-pipe peers."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid


def native():
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateNamedPipeW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD,
                                  W.DWORD, W.DWORD, C.c_void_p]
    k.CreateNamedPipeW.restype = W.HANDLE
    k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD,
                             W.DWORD, W.HANDLE]
    k.CreateFileW.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    return k


def valid(handle):
    assert handle not in (None, C.c_void_p(-1).value), C.WinError(C.get_last_error())
    return handle


def wait(predicate, seconds=10):
    until = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < until, 'Native fixture condition was not reached'
        time.sleep(.01)


def server(name):
    k = native()
    handle = valid(k.CreateNamedPipeW(name, 3 | 0x40000000, 0, 1, 4096, 4096, 0, None))
    print(json.dumps({'pid': os.getpid(), 'ready': True}), flush=True)
    try:
        assert sys.stdin.readline().strip() == 'close'
    finally:
        assert k.CloseHandle(handle)


def client(name, root):
    root = Path(root)
    k, handle = native(), None
    (root / 'client-started').write_text(str(os.getpid()))
    try:
        wait(lambda: (root / 'connect').exists() or (root / 'release').exists())
        if (root / 'release').exists():
            return
        handle = valid(k.CreateFileW(name, 0xC0000000, 0, None, 3, 0x40000000, None))
        (root / 'connected').write_text('ready')
        wait(lambda: (root / 'release').exists(), 25)
    finally:
        if handle:
            assert k.CloseHandle(handle)


def exercise(peer, root, result):
    from windows_process import Process
    name = '\\\\.\\pipe\\review-peer-' + uuid.uuid4().hex
    server_child = subprocess.Popen([sys.executable, '-B', __file__, '--server', name],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
    client_child = server_pin = client_pin = None
    try:
        ready = json.loads(server_child.stdout.readline())
        assert ready['pid'] == server_child.pid and ready['ready']
        server_pin = Process(server_child.pid, Path(sys.executable), str(Path(__file__).resolve()))
        # The observed caller has no inherited pipe streams, matching the CLI.
        with (root / 'client.stdout').open('wb') as out, (root / 'client.stderr').open('wb') as err:
            client_child = subprocess.Popen([sys.executable, '-B', __file__, '--client', name,
                                              '--private', str(root)], stdin=subprocess.DEVNULL,
                                             stdout=out, stderr=err)
        wait(lambda: (root / 'client-started').exists())
        client_pin = Process(client_child.pid, Path(sys.executable), str(root))
        command = [str(peer.resolve()), str(client_child.pid), str(server_child.pid),
                   str(client_pin.initial['creation_filetime']), client_pin.initial['image']]
        absent = subprocess.run(command, capture_output=True, timeout=10)
        result['before_connection'] = json.loads(absent.stdout)
        assert absent.returncode == 1 and result['before_connection']['matches'] == 0
        (root / 'connect').write_text('connect')
        wait(lambda: (root / 'connected').exists())
        connected = subprocess.run(command, capture_output=True, timeout=10)
        result['connected'] = json.loads(connected.stdout)
        assert connected.returncode == 0 and result['connected']['matches'] == 1
        wrong_birth = list(command)
        wrong_birth[3] = str(client_pin.initial['creation_filetime'] + 1)
        assert subprocess.run(wrong_birth, capture_output=True, timeout=10).returncode == 2
        wrong_server = list(command)
        wrong_server[2] = '0'
        assert subprocess.run(wrong_server, capture_output=True, timeout=10).returncode == 1
        result.update(wrong_birth_refused=True, wrong_server_not_matched=True, passed=True)
    finally:
        (root / 'release').write_text('close')
        if client_child:
            client_child.wait(timeout=10)
            result['client_exit'] = client_child.returncode
        server_child.communicate('close\n', timeout=10)
        result['server_exit'] = server_child.returncode
        for label, process in [('client', client_pin), ('server', server_pin)]:
            if process:
                result[label + '_native_exit'] = process.exited()
                process.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--peer', type=Path)
    p.add_argument('--out', type=Path)
    p.add_argument('--server')
    p.add_argument('--client')
    p.add_argument('--private')
    a = p.parse_args()
    assert os.name == 'nt'
    if a.server:
        server(a.server)
        return
    if a.client:
        client(a.client, a.private)
        return
    assert a.peer and a.out
    result = {'passed': False}
    try:
        with tempfile.TemporaryDirectory(prefix='pipe-peer-') as name:
            exercise(a.peer, Path(name), result)
    finally:
        a.out.write_text(json.dumps(result, indent=2) + '\n')
    assert result['passed'] and result['server_exit'] == result['client_exit'] == 0
    assert result['server_native_exit'] and result['client_native_exit']


if __name__ == '__main__':
    main()
