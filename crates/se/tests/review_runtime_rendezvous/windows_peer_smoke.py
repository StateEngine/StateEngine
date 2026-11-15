"""Exercise the native pipe observer on a real fresh server and client."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def server(name):
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateNamedPipeW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD,
                                  W.DWORD, W.DWORD, C.c_void_p]
    k.CreateNamedPipeW.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    handle = k.CreateNamedPipeW(name, 3 | 0x40000000, 0, 1, 4096, 4096, 0, None)
    assert handle not in (None, C.c_void_p(-1).value), C.WinError(C.get_last_error())
    print(json.dumps({'pid': os.getpid(), 'ready': True}), flush=True)
    try:
        assert sys.stdin.readline().strip() == 'close'
    finally:
        assert k.CloseHandle(handle)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--peer', type=Path)
    p.add_argument('--out', type=Path)
    p.add_argument('--server')
    a = p.parse_args()
    assert os.name == 'nt'
    if a.server:
        server(a.server)
        return
    assert a.peer and a.out
    from windows_process import Process
    name = '\\\\.\\pipe\\review-peer-' + uuid.uuid4().hex
    child = subprocess.Popen([sys.executable, '-B', __file__, '--server', name],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True)
    process, handle = None, None
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD,
                             W.DWORD, W.HANDLE]
    k.CreateFileW.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    result = {'passed': False}
    try:
        ready = json.loads(child.stdout.readline())
        assert ready['pid'] == child.pid and ready['ready']
        process = Process(child.pid, Path(sys.executable), str(Path(__file__).resolve()))
        command = [str(a.peer.resolve()), str(child.pid), str(os.getpid()),
                   str(process.initial['creation_filetime']), process.initial['image'],
                   '\\Device\\NamedPipe\\' + name[len('\\\\.\\pipe\\'):]]
        absent = subprocess.run(command, capture_output=True, timeout=10)
        result['before_connection'] = json.loads(absent.stdout)
        assert absent.returncode == 1 and result['before_connection']['matches'] == 0
        handle = k.CreateFileW(name, 0xC0000000, 0, None, 3, 0x40000000, None)
        assert handle not in (None, C.c_void_p(-1).value), C.WinError(C.get_last_error())
        connected = subprocess.run(command, capture_output=True, timeout=10)
        result['connected'] = json.loads(connected.stdout)
        assert connected.returncode == 0 and result['connected']['matches'] == 1
        wrong_birth = list(command)
        wrong_birth[3] = str(process.initial['creation_filetime'] + 1)
        wrong = subprocess.run(wrong_birth, capture_output=True, timeout=10)
        assert wrong.returncode == 2
        result['wrong_birth_refused'] = True
        result['passed'] = True
    finally:
        if handle not in (None, C.c_void_p(-1).value):
            assert k.CloseHandle(handle)
        child.communicate('close\n', timeout=10)
        result['server_exit'] = child.returncode
        if process:
            result['native_exit'] = process.exited()
            process.close()
        a.out.write_text(json.dumps(result, indent=2) + '\n')
    assert result['passed'] and result['server_exit'] == 0 and result['native_exit']


if __name__ == '__main__':
    main()
