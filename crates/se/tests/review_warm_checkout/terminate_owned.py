"""Emergency closure requires the exact owned process and observed full command."""
import os
from pathlib import Path
import signal


def terminate(child, expected):
    if os.name == 'nt':
        import ctypes as C
        from ctypes import wintypes as W
        from native_process import Process, k
        process = Process(child.pid, Path(expected[0]))
        shell = C.WinDLL('shell32', use_last_error=True)
        shell.CommandLineToArgvW.argtypes = [W.LPCWSTR, C.POINTER(C.c_int)]
        shell.CommandLineToArgvW.restype = C.POINTER(W.LPWSTR)
        k.LocalFree.argtypes, k.LocalFree.restype = [W.HANDLE], W.HANDLE
        k.TerminateProcess.argtypes, k.TerminateProcess.restype = [W.HANDLE, W.UINT], W.BOOL
        count = C.c_int()
        values = shell.CommandLineToArgvW(process.initial['command'], C.byref(count))
        assert values
        try:
            observed = [values[i] for i in range(count.value)]
        finally:
            k.LocalFree(C.cast(values, W.HANDLE))
        try:
            assert Path(observed[0]).samefile(expected[0]) and observed[1:] == expected[1:]
            # This exact still-unreaped Popen cannot be reused. Observe its
            # retained birth and full command before terminating its own handle.
            assert process.observe() == process.initial
            assert k.TerminateProcess(process.handle, 137)
        finally:
            process.close()
    else:
        fd = os.pidfd_open(child.pid)
        try:
            observed = Path(f'/proc/{child.pid}/cmdline').read_bytes().split(b'\0')[:-1]
            assert Path(os.fsdecode(observed[0])).samefile(expected[0])
            assert observed[1:] == [os.fsencode(x) for x in expected[1:]]
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        finally:
            os.close(fd)
