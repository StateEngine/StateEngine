"""Observe an exact process and pause a read of an owned test file."""

from contextlib import contextmanager
import ctypes as c
from ctypes import wintypes as w


class Overlapped(c.Structure):
    _fields_ = [("internal", c.c_size_t), ("internal_high", c.c_size_t),
                ("offset", w.DWORD), ("offset_high", w.DWORD), ("event", w.HANDLE)]


kernel = c.WinDLL("kernel32", use_last_error=True)


def bind(name, result, *args):
    function = getattr(kernel, name)
    function.restype = result
    function.argtypes = args
    return function


open_process = bind("OpenProcess", w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
close = bind("CloseHandle", w.BOOL, w.HANDLE)
wait = bind("WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)
times = bind("GetProcessTimes", w.BOOL, w.HANDLE, *[c.POINTER(w.FILETIME)] * 4)
event = bind("CreateEventW", w.HANDLE, w.LPVOID, w.BOOL, w.BOOL, w.LPCWSTR)
open_file = bind("CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID,
                 w.DWORD, w.DWORD, w.HANDLE)
device_control = bind("DeviceIoControl", w.BOOL, w.HANDLE, w.DWORD, w.LPVOID, w.DWORD,
                      w.LPVOID, w.DWORD, w.LPVOID, c.POINTER(Overlapped))


def ready(handle, milliseconds=0):
    status = wait(handle, milliseconds)
    if status not in (0, 258):  # WAIT_OBJECT_0 and WAIT_TIMEOUT
        raise c.WinError(c.get_last_error())
    return status == 0


@contextmanager
def own(handle):
    if handle in (None, c.c_void_p(-1).value):
        raise c.WinError(c.get_last_error())
    try:
        yield handle
    finally:
        if not close(handle):
            raise c.WinError(c.get_last_error())


@contextmanager
def process_identity(pid):
    with own(open_process(0x101000, False, pid)) as handle:  # query + synchronize
        timestamps = [w.FILETIME() for _ in range(4)]
        if not times(handle, *(c.byref(value) for value in timestamps)):
            raise c.WinError(c.get_last_error())
        created = (timestamps[0].dwHighDateTime << 32) | timestamps[0].dwLowDateTime
        yield handle, {"pid": pid, "creation_filetime": created}


@contextmanager
def pause_source_read(path):
    # The level-one oplock event is signalled when a competing open starts.
    # Closing our handle acknowledges the notification and releases that open.
    with own(event(None, True, False, None)) as signal:
        with own(open_file(str(path), 0x80000000, 7, None, 3, 0x40000000, None)) as file:
            request = Overlapped(event=signal)
            issued = device_control(file, 0x90000, None, 0, None, 0, None, c.byref(request))
            if issued or c.get_last_error() != 997:  # ERROR_IO_PENDING grants the lock
                raise RuntimeError(f"could not arm the fixture transcript oplock ({c.get_last_error()})")
            yield signal
