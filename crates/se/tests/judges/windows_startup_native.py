"""Native observations for the competing-client startup regression."""
import ctypes
from ctypes import wintypes as w
import json
import os
import time


class Overlapped(ctypes.Structure):
    _fields_ = [("internal", ctypes.c_size_t), ("high", ctypes.c_size_t),
                ("offset", w.DWORD), ("offset_high", w.DWORD), ("event", w.HANDLE)]


class ThreadEntry(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("tid", w.DWORD),
                ("owner", w.DWORD), ("priority", w.LONG), ("delta", w.LONG),
                ("flags", w.DWORD)]


class Native:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("REFUSE: native Windows is required")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD,
                             w.DWORD, w.HANDLE], w.HANDLE),
            "LockFileEx": ([w.HANDLE, w.DWORD, w.DWORD, w.DWORD, w.DWORD,
                            ctypes.POINTER(Overlapped)], w.BOOL),
            "UnlockFileEx": ([w.HANDLE, w.DWORD, w.DWORD, w.DWORD,
                              ctypes.POINTER(Overlapped)], w.BOOL),
            "CreateToolhelp32Snapshot": ([w.DWORD, w.DWORD], w.HANDLE),
            "Thread32First": ([w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            "Thread32Next": ([w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            "OpenThread": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "GetProcessIdOfThread": ([w.HANDLE], w.DWORD),
            "SuspendThread": ([w.HANDLE], w.DWORD),
            "ResumeThread": ([w.HANDLE], w.DWORD),
            "GetNamedPipeServerProcessId": ([w.HANDLE, ctypes.POINTER(w.ULONG)], w.BOOL),
            "GetFileSizeEx": ([w.HANDLE, ctypes.POINTER(ctypes.c_longlong)], w.BOOL),
            "ReadFile": ([w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD),
                          w.LPVOID], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.k, name)
            function.argtypes, function.restype = arguments, result

    def checked_handle(self, handle):
        if handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def close(self, handle):
        if not self.k.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def file(self, path, access):
        return self.checked_handle(self.k.CreateFileW(str(path), access, 7, None, 3, 0, None))

    def writer_present(self, path):
        handle = self.file(path, 0xC0000000)
        operation = Overlapped()
        try:
            if self.k.LockFileEx(handle, 1, 0, 1, 0, ctypes.byref(operation)):
                if not self.k.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(operation)):
                    raise ctypes.WinError(ctypes.get_last_error())
                return False
            error = ctypes.get_last_error()
            if error != 33:
                raise ctypes.WinError(error)
            return True
        finally:
            self.close(handle)

    def endpoint(self, path, deadline):
        while True:
            try:
                handle = self.file(path, 0x80000000)
                try:
                    length = ctypes.c_longlong()
                    if not self.k.GetFileSizeEx(handle, ctypes.byref(length)):
                        raise ctypes.WinError(ctypes.get_last_error())
                    if not 0 < length.value <= 32768:
                        raise RuntimeError("REFUSE: endpoint length is outside its native bound")
                    data, count = ctypes.create_string_buffer(length.value), w.DWORD()
                    if not self.k.ReadFile(handle, data, length.value, ctypes.byref(count), None):
                        raise ctypes.WinError(ctypes.get_last_error())
                    if count.value != length.value:
                        raise RuntimeError("REFUSE: endpoint read was incomplete")
                    return json.loads(data.raw.decode("utf-8"))
                finally:
                    self.close(handle)
            except OSError as error:
                if error.winerror not in (2, 32, 33) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.001)

    def connect(self, endpoint):
        address = endpoint["address"]
        name = address["name"]
        if address["kind"] != "windows_pipe" or not name.startswith("\\\\.\\pipe\\"):
            raise RuntimeError("REFUSE: expected a local Windows pipe")
        # Identification SQOS is set before connecting; no credential is sent.
        handle = self.checked_handle(self.k.CreateFileW(
            name, 0xC0020000, 0, None, 3, 0x40110000, None))
        try:
            pid = w.ULONG()
            if not self.k.GetNamedPipeServerProcessId(handle, ctypes.byref(pid)):
                raise ctypes.WinError(ctypes.get_last_error())
            if pid.value != endpoint["epoch"]["owner"]["pid"]:
                raise RuntimeError("REFUSE: competing connection reached a different server")
            return handle
        except BaseException:
            self.close(handle)
            raise

    def threads(self, pid):
        snapshot = self.checked_handle(self.k.CreateToolhelp32Snapshot(4, 0))
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            ok = self.k.Thread32First(snapshot, ctypes.byref(entry))
            result = set()
            while ok:
                if entry.owner == pid:
                    result.add(entry.tid)
                entry.size = ctypes.sizeof(entry)
                ok = self.k.Thread32Next(snapshot, ctypes.byref(entry))
            if ctypes.get_last_error() != 18:
                raise ctypes.WinError(ctypes.get_last_error())
            return result
        finally:
            self.close(snapshot)


class PausedParent:
    def __init__(self, native, child):
        self.native, self.handles = native, {}
        until = time.monotonic() + 1
        try:
            while True:
                if child.poll() is not None:
                    raise RuntimeError("REFUSE: owned startup parent already exited")
                threads = native.threads(child.pid)
                if threads and threads <= self.handles.keys():
                    break
                if not threads or len(threads) > 512 or time.monotonic() >= until:
                    raise RuntimeError("REFUSE: could not freeze the complete owned parent")
                for tid in threads - self.handles.keys():
                    handle = native.checked_handle(native.k.OpenThread(0x802, False, tid))
                    if native.k.GetProcessIdOfThread(handle) != child.pid:
                        native.close(handle)
                        raise RuntimeError("REFUSE: thread no longer belongs to the owned child")
                    if native.k.SuspendThread(handle) == 0xFFFFFFFF:
                        error = ctypes.WinError(ctypes.get_last_error())
                        native.close(handle)
                        raise error
                    self.handles[tid] = handle
        except BaseException:
            self.resume()
            raise

    def resume(self):
        failures = []
        for handle in self.handles.values():
            if self.native.k.ResumeThread(handle) == 0xFFFFFFFF:
                failures.append(ctypes.get_last_error())
            try:
                self.native.close(handle)
            except OSError as error:
                failures.append(str(error))
        self.handles.clear()
        if failures:
            raise RuntimeError(f"REFUSE: owned thread resume was incomplete: {failures}")
