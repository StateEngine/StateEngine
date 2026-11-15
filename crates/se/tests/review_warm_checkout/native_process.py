"""Retained native births and command lines for reviewer-owned processes."""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path

k = C.WinDLL('kernel32', use_last_error=True)
nt = C.WinDLL('ntdll')
for name, arguments, result in [
    ('OpenProcess', [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
    ('CloseHandle', [W.HANDLE], W.BOOL),
    ('GetProcessTimes', [W.HANDLE, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p], W.BOOL),
    ('QueryFullProcessImageNameW', [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)], W.BOOL),
    ('WaitForSingleObject', [W.HANDLE, W.DWORD], W.DWORD),
]:
    function = getattr(k, name)
    function.argtypes, function.restype = arguments, result
nt.NtQueryInformationProcess.argtypes = [W.HANDLE, W.ULONG, C.c_void_p, W.ULONG, C.c_void_p]
nt.NtQueryInformationProcess.restype = C.c_long


def require(ok):
    if not ok:
        raise C.WinError(C.get_last_error())


class UnicodeString(C.Structure):
    _fields_ = [('length', W.USHORT), ('maximum', W.USHORT), ('buffer', C.c_void_p)]


class Process:
    def __init__(self, pid, image, command_contains=None):
        self.pid, self.handle = int(pid), None
        self.handle = k.OpenProcess(0x1000 | 0x100000 | 1, False, self.pid)
        require(self.handle)
        try:
            self.initial = self.observe()
            assert not self.initial['exited'], 'Owned process exited before it could be pinned'
            assert Path(self.initial['image']).samefile(image), self.initial
            if command_contains:
                assert command_contains.casefold() in self.initial['command'].casefold(), self.initial
        except BaseException:
            self.close()
            raise

    def exited(self):
        code = k.WaitForSingleObject(self.handle, 0)
        assert code in (0, 258), f'Native wait failed: {code}'
        return code == 0

    def poll(self):
        return 0 if self.exited() else None

    def observe(self):
        created, exited, kernel, user = (C.c_ulonglong() for _ in range(4))
        require(k.GetProcessTimes(self.handle, C.byref(created), C.byref(exited),
                                 C.byref(kernel), C.byref(user)))
        image, count = C.create_unicode_buffer(32768), W.DWORD(32768)
        require(k.QueryFullProcessImageNameW(self.handle, 0, image, C.byref(count)))
        buffer = C.create_string_buffer(65536)
        status = nt.NtQueryInformationProcess(self.handle, 60, buffer, len(buffer), None)
        if status < 0:
            raise RuntimeError(f'Native command line query failed: {status:#x}')
        value = UnicodeString.from_buffer(buffer)
        start, end = C.addressof(buffer), C.addressof(buffer) + len(buffer)
        assert value.length % 2 == 0 and start <= value.buffer <= end
        assert value.buffer + value.length <= end
        return {'pid': self.pid, 'creation_filetime': created.value,
                'image': image.value, 'command': C.wstring_at(value.buffer, value.length // 2),
                'exited': self.exited()}

    def close(self):
        if self.handle:
            require(k.CloseHandle(self.handle))
            self.handle = None
