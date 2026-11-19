"""Read native Windows counters from the host process and runner."""
import ctypes as c
from ctypes import wintypes as w
import json
import sys


class ProcessMemory(c.Structure):
    _fields_ = [
        ("size", w.DWORD),
        ("faults", w.DWORD),
        ("peak_working_set", c.c_size_t),
        ("working_set", c.c_size_t),
        ("quota_peak_paged", c.c_size_t),
        ("quota_paged", c.c_size_t),
        ("quota_peak_nonpaged", c.c_size_t),
        ("quota_nonpaged", c.c_size_t),
        ("pagefile_usage", c.c_size_t),
        ("peak_commit", c.c_size_t),
        ("private_commit", c.c_size_t),
    ]


class GlobalMemory(c.Structure):
    _fields_ = [
        ("size", w.DWORD),
        ("load", w.DWORD),
        ("physical", c.c_uint64),
        ("physical_available", c.c_uint64),
        ("page_file", c.c_uint64),
        ("page_file_available", c.c_uint64),
        ("virtual", c.c_uint64),
        ("virtual_available", c.c_uint64),
        ("extended_virtual_available", c.c_uint64),
    ]


class CounterApi:
    def __init__(self):
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.kernel.OpenProcess.restype = w.HANDLE
        self.kernel.K32GetProcessMemoryInfo.argtypes = [
            w.HANDLE, c.POINTER(ProcessMemory), w.DWORD
        ]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.GetSystemTimes.argtypes = [c.POINTER(w.FILETIME)] * 3
        self.kernel.GlobalMemoryStatusEx.argtypes = [c.POINTER(GlobalMemory)]

    @staticmethod
    def check(success):
        if not success:
            raise c.WinError(c.get_last_error())

    def process(self, pid):
        handle = self.kernel.OpenProcess(0x1000, False, pid)
        self.check(handle)
        try:
            info = ProcessMemory()
            info.size = c.sizeof(info)
            self.check(self.kernel.K32GetProcessMemoryInfo(handle, c.byref(info), info.size))
            return {
                "private_commit": info.private_commit,
                "peak_commit": info.peak_commit,
                "working_set": info.working_set,
                "peak_working_set": info.peak_working_set,
                "page_faults": info.faults,
            }
        finally:
            self.check(self.kernel.CloseHandle(handle))

    def system(self):
        idle, kernel, user = (w.FILETIME() for _ in range(3))
        self.check(self.kernel.GetSystemTimes(c.byref(idle), c.byref(kernel), c.byref(user)))
        info = GlobalMemory()
        info.size = c.sizeof(info)
        self.check(self.kernel.GlobalMemoryStatusEx(c.byref(info)))

        def ticks(filetime):
            return filetime.dwLowDateTime + (filetime.dwHighDateTime << 32)

        return {
            "idle_ticks_100ns": ticks(idle),
            "kernel_ticks_100ns_includes_idle": ticks(kernel),
            "user_ticks_100ns": ticks(user),
            "physical_bytes": info.physical,
            "physical_available_bytes": info.physical_available,
            "physical_memory_load_percent": info.load,
        }


api = CounterApi()
mode, pid = sys.argv[1:]
if mode == "memory":
    print(json.dumps(api.process(int(pid))))
elif mode == "load":
    print(json.dumps(api.system()))
else:
    raise ValueError(mode)
