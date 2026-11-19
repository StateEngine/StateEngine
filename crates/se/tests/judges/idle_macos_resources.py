"""Read the host's process-wide scheduler switch counter on macOS."""
import ctypes


class ProcTaskInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "virtual_size", "resident_size", "total_user", "total_system",
        "threads_user", "threads_system",
    )] + [(name, ctypes.c_int32) for name in (
        "policy", "faults", "pageins", "cow_faults", "messages_sent",
        "messages_received", "syscalls_mach", "syscalls_unix", "csw",
        "threadnum", "numrunning", "priority",
    )]


def context_switches(pid):
    lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    call = lib.proc_pidinfo
    call.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                     ctypes.c_void_p, ctypes.c_int]
    call.restype = ctypes.c_int
    info = ProcTaskInfo()
    size = ctypes.sizeof(info)
    received = call(pid, 4, 0, ctypes.byref(info), size)  # PROC_PIDTASKINFO
    if received != size:
        raise OSError(ctypes.get_errno(), f"proc_pidinfo returned {received}, expected {size}")
    if info.csw < 0:
        raise RuntimeError("the host context-switch counter is negative")
    return info.csw
