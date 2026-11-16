"""Windows process accounting at cohort barriers, outside timed MCP requests.

The parent is the owning Rust observer/host, registered children are its owned
MCP bridges, and self is this Python driver. No process census or polling runs
during requests. Peak working sets cover each process's lifetime, not a phase.
"""
import ctypes
from ctypes import wintypes
import os
import threading
import time


class Memory(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in (
            "peak_working_set", "working_set", "peak_paged", "paged",
            "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile")]


def ticks(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


def process_snapshot(pid):
    if os.name != "nt":
        raise RuntimeError("native resource observer requires Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [
        ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        created, exited, system, user = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                      ctypes.byref(system), ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        memory = Memory()
        memory.cb = ctypes.sizeof(memory)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"pid": pid, "created_100ns": ticks(created),
                "cpu_100ns": ticks(system) + ticks(user),
                "working_set_bytes": memory.working_set,
                "lifetime_peak_working_set_bytes": memory.peak_working_set}
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


class CohortMetrics:
    def __init__(self, count):
        self.count = count
        self.pids = {"host": os.getppid(), "python": os.getpid()}
        self.lock = threading.Lock()
        self.snapshots = []
        self.error = None

    def register(self, pid):
        with self.lock:
            if pid in self.pids.values():
                raise ValueError("resource observer repeated a process")
            self.pids[f"bridge-{len(self.pids) - 2}"] = pid

    def boundary(self):
        try:
            if len(self.pids) != self.count + 2:
                raise ValueError("not all bridges registered before phase boundary")
            started = time.perf_counter_ns()
            processes = {name: process_snapshot(pid) for name, pid in self.pids.items()}
            finished = time.perf_counter_ns()
            self.snapshots.append({"started_ns": started, "finished_ns": finished,
                                   "processes": processes})
        except Exception as error:
            self.error = repr(error)
            raise

    def report(self):
        result = {"qualified": self.error is None and len(self.snapshots) == 4,
                  "snapshots": self.snapshots, "phases": {}, "error": self.error,
                  "scope": "host Rust process, Python observer and owned MCP bridges only; no provider processes",
                  "memory_scope": "boundary working sets and process-lifetime peaks; no timed polling"}
        if not result["qualified"]:
            return result
        for index, operation in enumerate(("stateengine_msg_send", "stateengine_working_state_set")):
            before, after = self.snapshots[index * 2:index * 2 + 2]
            wall_ms = (after["started_ns"] - before["finished_ns"]) / 1e6
            cpu = {}
            for name, left in before["processes"].items():
                right = after["processes"][name]
                if left["created_100ns"] != right["created_100ns"]:
                    raise ValueError("process identity changed across a phase")
                cpu[name] = (right["cpu_100ns"] - left["cpu_100ns"]) / 10_000
                if cpu[name] < 0:
                    raise ValueError("process CPU counter decreased")
            result["phases"][operation] = {
                "wall_ms": wall_ms, "cpu_ms_by_process": cpu,
                "cpu_ms_total": sum(cpu.values()), "writes": self.count * 30,
                "writes_per_second": self.count * 30 * 1000 / wall_ms,
                "cpu_ms_per_write": sum(cpu.values()) / (self.count * 30),
                "ending_working_set_bytes": sum(p["working_set_bytes"] for p in after["processes"].values()),
                "sum_lifetime_peak_working_set_bytes": sum(
                    p["lifetime_peak_working_set_bytes"] for p in after["processes"].values()),
            }
        return result
