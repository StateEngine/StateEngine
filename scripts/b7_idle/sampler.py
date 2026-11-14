"""Outside-process CPU and wakeup counters for the B7 idle measurement.

Definitions (repeated in every receipt):
  cpu_percent_one_core
      100 * (user + system CPU seconds consumed by the process's threads)
      divided by wall seconds. One core busy the whole window is 100.
  wakeups_per_second, Linux
      delta of voluntary_ctxt_switches summed over every thread of the
      process, divided by wall seconds: the rate at which the process's
      threads wake out of waits (timer, futex, poll).
  wakeups_per_second, macOS
      delta of ri_pkg_idle_wkups_expired from libproc rusage, divided by
      wall seconds: package-idle wakeups attributable to the process's
      threads. A best-effort DTrace sched_switch count for the pid is
      reported as a cross-check when sudo dtrace is available.

The sampler runs as a separate process and only reads the OS accounting of
the observed pid; it never talks to the host.
"""
import ctypes
import json
import os
import signal
import statistics
import subprocess
import time


def _read_linux_snapshot(pid):
    ticks = 0
    voluntary = 0
    nonvoluntary = 0
    threads = 0
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            with open(f"/proc/{pid}/task/{tid}/stat") as stream:
                body = stream.read()
        except (FileNotFoundError, ProcessLookupError):
            continue
        fields = body[body.rfind(")") + 2:].split()
        if len(fields) < 41:
            continue
        ticks += int(fields[11]) + int(fields[12])
        voluntary += int(fields[39])
        nonvoluntary += int(fields[40])
        threads += 1
    if threads == 0:
        raise ProcessLookupError(f"process {pid} disappeared during sampling")
    return {"ticks": ticks, "voluntary": voluntary,
            "nonvoluntary": nonvoluntary, "threads": threads}


class _RusageInfoV3(ctypes.Structure):
    _fields_ = [
        ("ri_user_time", ctypes.c_double),
        ("ri_system_time", ctypes.c_double),
        ("ri_pkg_idle_wkups_expired", ctypes.c_uint64),
        ("ri_cpu_clamped_time", ctypes.c_uint64),
        ("ri_init_time", ctypes.c_uint64),
        ("ri_expected_idle", ctypes.c_uint64),
        ("ri_num_threads", ctypes.c_uint32),
        ("ri_total_num_threads", ctypes.c_uint32),
        ("ri_unicore_system_time", ctypes.c_uint64),
    ]


def _make_mac_reader():
    libproc = ctypes.CDLL("libproc.dylib", use_errno=True)
    libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int]
    libproc.proc_pid_rusage.restype = ctypes.c_int

    def read(pid):
        info = _RusageInfoV3()
        if libproc.proc_pid_rusage(pid, 3, ctypes.byref(info)) != ctypes.sizeof(info):
            errno = ctypes.get_errno()
            if errno == 3:  # ESRCH
                raise ProcessLookupError(f"process {pid} disappeared during sampling")
            raise OSError(f"proc_pid_rusage refused: errno {errno}")
        return {"cpu_seconds": info.ri_user_time + info.ri_system_time,
                "wkups": info.ri_pkg_idle_wkups_expired,
                "threads": info.ri_num_threads}

    return read


class Sampler:
    def __init__(self, pid):
        self.pid = pid
        self.platform = "linux" if os.path.exists("/proc") else "macos"
        if self.platform == "linux":
            self.hz = os.sysconf("SC_CLK_TCK")
            self._read = _read_linux_snapshot
        else:
            self._read = _make_mac_reader()

    def snapshot(self):
        return {"t": time.time(), "raw": self._read(self.pid)}

    def report(self, samples):
        first, last = samples[0], samples[-1]
        wall = last["t"] - first["t"]
        if wall <= 0:
            raise ValueError("measurement window is zero")
        if self.platform == "linux":
            cpu = 100.0 * (last["raw"]["ticks"] - first["raw"]["ticks"]) / self.hz / wall
            wake = (last["raw"]["voluntary"] - first["raw"]["voluntary"]) / wall
            nonvol = (last["raw"]["nonvoluntary"] - first["raw"]["nonvoluntary"]) / wall
        else:
            cpu = 100.0 * (last["raw"]["cpu_seconds"] - first["raw"]["cpu_seconds"]) / wall
            wake = (last["raw"]["wkups"] - first["raw"]["wkups"]) / wall
            nonvol = None
        per_second = []
        if self.platform == "linux":
            for prev, cur in zip(samples, samples[1:]):
                dt = cur["t"] - prev["t"]
                if dt > 0:
                    per_second.append(
                        (cur["raw"]["voluntary"] - prev["raw"]["voluntary"]) / dt)
        return {
            "pid": self.pid,
            "platform": self.platform,
            "wall_seconds": round(wall, 3),
            "samples": len(samples),
            "cpu_percent_one_core": round(cpu, 6),
            "wakeups_per_second": round(wake, 6),
            "nonvoluntary_ctxt_switches_per_second": (
                round(nonvol, 6) if nonvol is not None else None),
            "wakeup_rate_min_per_second": round(min(per_second), 6) if per_second else None,
            "wakeup_rate_median_per_second": (
                round(statistics.median(per_second), 6) if per_second else None),
            "wakeup_rate_max_per_second": round(max(per_second), 6) if per_second else None,
            "threads_at_end": last["raw"]["threads"],
            "definition": {
                "cpu_percent_one_core": "100 * delta(user+system CPU seconds) / wall seconds",
                "wakeups_per_second": (
                    "delta voluntary_ctxt_switches over all threads / wall seconds"
                    if self.platform == "linux"
                    else "delta ri_pkg_idle_wkups_expired (libproc rusage) / wall seconds"),
            },
        }


def dtrace_cross_check(pid, duration_s):
    """Best-effort macOS sched_switch count for the pid; None when unavailable."""
    if os.path.exists("/proc") or not os.path.exists("/usr/sbin/dtrace"):
        return None
    try:
        probe = f"sched:sched_switch /pid == {pid}/ {{ @ = count() }}"
        child = subprocess.Popen(
            ["sudo", "-n", "/usr/sbin/dtrace", "-q", "-n", probe],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(duration_s)
        child.send_signal(signal.SIGINT)
        out, _ = child.communicate(timeout=20)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                return int(parts[1])
        return None
    except (OSError, subprocess.TimeoutExpired):
        if child.poll() is None:
            child.kill()
        return None


def sample_window(pid, duration_s, interval_s=1.0):
    sampler = Sampler(pid)
    samples = [sampler.snapshot()]
    deadline = time.time() + duration_s
    while time.time() < deadline - interval_s:
        time.sleep(interval_s)
        samples.append(sampler.snapshot())
    time.sleep(max(0.0, deadline - time.time()))
    samples.append(sampler.snapshot())
    report = sampler.report(samples)
    if not os.path.exists("/proc"):
        report["dtrace_sched_switch_cross_check"] = dtrace_cross_check(
            pid, min(10.0, duration_s))
    return report
