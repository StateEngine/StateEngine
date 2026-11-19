"""Observe the actual release owner consumer from outside its process."""
import ctypes as c
from ctypes import wintypes as w
import glob
import json
import os
from pathlib import Path
import subprocess
import sys
import time

class ProcessMemory(c.Structure):
    _fields_ = [("size", w.DWORD), ("faults", w.DWORD),
                ("peak_working_set", c.c_size_t), ("working_set", c.c_size_t),
                ("quota_peak_paged", c.c_size_t), ("quota_paged", c.c_size_t),
                ("quota_peak_nonpaged", c.c_size_t), ("quota_nonpaged", c.c_size_t),
                ("pagefile_usage", c.c_size_t), ("peak_commit", c.c_size_t),
                ("private_commit", c.c_size_t)]

root = Path(sys.argv[1]).resolve()
target = root / "target" / "judge-diagnostics"
target.mkdir(parents=True, exist_ok=True)
pattern = "atlas_startup_dev-*.exe" if os.name == "nt" else "atlas_startup_dev-*"
executables = [path for path in glob.glob(str(root / "target" / "release" / "deps" / pattern))
               if Path(path).is_file() and os.access(path, os.X_OK)]
if len(executables) != 1:
    raise RuntimeError(f"expected exactly one test executable, found {len(executables)}")
env = os.environ.copy()
env["ATLAS_FULL_REPOSITORY"] = str(root)
if os.name == "nt":
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.K32GetProcessMemoryInfo.argtypes = [w.HANDLE, c.POINTER(ProcessMemory), w.DWORD]
    kernel.CloseHandle.argtypes = [w.HANDLE]
log = target / "atlas-full-owner.log"
with log.open("wb") as out:
    child = subprocess.Popen([executables[0], "--exact", "automatic_owner_indexes_and_catches_committed_records_up", "--nocapture"], env=env, stdout=out, stderr=subprocess.STDOUT)
    handle = kernel.OpenProcess(0x1000, False, child.pid) if os.name == "nt" else None
    if os.name == "nt" and not handle:
        raise c.WinError(c.get_last_error())
    peak_private = 0
    peak_commit = 0
    post_baseline_peak_private = 0
    peak_at_baseline = None
    observations = 0
    try:
        while True:
            if os.name == "nt":
                info = ProcessMemory()
                info.size = c.sizeof(info)
                measured = (info.private_commit, info.peak_commit) if kernel.K32GetProcessMemoryInfo(handle, c.byref(info), info.size) else None
            else:
                try:
                    virtual = int(Path(f"/proc/{child.pid}/statm").read_text().split()[0]) * os.sysconf("SC_PAGE_SIZE")
                    fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in Path(f"/proc/{child.pid}/status").read_text().splitlines() if ":" in line}
                    peak = int(fields["VmPeak"].split()[0]) * 1024
                    measured = (virtual, peak)
                except (FileNotFoundError, ProcessLookupError, KeyError, ValueError):
                    measured = None
            if measured is not None:
                current, native_peak = measured
                peak_private = max(peak_private, current)
                peak_commit = max(peak_commit, native_peak)
                observations += 1
                if peak_at_baseline is None and b"ATLAS_BENCH_BASELINE " in log.read_bytes():
                    peak_at_baseline = native_peak
                if peak_at_baseline is not None:
                    post_baseline_peak_private = max(post_baseline_peak_private, current)
            if child.poll() is not None:
                break
            time.sleep(0.01)
        status = child.wait()
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)
text = log.read_text(encoding="utf-8", errors="replace")
print(text, flush=True)
lines = [line[line.index("ATLAS_BENCH_"):] for line in text.splitlines() if "ATLAS_BENCH_" in line]
def item(prefix):
    values = [line.split() for line in lines if line.startswith(prefix + " ")]
    if len(values) != 1:
        raise RuntimeError(f"missing or repeated {prefix} observation")
    return values[0]
baseline = int(item("ATLAS_BENCH_BASELINE")[1])
first_index_ms = int(item("ATLAS_BENCH_FIRST_INDEX_MS")[1])
history_count = int(item("ATLAS_BENCH_HISTORY")[1])
indexed_files = int(item("ATLAS_BENCH_INDEXED_FILES")[1])
queries = [line.split() for line in lines if line.startswith("ATLAS_BENCH_QUERY ")]
if status != 0 or observations == 0 or peak_at_baseline is None or len(queries) != 4 or history_count < 2:
    raise RuntimeError(f"owner benchmark incomplete: exit={status}, observations={observations}, queries={len(queries)}, history={history_count}")
report = {
    "basis": "release automatic-owner consumer process, sampled externally; includes test harness and query client, excludes child processes",
    "baseline_private_commit_bytes": baseline,
    "peak_private_commit_sampled_bytes": peak_private,
    "peak_private_commit_sampled_after_baseline_bytes": post_baseline_peak_private,
    "sampled_peak_minus_baseline_bytes": post_baseline_peak_private - baseline,
    "native_peak_at_baseline_bytes": peak_at_baseline,
    "peak_commit_native_bytes": peak_commit,
    "native_peak_minus_baseline_bytes": peak_commit - baseline,
    "native_peak_not_above_first_post_baseline_sample": peak_commit == peak_at_baseline,
    "documented_reservation_sum_bytes": 16100000,
    "first_index_ms": first_index_ms,
    "history_commits": history_count,
    "indexed_files": indexed_files,
    "query_response_bytes": {parts[1]: int(parts[2]) for parts in queries},
    "query_result_counts": {parts[1]: int(parts[3]) for parts in queries},
    "max_query_limit": 50,
    "max_query_byte_budget": 32768,
    "observations": observations,
}
if os.name != "nt":
    report = {
        "basis": "release automatic-owner consumer virtual address space, sampled externally; includes test harness and query client, excludes child processes",
        "baseline_virtual_bytes": baseline,
        "peak_virtual_sampled_bytes": peak_private,
        "peak_virtual_sampled_after_baseline_bytes": post_baseline_peak_private,
        "sampled_peak_minus_baseline_bytes": post_baseline_peak_private - baseline,
        "native_peak_at_baseline_bytes": peak_at_baseline,
        "native_peak_virtual_bytes": peak_commit,
        "native_peak_minus_baseline_bytes": peak_commit - baseline,
        "first_index_ms": first_index_ms,
        "history_commits": history_count,
        "indexed_files": indexed_files,
        "query_response_bytes": {parts[1]: int(parts[2]) for parts in queries},
        "query_result_counts": {parts[1]: int(parts[3]) for parts in queries},
        "observations": observations,
    }
(target / "atlas-full-owner.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2), flush=True)
