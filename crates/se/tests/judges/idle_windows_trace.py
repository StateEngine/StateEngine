"""Measure host switch-ins with a loss-checked Windows scheduler trace."""
from collections import Counter
import csv
import os
from pathlib import Path
import re
import subprocess
import time


def _run(arguments, timeout):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"trace command failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout


def measure(pid, root):
    kits = Path(os.environ.get("ProgramFiles(x86)", ""))
    xperf = kits / "Windows Kits/10/Windows Performance Toolkit/xperf.exe"
    if not xperf.is_file():
        raise RuntimeError("Windows Performance Toolkit is unavailable")
    trace = root / "switches.etl"
    dump_path = root / "switches.txt"
    _run([str(xperf), "-on", "PROC_THREAD+CSWITCH"], 30)
    try:
        time.sleep(62)
    finally:
        _run([str(xperf), "-d", str(trace)], 60)
    report = _run([str(xperf), "-i", str(trace), "-a", "cswitch", "-process"], 60)
    pattern = re.compile(r"\(\s*" + str(pid) + r"\s*\)$")
    seen_process = any(pattern.search(line.strip()) for line in report.splitlines())
    _run([str(xperf), "-i", str(trace), "-o", str(dump_path), "-a", "dumper"], 180)
    lost = reliable = trace_length = None
    incoming = 0
    wait_reasons = Counter()
    with dump_path.open(encoding="latin-1", newline="") as rows:
        for line in rows:
            if line.startswith("OS Version:"):
                metadata = re.search(
                    r"Events Lost: (\d+), Buffers lost: (\d+).*Trace Length: (\d+) sec", line
                )
                if metadata:
                    lost = int(metadata[1]) + int(metadata[2])
                    trace_length = int(metadata[3])
            parts = next(csv.reader([line]))
            if (len(parts) >= 3 and parts[0].strip() in ("P-Start", "P-DCStart", "T-Start", "T-DCStart")
                    and pattern.search(parts[2].strip())):
                seen_process = True
            if len(parts) == 2 and parts[0].strip() == "FirstReliableCSwitchEventTimeStamp":
                value = parts[1].strip()
                if value.isdigit():
                    reliable = int(value)
            if len(parts) < 14 or parts[0].strip() != "CSwitch":
                continue
            stamp = parts[1].strip()
            if not stamp.isdigit() or not 1_000_000 <= int(stamp) < 61_000_000:
                continue
            if pattern.search(parts[2].strip()):
                incoming += 1
            if pattern.search(parts[8].strip()):
                wait_reasons[parts[13].strip()] += 1
    if not seen_process:
        raise RuntimeError("the host is absent from the scheduler trace")
    if lost != 0 or reliable is None or reliable > 1_000_000 or trace_length is None or trace_length < 61:
        raise RuntimeError(f"incomplete scheduler trace: lost={lost}, reliable={reliable}, length={trace_length}")
    return {
        "switch_ins": incoming,
        "seconds": 60,
        "switches_per_second": incoming / 60,
        "wait_reasons": dict(wait_reasons),
        "method": "scheduler switch-ins with tracing enabled, including preemptions; a proxy for wakeups",
    }
