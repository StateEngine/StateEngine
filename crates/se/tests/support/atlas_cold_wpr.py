"""Record a bounded native cold-worker trace in the hosted diagnostic run."""
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time


def start(owner, log, target):
    def record():
        report = {"owner_pid": owner.pid, "status": "not_started"}
        trace = target / "atlas-full-owner.etl"
        report_path = target / "atlas-full-owner.wpr.json"
        wpr = str(Path(os.environ["SystemRoot"]) / "System32" / "wpr.exe")
        xperf = Path(os.environ["ProgramFiles(x86)"]) / "Windows Kits/10/Windows Performance Toolkit/xperf.exe"
        recording = False

        def run(args, timeout=60):
            return subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout)

        def worker():
            script = (f"$p=Get-CimInstance Win32_Process -Filter 'ParentProcessId={owner.pid}' | "
                      "Where-Object { $_.CommandLine -like '*--stateengine-private-atlas-cold*' }; "
                      "$p | Select-Object ProcessId,CreationDate,CommandLine | ConvertTo-Json -Compress")
            result = run(["powershell.exe", "-NoProfile", "-Command", script])
            if result.returncode != 0 or not result.stdout.strip():
                raise RuntimeError(f"cold worker lookup failed: {result.stderr}")
            value = json.loads(result.stdout)
            if isinstance(value, list):
                if len(value) != 1:
                    raise RuntimeError(f"expected one cold worker, found {len(value)}")
                value = value[0]
            return value

        try:
            if not xperf.is_file():
                raise RuntimeError("Windows Performance Toolkit xperf unavailable")
            until = time.monotonic() + 100
            while time.monotonic() < until and owner.poll() is None:
                progress = re.findall(r"ATLAS_PROGRESS elapsed_s=(\d+)", log.read_text(encoding="utf-8", errors="replace"))
                if progress and int(progress[-1]) >= 30:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("cold indexing did not reach the 30 second trace start")
            before = worker()
            report["worker_before"] = before
            started = run([wpr, "-start", "CPU", "-start", "FileIO", "-start", "DiskIO", "-filemode"])
            report["start"] = {"returncode": started.returncode, "stdout": started.stdout, "stderr": started.stderr}
            if started.returncode:
                raise RuntimeError("WPR did not start")
            recording = True
            status = run([wpr, "-status", "collectors"])
            report["collectors_start"] = {"returncode": status.returncode, "stdout": status.stdout, "stderr": status.stderr}
            begin = time.monotonic()
            while time.monotonic() - begin < 60:
                if owner.poll() is not None:
                    raise RuntimeError("owner exited during trace")
                time.sleep(min(0.5, 60 - (time.monotonic() - begin)))
            after = worker()
            report["worker_after"] = after
            if before.get("ProcessId") != after.get("ProcessId") or before.get("CreationDate") != after.get("CreationDate"):
                raise RuntimeError("cold worker changed during trace")
            status = run([wpr, "-status", "collectors"])
            report["collectors_end"] = {"returncode": status.returncode, "stdout": status.stdout, "stderr": status.stderr}
            stopped = run([wpr, "-stop", str(trace)], timeout=180)
            recording = False
            report["stop"] = {"returncode": stopped.returncode, "stdout": stopped.stdout, "stderr": stopped.stderr}
            if stopped.returncode or not trace.is_file():
                raise RuntimeError("WPR trace was not saved")
            report["trace_bytes"] = trace.stat().st_size
            for action, args in [("tracestats", []), ("profile", ["-detail"]), ("fileio", ["-summary"])]:
                result = run([str(xperf), "-i", str(trace), "-a", action, *args], timeout=180)
                (target / f"atlas-full-owner.{action}.txt").write_text(result.stdout + "\n" + result.stderr, encoding="utf-8")
                report[action] = {"returncode": result.returncode}
            dump = target / "wpr-event-dump.txt"
            result = run([str(xperf), "-i", str(trace), "-o", str(dump), "-a", "dumper"], timeout=300)
            report["dump_returncode"] = result.returncode
            if result.returncode or not dump.is_file():
                raise RuntimeError("xperf event dump failed")
            with dump.open(encoding="utf-8", errors="replace") as rows:
                metadata = next((line.strip() for line in rows if line.startswith("OS Version:")), "")
            report["trace_metadata"] = metadata
            match = re.search(r"Events Lost: (\d+), Buffers lost: (\d+).*Trace Length: (\d+) sec", metadata)
            if not match:
                raise RuntimeError("trace loss metadata unavailable")
            report["events_lost"], report["buffers_lost"], report["duration_seconds"] = map(int, match.groups())
            if report["events_lost"] or report["buffers_lost"] or report["duration_seconds"] < 60:
                raise RuntimeError("trace lost events or was shorter than 60 seconds")
            collectors = report["collectors_start"]
            stacks = collectors["stdout"].lower().split("system stacks", 1)
            report["stack_description"] = stacks[1][:2000] if len(stacks) == 2 else ""
            report["cpu_stack_witnessed"] = "sampledprofile" in report["stack_description"]
            report["file_stack_witnessed"] = any(name in report["stack_description"] for name in ("fileread", "filewrite", "filecreate", "filecleanup", "fileclose"))
            if collectors["returncode"] or not report["cpu_stack_witnessed"] or not report["file_stack_witnessed"]:
                raise RuntimeError("collector status did not witness CPU and file I/O stacks")
            report["status"] = "captured_loss_checked"
        except Exception as error:
            report["status"] = "failed"
            report["error"] = str(error)
        finally:
            if recording:
                cancelled = run([wpr, "-cancel"], timeout=60)
                report["cancel"] = {"returncode": cancelled.returncode, "stdout": cancelled.stdout, "stderr": cancelled.stderr}
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    thread = threading.Thread(target=record, name="atlas-cold-wpr")
    thread.start()
    return thread
