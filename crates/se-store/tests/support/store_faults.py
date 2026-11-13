"""Exercise real SQLite I/O with a single externally injected native syscall fault."""
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

FIXTURE = "native_faults::fault_child_fixture"


PROJECT_LOGS = Path(tempfile.gettempdir()) / "se-store-native-faults"


def wait_until(predicate, timeout=15):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.005)
    raise RuntimeError("native SQLite fault fixture did not reach its witnessed phase")


def stop_owned(process, required):
    if process is None or process.poll() is not None:
        return
    command = Path(f"/proc/{process.pid}/cmdline").read_bytes()
    if required.encode() not in command:
        raise RuntimeError(f"REFUSE: owned process identity changed: {process.pid}")
    process.terminate()
    process.wait(timeout=10)


def run(mode, executable, injection=None):
    PROJECT_LOGS.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=mode + "-", dir=PROJECT_LOGS))
    child = tracer = None
    try:
        environment = dict(os.environ, SE_SQLITE_FAULT_ROOT=str(root), SE_SQLITE_FAULT_MODE=mode)
        with (root / "child.log").open("w") as output:
            child = subprocess.Popen([sys.executable, __file__, "native-child", executable,
                                      "--exact", FIXTURE, "--ignored", "--nocapture"],
                                     env=environment, stdout=output, stderr=subprocess.STDOUT)
            wait_until(lambda: (root / "ready.json").exists())
            ready = json.loads((root / "ready.json").read_text())
            if ready["pid"] != child.pid:
                raise RuntimeError("REFUSE: native fixture PID differs from owned process")
            arguments = ["strace", "-qq", "-yy", "-k", "--stack-trace-frame-limit=24",
                         "-e", "trace=pwrite64,fdatasync", "-o", str(root / "syscalls.log"),
                         "-p", ready["tid"]]
            if injection:
                arguments += ["-e", f"inject=pwrite64:error={injection[1]}:when={injection[0]}"]
            with (root / "tracer.log").open("w") as trace_output:
                tracer = subprocess.Popen(arguments, stdout=trace_output, stderr=subprocess.STDOUT)
                def attached():
                    status = Path(f"/proc/{ready['tid']}/status").read_text()
                    return f"TracerPid:\t{tracer.pid}\n" in status
                wait_until(attached)
                (root / "go").write_text("tracer identity witnessed outside writer")
                exit_code = child.wait(timeout=40)
                trace_exit = tracer.wait(timeout=10)
            if exit_code != 0 or trace_exit != 0:
                raise RuntimeError(f"native child/tracer failed: {exit_code}/{trace_exit}: " + (root / "child.log").read_text())
        return json.loads((root / "outcome.json").read_text()), (root / "syscalls.log").read_text(), root
    finally:
        stop_owned(child, FIXTURE)
        stop_owned(tracer, str(root))
        if sys.exc_info()[0] is not None and root.exists():
            print(f"retained fixture root after failure: {root}")


def blocks(trace):
    found = []
    for line in trace.splitlines():
        if line.startswith("pwrite64("):
            found.append([line])
        elif line.startswith(" >") and found:
            found[-1].append(line)
    return ["\n".join(lines) for lines in found]


def main():
    if sys.argv[1] == "native-child":
        native = ctypes.CDLL(None, use_errno=True)
        if native.prctl(0x59616D61, ctypes.c_ulong(-1), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "allow external tracing of this isolated native fixture")
        os.execv(sys.argv[2], sys.argv[2:])
    roots = []
    try:
        requested, executable = sys.argv[1:3]
        mode = "commit" if requested == "commit-io" else requested
        original, trace, baseline_root = run(mode, executable)
        roots.append(baseline_root)
        if any(result["code"] != "Committed" for result in original["results"]):
            raise RuntimeError("REFUSE: baseline did not commit its requests: " + json.dumps(original))
        marker = {"before": "pagerStress", "commit": "sqlite3PagerCommitPhaseOne", "checkpoint": "walCheckpoint"}[mode]
        candidates = [(number, block) for number, block in enumerate(blocks(trace), 1)
                      if marker in block and ("state.db>" in block if mode == "checkpoint" else "state.db-wal>" in block)]
        if not candidates:
            raise RuntimeError("REFUSE: baseline never reached " + marker + " in " + str(baseline_root))
        number, _ = candidates[0]
        errno = "EIO" if requested == "commit-io" else "ENOSPC"
        report, fault_trace, fault_root = run(mode, executable, (number, errno))
        roots.append(fault_root)
        injected = [block for block in blocks(fault_trace) if "(INJECTED)" in block]
        if len(injected) != 1 or marker not in injected[0]:
            raise RuntimeError("REFUSE: syscall counter moved outside intended SQLite phase: " + str(fault_root))
        failures = []
        codes = [result["code"] for result in report["results"]]
        if report["integrity"] != "ok":
            failures.append("outside native integrity_check failed")
        if mode in ("before", "commit") and any(key in ("fault-primary", "fault-secondary") for key in report["timing_keys"]):
            failures.append("failed commit manufactured a successful zero timing")
        if mode == "before":
            if codes != ["DiskFull", "DiskFull"]:
                failures.append("pre-COMMIT ENOSPC must report DiskFull for every group member")
            database = report["database"]
            for result in report["results"]:
                if database not in result.get("detail", ""):
                    failures.append(f"pre-COMMIT DiskFull lost the opened store path: {result}")
            if report["next"]["code"] != "Committed":
                failures.append("confirmed full rollback must leave the same writer usable")
        elif mode == "commit":
            if codes != ["CommitOutcomeUnknown"]:
                failures.append("ENOSPC or IO during COMMIT must retain outcome-unknown identity")
            if report["next"]["code"] != "Committed":
                failures.append("custody-checked reopen failed to re-admit writes in the same writer")
            if "fault-primary" not in json.dumps(report["drain"]):
                failures.append("drain omitted the original indeterminate request key")
            if "fault-primary" not in json.dumps(report["close"]):
                failures.append("close_clean omitted the original indeterminate request key")
        elif mode == "checkpoint":
            if codes != ["Committed"]:
                failures.append("post-COMMIT checkpoint failure relabelled a known committed receipt")
            if not report["results"][0].get("maintenance_pending"):
                failures.append("failed post-COMMIT checkpoint omitted maintenance_pending")
            if report["returned"] != report["results"]:
                failures.append("later maintenance changed the already returned receipt")
            if json.loads((fault_root / "returned.json").read_text()) != report["returned"]:
                failures.append("receipt captured before maintenance differs from final report")
            if report["retained_primary"] != 1:
                failures.append("known committed event missing from independently reopened store")
            if report["returned"][0].get("maintenance_failed") is not False:
                failures.append("receipt claimed a deferred checkpoint had already failed")
            if report["returned"][0].get("checkpoint_ran") is not False:
                failures.append("returned receipt claimed a deferred checkpoint already ran")
            # The stack-bound injected walCheckpoint write above is the maintenance
            # observation; its timing cannot be added to an already returned receipt.
            if report["next"]["code"] != "Committed":
                failures.append("checkpoint maintenance failure permanently closed ordinary write admission")
        print(json.dumps({"phase": marker, "errno": errno, "baseline": str(baseline_root),
                          "fault": str(fault_root), "write": number, "report": report,
                          "failures": failures}, indent=2))
        if failures:
            raise SystemExit(1)
    except BaseException:
        # A failed run leaves exactly the roots it created, each named, so the
        # residue can be read and deleted.
        for kept in roots:
            if kept.exists():
                print(f"retained fixture root after failure: {kept}")
        raise
    # A passing run leaves no artifacts: remove both trees and the shared
    # parent directory when it is empty.
    for kept in roots:
        shutil.rmtree(kept)
    try:
        PROJECT_LOGS.rmdir()
    except OSError:
        pass


if __name__ == "__main__":
    main()
