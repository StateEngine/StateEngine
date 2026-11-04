"""Linux process-crash judge for the real importer and its SQLite writer.

An outside SQLite reader waits for the first imported payload. strace delays
only writes to this fixture's WAL so a later checkpoint transaction cannot race
past the observer. Kill only the exact new native host identified by its image,
birth, command and open WAL; then read data/checkpoint and retry through the CLI.
"""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
import uuid

from history_import import Fixture, write_row

MARKER = "S15-CRASH-ATOMIC-DATA"


def outside(home):
    with closing(sqlite3.connect(f"file:{home / 'state.db'}?mode=ro", uri=True, timeout=1)) as db:
        db.execute("BEGIN")
        bodies = db.execute("select count(*) from payloads where instr(content,?)>0",
                            (MARKER.encode(),)).fetchone()[0]
        progress = db.execute("select row_offset,byte_offset from import_progress where family='messages'").fetchall()
        assert db.execute("pragma integrity_check").fetchone() == ("ok",)
        return {"body_count": bodies, "progress": progress}


def kill_writer(f):
    traces = [p for p in f.root.glob("trace.*") if MARKER in p.read_text()]
    assert len(traces) == 1, "REFUSE: marker has no unique traced writer"
    tid = int(traces[0].suffix[1:])
    status = Path(f"/proc/{tid}/status").read_text()
    pid = int(next(line.split()[1] for line in status.splitlines() if line.startswith("Tgid:")))
    proc = Path(f"/proc/{pid}")
    birth = (proc / "stat").read_text().rsplit(") ", 1)[1].split()[19]
    command = (proc / "cmdline").read_bytes().split(b"\0")
    assert command == [os.fsencode(f.se), b"--stateengine-private-runtime-bootstrap", b""], "REFUSE: host command changed"
    assert (proc / "exe").resolve() == f.se, "REFUSE: host image changed"
    wal = str(f.home / "state.db-wal")
    owns_wal = False
    for fd in (proc / "fd").iterdir():
        try:
            owns_wal = os.readlink(fd) == wal
        except FileNotFoundError:
            continue  # A closed descriptor does not identify this writer.
        if owns_wal:
            break
    assert owns_wal, "REFUSE: target does not own this WAL"
    assert (proc / "stat").read_text().rsplit(") ", 1)[1].split()[19] == birth, "REFUSE: host PID reused"
    (f.root / "crash-identity.json").write_text(json.dumps({"pid": pid, "tid": tid,
        "birth": birth, "command": [os.fsdecode(part) for part in command], "owned_wal": wal}))
    os.kill(pid, signal.SIGKILL)


def crash(f):
    write_row(f.messages, f.message(1, MARKER))
    arguments = ["strace", "-ff", "-qq", "-yy", "-s", "4096", "-e", "trace=pwrite64",
                 "-P", str(f.home / "state.db-wal"), "-e", "inject=pwrite64:delay_enter=10ms",
                 "-o", str(f.root / "trace"), *f.command("import", "--from-node", str(f.source))]
    out, err = f.root / "import.stdout", f.root / "import.stderr"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        child = subprocess.Popen(arguments, env=f.environment, stdout=stdout, stderr=stderr)
        try:
            until = time.monotonic() + 60
            while True:
                observation = outside(f.home)
                if observation["body_count"]:
                    kill_writer(f)
                    break
                assert child.poll() is None, "import exited before its row became visible"
                assert time.monotonic() < until, "outside observer never saw imported data"
                time.sleep(0.001)
            code = child.wait(timeout=35)
            assert code != 0, "crashed request returned success"
        finally:
            # If the assertion or setup failed, retire only this fixture through
            # the product's authenticated door. Retain the original refusal/logs.
            if child.poll() is None:
                f.call("down")
                child.wait(timeout=35)
    snapshot = outside(f.home)
    assert snapshot == observation, "post-crash read differs from the observed committed snapshot"
    assert snapshot["body_count"] == 1 and snapshot["progress"] == [(1, f.messages.stat().st_size)], (
        "data/checkpoint split across crash", snapshot)
    assert f.import_history()["complete"], "retry did not finish interrupted import"
    assert f.count(MARKER) == 1, "crash retry lost or duplicated the row"
    f.ok("down")
    (f.root / "result.json").write_text(json.dumps({"passed": 1, "failed": 0,
        "outside_after_crash": snapshot, "public_body_count_after_retry": 1}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "linux", "native syscall crash judge requires Linux"
    output = args.output.resolve() / uuid.uuid4().hex[:8]
    output.mkdir(parents=True)
    crash(Fixture(args.se.resolve(), output / "fault"))
    print("Import crash/data-checkpoint consumer: 1 passed; 0 failed", flush=True)


if __name__ == "__main__":
    main()
