"""Persistent CI custody. Missing/unknown state refuses guest admission after crashes."""
import json
import os
from pathlib import Path
import re
import pwd
import stat
import selectors
import subprocess
import time
from contextlib import contextmanager
from functools import wraps
import threading

import admission
import engine
from engine import command, engine_args
from journal_lock import locked

RECORDS = Path("/var/lib/stateengine-ci-jobs")
BOOT = Path("/proc/sys/kernel/random/boot_id")


def pin(pid):
    if type(pid) is not int or pid <= 0:
        return None
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return {"pid": pid, "birth": fields[19], "boot": BOOT.read_text().strip()}
    except FileNotFoundError:
        return None


def remaining(native):
    for value in native.get("processes", []):
        if pin(value["pid"]) == value:
            return True
    relative = native.get("cgroup")
    if relative:
        if not relative.startswith("/") or ".." in Path(relative).parts or "libpod-" not in relative:
            raise RuntimeError("recorded CI cgroup identity malformed")
        path = Path("/sys/fs/cgroup") / relative.lstrip("/")
        if path.exists():
            if not path.is_dir():
                raise RuntimeError("recorded CI cgroup is not a directory")
            for file in [path / "cgroup.procs", *path.rglob("cgroup.procs")]:
                try:
                    if file.read_text().strip():
                        return True
                except FileNotFoundError:
                    pass  # A concurrently removed cgroup has no remaining tasks there.
    return False


def native_state(value):
    state = value["State"]
    pid = state["Pid"]
    processes = [p for n in (pid, state.get("ConmonPid", 0)) if (p := pin(n))]
    group = None
    if pid:
        groups = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        matches = [line[3:] for line in groups if line.startswith("0::/")]
        if len(matches) != 1 or ".." in Path(matches[0]).parts or "libpod-" not in matches[0]:
            raise RuntimeError("native private CI cgroup unavailable")
        group = matches[0]
    return {"processes": processes, "cgroup": group}


def _read_records(directory=RECORDS):
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or
            (directory == RECORDS and info.st_uid != pwd.getpwnam("stateengine-ci-controller").pw_uid)):
        raise RuntimeError("controller-owned CI records unavailable")
    rows = []
    for path in directory.iterdir():
        if path.name == ".lock":
            continue  # The caller holds this validated regular lock descriptor.
        if not re.fullmatch(r"se-ci-[a-f0-9]{32}\.json", path.name):
            raise RuntimeError("unknown entry in CI custody directory")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != directory.stat().st_uid or
                    info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 65536):
                raise RuntimeError("CI record ownership/type differs")
            with os.fdopen(fd, closefd=False) as stream:
                row = json.load(stream)
            if (row.get("name") + ".json" != path.name
                    or set(row) not in ({"name", "id", "native"}, {"name", "id", "native", "slot"})
                    or row.get("slot") not in (None, "primary", "secondary")):
                raise RuntimeError("CI record identity malformed")
            rows.append((path, row))
        finally:
            os.close(fd)
    return rows


def read_records(directory=RECORDS):
    with locked(directory):
        return _read_records(directory)


def inventory():
    rows = json.loads(command("ps", "--all", "--format=json"))
    if not isinstance(rows, list):
        raise RuntimeError("complete CI engine inventory unavailable")
    return rows


def idle(directory=RECORDS):
    with locked(directory):
        records = _read_records(directory)
        rows = inventory()
        if rows:
            raise RuntimeError("CI custody: persistent engine jobs remain")
        for _, row in records:
            if remaining(row["native"]):
                raise RuntimeError("CI custody: native container/cgroup tasks remain")
        if records:
            raise RuntimeError("CI custody: creation or cleanup needs controller reconciliation")
    return {"schema": "stateengine-ci-idle/v1", "idle": True}


def serialized(method):
    @wraps(method)
    def invoke(self, *args, **kwargs):
        with self.transaction():
            return method(self, *args, **kwargs)
    return invoke


class Journal:
    def __init__(self, directory=RECORDS, *, slot=None):
        self.directory = directory
        if slot not in (None, "primary", "secondary"):
            raise ValueError("fixed runner slot required")
        self.slot = slot
        self.mutex, self.depth = threading.RLock(), 0
        info = directory.lstat()
        if info.st_uid != os.getuid() or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise RuntimeError("private controller job journal unavailable")

    @contextmanager
    def transaction(self):
        with self.mutex:
            if self.depth:
                yield
                return
            with locked(self.directory, exclusive=True):
                self.depth += 1
                try:
                    yield
                finally:
                    self.depth -= 1

    @serialized
    def write(self, name, row, initial=False):
        if self.slot is not None:
            if row.get("slot", self.slot) != self.slot:
                raise RuntimeError("journal write belongs to another runner slot")
            row = {**row, "slot": self.slot}
        path = self.directory / (name + ".json")
        if initial:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o640)
        else:
            if self.slot is not None:
                previous = dict((row["name"], row) for _, row in _read_records(self.directory))[name]
                if previous.get("slot") != self.slot:
                    raise RuntimeError("journal update belongs to another runner slot")
            fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w") as out:
            json.dump(row, out)
            out.flush()
            os.fsync(out.fileno())
        # A torn update refuses the helper; creation/removal must survive a crash.
        fd = os.open(self.directory, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def intent(self, name):
        if not re.fullmatch(r"se-ci-[a-f0-9]{32}", name):
            raise ValueError("controller-generated CI name required")
        self.write(name, {"name": name, "id": None, "native": {}}, initial=True)

    @serialized
    def create(self, name, args):
        # The worker door waits for acknowledgement before execing podman create.
        # A controller crash before pin persistence gives it EOF, not permission to create.
        child = subprocess.Popen(engine_args("--stateengine-create-transaction", *args),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True)
        selector = selectors.DefaultSelector()
        try:
            selector.register(child.stdout, selectors.EVENT_READ)
            if not selector.select(15):
                raise RuntimeError("creation custody handshake unavailable")
            header = child.stdout.readline(1024)
            pid = json.loads(header)["pid"]
            native = pin(pid)
            if native is None:
                raise RuntimeError("native creation worker disappeared")
            command_line = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if engine.ENGINE_DOOR.encode() not in command_line:
                raise RuntimeError("creation worker does not name the fixed engine door")
            self.write(name, {"name": name, "id": None,
                             "native": {"processes": [native], "cgroup": None}})
            child.stdin.write(b"RUN\n")
            child.stdin.flush()
            output, diagnostic = child.communicate(timeout=90)
            if child.returncode or len(output) > 1024:
                raise RuntimeError("registered engine creation refused; diagnostics withheld")
            return output.decode().strip()
        finally:
            selector.close()
            if child.poll() is None:
                # Close the permission pipe first. A not-yet-acknowledged child cannot create.
                child.stdin.close()
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            for pipe in (child.stdin, child.stdout, child.stderr):
                pipe.close()

    @serialized
    def observe(self, name, value):
        if value["Name"].lstrip("/") != name or not re.fullmatch(r"[a-f0-9]{64}", value["Id"]):
            raise RuntimeError("engine identity differs from creation intent")
        previous = dict((row["name"], row) for _, row in _read_records(self.directory))[name]
        if self.slot is not None and previous.get("slot") != self.slot:
            raise RuntimeError("container observation belongs to another runner slot")
        if previous["id"] not in (None, value["Id"]):
            raise RuntimeError("recorded CI container identity changed")
        old, current = previous["native"], native_state(value)
        if old.get("cgroup") and current["cgroup"] not in (None, old["cgroup"]):
            raise RuntimeError("CI container moved to an unrecorded cgroup")
        current["cgroup"] = old.get("cgroup") or current["cgroup"]
        current["processes"] = list({json.dumps(p, sort_keys=True): p for p in
                                     old.get("processes", []) + current["processes"]}.values())
        self.write(name, {**previous, "id": value["Id"], "native": current})

    @serialized
    def closed(self, name):
        entries = dict((row["name"], (path, row)) for path, row in _read_records(self.directory))
        path, row = entries[name]
        if self.slot is not None and row.get("slot") != self.slot:
            raise RuntimeError("container closure belongs to another runner slot")
        if remaining(row["native"]):
            raise RuntimeError("CI native closure has not joined")
        if any(row["name"] in x.get("Names", []) or row["id"] == x.get("Id") for x in inventory()):
            raise RuntimeError("CI object still present after cleanup")
        # Closure of this exact object is now proved: retire its memory charge
        # before the custody record that names it disappears.
        admission.retire(name)
        path.unlink()
        fd = os.open(self.directory, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @serialized
    def reconcile(self):
        records = _read_records(self.directory)
        if self.slot is not None and any(row.get("slot") is None for _, row in records):
            raise RuntimeError("unassigned CI custody requires exclusive maintenance reconciliation")
        known = {row["name"]: row for _, row in records}
        # Never remove an unknown engine entry, even if it shares a label.
        for item in inventory():
            names = item.get("Names", [])
            if len(names) != 1 or names[0] not in known:
                raise RuntimeError("unknown CI engine object; supported reconciliation required")
            row = known[names[0]]
            if row["id"] not in (None, item["Id"]):
                raise RuntimeError("CI reconciliation identity changed")
            if self.slot is not None and row.get("slot") != self.slot:
                continue
            value, = json.loads(command("inspect", item["Id"]))
            self.observe(row["name"], value)
            command("rm", "--force", "--time=5", item["Id"])
        end = time.monotonic() + 15
        for _, row in records:
            if self.slot is not None and row.get("slot") != self.slot:
                continue
            while True:
                try:
                    self.closed(row["name"])
                    break
                except RuntimeError:
                    if time.monotonic() >= end:
                        raise
                    time.sleep(.1)
        if any(self.slot is None or row.get("slot") == self.slot
               for _, row in _read_records(self.directory)):
            raise RuntimeError("CI slot still has unresolved custody records")
