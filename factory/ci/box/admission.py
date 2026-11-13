"""Charge every live container against one shared memory budget.

The two paired runner slots are separate processes of the same account, so the
budget cannot live in one process. Each charge is recorded in a per-account
directory, and admission sums every live charge before it adds one more.

A charge outlives the process that made it, because the container it stands for
can outlive that process. A charge is live until the existing custody closure
proof retires the exact container -- `Journal.closed` after removal, or the same
check during restart reconciliation -- so an uncertain cleanup or a dead
controller keeps the memory counted instead of handing it to the peer slot. A
charge made without a container (a bare capacity probe) has nothing to outlive
and ends with the process or thread that made it.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import pwd
import stat
import threading

BOOT = Path("/proc/sys/kernel/random/boot_id")
BOUND = 4096
FIELDS = {"pid", "tid", "birth", "boot", "memory", "container"}


def read(path):
    """Read one small bounded file without following links."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        return os.read(fd, BOUND)
    finally:
        os.close(fd)


def boot():
    return read(BOOT).decode().strip()


def birth(pid, tid):
    """The kernel's start time for one task, which a reused id cannot repeat."""
    fields = read(f"/proc/{pid}/task/{tid}/stat").decode().rsplit(")", 1)[1].split()
    return int(fields[19])


def holder():
    """The exact live execution making a charge."""
    pid, tid = os.getpid(), threading.get_native_id()
    return {"pid": pid, "tid": tid, "birth": birth(pid, tid), "boot": boot()}


def folder():
    """One private directory per account: both fixed slots share it.

    The home directory comes from the account entry, not the environment, so a
    stray `$HOME` cannot point two slots at different budgets.
    """
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".stateengine-ci-admission"


def holder_live(row):
    if row["boot"] != boot() or not Path("/proc", str(row["pid"])).is_dir():
        return False
    try:
        return birth(row["pid"], row["tid"]) == row["birth"]
    except (OSError, IndexError, ValueError):
        return False


def live(row):
    # A container-backed charge is live until closure retires it, whatever
    # became of its admitting process. Only a bare probe ends with its holder.
    return True if row["container"] is not None else holder_live(row)


def records(directory):
    rows = []
    for path in sorted(directory.glob("*.json")):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > BOUND):
                raise RuntimeError("CI admission record ownership/type differs")
            row = json.loads(os.read(fd, BOUND))
        finally:
            os.close(fd)
        if (not isinstance(row, dict) or set(row) != FIELDS
                or any(type(row[name]) is not int for name in ("pid", "tid", "birth", "memory"))
                or not isinstance(row["boot"], str) or row["memory"] <= 0
                or not (row["container"] is None or isinstance(row["container"], str))):
            raise RuntimeError("CI admission record is malformed")
        rows.append((path, row))
    return rows


@contextmanager
def locked(directory):
    fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise RuntimeError("CI admission lock is unavailable")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def write(directory, mine, memory, container):
    name = f"{mine['pid']}-{mine['tid']}"
    temporary = directory / (name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump({**mine, "memory": memory, "container": container}, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, directory / (name + ".json"))


def reserve(memory, available, margin, container=None):
    """Charge `memory` beside every live peer, or refuse before anything starts."""
    directory = folder()
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise RuntimeError("CI admission directory is not private to this account")
    mine = holder()
    with locked(directory):
        peers, held = 0, []
        for path, row in records(directory):
            if (row["pid"], row["tid"]) == (mine["pid"], mine["tid"]):
                # This holder names one charge. It may replace its own bare
                # probe, but never a retained charge for a container whose
                # closure it has not proved.
                if row["container"] is not None and row["container"] != container:
                    raise RuntimeError(
                        "this execution still holds a charge for an unclosed container")
                continue
            if not live(row):
                path.unlink()
            else:
                peers += row["memory"]
                held.append(row["container"] or f"probe {row['pid']}")
        if peers + memory + margin > available:
            raise RuntimeError(
                f"infrastructure unavailable: preserve 6 GiB after bounded allocation; "
                f"{', '.join(held)} already hold {peers} bytes and this job needs {memory}, "
                f"leaving under the {margin}-byte margin out of {available} available")
        write(directory, mine, memory, container)


def retire(container):
    """Drop the charge for one container, only once its closure is proved."""
    try:
        directory = folder()
        with locked(directory):
            for path, row in records(directory):
                if row["container"] == container:
                    path.unlink()
    except FileNotFoundError:
        pass
