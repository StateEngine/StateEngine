"""Charge every live container against one shared memory budget.

The two paired runner slots are separate processes of the same account, so the
budget cannot live in one process. Each holder records its reservation in a
per-account directory, and admission sums every live record before it charges
one more. The other entry point takes the maintenance lock exclusively while a
slot takes it shared, so no third process can hold a reservation beside a slot;
only the two slots are ever live together, and they share this directory.

A holder is live only while its exact process and thread exist in this boot, so
a crash or a dead thread stops charging without a separate delete pass. A
holder runs one bounded container at a time, so asking again replaces that
holder's own charge instead of adding a second one.
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
FIELDS = {"pid", "tid", "birth", "boot", "memory"}


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
    """The exact live execution that owns a reservation."""
    pid, tid = os.getpid(), threading.get_native_id()
    return {"pid": pid, "tid": tid, "birth": birth(pid, tid), "boot": boot()}


def folder():
    """One private directory per account: both fixed slots share it.

    The home directory comes from the account entry, not the environment, so a
    stray `$HOME` cannot point two slots at different budgets.
    """
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".stateengine-ci-admission"


def live(row):
    if row["boot"] != boot() or not Path("/proc", str(row["pid"])).is_dir():
        return False
    try:
        return birth(row["pid"], row["tid"]) == row["birth"]
    except (OSError, IndexError, ValueError):
        return False


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
                or not isinstance(row["boot"], str) or row["memory"] <= 0):
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


def write(directory, mine, memory):
    temporary = directory / f"{mine['pid']}-{mine['tid']}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump({**mine, "memory": memory}, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, directory / f"{mine['pid']}-{mine['tid']}.json")


def reserve(memory, available, margin):
    """Charge `memory` beside every live peer, or refuse before anything starts."""
    directory = folder()
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise RuntimeError("CI admission directory is not private to this account")
    mine = holder()
    with locked(directory):
        peers = 0
        for path, row in records(directory):
            if not live(row):
                path.unlink()
            elif (row["pid"], row["tid"]) != (mine["pid"], mine["tid"]):
                peers += row["memory"]
        if peers + memory + margin > available:
            raise RuntimeError(
                f"infrastructure unavailable: preserve 6 GiB after bounded allocation; "
                f"a paired peer already reserved {peers} bytes and this job needs {memory}, "
                f"leaving under the {margin}-byte margin out of {available} available")
        write(directory, mine, memory)
    return mine


def release(mine):
    """Drop exactly the charge its holder made, once that container is gone."""
    if not mine:
        return
    try:
        (folder() / f"{mine['pid']}-{mine['tid']}.json").unlink()
    except FileNotFoundError:
        pass
