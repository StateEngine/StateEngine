"""Resolve a fixed runner's private paths from administrator-owned configuration."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import sys
import time

SLOTS = ("primary", "secondary")


def holders(fd):
    """Describe the kernel's flock rows for this opened inode, without argv."""
    info = os.fstat(fd)
    owners = []
    try:
        with open("/proc/locks") as stream:
            rows = stream.read(1024 * 1024 + 1)
        if len(rows) > 1024 * 1024:
            return "holder inventory exceeds its read bound"
        for line in rows.splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[1] != "FLOCK":
                continue
            major, minor, inode = fields[5].split(":")
            if (int(major, 16), int(minor, 16), int(inode)) != (
                    os.major(info.st_dev), os.minor(info.st_dev), info.st_ino):
                continue
            pid = int(fields[4])
            try:
                name = Path("/proc", str(pid), "comm").read_text().strip()
            except FileNotFoundError:
                name = "joined before diagnostic"
            owners.append(f"pid={pid} name={name!r} mode={fields[3]}")
    except (OSError, ValueError) as error:
        return "holder unreadable: " + type(error).__name__ + ": " + str(error)
    return "; ".join(owners) or "no holder visible in this kernel snapshot"


def acquire(fd, mode, path, wait_seconds, deadline):
    announced = False
    while True:
        try:
            fcntl.flock(fd, mode | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if not wait_seconds:
                raise
            if not announced:
                print(f"CI cleanup waiting for lease {path}: {holders(fd)}",
                      file=sys.stderr, flush=True)
                announced = True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"CI cleanup could not obtain lease {path} within {wait_seconds}s: "
                                   f"{holders(fd)}; retry after that owner finishes") from None
            time.sleep(min(0.2, remaining))


def select(config, slot):
    if slot not in SLOTS:
        raise ValueError("fixed runner slot required")
    slots = config.get("slots")
    if slots is None:
        if slot != "primary":
            raise RuntimeError("second runner slot is not configured")
        return {**config, "slot": slot, "parallel": False}
    if not isinstance(slots, dict) or set(slots) != set(SLOTS):
        raise RuntimeError("both fixed runner slots must be configured")
    paths = []
    for value in slots.values():
        if not isinstance(value, dict) or set(value) != {"state", "runner_work", "slot_lock"}:
            raise RuntimeError("runner slot paths are incomplete")
        for raw in value.values():
            path = Path(raw)
            if not path.is_absolute() or ".." in path.parts:
                raise RuntimeError("absolute fixed runner slot paths required")
            path = path.resolve(strict=True)
            if any(path == old or path in old.parents or old in path.parents for old in paths):
                raise RuntimeError("runner slot paths must be separate")
            paths.append(path)
    return {**config, **slots[slot], "slot": slot, "parallel": True}


@contextmanager
def venue(config, *, wait_seconds=0):
    if type(wait_seconds) is not int or not 0 <= wait_seconds <= 600:
        raise ValueError("fixed lease wait must be between zero and 600 seconds")
    deadline = time.monotonic() + wait_seconds
    with open(config["ci_lock"], "r") as maintenance:
        acquire(maintenance.fileno(), fcntl.LOCK_SH if config.get("parallel") else fcntl.LOCK_EX,
                config["ci_lock"], wait_seconds, deadline)
        if not config.get("parallel"):
            yield
            return
        fd = os.open(config["slot_lock"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or info.st_mode & 0o022 or info.st_nlink != 1):
                raise RuntimeError("fixed runner slot lease is unavailable")
            acquire(fd, fcntl.LOCK_EX, config["slot_lock"], wait_seconds, deadline)
            yield
        finally:
            os.close(fd)
