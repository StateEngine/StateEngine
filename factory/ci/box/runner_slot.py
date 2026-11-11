"""Resolve a fixed runner's private paths from administrator-owned configuration."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

SLOTS = ("primary", "secondary")


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
            if any(path == old or path in old.parents or old in path.parents for old in paths):
                raise RuntimeError("runner slot paths must be separate")
            paths.append(path)
    return {**config, **slots[slot], "slot": slot, "parallel": True}


@contextmanager
def venue(config):
    with open(config["ci_lock"], "r") as maintenance:
        fcntl.flock(maintenance, (fcntl.LOCK_SH if config.get("parallel") else fcntl.LOCK_EX)
                    | fcntl.LOCK_NB)
        if not config.get("parallel"):
            yield
            return
        fd = os.open(config["slot_lock"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or info.st_mode & 0o022 or info.st_nlink != 1):
                raise RuntimeError("fixed runner slot lease is unavailable")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)
