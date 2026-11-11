"""Serialize custody metadata while independent containers execute concurrently."""
from contextlib import contextmanager
import fcntl
import os
import stat


@contextmanager
def locked(directory, exclusive=False):
    parent = directory.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
        raise RuntimeError("private controller custody directory is unavailable")
    owner = parent.st_uid
    flags = (os.O_RDWR if exclusive or os.getuid() == owner else os.O_RDONLY)
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    if os.getuid() == owner:
        flags |= os.O_CREAT
    fd = os.open(directory / ".lock", flags, 0o640)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise RuntimeError("controller custody metadata lock is unavailable")
        if os.getuid() == owner:
            os.fchmod(fd, 0o640)  # Retain the existing group-readable idle-query route under a private umask.
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        os.close(fd)
