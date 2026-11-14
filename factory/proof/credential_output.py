"""Keep an active automation token out of retained subprocess output."""
import os
from pathlib import Path
import selectors
import stat
import subprocess
import time


def redacted_command(argv, env, output, timeout, token):
    needle, replacement = token.encode(), b"<redacted-automation-token>"
    if needle in replacement:
        replacement = b""
    pending = b""
    deadline = time.monotonic() + timeout
    with subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          close_fds=True) as child, selectors.DefaultSelector() as ready:
        ready.register(child.stdout, selectors.EVENT_READ)
        try:
            while ready.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in ready.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        ready.unregister(key.fileobj)
                        break
                    pending += chunk
                    pending = pending.replace(needle, replacement)
                    keep = min(len(pending), len(needle) - 1)
                    while keep and not pending.endswith(needle[:keep]):
                        keep -= 1
                    safe = len(pending) - keep
                    output.write(pending[:safe])
                    pending = pending[safe:]
            output.write(pending)
            return child.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            child.kill()
            child.wait()
            if pending:
                output.write(b"\n[interrupted output: possible token prefix withheld]\n")
            raise


def require_token_absent(roots, token):
    needle, stack = token.encode(), [Path(root) for root in roots]
    while stack:
        path = stack.pop()
        if token in path.name:
            raise RuntimeError("automation token found in an output filename; preserve the private fixture and remove the exposed token before retrying")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        if stat.S_ISDIR(info.st_mode):
            stack.extend(path.iterdir())
        elif stat.S_ISREG(info.st_mode):
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise RuntimeError("automation output scan requires regular files")
                tail, remaining = b"", before.st_size
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise RuntimeError("automation output changed during its scan; preserve the private fixture for inspection")
                    remaining -= len(chunk)
                    data = tail + chunk
                    if needle in data:
                        raise RuntimeError("automation token found in retained output; preserve the private fixture and remove the exposed token before retrying")
                    tail = data[-(len(needle) - 1):] if len(needle) > 1 else b""
                after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise RuntimeError("automation output changed during its scan; preserve the private fixture for inspection")
        else:
            raise RuntimeError("automation output scan encountered a non-regular file; preserve the private fixture for inspection")
