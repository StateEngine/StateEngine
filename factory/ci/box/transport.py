"""Bound candidate pipes and opaque artifacts; never interpret their output as authority."""
import hashlib
import os
from pathlib import Path
import selectors
import subprocess
import time

from engine import engine_args


class WorkloadFailure(RuntimeError):
    """An outside-observed workload limit, independent of cleanup availability."""


def close_child(container, process, remove):
    error = None
    if remove:
        try:
            container.close()
        except Exception as observed:
            error = observed
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    except Exception as observed:
        error = observed
    finally:
        process.stdout.close()
        process.stderr.close()
    return error


def execute(container, argv, output, *, stdin=None, limit=8 * 1024**2, deadline=None, canceled=None):
    """Drain both pipes within one byte/deadline budget; return an outside outcome."""
    end = min(container.started + container.deadline,
              time.monotonic() + (deadline or container.deadline))
    process = subprocess.Popen(engine_args("exec", "--interactive", container.id, *argv),
                               stdin=stdin if stdin is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    selector = selectors.DefaultSelector()
    for pipe in (process.stdout, process.stderr):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    size = 0
    reason = None
    code = None
    exit_observed_before_cancel = False
    cleanup_error = None
    try:
        with Path(output).open("xb") as dest:
            while selector.get_map():
                if time.monotonic() >= end:
                    reason = "deadline exceeded"
                    break
                for key, _ in selector.select(min(.2, max(0, end - time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = limit - size
                    dest.write(data[:remaining])
                    size += min(len(data), remaining)
                    if len(data) > remaining:
                        reason = "output exceeds byte budget"
                        break
                if reason:
                    break
            if reason is None:
                try:
                    code = process.wait(timeout=max(.01, end - time.monotonic()))
                    exit_observed_before_cancel = canceled is None or not canceled.is_set()
                except subprocess.TimeoutExpired:
                    reason = "deadline exceeded"
    finally:
        selector.close()
        # Remove the exact owned container before signaling its retained CLI child.
        cleanup_error = close_child(container, process, reason or process.poll() is None)
    # Custody remains fenced when cleanup fails, but an observed workload failure
    # must reach the stage recorder before later reconciliation can throw again.
    if cleanup_error is not None and reason is None and code in (None, 0):
        raise cleanup_error
    return {"exit_code": code, "reason": reason, "output_bytes": size,
            "success": reason is None and code == 0,
            "exit_observed_before_cancel": exit_observed_before_cancel,
            "cleanup_error": None if cleanup_error is None else str(cleanup_error)}


# The code is trusted and the host names the artifact. Candidate filesystem
# objects can race, but an opened regular FD and a bounded pipe remain opaque.
EXPORT = """import os,stat,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
s=os.fstat(fd)
if not stat.S_ISREG(s.st_mode) or s.st_size>int(sys.argv[2]):
 raise RuntimeError('artifact is not a bounded regular file')
with os.fdopen(fd,'rb') as source:
 while chunk:=source.read(65536): sys.stdout.buffer.write(chunk)
"""
ARTIFACTS = {"archive": ("/work/source/tests.tar.zst", 1024**3),
             "trace": ("/work/source/target/cargo-timings/linker-processes.trace", 128 * 1024**2),
             "junit": ("/work/source/target/nextest/ci/junit.xml", 4 * 1024**2)}


def export(container, kind, output):
    path, limit = ARTIFACTS[kind]
    # Stderr cannot contaminate the opaque archive stream: export through a
    # separate bounded reader with a diagnostic FD owned by the controller.
    end = min(container.started + container.deadline, time.monotonic() + 90)
    process = subprocess.Popen(engine_args("exec", container.id, "python3", "-c", EXPORT,
                                           path, str(limit)), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, close_fds=True)
    selector = selectors.DefaultSelector()
    for pipe in (process.stdout, process.stderr):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    total = 0
    diagnostic = bytearray()
    digest = hashlib.sha256()
    failure = None
    try:
        with Path(output).open("xb") as dest:
            while selector.get_map():
                if time.monotonic() >= end:
                    raise WorkloadFailure("artifact export deadline exceeded")
                for key, _ in selector.select(.2):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is process.stdout:
                        total += len(chunk)
                        if total > limit:
                            raise WorkloadFailure("artifact exceeds outside byte budget")
                        digest.update(chunk)
                        dest.write(chunk)
                    else:
                        diagnostic.extend(chunk[:4096-len(diagnostic)])
            try:
                code = process.wait(timeout=max(.01, end-time.monotonic()))
            except subprocess.TimeoutExpired:
                raise WorkloadFailure("artifact export deadline exceeded") from None
            if code:
                raise RuntimeError(f"infrastructure artifact export refused (exit {code}); output remains unaccepted")
        return {"bytes": total, "sha256": digest.hexdigest()}
    except BaseException as error:
        failure = error
        raise
    finally:
        cleanup_error = None
        try:
            with Path(str(output) + ".stderr").open("xb") as log:
                log.write(diagnostic)
                if len(diagnostic) == 4096:
                    log.write(b"\n[diagnostic byte limit reached]\n")
        except Exception as error:
            cleanup_error = error
        finally:
            selector.close()
            cleanup_error = close_child(container, process, process.poll() is None) or cleanup_error
        if failure is None and cleanup_error is not None:
            raise cleanup_error
