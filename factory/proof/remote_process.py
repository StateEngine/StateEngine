"""Bounded raw command observations and exact Linux child-process custody."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


def identity(pid):
    path = Path("/proc") / str(pid)
    return ((path / "stat").read_text().rsplit(")", 1)[1].split()[19],
            (path / "cmdline").read_bytes())


class Command:
    """Keep both raw pipes, bounded line observations and exact child custody."""
    def __init__(self, argv, prefix, env, data=None, hold_stdin=False):
        self.started = time.monotonic_ns()
        self.argv, self.prefix = [str(v) for v in argv], prefix
        self.process = subprocess.Popen(self.argv, env=env,
            stdin=subprocess.PIPE if data is not None or hold_stdin else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.identity = None
        self.selector = selectors.DefaultSelector()
        self.buffers, self.files, self.rows = {}, {}, []
        self.count = 0
        try:
            try:
                self.identity = identity(self.process.pid)
            except FileNotFoundError:
                pass
            for name, pipe in (("stdout", self.process.stdout), ("stderr", self.process.stderr)):
                self.selector.register(pipe, selectors.EVENT_READ, name)
                self.buffers[name] = b""
                self.files[name] = prefix.with_suffix("." + name).open("xb")
            if data is not None:
                self.process.stdin.write(data)
                self.process.stdin.close()
        except BrokenPipeError as error:
            try:
                self.pump(0.1)
                reason = self.diagnostic("command closed stdin before accepting the request")
            finally:
                self.close()
            raise RuntimeError(reason) from error
        except BaseException:
            # Construction itself can be interrupted while writing SSH's stdin.
            self.close()
            raise

    def diagnostic(self, reason):
        # Keep raw pipes in full; quote only a bounded native error in the row.
        self.files["stderr"].flush()
        detail = self.prefix.with_suffix(".stderr").read_bytes()[-2048:].decode("utf-8", errors="replace").strip()
        return reason + ("; stderr: " + repr(detail) if detail else "; stderr was empty")

    def pump(self, seconds):
        for key, _ in self.selector.select(max(0, seconds)):
            name = key.data
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                self.selector.unregister(key.fileobj)
                if self.buffers[name]:
                    raise RuntimeError("command ended with an unterminated structured line")
                continue
            self.files[name].write(data)
            self.files[name].flush()
            self.count += len(data)
            if self.count > 8 * 1024 * 1024:
                raise RuntimeError("command exceeded 8 MiB; raw evidence retained, no silent truncation")
            self.buffers[name] += data
            while b"\n" in self.buffers[name]:
                line, self.buffers[name] = self.buffers[name].split(b"\n", 1)
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeError):
                    continue  # Raw native diagnostics remain in their original pipe.
                self.rows.append((name, time.monotonic_ns(), value))

    def until(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while True:
            found = next((row for row in self.rows if predicate(*row)), None)
            if found is not None:
                return found
            if not self.selector.get_map():
                raise RuntimeError(self.diagnostic(f"command exited {self.process.wait()} before the expected observation"))
            if time.monotonic() >= deadline:
                raise RuntimeError("expected command observation timed out; inspect retained raw output")
            self.pump(min(0.25, deadline - time.monotonic()))

    def finish(self, timeout):
        deadline = time.monotonic() + timeout
        while self.selector.get_map():
            if time.monotonic() >= deadline:
                raise RuntimeError("command deadline expired; inspect retained raw output")
            self.pump(min(0.25, deadline - time.monotonic()))
        code = self.process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code:
            raise RuntimeError(self.diagnostic(f"command exited {code}"))
        values = [value for pipe, _, value in self.rows if pipe == "stdout"]
        if len(values) != 1 or not isinstance(values[0], dict):
            raise RuntimeError("expected exactly one structured command result")
        return values[0].get("value", values[0])

    def close(self):
        try:
            if self.process.poll() is None:
                if self.identity is None or identity(self.process.pid) != self.identity:
                    raise RuntimeError("owned command identity unavailable; no signal sent")
                self.process.send_signal(signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if identity(self.process.pid) != self.identity:
                        raise RuntimeError("owned command identity changed; no signal sent")
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            self.selector.close()
            self.process.stdout.close()
            self.process.stderr.close()
            if self.process.stdin is not None and not self.process.stdin.closed:
                try:
                    self.process.stdin.close()
                except BrokenPipeError:
                    pass  # The child already closed its side; both raw pipes still close.
            for stream in self.files.values():
                stream.close()
            self.prefix.with_suffix(".json").write_text(json.dumps({
                "argv": self.argv, "pid": self.process.pid, "exit": self.process.returncode,
                "native_identity_observed": self.identity is not None,
                "elapsed_ms": (time.monotonic_ns() - self.started) / 1e6,
                "stdin_recorded": False}, indent=2) + "\n")
