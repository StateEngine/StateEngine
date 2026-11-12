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
        try:
            self.identity = identity(self.process.pid)
        except FileNotFoundError:
            self.identity = None
        self.selector = selectors.DefaultSelector()
        self.buffers, self.files, self.rows = {}, {}, []
        self.count = 0
        for name, pipe in (("stdout", self.process.stdout), ("stderr", self.process.stderr)):
            self.selector.register(pipe, selectors.EVENT_READ, name)
            self.buffers[name] = b""
            self.files[name] = prefix.with_suffix("." + name).open("xb")
        if data is not None:
            self.process.stdin.write(data)
            self.process.stdin.close()

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
                raise RuntimeError(f"command exited {self.process.wait()} before the expected observation")
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
            raise RuntimeError(f"command exited {code}; inspect retained stdout and stderr")
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
                self.process.stdin.close()
            for stream in self.files.values():
                stream.close()
            self.prefix.with_suffix(".json").write_text(json.dumps({
                "argv": self.argv, "pid": self.process.pid, "exit": self.process.returncode,
                "native_identity_observed": self.identity is not None,
                "elapsed_ms": (time.monotonic_ns() - self.started) / 1e6,
                "stdin_recorded": False}, indent=2) + "\n")

