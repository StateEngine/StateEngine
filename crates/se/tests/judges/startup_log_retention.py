"""Protects: CLI startup refusal retention, current-log custody and honest cleanup failure."""
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time


NAME = re.compile(r"runtime-startup-[0-9a-f]{32}\.log")
SE = str(Path(sys.argv[1]).resolve(strict=True))
ROOT = Path(tempfile.mkdtemp(prefix="se-startup-retention-"))
ENV = {k: v for k, v in os.environ.items()
       if not k.startswith(("SE_", "STATEENGINE_", "SECODE_", "CLAUDE_", "CODEX_", "GIT_"))
       and k != "CLAUDECODE"}
CALLS = []


def call(home, *args):
    child = subprocess.Popen([SE, "--home", str(home), "--json", *args],
                             env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    row = dict(argv=child.args, pid=child.pid, exit="in flight")
    CALLS.append(row)
    (ROOT / "calls.json").write_text(json.dumps(CALLS, indent=2))
    try:
        out, err = child.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        row["exit"] = "timeout; exact CLI retained for diagnosis"
        (ROOT / "calls.json").write_text(json.dumps(CALLS, indent=2))
        raise
    row.update(exit=child.returncode, stdout=out.decode(errors="replace"),
               stderr=err.decode(errors="replace"))
    (ROOT / "calls.json").write_text(json.dumps(CALLS, indent=2))
    return row, json.loads(out)


def occupied_port():
    for port in range(24000, 30000):
        listener = socket.socket()
        try:
            listener.bind(("127.0.0.1", port))
            listener.listen()
            return listener, port
        except OSError:
            listener.close()
    raise AssertionError("no private supported test port available")


def setup(name, port):
    root = ROOT / name
    repo, home = root / "repo", root / "state"
    repo.mkdir(parents=True)
    row, value = call(home, "init", "--repo", str(repo), "--name", "Startup diagnostics",
                      "--agent", "Local agent", "--provider", "codex")
    assert row["exit"] == 0, value
    config = home / "config.toml"
    text, count = re.subn(r"(?m)^listen_port = \d+$", f"listen_port = {port}", config.read_text())
    assert count == 1, "initialized config must name exactly one listener port"
    config.write_text(text)
    return home


def logs(home):
    return {p.name for p in home.iterdir()
            if NAME.fullmatch(p.name) and stat.S_ISREG(p.lstat().st_mode)}


def seed(home, count):
    paths = []
    for index in range(count):
        path = home / f"runtime-startup-{index:032x}.log"
        path.write_text(f"old diagnostic {index}\n")
        path.chmod(0o600)
        # A future timestamp must not evict this call's advertised current log.
        os.utime(path, (time.time() + 86400 + index, time.time() + 86400 + index))
        paths.append(path)
    return paths


def refusal(home, cleanup=False):
    row, value = call(home, "up")
    assert row["exit"] != 0 and value["code"] == "source-unreadable", value
    assert "listener-unavailable" in value["message"], value
    assert "Address already in use" in value["message"], value
    remedy = value["remedy"]["text"]
    names = NAME.findall(remedy)
    assert names, "refusal must advertise its actual log"
    current = home / names[0]
    assert str(current) in remedy and current.name in logs(home), remedy
    content = current.read_text()
    assert "Startup refused:" in content and "listener-unavailable" in content, content
    assert ("Older startup logs could not be removed:" in remedy) == cleanup, remedy
    assert "Older startup logs could not be removed:" not in value["message"], value
    return current


def down(home):
    assert all(isinstance(row["exit"], int) for row in CALLS), \
        "timed-out CLI retained in calls.json; no overlapping shutdown submitted"
    row, value = call(home, "down")
    assert row["exit"] == 0 and value["complete"] is True, value


def retention():
    listener, port = occupied_port()
    home = setup("retention", port)
    try:
        old = seed(home, 10)
        unrelated = home / "runtime-startup-user.log"
        unrelated.write_text("user text\n")
        uppercase = home / ("runtime-startup-" + "A" * 32 + ".log")
        uppercase.write_text("non-native name\n")
        directory = home / ("runtime-startup-" + "d" * 32 + ".log")
        directory.mkdir()
        target = ROOT / "symlink-target"
        target.write_text("outside user bytes\n")
        link = home / ("runtime-startup-" + "e" * 32 + ".log")
        link.symlink_to(target)
        for _ in range(2):
            current = refusal(home)
            expected = {p.name for p in old[-7:]} | {current.name}
            assert logs(home) == expected, f"retention expected eight exact logs: {logs(home)}"
            assert unrelated.read_text() == "user text\n"
            assert uppercase.read_text() == "non-native name\n"
            assert directory.is_dir() and link.is_symlink()
            assert target.read_text() == "outside user bytes\n"
        listener.close()
        before = logs(home)
        row, value = call(home, "up")
        assert row["exit"] == 0, value
        assert logs(home) == before, "successful startup must create or prune no refusal log"
    finally:
        listener.close()
        down(home)


def failed_cleanup():
    listener, port = occupied_port()
    home = setup("cleanup", port)
    try:
        old = seed(home, 8)
        blocked = old[0]
        os.utime(blocked, (1, 1))
        external = ROOT / "retained-hardlink"
        os.link(blocked, external)
        before = external.read_bytes()
        current = refusal(home, cleanup=True)
        assert len(logs(home)) == 9 and current.name in logs(home)
        assert blocked.read_bytes() == before == external.read_bytes()
        assert blocked.stat().st_nlink == 2, "cleanup cannot unlink a protected hard link"
        external.unlink()
        current = refusal(home)
        assert len(logs(home)) == 8 and current.name in logs(home)
    finally:
        listener.close()
        down(home)


def owned_processes():
    remaining = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            if argv and argv[0].decode(errors="replace") == SE and any(
                    str(ROOT).encode() in arg for arg in argv[1:]):
                remaining.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return remaining


def main():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("native Linux judge; other platforms are unqualified")
    # Reap only this judge's adopted descendants, including failed native starts.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "enable child subreaper")
    passed = []
    try:
        retention()
        passed.append("cap/current-clock-skew/names/non-files/success")
        failed_cleanup()
        passed.append("protected-cleanup-refusal/recovery/original-error")
    finally:
        while True:
            try:
                if os.waitpid(-1, os.WNOHANG)[0] == 0:
                    break
            except ChildProcessError:
                break
        live = owned_processes()
        result = dict(passed=passed, remaining_owned_pids=live, artifacts=str(ROOT))
        (ROOT / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
        assert not live, f"owned runtime processes remain: {live}"
    assert len(passed) == 2
    # A passing run leaves no artifacts behind. A failing run raises above and
    # keeps ROOT, whose path was printed and written to result.json.
    try:
        shutil.rmtree(ROOT)
    except OSError as error:
        raise SystemExit(f"passing run left artifacts at {ROOT}: {error}")


if __name__ == "__main__":
    main()
