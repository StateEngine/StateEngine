"""Judge the production spawner timer with exact Windows exit observations."""

import argparse
import ctypes
from ctypes import wintypes
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from judge_records import wait_json, write_json
from mail_cli import Fixture


WAIT_SIGNALED = 0
WAIT_LIVE = 258
GRACE_SECONDS = 600
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))
from windows_journeys.credentials import protect


def windows_process_api():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [
        wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)
    ]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


class Birth:
    def __init__(self, kernel, pid, scope):
        self.kernel = kernel
        self.pid = pid
        # The observer can query and wait on this one process.
        self.handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        scope.callback(self.close)
        timestamps = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(self.handle, *(ctypes.byref(t) for t in timestamps)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.start = (timestamps[0].dwHighDateTime << 32) | timestamps[0].dwLowDateTime
        assert self.start > 0 and not self.exited(), f"PID {pid} must begin live"

    def close(self):
        if not self.kernel.CloseHandle(self.handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def exited(self, timeout_ms=0):
        result = self.kernel.WaitForSingleObject(self.handle, timeout_ms)
        if result not in (WAIT_SIGNALED, WAIT_LIVE):
            raise ctypes.WinError(ctypes.get_last_error())
        return result == WAIT_SIGNALED

    def argument(self):
        return f"{self.pid}:{self.start}"


def drive_owner(binary, home, repo, reply_file):
    with ExitStack() as scope:
        caller = Birth(windows_process_api(), os.getpid(), scope)
        reply = subprocess.run(
            [binary, "--home", home, "--json", "up", "--spawner", caller.argument()],
            cwd=repo,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=95,
        )
        write_json(reply_file, {
            "exit": reply.returncode,
            "stdout": reply.stdout.decode("utf-8", "replace"),
            "stderr": reply.stderr.decode("utf-8", "replace"),
        })
        if reply.returncode == 0:
            sys.stdin.buffer.read()
        return reply.returncode


class Owner:
    def __init__(self, fixture, name, kernel, scope):
        result = fixture.root / f"{name}-ready.json"
        self.child = subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).resolve()), "--owner",
             str(fixture.se), str(fixture.home), str(fixture.repo), str(result)],
            stdin=subprocess.PIPE,
            env=fixture.env,
        )
        scope.callback(self.close)
        self.birth = Birth(kernel, self.child.pid, scope)
        reply = wait_json(result, seconds=100)
        assert reply["exit"] == 0, reply
        self.runtime = json.loads(reply["stdout"])

    def close(self):
        if not self.child.stdin.closed:
            self.child.stdin.close()
        self.child.wait(timeout=105)

    def leave(self):
        self.close()
        assert self.child.returncode == 0 and self.birth.exited(), "owner exit was not witnessed"
        return time.monotonic()


def binding(fixture, owner, state, generation):
    runtime = fixture.ok("status")["runtime"]
    assert runtime["state"] == "running", runtime
    assert runtime["generation"] == generation, runtime
    assert runtime["spawner"] == {
        "pid": owner.pid, "birth": str(owner.start), "state": state,
    }, runtime
    return runtime


def wait_for_grace(fixture, owner, generation):
    until = time.monotonic() + 25
    while time.monotonic() < until:
        runtime = fixture.ok("status")["runtime"]
        if runtime["spawner"]["state"] == "reclaim-window":
            return binding(fixture, owner, "reclaim-window", generation)
        time.sleep(0.4)
    raise AssertionError("the runtime never reported the witnessed owner exit")


def check_liveness(processes):
    for role, process in processes.items():
        assert not process.exited(), f"{role} exited before the grace window ended"


def review(fixture, receipt):
    kernel = windows_process_api()
    marker = "Saved probe work survives automatic runtime drain."
    source = fixture.repo / "work.txt"
    source.write_text(marker, encoding="utf-8")
    endpoint = fixture.home / "endpoint.json"
    cleanup_path = fixture.home / "runtime-spawner-close.json"
    with ExitStack() as scope:
        observer = Birth(kernel, os.getpid(), scope)
        original = Owner(fixture, "original", kernel, scope)
        generation = original.runtime["generation"]
        host_pid = original.runtime["process"]["pid"]
        binding(fixture, original.birth, "watching", generation)
        fixture.launch()
        provider = wait_json(fixture.repo / "provider-ready.json")
        roles = {"runtime": host_pid, "provider": provider["native_root_pid"],
                 "provider_helper": provider["helper_pid"]}
        assert len(set(roles.values())) == len(roles), roles
        processes = {role: Birth(kernel, pid, scope) for role, pid in roles.items()}
        message = fixture.mail("send", fixture.agent, marker)["message_id"]

        competing = fixture.call("up", "--spawner", observer.argument())
        assert competing.returncode != 0 and b"reclaim window" in competing.stdout + competing.stderr
        live_until = time.monotonic() + 5
        while time.monotonic() < live_until:
            binding(fixture, original.birth, "watching", generation)
            assert not original.birth.exited() and not cleanup_path.exists()
            check_liveness(processes)
            time.sleep(0.5)
        receipt["live_owner_kept_binding"] = True

        original.leave()
        wait_for_grace(fixture, original.birth, generation)
        check_liveness(processes)
        replacement = Owner(fixture, "replacement", kernel, scope)
        assert replacement.runtime["process"]["pid"] == host_pid
        assert replacement.runtime["generation"] == generation
        binding(fixture, replacement.birth, "watching", generation)
        receipt["reclaimed_same_generation"] = True

        witnessed_exit = replacement.leave()
        wait_for_grace(fixture, replacement.birth, generation)
        receipt["replacement_exit_observed"] = True
        print("Exact replacement owner exited. Waiting for the production reclaim window.", flush=True)
        while time.monotonic() - witnessed_exit < GRACE_SECONDS - 2:
            check_liveness(processes)
            assert endpoint.is_file() and not cleanup_path.exists(), "drain began inside the reclaim window"
            time.sleep(0.5)
        remaining = witnessed_exit + GRACE_SECONDS + 105 - time.monotonic()
        assert processes["runtime"].exited(max(0, round(remaining * 1000))), "bound runtime never exited"
        elapsed = time.monotonic() - witnessed_exit
        assert elapsed >= GRACE_SECONDS - 2, f"drain ended after only {elapsed:.3f} seconds"
        assert all(process.exited() for process in processes.values()), "a tracked native birth remains live"
        assert not endpoint.exists(), "runtime exit left its endpoint published"
        receipt["seconds_after_exit"] = round(elapsed, 3)
        receipt["native_exits"] = {role: {"pid": process.pid, "birth": str(process.start)}
                                  for role, process in processes.items()}

        closed = wait_json(cleanup_path)
        row, = [row for row in closed["stops"] if row["session"] == fixture.session]
        assert closed["generation"] == generation and closed["resources_closed"] and not closed["pending"]
        assert row["witness"] is not None and row["reason"] is None, row
        visible = fixture.ok("status")["runtime"]["spawner_cleanup"]
        assert visible["complete"] and not visible["pending"], visible
        assert any(row["session"] == fixture.session and row["stopped"] for row in visible["sessions"])
        denied = fixture.call("up", "--spawner", observer.argument())
        reply = denied.stdout + denied.stderr
        assert denied.returncode != 0 and fixture.session.encode() in reply, reply
        assert b"--home" in reply and b"without --spawner" in reply and not endpoint.exists(), reply
        assert fixture.ok("up")["state"] == "running"
        assert marker in json.dumps(fixture.mail("read", message))
        assert source.read_text(encoding="utf-8") == marker
        receipt["saved_work_reopened_unbound"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "win32", "native Windows is required"
    assert os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted", (
        "Use a disposable Windows VM that supports detached startup."
    )
    for name in list(os.environ):
        if name.upper().startswith(("SE_", "STATEENGINE_", "CODEX", "CLAUDE", "ANTHROPIC_", "OPENAI_")):
            del os.environ[name]
    output = args.output.resolve()
    output.mkdir()
    protect(output)
    for variable in ("APPDATA", "LOCALAPPDATA"):
        profile = output / variable.lower()
        profile.mkdir()
        os.environ[variable] = str(profile)
    image = output / "se.exe"
    shutil.copyfile(args.se.resolve(strict=True), image)
    assert image.stat().st_nlink == 1, "the probe needs a single-link candidate image"
    receipt = {"schema": "spawner-bound-home-review/v1", "result": "failed"}
    fixture = None
    try:
        fixture = Fixture(image, output / "fixture")
        review(fixture, receipt)
        fixture.close()
        receipt["result"] = "passed"
    finally:
        try:
            if fixture is not None and (fixture.home / "endpoint.json").exists():
                fixture.close()
        finally:
            write_json(output / "receipt.json", receipt)
            print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--owner":
        raise SystemExit(drive_owner(*sys.argv[2:]))
    main()
