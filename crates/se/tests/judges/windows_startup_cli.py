r"""Bug: 7734bbdc — normal-user cold startup stalled without a useful reason or log.

Run from a real local standard-user desktop session in the isolated Windows VM,
with an initialized private test home, saved test agent and its installed exact-candidate binary.
This does not create an account, install a product, change configuration, or
choose the cause of a pending startup. The pending case requires its caller to
establish and name that real condition; an unreached condition never passes.

  python windows_startup_cli.py --se C:\test\bin\se.exe --home C:\test\state \
    --project PROJECT --agent AGENT --expect success --out C:\test\new-results
  python windows_startup_cli.py ... --expect pending --waiting-for "listener"

Timeouts retain the exact in-flight CLI for the VM owner to diagnose. This judge
never kills by name or hides an incomplete shutdown behind a successful result.
"""

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def standard_user():
    if os.name != "nt":
        raise RuntimeError("REFUSE: native Windows user precondition not reached")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    secur = ctypes.WinDLL("secur32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                         ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        def information(kind):
            value, length = wintypes.DWORD(), wintypes.DWORD()
            if not advapi.GetTokenInformation(token, kind, ctypes.byref(value),
                                              ctypes.sizeof(value), ctypes.byref(length)):
                raise ctypes.WinError(ctypes.get_last_error())
            return value.value
        elevation_type, elevated = information(18), information(20)
    finally:
        kernel.CloseHandle(token)
    session = wintypes.DWORD()
    if not kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        raise ctypes.WinError(ctypes.get_last_error())
    name, size = ctypes.create_unicode_buffer(512), wintypes.ULONG(512)
    if not secur.GetUserNameExW(2, name, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    computer, size = ctypes.create_unicode_buffer(512), wintypes.DWORD(512)
    if not kernel.GetComputerNameW(computer, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    local = name.value.split("\\", 1)[0].casefold() == computer.value.casefold()
    result = dict(account=name.value, local=local, session=session.value,
                  elevation_type=elevation_type, elevated=bool(elevated))
    if elevation_type != 1 or elevated or session.value == 0 or not local:
        raise RuntimeError(f"REFUSE: ordinary local standard-user session not reached: {result}")
    return result


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


class Probe:
    def __init__(self, args):
        self.args = args
        self.out = args.out
        self.out.mkdir(mode=0o700, exist_ok=False)
        self.rows = []
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("SE_", "STATEENGINE_", "SECODE_", "CODEX_"))
                    and key != "CLAUDECODE"}

    def call(self, *operation):
        argv = [str(self.args.se), "--home", str(self.args.home)]
        if operation[0] != "down":
            argv.extend(["--project", self.args.project])
        argv.extend(["--json", *operation])
        stem = self.out / f"{len(self.rows) + 1:02}-{operation[0]}"
        started = time.monotonic()
        with stem.with_suffix(".stdout").open("wb") as out, \
                stem.with_suffix(".stderr").open("wb") as err:
            child = subprocess.Popen(argv, env=self.env, stdout=out, stderr=err)
            try:
                code = child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                code = "timeout; exact CLI retained for owner diagnosis"
        row = dict(argv=argv, pid=child.pid, exit=code,
                   seconds=round(time.monotonic() - started, 3),
                   stdout=stem.with_suffix(".stdout").read_text(errors="replace"),
                   stderr=stem.with_suffix(".stderr").read_text(errors="replace"))
        self.rows.append(row)
        (self.out / "commands.json").write_text(json.dumps(self.rows, indent=2))
        if not isinstance(code, int):
            raise RuntimeError(f"REFUSE: in-flight CLI retained; see {stem}")
        return row

    def advertised_log(self, error):
        public = "\n".join(strings(error)).replace("/", "\\").casefold()
        root = self.args.home.resolve(strict=True)
        for path in root.rglob("*"):
            if path.is_symlink() or path.suffix not in (".log", ".txt", ".jsonl"):
                continue
            actual = path.resolve(strict=True)
            if not actual.is_relative_to(root) or not actual.is_file():
                continue
            if str(path).replace("/", "\\").casefold() not in public:
                continue
            with actual.open("rb") as stream:
                first = stream.read(65536)
            if first:
                return dict(path=str(path), readable=True, nonempty=True)
        raise AssertionError("pending startup advertises no readable nonempty log in its own home")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("se", "home", "out"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--task", default="Reply that the startup regression reached the provider.")
    parser.add_argument("--expect", choices=["success", "pending"], required=True)
    parser.add_argument("--waiting-for")
    args = parser.parse_args()
    if args.expect == "pending" and not args.waiting_for:
        parser.error("--expect pending requires the independently established --waiting-for condition")
    probe = Probe(args)
    result = dict(passed=False, expected=args.expect, cleanup="not reached")
    try:
        result["native_user"] = standard_user()
        reply = probe.call("launch", args.agent, "--detach", "--task", args.task)
        value = json.loads(reply["stdout"])
        if args.expect == "success":
            assert reply["exit"] == 0, "ordinary standard-user startup did not complete"
            status = probe.call("status")
            view = json.loads(status["stdout"])
            assert status["exit"] == 0 and view["runtime"]["state"] == "running"
            assert view["runtime"]["process"]["pid"] > 0, "no actual published owner process"
            result["runtime"] = view["runtime"]
        else:
            assert reply["exit"] != 0 and value["code"] == "runtime-start-pending", \
                "REFUSE: real pending-startup condition was not reached"
            human = value["message"] + "\n" + value["remedy"]["text"]
            assert args.waiting_for.casefold() in human.casefold(), \
                "pending output hides the actual condition behind a generic startup message"
            result["waiting_for"] = args.waiting_for
            result["log"] = probe.advertised_log(value)
        result["passed"] = True
    except (AssertionError, OSError, ValueError, KeyError, RuntimeError) as error:
        result["error"] = str(error)
    finally:
        # Do not submit another startup or shutdown while a timed-out CLI is
        # retained. The VM owner needs that exact failure, not overlapping calls.
        if args.expect == "pending":
            result["cleanup"] = "caller must release its owned pending condition and run public down"
        elif probe.rows and isinstance(probe.rows[-1]["exit"], int):
            try:
                down = probe.call("down")
                result["cleanup"] = down["exit"]
                if down["exit"] != 0:
                    result["passed"] = False
            except (OSError, RuntimeError) as error:
                result["cleanup"] = str(error)
                result["passed"] = False
        (probe.out / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
