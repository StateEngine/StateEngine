"""Protects uninstall: unavailable native carrier preserves a working installation.

Run from an ordinary local Windows desktop console, outside agent ancestry, with
exclusive use of an isolated test account. The caller prepares an actual public
installation and, for `unavailable`, sets that account's CurrentUser policy to
Restricted and restores it afterward. This judge changes no policy or Defender
setting. `quarantined` requires a matching actual Defender detection and native
image absence; it never deletes an image to manufacture that precondition.
The unavailable case requires a started carrier's exit; an earlier preparation
failure leaves its intended execution-policy condition unqualified.

The private fixture JSON contains archive, candidate, archive_sha256 (se.exe,
uninstall.ps1 and manifest.json), home, localappdata, and preserved paths keyed
history/configuration/provider_login. It contains no credentials. Each invocation
uses one fresh installation; removal is through its archive's public uninstall.ps1.

If the standard user cannot read Defender exclusions, fixture.defender_witness
names a fresh shared directory. First run this judge elevated with
--observe-defender DIRECTORY; then run the normal consumer as the standard user.
The observer answers fresh before/after challenges using read-only native CIM.
Its bounded wait ends automatically; it changes no Defender or policy setting.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import uuid

from windows_startup_cli import standard_user


POWERSHELL_JSON_PREFIX = (
    "$ErrorActionPreference='Stop'; "
    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
    "$OutputEncoding=[Console]::OutputEncoding; "
)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def observation(path):
    path = Path(path)
    try:
        value = path.lstat()
    except FileNotFoundError:
        return {"state": "absent"}
    assert stat.S_ISREG(value.st_mode), f"not a regular fixture file: {path}"
    assert not value.st_file_attributes & 1024, f"linked fixture file: {path}"
    assert value.st_size <= 512 * 1024 * 1024, "fixture file exceeds hash bound"
    return dict(state="present", sha256=digest(path), bytes=value.st_size,
                device=value.st_dev, inode=value.st_ino)


def user_path():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, kind = winreg.QueryValueEx(key, "Path")
        return dict(state="present", value=value, kind=kind)
    except FileNotFoundError:
        return dict(state="absent")


def carrier_started_refusal(error):
    detail = error.get("detail", {})
    return (detail.get("subject") == "Windows uninstall carrier preparation" and
            "system carrier exited; installation remains unchanged" in detail.get("reason", ""))


def json_results(text):
    """Console line wrapping is contiguous; actual line ends become blank cells."""
    decoder, values, offset = json.JSONDecoder(), [], 0
    while (offset := text.find("{", offset)) >= 0:
        try:
            value, offset = decoder.raw_decode(text, offset)
            values.append(value)
        except ValueError:
            offset += 1
    return values


def console_position():
    class Coord(ctypes.Structure):
        _fields_ = [("x", ctypes.c_short), ("y", ctypes.c_short)]

    class Rect(ctypes.Structure):
        _fields_ = [("left", ctypes.c_short), ("top", ctypes.c_short),
                    ("right", ctypes.c_short), ("bottom", ctypes.c_short)]

    class Info(ctypes.Structure):
        _fields_ = [("size", Coord), ("cursor", Coord), ("attributes", ctypes.c_ushort),
                    ("window", Rect), ("maximum", Coord)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetStdHandle.restype = ctypes.c_void_p
    kernel.GetConsoleScreenBufferInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Info)]
    handle, info = kernel.GetStdHandle(-11), Info()
    assert kernel.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)), \
        "genuine console stdout required; do not redirect this consumer"
    return handle, info.size.x, info.size.y, info.cursor.x, info.cursor.y


def console_read(handle, width, offset, length):
    class Coord(ctypes.Structure):
        _fields_ = [("x", ctypes.c_short), ("y", ctypes.c_short)]

    assert 0 <= length <= 1024 * 1024, "console capture exceeds read bound"
    if not length:
        return ""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ReadConsoleOutputCharacterW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
        ctypes.c_ulong, Coord, ctypes.POINTER(ctypes.c_ulong)]
    buffer, count = ctypes.create_unicode_buffer(length + 1), ctypes.c_ulong()
    assert kernel.ReadConsoleOutputCharacterW(handle, buffer, length,
        Coord(offset % width, offset // width), ctypes.byref(count))
    assert count.value == length, "console capture was incomplete"
    return buffer[:length]


def default_defender(value):
    assert value["antivirus"] is True and value["realtime"] is True
    for key in ("paths", "processes", "extensions"):
        entries = value[key]
        assert isinstance(entries, list), "Defender exclusion read is not an array"
        if any(isinstance(x, str) and x.casefold().startswith("n/a") for x in entries):
            raise RuntimeError("Defender exclusions unreadable; use the separate elevated observer")
        assert all(x is None or isinstance(x, str) for x in entries), "Defender exclusion read malformed"
        assert not any(x for x in entries), "Defender exclusions present; default-Defender case not reached"
    return value


def read_witness(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and not info.st_file_attributes & 1024
    assert info.st_size <= 65536, "Defender witness exceeds read bound"
    return json.loads(path.read_text(encoding="utf-8-sig"))


def checked_witness(value, request):
    assert all(value[k] == request[k] for k in ("nonce", "phase", "candidate", "archive_sha256")), \
        "Defender witness does not match this fresh request"
    assert value["privileged"] is True and value["observer_pid"] != os.getpid(), \
        "separate privileged Defender observer not reached"
    assert request["requested_ns"] <= value["started_ns"] <= value["finished_ns"] <= time.monotonic_ns(), \
        "Defender witness does not bracket this phase"
    return default_defender(value)


def observe_defender(directory, timeout):
    assert sys.platform == "win32" and ctypes.windll.shell32.IsUserAnAdmin(), \
        "Defender observer requires a separate elevated Windows process"
    directory = directory.resolve(strict=True)
    powershell = str(Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    for phase in ("before", "after"):
        request_path = directory / (phase + ".request.json")
        response_path = directory / (phase + ".response.json")
        assert not response_path.exists(), "use a fresh Defender witness directory"
        deadline = time.monotonic() + timeout
        while not request_path.exists():
            assert time.monotonic() < deadline, "Defender observer request deadline"
            time.sleep(.2)
        request = read_witness(request_path)
        assert request["phase"] == phase and isinstance(request["nonce"], str)
        assert request["requested_ns"] <= time.monotonic_ns()
        started = time.monotonic_ns()
        code = POWERSHELL_JSON_PREFIX + (
            "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); "
            "$a=([Security.Principal.WindowsPrincipal]$i).IsInRole("
            "[Security.Principal.WindowsBuiltInRole]::Administrator); if(!$a){throw 'not elevated'}; "
            "$s=Get-MpComputerStatus; "
            "$p=Get-CimInstance -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpPreference; "
            "foreach($n in @('ExclusionPath','ExclusionProcess','ExclusionExtension')){"
            "if(!$p.CimInstanceProperties[$n]){throw 'missing Defender exclusion property'}}; "
            "@{privileged=$a; observer_sid=$i.User.Value; native_pid=$PID; "
            "antivirus=$s.AntivirusEnabled; realtime=$s.RealTimeProtectionEnabled; "
            "paths=@($p.ExclusionPath); processes=@($p.ExclusionProcess); "
            "extensions=@($p.ExclusionExtension)} | ConvertTo-Json -Depth 5 -Compress")
        native = subprocess.run([powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", code],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        (directory / (phase + ".native.stdout")).write_bytes(native.stdout)
        (directory / (phase + ".native.stderr")).write_bytes(native.stderr)
        assert native.returncode == 0, "privileged Defender CIM read failed; raw result retained"
        value = default_defender(json.loads(native.stdout.decode("utf-8-sig")))
        assert value["privileged"] is True
        value.update({k: request[k] for k in ("nonce", "phase", "candidate", "archive_sha256", "requested_ns")})
        value.update(observer_pid=os.getpid(), started_ns=started,
                     finished_ns=time.monotonic_ns())
        temporary = response_path.with_suffix(".pending")
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream)
        os.replace(temporary, response_path)
        print("Defender " + phase + " observation complete", flush=True)


class Judge:
    def __init__(self, args):
        self.args = args
        args.out.mkdir(mode=0o700, exist_ok=False)
        self.result = dict(passed=False, precondition_reached=False, calls=[],
                           expected=args.expect, pid=os.getpid(), parent=os.getppid())
        self.fixture = json.loads(args.fixture.read_text())
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("SE_", "STATEENGINE_", "SECODE_", "CODEX_"))
                    and k not in ("CLAUDECODE", "PSExecutionPolicyPreference")}
        self.env["LOCALAPPDATA"] = self.fixture["localappdata"]
        self.powershell = str(Path(os.environ.get("WINDIR", "C:/Windows")) / "System32" /
                              "WindowsPowerShell/v1.0/powershell.exe")

    def save(self):
        (self.args.out / "result.json").write_text(json.dumps(self.result, indent=2))

    def call(self, argv, timeout=60, console=False):
        stem = self.args.out / f"call-{len(self.result['calls']) + 1:02}"
        started = time.monotonic()
        if console:
            handle, width, height, x, y = console_position()
            origin = y * width + x
            prefix = console_read(handle, width, 0, origin)
        with stem.with_suffix(".stdout").open("wb") as out, \
                stem.with_suffix(".stderr").open("wb") as err:
            # Human mutations inherit the existing real console for all streams.
            # Reading its screen buffer afterward does not substitute a pipe.
            child = subprocess.Popen(argv, env=self.env, **({} if console else
                                     dict(stdout=out, stderr=err)))
            row = dict(argv=argv, pid=child.pid, exit="in-flight")
            self.result["calls"].append(row)
            self.save()
            try:
                row["exit"] = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row["exit"] = "timeout; exact child retained for venue owner"
            row.update(seconds=round(time.monotonic() - started, 3),
                       stdout=stem.with_suffix(".stdout").read_text(encoding="utf-8-sig"),
                       stderr=stem.with_suffix(".stderr").read_text(encoding="utf-8-sig", errors="replace"))
            if console:
                end_handle, end_width, end_height, end_x, end_y = console_position()
                assert (handle, width, height) == (end_handle, end_width, end_height), \
                    "console buffer changed during capture"
                assert end_y < height - 1 and end_y * width + end_x >= origin, \
                    "console scrolled or cursor moved backward; rendered output is unqualified"
                assert console_read(handle, width, 0, origin) == prefix, \
                    "console history changed during capture"
                row["console_output"] = console_read(handle, width, origin,
                                                     end_y * width + end_x - origin)
                row["capture"] = "existing console screen buffer; stdout/stderr merged"
                stem.with_suffix(".console.txt").write_text(row["console_output"], encoding="utf-8")
            self.save()
        assert isinstance(row["exit"], int), f"in-flight native child {child.pid}; do not overlap cleanup"
        return row

    def powershell_json(self, code):
        row = self.call([self.powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
                         "-Command", POWERSHELL_JSON_PREFIX + code], timeout=20)
        assert row["exit"] == 0, "native policy/security read failed; raw result retained"
        return json.loads(row["stdout"])

    def defender(self, phase):
        if self.fixture.get("defender_witness"):
            directory = Path(self.fixture["defender_witness"])
            assert directory.is_absolute() and directory.is_dir()
            request_path = directory / (phase + ".request.json")
            response_path = directory / (phase + ".response.json")
            assert not response_path.exists(), "stale Defender response precedes this consumer"
            request = dict(nonce=uuid.uuid4().hex, phase=phase, candidate=self.fixture["candidate"],
                           archive_sha256=self.fixture["archive_sha256"], requested_ns=time.monotonic_ns())
            temporary = request_path.with_suffix(".pending")
            assert not request_path.exists(), "use a fresh Defender witness directory"
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(request, stream)
            os.replace(temporary, request_path)
            deadline = time.monotonic() + 45
            while not response_path.exists():
                assert time.monotonic() < deadline, "privileged Defender witness not received"
                time.sleep(.2)
            return checked_witness(read_witness(response_path), request)
        value = self.powershell_json(
            "$s=Get-MpComputerStatus; $p=Get-MpPreference; "
            "@{antivirus=$s.AntivirusEnabled; realtime=$s.RealTimeProtectionEnabled; "
            "paths=@($p.ExclusionPath); processes=@($p.ExclusionProcess); "
            "extensions=@($p.ExclusionExtension)} | ConvertTo-Json -Depth 5 -Compress")
        return default_defender(value)

    def run(self):
        f = self.fixture
        self.result["native_user"] = standard_user()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.restype = ctypes.c_void_p
        kernel.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        assert kernel.GetConsoleMode(kernel.GetStdHandle(-10), ctypes.byref(ctypes.c_ulong())), \
            "real native console stdin required"
        archive, home = Path(f["archive"]), Path(f["home"])
        assert archive.is_absolute() and home.is_absolute()
        for name in ("se.exe", "uninstall.ps1", "manifest.json"):
            assert observation(archive / name)["sha256"] == f["archive_sha256"][name]
        image = Path(f["localappdata"]) / "StateEngine/bin/se.exe"
        record = home / "standalone-install.json"
        before_record = observation(record)
        assert before_record["state"] == "present", "actual installed record missing"
        plan = json.loads(record.read_text(encoding="utf-8-sig"))
        assert plan["schema"] == "stateengine-install/v1"
        planned = {x["path"]: x["sha256"] for x in plan["files"]}
        assert len(planned) == len(plan["files"]) and str(image).casefold() in {p.casefold() for p in planned}
        files = {p: observation(p) for p in planned}
        for path, expected in planned.items():
            if self.args.expect == "quarantined" and Path(path) == image:
                assert files[path]["state"] == "absent"
            else:
                assert files[path].get("sha256") == expected, "installed payload differs before test"
        preserve = f["preserved"]
        assert all(k in preserve for k in ("history", "configuration", "provider_login"))
        retained = {k: observation(p) for k, p in preserve.items()}
        assert all(x["state"] == "present" for x in retained.values())
        before_path = user_path()
        self.result.update(before_files=files, before_record=before_record,
                           before_path=before_path, retained=retained, candidate=f["candidate"])
        self.result["defender_before"] = self.defender("before")
        if self.args.expect == "unavailable":
            policy = self.powershell_json(
                "$v=@{}; Get-ExecutionPolicy -List | ForEach-Object {"
                "$v[[string]$_.Scope]=[string]$_.ExecutionPolicy}; $v | ConvertTo-Json -Compress")
            assert (policy["CurrentUser"] == "Restricted" and
                    all(policy[k] == "Undefined" for k in ("MachinePolicy", "UserPolicy"))), \
                "real CurrentUser carrier policy refusal not established"
            self.result["carrier_policy"] = policy
        if self.args.expect == "quarantined":
            detections = self.powershell_json(
                "@(Get-MpThreatDetection | Select-Object ActionSuccess,Resources,InitialDetectionTime,ThreatID) "
                "| ConvertTo-Json -Depth 6 -Compress")
            if isinstance(detections, dict):
                detections = [detections]
            assert any(x.get("ActionSuccess") is True and any(
                str(image).casefold() in str(p).casefold() for p in (x.get("Resources") or []))
                for x in (detections or [])), "actual Defender removal of this installed image not reached"
            self.result["native_defender_detections"] = detections
        else:
            version = self.call([str(image), "--version"])
            assert version["exit"] == 0 and version["stdout"].strip(), "working installation not reached"
        self.result["precondition_reached"] = True
        # Bypass permits only this public test entry. The production carrier must
        # discard its inherited process-policy preference and face CurrentUser policy.
        row = self.call([self.powershell, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", str(archive / "uninstall.ps1"), "--home", str(home), "--json"],
                        timeout=90, console=True)
        self.result["defender_after"] = self.defender("after")
        after_files = {p: observation(p) for p in planned}
        self.result.update(after_files=after_files, after_record=observation(record), after_path=user_path())
        assert {k: observation(p) for k, p in preserve.items()} == retained, "retained user data changed"
        if self.args.expect == "unavailable":
            errors = json_results(row["console_output"])
            assert after_files == files and observation(record) == before_record and user_path() == before_path, \
                "carrier refusal changed installation payload, record or user PATH"
            if row["exit"] == 0 or not any(carrier_started_refusal(x) for x in errors):
                self.result["precondition_reached"] = False
                raise RuntimeError("started-carrier refusal not reached; earlier failures cannot qualify policy denial")
            self.result["carrier_start_and_exit_reached"] = True
            assert self.call([str(image), "--version"])["exit"] == 0, "working retry entry lost"
        else:
            assert row["exit"] == 0, "public uninstall did not complete"
            assert all(x["state"] == "absent" for x in after_files.values())
            assert observation(record)["state"] == "absent"
            values = json_results(row["console_output"])
            assert any(x.get("schema") == "se.uninstall-completion/v1" and x.get("complete") is True
                       for x in values), "no outside completion witness"
            blocks = [x["block"] for x in plan["path_edits"] if x["target"] == "HKCU\\Environment\\Path"]
            if blocks:
                assert len(blocks) == 1 and before_path["state"] == "present"
                old = before_path["value"].split(";")
                assert old.count(blocks[0]) == 1, "isolated recorded PATH entry not reached"
                old.remove(blocks[0])
                after = user_path()
                if old:
                    assert after == dict(state="present", value=";".join(old), kind=before_path["kind"])
                else:
                    assert after["state"] == "absent" or after.get("value") == ""
            else:
                assert user_path() == before_path
            if self.args.expect == "quarantined":
                assert "absent" in row["console_output"].casefold() and "cleanup" in row["console_output"].casefold()
        self.result["passed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--expect", choices=["unavailable", "removed", "quarantined"])
    parser.add_argument("--observe-defender", type=Path)
    parser.add_argument("--observer-timeout", type=int, default=180)
    args = parser.parse_args()
    if args.observe_defender:
        assert 1 <= args.observer_timeout <= 600
        observe_defender(args.observe_defender, args.observer_timeout)
        return 0
    if not all((args.fixture, args.out, args.expect)):
        parser.error("normal consumer requires --fixture, --out and --expect")
    judge = Judge(args)
    try:
        judge.run()
    except (AssertionError, OSError, ValueError, KeyError, RuntimeError) as error:
        judge.result["error"] = str(error)
    judge.save()
    print("Windows uninstall: " + ("1 passed, 0 failed" if judge.result["passed"] else
          "0 passed, 1 failed" if judge.result["precondition_reached"] else "precondition not reached"))
    return 0 if judge.result["passed"] else 1 if judge.result["precondition_reached"] else 2


if __name__ == "__main__":
    sys.exit(main())
