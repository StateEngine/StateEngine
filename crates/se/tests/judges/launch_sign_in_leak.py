"""Protects: a launching terminal's Claude sign-in reaches that launch's child only.

Run against an isolated binary with --se IMAGE --output NEW_DIRECTORY. A native
Claude double reports signed in only while the synthetic token is in its
environment, and records whether each child it starts saw the token.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from mail_cli import Fixture

TOKEN = "test-token-not-real-0000"
ENVIRONMENT = "CLAUDE_CODE_OAUTH_TOKEN"
SIGNED_IN_LINE = """if a.get(1).map(String::as_str)==Some("auth") {println!(r#"{{"loggedIn":true}}"#);return;}"""
STUB = """if a.get(1).map(String::as_str)==Some("auth") {
let ok=std::env::var("@NAME@").as_deref()==Ok("@VALUE@");
if ok {println!(r#"{{"loggedIn":true}}"#);} else {println!(r#"{{"loggedIn":false}}"#);std::process::exit(1);}
return;}
{use std::io::Write;let seen=std::env::var("@NAME@").as_deref()==Ok("@VALUE@");
let mut f=std::fs::OpenOptions::new().create(true).append(true).open("child-env.log").unwrap();
writeln!(f,"child_has_token={}",seen).unwrap();}""".replace("@NAME@", ENVIRONMENT).replace("@VALUE@", TOKEN)


def install_double(fixture):
    source = fixture.root / "provider.rs"
    text = source.read_text()
    assert SIGNED_IN_LINE in text, "the shared double changed its sign-in probe"
    # The current provider qualification contract needs this version.
    source.write_text(text.replace(SIGNED_IN_LINE, STUB).replace("2.1.287", "2.1.318"))
    executable = fixture.root / ("provider.exe" if os.name == "nt" else "provider")
    subprocess.run(["rustc", "--edition=2024", str(source), "-o", str(executable)],
                   stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=60)


def child_lines(fixture):
    path = fixture.repo / "child-env.log"
    return path.read_text().splitlines() if path.exists() else []


def files_with_token(fixture, locked=None):
    """Files holding the token. A running Windows host locks some of its files;
    with `locked` given they are listed there instead of read, and only the
    after-shutdown scan, which reads everything, may call the home clean."""
    roots = [fixture.home, *fixture.root.glob("call-*")]
    found = []
    for root in roots:
        paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and not p.is_symlink()]
        for path in paths:
            try:
                data = path.read_bytes()
            except PermissionError:
                if locked is None:
                    raise
                locked.append(str(path))
                continue
            if TOKEN.encode() in data:
                found.append(str(path))
    return found


def windows_environment(pid):
    """Read another process's environment block from its PEB (x64 layout)."""
    import ctypes
    from ctypes import wintypes as w
    kernel, ntdll = ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("ntdll")
    kernel.OpenProcess.restype = w.HANDLE
    kernel.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = (ctypes.c_void_p * 6)()
        status = ntdll.NtQueryInformationProcess(w.HANDLE(handle), 0, info, ctypes.sizeof(info), None)
        assert status == 0, f"NtQueryInformationProcess {status:#x}"
        def read(address, size):
            buffer = ctypes.create_string_buffer(size)
            ok = kernel.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, None)
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            return buffer.raw
        peb = info[1]
        parameters = int.from_bytes(read(peb + 0x20, 8), "little")
        environment = int.from_bytes(read(parameters + 0x80, 8), "little")
        size = int.from_bytes(read(parameters + 0x3F0, 8), "little")
        return read(environment, size).decode("utf-16-le", errors="replace").split("\0")
    finally:
        kernel.CloseHandle(handle)


def windows_host_environments_with_token(fixture):
    query = ("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq '"
             + str(fixture.se).replace("'", "''") + "' } | ForEach-Object { $_.ProcessId }")
    listed = subprocess.run(["powershell", "-NoProfile", "-Command", query],
                            capture_output=True, text=True, check=True, timeout=60)
    owner = str(fixture.root / "owner").lower()
    seen, leaked = 0, []
    for pid in (int(line) for line in listed.stdout.split() if line.strip().isdecimal()):
        try:
            environment = windows_environment(pid)
        except OSError:
            continue
        if any(owner in entry.lower() for entry in environment):
            seen += 1
            if any(TOKEN in entry for entry in environment):
                leaked.append(str(pid))
    return seen, leaked


def host_environments_with_token(fixture):
    if os.name == "nt":
        return windows_host_environments_with_token(fixture)
    owner = f"HOME={fixture.root / 'owner'}".encode()
    seen, leaked = 0, []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if Path(os.readlink(entry / "exe")) != fixture.se:
                continue
            environ = (entry / "environ").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if owner in environ.split(b"\0"):
            seen += 1
            if TOKEN.encode() in environ:
                leaked.append(entry.name)
    return seen, leaked


def run(image, output):
    if os.name == "nt":
        # Cargo hard-links its outputs on Windows; the runtime pins only a
        # single-link file, so launch a private copy as an installed image is.
        import shutil
        single = output.parent / "image" / image.name
        single.parent.mkdir()
        shutil.copyfile(image, single)
        image = single
    fixture = Fixture(image, output)
    install_double(fixture)
    host = None
    try:
        if os.name == "nt":
            # Hosted Windows runners may refuse job breakaway, so own the host in
            # the foreground as the other Windows fixtures do.
            log = (fixture.root / "host.log").open("wb")
            host = subprocess.Popen([str(fixture.se), "--json", "--home", str(fixture.home), "up", "--foreground"],
                                    env=fixture.env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 120
            while fixture.ok("status")["runtime"]["state"] != "running":
                assert host.poll() is None and time.monotonic() < deadline, (
                    "foreground host did not start", (fixture.root / "host.log").read_text(errors="replace"))
                time.sleep(0.5)
        else:
            fixture.ok("up")
        fixture.env[ENVIRONMENT] = TOKEN
        try:
            fixture.launch()
        finally:
            del fixture.env[ENVIRONMENT]
        assert "child_has_token=true" in child_lines(fixture), (
            "a terminal launch must hand its sign-in to the child", child_lines(fixture))
        print("ok 1 - terminal launch passes sign-in and the child receives the token", flush=True)

        fixture.ok("--project", fixture.project, "stop", fixture.agent)
        before = len(child_lines(fixture))
        refused = fixture.call("--project", fixture.project, "launch", fixture.agent,
                               "--detach", "--task", "second launch")
        text = (refused.stdout + refused.stderr).decode(errors="replace").lower()
        assert refused.returncode != 0 and "sign" in text, (refused.returncode, text)
        assert "child_has_token=true" not in child_lines(fixture)[before:], "the token outlived its launch"
        print("ok 2 - the next launch without the token is refused as signed out", flush=True)

        locked = [] if os.name == "nt" else None
        leaks = files_with_token(fixture, locked)
        assert not leaks, ("token found in", leaks)
        if locked:
            print(f"# {len(locked)} files held open by the running host are read after shutdown", flush=True)
        hosts, leaked = host_environments_with_token(fixture)
        assert not leaked, ("host process environment holds the token", leaked)
        print(f"ok 3 - token absent from data home, call output and {hosts} host environments", flush=True)
    finally:
        fixture.call("down")
        if host is not None:
            host.wait(timeout=60)
    assert not files_with_token(fixture), "token appeared during shutdown"
    print("ok 4 - token absent after shutdown", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    run(args.se, args.output)
