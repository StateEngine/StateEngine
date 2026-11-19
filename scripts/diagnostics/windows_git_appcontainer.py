"""Observe whether a no-network AppContainer can run the installed Git.

The only ACL changes apply to a newly created temporary directory. No user
repository, normal home, or installed executable is modified.
"""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

if os.name != "nt":
    raise RuntimeError("native Windows is required")

kernel = c.WinDLL("kernel32", use_last_error=True)
security = c.WinDLL("advapi32", use_last_error=True)
userenv = c.WinDLL("userenv", use_last_error=True)
HANDLE = w.HANDLE
SIZE_T = c.c_size_t
LPVOID = c.c_void_p

class StartupInfo(c.Structure):
    _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR),
                ("title", w.LPWSTR), ("x", w.DWORD), ("y", w.DWORD),
                ("xsize", w.DWORD), ("ysize", w.DWORD), ("xchars", w.DWORD),
                ("ychars", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
                ("show", w.WORD), ("reserved_len", w.WORD), ("reserved_data", LPVOID),
                ("stdin", HANDLE), ("stdout", HANDLE), ("stderr", HANDLE)]

class StartupInfoEx(c.Structure):
    _fields_ = [("startup", StartupInfo), ("attributes", LPVOID)]

class ProcessInfo(c.Structure):
    _fields_ = [("process", HANDLE), ("thread", HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]

class SecurityCapabilities(c.Structure):
    _fields_ = [("sid", LPVOID), ("capabilities", LPVOID),
                ("capability_count", w.DWORD), ("reserved", w.DWORD)]

userenv.CreateAppContainerProfile.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, LPVOID, w.DWORD, c.POINTER(LPVOID)]
userenv.CreateAppContainerProfile.restype = c.c_long
userenv.DeleteAppContainerProfile.argtypes = [w.LPCWSTR]
userenv.DeleteAppContainerProfile.restype = c.c_long
security.ConvertSidToStringSidW.argtypes = [LPVOID, c.POINTER(w.LPWSTR)]
security.ConvertSidToStringSidW.restype = w.BOOL
security.FreeSid.argtypes = [LPVOID]
security.FreeSid.restype = LPVOID
kernel.LocalFree.argtypes = [LPVOID]
kernel.LocalFree.restype = LPVOID
kernel.InitializeProcThreadAttributeList.argtypes = [LPVOID, w.DWORD, w.DWORD, c.POINTER(SIZE_T)]
kernel.InitializeProcThreadAttributeList.restype = w.BOOL
kernel.UpdateProcThreadAttribute.argtypes = [LPVOID, w.DWORD, SIZE_T, LPVOID, SIZE_T, LPVOID, LPVOID]
kernel.UpdateProcThreadAttribute.restype = w.BOOL
kernel.DeleteProcThreadAttributeList.argtypes = [LPVOID]
kernel.CreateProcessW.argtypes = [w.LPCWSTR, w.LPWSTR, LPVOID, LPVOID, w.BOOL, w.DWORD,
                                  LPVOID, w.LPCWSTR, c.POINTER(StartupInfo), c.POINTER(ProcessInfo)]
kernel.CreateProcessW.restype = w.BOOL
kernel.WaitForSingleObject.argtypes = [HANDLE, w.DWORD]
kernel.WaitForSingleObject.restype = w.DWORD
kernel.GetExitCodeProcess.argtypes = [HANDLE, c.POINTER(w.DWORD)]
kernel.GetExitCodeProcess.restype = w.BOOL
kernel.TerminateProcess.argtypes = [HANDLE, w.UINT]
kernel.TerminateProcess.restype = w.BOOL
kernel.CloseHandle.argtypes = [HANDLE]
kernel.CloseHandle.restype = w.BOOL


def checked(result, operation):
    if not result:
        raise OSError(c.get_last_error(), operation)


def host_run(args):
    env = os.environ.copy()
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "NUL", "GIT_TERMINAL_PROMPT": "0"})
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr}")
    return result.stdout.strip()


def run_container(image, arguments, sid, home, output):
    # Exactly the two listed inherited handles cross the process boundary.
    with open(os.devnull, "rb") as null, open(output, "wb") as capture:
        import msvcrt
        null_handle = msvcrt.get_osfhandle(null.fileno())
        output_handle = msvcrt.get_osfhandle(capture.fileno())
        os.set_handle_inheritable(null_handle, True)
        os.set_handle_inheritable(output_handle, True)
        handles = (HANDLE * 2)(null_handle, output_handle)
        caps = SecurityCapabilities(sid, None, 0, 0)
        size = SIZE_T()
        kernel.InitializeProcThreadAttributeList(None, 2, 0, c.byref(size))
        storage = c.create_string_buffer(size.value)
        checked(kernel.InitializeProcThreadAttributeList(storage, 2, 0, c.byref(size)), "initialize attributes")
        try:
            checked(kernel.UpdateProcThreadAttribute(storage, 0, 0x20009, c.byref(caps), c.sizeof(caps), None, None), "set AppContainer")
            checked(kernel.UpdateProcThreadAttribute(storage, 0, 0x20002, c.byref(handles), c.sizeof(handles), None, None), "set handle list")
            startup = StartupInfoEx()
            startup.startup.cb = c.sizeof(startup)
            startup.startup.flags = 0x100
            startup.startup.stdin = null_handle
            startup.startup.stdout = output_handle
            startup.startup.stderr = output_handle
            startup.attributes = c.cast(storage, LPVOID)
            process = ProcessInfo()
            line = c.create_unicode_buffer(subprocess.list2cmdline([str(image), *map(str, arguments)]))
            system = os.environ["SystemRoot"]
            values = {
                "SystemRoot": system,
                "WINDIR": system,
                "PATH": str(image.parent) + ";" + str(Path(system) / "System32"),
                "TEMP": str(home), "TMP": str(home),
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "NUL",
                "GIT_CONFIG_SYSTEM": "NUL", "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
            }
            env = c.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in sorted(values.items(), key=lambda pair: pair[0].lower())) + "\0\0")
            started = kernel.CreateProcessW(str(image), line, None, None, True, 0x80000 | 0x8000000 | 0x400,
                                             c.cast(env, LPVOID), str(home), c.byref(startup.startup), c.byref(process))
            if not started:
                return {"started": False, "error": c.get_last_error()}
            try:
                wait = kernel.WaitForSingleObject(process.process, 30000)
                if wait == 0x102:
                    checked(kernel.TerminateProcess(process.process, 1), "terminate exact timed-out probe")
                    if kernel.WaitForSingleObject(process.process, 5000) != 0:
                        raise OSError(c.get_last_error(), "reap exact timed-out probe")
                    return {"started": True, "timed_out": True}
                if wait != 0:
                    raise OSError(c.get_last_error(), "wait for container probe")
                code = w.DWORD()
                checked(kernel.GetExitCodeProcess(process.process, c.byref(code)), "read probe exit")
                return {"started": True, "exit_code": code.value}
            finally:
                kernel.CloseHandle(process.thread)
                kernel.CloseHandle(process.process)
        finally:
            kernel.DeleteProcThreadAttributeList(storage)
            os.set_handle_inheritable(null_handle, False)
            os.set_handle_inheritable(output_handle, False)


def main():
    name = "StateEngine.GitProbe." + uuid.uuid4().hex
    sid = LPVOID()
    hr = userenv.CreateAppContainerProfile(name, "Git probe", "Temporary process isolation observation", None, 0, c.byref(sid))
    if hr < 0:
        raise OSError(hr, "create AppContainer profile")
    try:
        text_sid = w.LPWSTR()
        checked(security.ConvertSidToStringSidW(sid, c.byref(text_sid)), "format AppContainer SID")
        try:
            sid_text = text_sid.value
        finally:
            kernel.LocalFree(c.cast(text_sid, LPVOID))
        with tempfile.TemporaryDirectory(prefix="se-git-probe-") as temp:
            root = Path(temp)
            source = root / "source"
            allowed = root / "allowed.git"
            denied = root / "denied.git"
            host_run(["git", "init", "--initial-branch=main", str(source)])
            host_run(["git", "-C", str(source), "-c", "user.name=Fixture", "-c", "user.email=fixture.invalid", "commit", "--allow-empty", "-m", "synthetic"])
            oid = host_run(["git", "-C", str(source), "rev-parse", "HEAD"])
            host_run(["git", "clone", "--bare", "--no-hardlinks", str(source), str(allowed)])
            host_run(["git", "clone", "--bare", "--no-hardlinks", str(source), str(denied)])
            host_run(["git", "--git-dir", str(allowed), "cat-file", "-e", oid])
            host_run(["git", "--git-dir", str(denied), "cat-file", "-e", oid])
            exec_path = Path(host_run(["git", "--exec-path"]))
            image = exec_path / "git.exe"
            if not image.is_file():
                image = Path(shutil.which("git") or "")
            if not image.is_file():
                raise RuntimeError("installed Git executable was not found")
            host_run(["icacls", str(root), "/grant", f"*{sid_text}:(RX)"])
            host_run(["icacls", str(allowed), "/grant", f"*{sid_text}:(OI)(CI)(RX)", "/T"])
            results = {}
            for label, directory in [("allowed", allowed), ("denied", denied)]:
                capture = root / (label + ".log")
                results[label] = run_container(image, ["--git-dir", directory, "cat-file", "-e", oid], sid, allowed, capture)
                raw = capture.read_bytes()
                results[label]["output_bytes"] = len(raw)
                results[label]["output_truncated"] = len(raw) > 4096
                results[label]["output"] = raw[:4096].decode("utf-8", errors="replace")
            results["scope"] = "AppContainer with no capabilities; copied synthetic Git repositories; job limits not exercised"
            print(json.dumps(results, indent=2), flush=True)
    finally:
        free_error = security.FreeSid(sid)
        deletion = userenv.DeleteAppContainerProfile(name)
        if free_error or deletion < 0:
            raise OSError(deletion, "AppContainer probe cleanup failed")

if __name__ == "__main__":
    main()
