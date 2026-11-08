"""Refuse account-wide installation tests without an administrator's account registration.

This is test plumbing only. The product still resolves and locks the native OS
profile. Provision disposable CI/VM accounts once, never a developer's account.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import stat
import subprocess


def registration(identity):
    if os.name == "nt":
        common = powershell("[Environment]::GetFolderPath('CommonApplicationData')")
        return Path(common) / "StateEngineTestAccounts" / (identity + ".json")
    return Path("/etc/stateengine-test-accounts") / (identity + ".json")


def windows_shell():
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer)):
        raise RuntimeError("native Windows directory unavailable")
    return str(Path(buffer.value) / "System32/WindowsPowerShell/v1.0/powershell.exe")


def powershell(script, *args):
    result = subprocess.run([windows_shell(), "-NoProfile", "-NonInteractive", "-Command",
                             script, *args], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError("native account registration: " + result.stderr.strip())
    return result.stdout.strip()


def account():
    if os.name != "nt":
        import pwd
        entry = pwd.getpwuid(os.geteuid())
        return str(entry.pw_uid), Path(entry.pw_dir)
    # Query the same current-token profile used by NativeInstallationClaim.
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    userenv.GetUserProfileDirectoryW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        profile, size = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
        if not userenv.GetUserProfileDirectoryW(token, profile, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(token)
    identity = powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    return identity, Path(profile.value)


def registered(identity, profile):
    path = registration(identity)
    if os.name != "nt":
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise RuntimeError("account registration directory must be administrator-owned and not writable by the test account")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
                raise RuntimeError("account registration must be one bounded regular file")
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("account registration must be administrator-owned and not writable by the test account")
            data = stream.read(4097)
    else:
        # Reject inherited user write access too; ownership alone is insufficient.
        literal = str(path).replace("'", "''")
        powershell("$ErrorActionPreference='Stop'; foreach($p in @('" + literal + "', '" + str(path.parent).replace("'", "''") + "')) { "
                   "if ((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'linked registration'}; "
                   "$a=Get-Acl -LiteralPath $p; $admins=@('S-1-5-18','S-1-5-32-544'); "
                   "if ($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $admins) {throw 'registration owner is not administrator'}; "
                   "foreach($r in $a.Access) {if($r.AccessControlType -eq 'Allow' -and "
                   "$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $admins -and "
                   "([int]$r.FileSystemRights -band 0x000D0156)) {throw 'registration permits non-administrator writes'}} }")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
            raise RuntimeError("account registration must be one bounded regular file")
        with path.open("rb") as stream:
            data = stream.read(4097)
    if len(data) > 4096:
        raise RuntimeError("account registration exceeds its finite bound")
    value = json.loads(data)
    if value != {"schema": "stateengine-test-account/v1", "identity": identity, "profile": str(profile)}:
        raise RuntimeError("account registration does not match the native account and profile")


def require():
    try:
        identity, profile = account()
        registered(identity, profile)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise RuntimeError("REFUSED account-wide installation test: use an administrator-registered dedicated OS test account; "
                           "HOME and --home do not isolate the native installation lock. " + str(error)) from error


def provision(identity, profile):
    if os.name != "nt" and os.geteuid() != 0:
        raise RuntimeError("administrator required to register a dedicated test account")
    profile = Path(profile)
    if os.name == "nt":
        import re
        if not re.fullmatch(r"S-[0-9-]+", identity):
            raise ValueError("native account SID required")
        powershell("$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); "
                   "if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'administrator required'}")
    elif not identity.isdecimal():
        raise ValueError("native numeric account UID required")
    path = registration(identity)
    value = {"schema": "stateengine-test-account/v1", "identity": identity, "profile": str(profile)}
    if path.exists():
        registered(identity, profile)
        return
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if os.name == "nt":
        windows_acl(path.parent, directory=True)
    else:
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise RuntimeError("account registration directory must be private to administrators")
    # Creation never replaces a prior registration or follows its final symlink.
    with path.open("x") as stream:
        json.dump(value, stream)
    if os.name == "nt":
        windows_acl(path)
    else:
        path.chmod(0o644)
    registered(identity, profile)


def windows_acl(path, directory=False):
    kind = "DirectorySecurity" if directory else "FileSecurity"
    literal = str(path).replace("'", "''")
    powershell("$ErrorActionPreference='Stop'; $a=New-Object Security.AccessControl." + kind + "; "
               "$a.SetAccessRuleProtection($true,$false); "
               "$admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'); $a.SetOwner($admins); "
               "foreach($s in @('S-1-5-18','S-1-5-32-544')) { $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
               "[Security.Principal.SecurityIdentifier]::new($s),'FullControl','Allow')) }; "
               "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
               "[Security.Principal.SecurityIdentifier]::new('S-1-5-11'),'ReadAndExecute','Allow')); "
               "Set-Acl -LiteralPath '" + literal + "' -AclObject $a")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "provision"))
    parser.add_argument("--identity")
    parser.add_argument("--profile")
    args = parser.parse_args()
    if args.action == "check":
        require()
    else:
        native_identity, native_profile = account()
        provision(args.identity or native_identity, args.profile or native_profile)
