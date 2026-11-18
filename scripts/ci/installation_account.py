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


def windows_registered_acl(path):
    """Inspect owner and every allow ACE without starting another shell."""
    from ctypes import wintypes

    class AclSize(ctypes.Structure):
        _fields_ = [("count", wintypes.DWORD), ("used", wintypes.DWORD), ("free", wintypes.DWORD)]

    class AceHeader(ctypes.Structure):
        _fields_ = [("kind", ctypes.c_ubyte), ("flags", ctypes.c_ubyte), ("size", wintypes.WORD)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                                            ctypes.POINTER(pointer), ctypes.POINTER(pointer),
                                            ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAclInformation.argtypes = [pointer, pointer, wintypes.DWORD, ctypes.c_int]
    advapi.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    advapi.IsValidSid.argtypes = [pointer]
    advapi.GetLengthSid.argtypes = [pointer]
    advapi.GetLengthSid.restype = wintypes.DWORD
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(pointer)]
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer

    def sid_text(sid):
        if not sid or not advapi.IsValidSid(sid):
            raise RuntimeError("registration has an invalid security identifier")
        text = pointer()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text.value)
        finally:
            kernel.LocalFree(text)

    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise RuntimeError("linked registration")
    owner, acl, descriptor = pointer(), pointer(), pointer()
    status = advapi.GetNamedSecurityInfoW(str(path), 1, 0x1 | 0x4, ctypes.byref(owner), None,
                                          ctypes.byref(acl), None, ctypes.byref(descriptor))
    if status:
        raise OSError(status, "native registration security read failed")
    try:
        admins = {"S-1-5-18", "S-1-5-32-544"}
        if sid_text(owner) not in admins:
            raise RuntimeError("registration owner is not administrator")
        if not acl:
            raise RuntimeError("registration has an unrestricted access list")
        size = AclSize()
        if not advapi.GetAclInformation(acl, ctypes.byref(size), ctypes.sizeof(size), 2):
            raise ctypes.WinError(ctypes.get_last_error())
        for index in range(size.count):
            ace = pointer()
            if not advapi.GetAce(acl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            header = AceHeader.from_address(ace.value)
            if header.kind in (1, 2, 6, 7, 10, 12, 13, 15):
                continue
            if header.kind not in (0, 5, 9, 11) or header.size < 16:
                raise RuntimeError("registration contains an unsupported access rule")
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            offset = 8
            if header.kind in (5, 11):
                flags = ctypes.c_uint32.from_address(ace.value + 8).value
                if flags & ~3:
                    raise RuntimeError("registration contains an unsupported access rule")
                offset = 12 + (16 if flags & 1 else 0) + (16 if flags & 2 else 0)
            if offset + 8 > header.size:
                raise RuntimeError("registration contains a malformed access rule")
            sid = pointer(ace.value + offset)
            subauthorities = ctypes.c_ubyte.from_address(sid.value + 1).value
            if (offset + 8 + 4 * subauthorities > header.size or not advapi.IsValidSid(sid)
                    or offset + advapi.GetLengthSid(sid) > header.size):
                raise RuntimeError("registration contains a malformed security identifier")
            if mask & 0x500D0156 and sid_text(sid) not in admins:
                raise RuntimeError("registration permits non-administrator writes")
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)


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
        windows_registered_acl(path)
        windows_registered_acl(path.parent)
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
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Account registration check timed out; retry the test") from error
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
