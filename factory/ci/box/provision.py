#!/usr/bin/env python3
"""Provision the dedicated, locked Linux shadow-CI account (administrator only)."""
import json
import hashlib
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess

ACCOUNT = "stateengine-ci"
HOME = Path("/var/lib/stateengine-ci")


def seccomp_policy():
    """Keep the installed default, restricting only creation of nested user namespaces."""
    original = Path("/usr/share/containers/seccomp.json").read_bytes()
    policy = json.loads(original)
    if policy["defaultAction"] != "SCMP_ACT_ERRNO":
        raise RuntimeError("installed seccomp default is not deny-by-default")
    retained = []
    for rule in policy["syscalls"]:
        rule["names"] = [n for n in rule["names"] if n not in ("clone", "clone3", "unshare")]
        if rule["names"]:
            retained.append(rule)
    for name in ("clone", "unshare"):
        retained.append({"names": [name], "action": "SCMP_ACT_ALLOW", "args": [
            {"index": 0, "value": 0x10000000, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}]})
    # clone3 places flags behind a pointer, which classic seccomp cannot inspect.
    # ENOSYS preserves the ordinary libc clone fallback; its flags remain filtered.
    retained.append({"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38})
    policy["syscalls"] = retained
    encoded = (json.dumps(policy, sort_keys=True) + "\n").encode()
    directory = Path("/etc/stateengine-ci")
    directory.mkdir(mode=0o755, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("CI policy directory is linked or writable by non-administrators")
    path = directory / "seccomp.json"
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("CI seccomp policy ownership differs")
        if path.read_bytes() != encoded:
            raise RuntimeError("CI seccomp policy differs; retain it for explicit maintainer review")
    else:
        with path.open("xb") as stream:
            stream.write(encoded)
        path.chmod(0o644)
    return {"installed_default_sha256": hashlib.sha256(original).hexdigest(),
            "job_policy_sha256": hashlib.sha256(encoded).hexdigest()}


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=90,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})


def provision():
    if os.geteuid() != 0:
        raise RuntimeError("administrator required to provision the dedicated account")
    for tool in ("podman", "newuidmap", "newgidmap", "loginctl", "systemctl"):
        if not shutil.which(tool):
            raise RuntimeError(f"required installed tool unavailable: {tool}")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise RuntimeError("cgroup v2 is required; no global host settings were changed")
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        if HOME.exists() or HOME.is_symlink():
            raise RuntimeError("unowned existing CI home; refusing adoption")
        command("useradd", "--create-home", "--home-dir", str(HOME),
                "--shell", "/usr/sbin/nologin", "--user-group", ACCOUNT)
        account = pwd.getpwnam(ACCOUNT)
    if account.pw_uid == 0 or account.pw_dir != str(HOME) or account.pw_shell != "/usr/sbin/nologin":
        raise RuntimeError("existing CI account does not match the admitted locked profile")
    if os.getgrouplist(ACCOUNT, account.pw_gid) != [account.pw_gid]:
        raise RuntimeError("CI account has supplementary groups; refusing admission")
    if command("passwd", "--status", ACCOUNT).stdout.split()[1] != "L":
        raise RuntimeError("CI account password is not locked")
    info = HOME.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid:
        raise RuntimeError("CI home is linked, not a directory, or owned by another user")
    HOME.chmod(0o700)
    for filename in ("/etc/subuid", "/etc/subgid"):
        ranges = [line.split(":") for line in Path(filename).read_text().splitlines()
                  if line.startswith(ACCOUNT + ":")]
        if len(ranges) != 1 or int(ranges[0][1]) < 65536 or int(ranges[0][2]) < 65536:
            raise RuntimeError(f"dedicated subordinate ID range unavailable in {filename}")
    command("loginctl", "enable-linger", ACCOUNT)
    command("systemctl", "start", f"user@{account.pw_uid}.service")
    runtime = Path(f"/run/user/{account.pw_uid}")
    if runtime.stat().st_uid != account.pw_uid or not (runtime / "bus").is_socket():
        raise RuntimeError("dedicated user manager and runtime bus unavailable")
    policy = seccomp_policy()
    return {"account": ACCOUNT, "uid": account.pw_uid, "gid": account.pw_gid,
            "home": str(HOME), "runtime": str(runtime), "password_locked": True,
            "shell": account.pw_shell,
            "containers_started": False, "seccomp": policy}


if __name__ == "__main__":
    print(json.dumps(provision(), indent=2))
