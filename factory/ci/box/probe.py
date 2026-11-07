"""Trusted, pre-source native observations; no candidate imports."""
import json
import os
from pathlib import Path
import subprocess


def observations():
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    limits = {name: Path("/sys/fs/cgroup", name).read_text().strip()
              for name in ("cpu.max", "memory.max", "memory.swap.max", "pids.max")}
    mounts = Path("/proc/mounts").read_text().splitlines()
    return {"uid": os.getuid(), "gid": os.getgid(),
            "capabilities": {k: status[k].strip() for k in
                             ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
            "no_new_privs": status["NoNewPrivs"].strip(), "seccomp": status["Seccomp"].strip(),
            "namespaces": {n: os.readlink("/proc/self/ns/" + n)
                           for n in ("user", "pid", "mnt", "net", "ipc", "uts", "cgroup")},
            "limits": limits, "mounts": mounts,
            "environment_names": sorted(os.environ),
            "open_fds": sorted(os.listdir("/proc/self/fd")),
            "storage": {path: os.statvfs(path).f_blocks * os.statvfs(path).f_frsize
                        for path in ("/work", "/home", "/t", "/tmp", "/run")},
            "uid_map": Path("/proc/self/uid_map").read_text(),
            "gid_map": Path("/proc/self/gid_map").read_text(),
            "interfaces": sorted(os.listdir("/sys/class/net")),
            "routes": Path("/proc/net/route").read_text(),
            "versions": {tool: subprocess.check_output(command, text=True).splitlines()[0]
                         for tool, command in {
                             "rust": ["rustc", "--version"], "nextest": ["cargo", "nextest", "--version"],
                             "python": ["python3", "--version"], "node": ["node", "--version"]}.items()}}


if __name__ == "__main__":
    print(json.dumps(observations()))
