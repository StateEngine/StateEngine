"""Host-only rootless engine access. Candidate bytes never select host commands."""
import json
import hashlib
import os
from pathlib import Path
import pwd
import re
import subprocess
import stat
import time
import uuid

ACCOUNT = "stateengine-ci"
ENGINE_DOOR = "/usr/local/libexec/stateengine-ci-engine"
GIB = 1024 ** 3


def account_args(*args):
    user = pwd.getpwnam(ACCOUNT)
    if user.pw_uid == 0 or user.pw_dir != "/var/lib/stateengine-ci":
        raise RuntimeError("dedicated account identity differs")
    prefix = [] if os.getuid() == user.pw_uid else ["sudo", "-n", "-u", ACCOUNT]
    return [*prefix, "env", "-i", "PATH=/usr/bin:/bin",
            "HOME=" + user.pw_dir, "LANG=C.UTF-8", f"XDG_RUNTIME_DIR=/run/user/{user.pw_uid}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{user.pw_uid}/bus", *args]


def engine_args(*args):
    # The dedicated controller gets only this fixed root-owned worker-engine door.
    if pwd.getpwuid(os.getuid()).pw_name == "stateengine-ci-controller":
        return ["sudo", "-n", "-u", ACCOUNT, ENGINE_DOOR, *args]
    if args[:1] == ("--stateengine-create-transaction",):
        return account_args(ENGINE_DOOR, *args)
    return account_args("podman", *args)


def command(*args, input=None, timeout=90):
    result = subprocess.run(engine_args(*args), input=input, capture_output=True, timeout=timeout,
                            cwd="/", close_fds=True)
    if result.returncode:
        raise RuntimeError(f"engine {args[0]} refused (exit {result.returncode}): " +
                           result.stderr.decode(errors="replace")[-4000:])
    return result.stdout


def capacity(memory):
    available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                         if line.startswith("MemAvailable:"))) * 1024
    if memory > 18 * GIB or memory <= 0 or available < 34 * GIB + memory:
        raise RuntimeError("infrastructure unavailable: preserve 34 GiB after bounded allocation")
    return available


class Container:
    def __init__(self, image, memory=18 * GIB, cpus=12, pids=512, work=12 * GIB, deadline=900, journal=None):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
            raise ValueError("immutable image ID required")
        if (type(cpus) is not int or not 1 <= cpus <= 12 or type(pids) is not int or
                not 16 <= pids <= 512 or not 1 <= deadline <= 1800 or
                not 1024**2 <= work <= 12 * GIB):
            raise ValueError("job resource limits exceed the admitted bounds")
        capacity(memory)
        policy = Path("/etc/stateengine-ci/seccomp.json")
        info = policy.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("administrator-owned job seccomp policy unavailable")
        self.policy_sha256 = hashlib.sha256(policy.read_bytes()).hexdigest()
        self.expected = {"memory.max": str(memory), "memory.swap.max": "0", "pids.max": str(pids),
                         "cpu.max": f"{cpus * 100000} 100000"}
        self.name = "se-ci-" + uuid.uuid4().hex
        self.id = None
        self.journal = journal
        self.deadline = deadline
        self.storage = {"/work": work, "/home": 3 * GIB, "/t": GIB,
                        "/tmp": 2 * GIB, "/run": 16 * 1024**2}
        self.started = time.monotonic()
        args = ["create", "--name", self.name, "--label", "stateengine.shadow=true", "--pull=never",
                "--user", "1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--security-opt=seccomp=" + str(policy),
                "--uidmap=0:0:65536", "--gidmap=0:0:65536",
                "--pid=private", "--ipc=private", "--cgroupns=private", "--http-proxy=false",
                "--network=none", "--read-only", "--read-only-tmpfs=false", "--log-driver=none",
                "--memory", str(memory), "--memory-swap", str(memory), "--cpus", str(cpus),
                "--pids-limit", str(pids), "--stop-timeout", "5", "--timeout", str(deadline), "--workdir=/work",
                "--env=HOME=/home/ci", "--env=TMPDIR=/t/j", "--env=TMP=/t/j", "--env=TEMP=/t/j"]
        for path, size in (("/work", work), ("/home", 3 * GIB), ("/t", GIB),
                           ("/tmp", 2 * GIB), ("/run", 16 * 1024**2)):
            args += ["--tmpfs", f"{path}:rw,nosuid,nodev,mode=1777,size={size}"]
        if self.journal:
            self.journal.intent(self.name)
        try:
            raw = (self.journal.create(self.name, [*args, image, "hold"]) if self.journal else
                   command(*args, image, "hold").decode().strip())
            if not re.fullmatch(r"[a-f0-9]{64}", raw):
                raise RuntimeError("engine returned an invalid container identity")
            self.id = raw
            command("start", self.id)
            if self.journal:
                self.journal.observe(self.name, self.inspect())
            command("exec", self.id, "mkdir", "--parents", "--mode=700", "--", "/home/ci", "/t/j")
            command("exec", self.id, "chmod", "0700", "--", "/home/ci", "/t/j")
            directories = command("exec", self.id, "stat", "--format=%u:%g:%a", "/home/ci", "/t/j")
            if directories.decode().splitlines() != ["1000:1000:700", "1000:1000:700"]:
                raise RuntimeError("private HOME/TMP owner or permissions differ: " + repr(directories))
            self.proof = self.admit()
        except BaseException:
            if self.id is None:
                # Creation may have succeeded before its response failed. The
                # unpredictable controller-owned name recovers only that object.
                exists = subprocess.run(engine_args("container", "exists", self.name),
                                        capture_output=True, timeout=30, cwd="/", close_fds=True)
                if exists.returncode == 0:
                    value, = json.loads(command("inspect", self.name))
                    if value["Name"].lstrip("/") != self.name or not re.fullmatch(r"[a-f0-9]{64}", value["Id"]):
                        raise RuntimeError("partial creation identity is unproved")
                    self.id = value["Id"]
                elif exists.returncode != 1:
                    raise RuntimeError("partial creation cleanup is unmeasured")
            self.close()
            raise

    def inspect(self):
        value, = json.loads(command("inspect", self.id))
        if value["Id"] != self.id or value["Name"].lstrip("/") != self.name:
            raise RuntimeError("container identity changed")
        return value

    def admit(self):
        outside = self.inspect()
        proof = json.loads(command("exec", self.id, "python3", "/opt/box/probe.py"))
        if proof["uid"] != 1000 or proof["gid"] != 1000:
            raise RuntimeError("nonzero explicit job identity not witnessed")
        if (set(proof["capabilities"]) != {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} or
                any(int(v, 16) for v in proof["capabilities"].values())):
            raise RuntimeError("job capability set is nonzero")
        if proof["no_new_privs"] != "1" or proof["seccomp"] != "2":
            raise RuntimeError("NoNewPrivs or seccomp unavailable")
        if proof["limits"] != self.expected or proof["interfaces"] != ["lo"]:
            raise RuntimeError("native limits or isolated network differ")
        if (set(proof["namespaces"]) != {"user", "pid", "mnt", "net", "ipc", "uts", "cgroup"} or
                any(proof["namespaces"][n] == os.readlink("/proc/self/ns/" + n)
                    for n in proof["namespaces"])):
            raise RuntimeError("host namespace shared")
        if not any(line.split()[1] == "/" and "ro" in line.split()[3].split(",")
                   for line in proof["mounts"]):
            raise RuntimeError("root filesystem is not read-only")
        host = outside["HostConfig"]
        if (not host["ReadonlyRootfs"] or host["Privileged"] or host.get("Binds") or
                host["NetworkMode"] != "none" or host["Memory"] != int(self.expected["memory.max"]) or
                host["PidsLimit"] != int(self.expected["pids.max"]) or outside["Config"]["User"] != "1000:1000"):
            raise RuntimeError("outside engine configuration differs")
        for path, size in self.storage.items():
            mount = [line.split() for line in proof["mounts"] if line.split()[1] == path]
            if (len(mount) != 1 or mount[0][2] != "tmpfs" or
                    not {"nosuid", "nodev"}.issubset(mount[0][3].split(","))):
                raise RuntimeError("bounded private writable mount missing: " + path)
            if proof["storage"][path] != size:
                raise RuntimeError("native writable storage size differs: " + path)
        proof["engine_pid"] = outside["State"]["Pid"]
        proof["container_id"] = self.id
        proof["seccomp_profile_sha256"] = self.policy_sha256
        return proof

    def close(self):
        if self.id is None:
            return
        identity = self.id
        outside = self.inspect()
        if self.journal:
            self.journal.observe(self.name, outside)
        command("rm", "--force", "--time=5", identity)
        observed = subprocess.run(engine_args("container", "exists", identity), capture_output=True,
                                  timeout=30, cwd="/", close_fds=True)
        if observed.returncode != 1:
            raise RuntimeError("owned container removal is unproved")
        if self.journal:
            end = time.monotonic() + 15
            while True:
                try:
                    self.journal.closed(self.name)
                    break
                except RuntimeError:
                    if time.monotonic() >= end:
                        raise
                    time.sleep(.1)
        self.id = None
