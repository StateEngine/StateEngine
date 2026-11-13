#!/usr/bin/env python3
"""Exercise the real rootless boundary with synthetic host objects; no PR execution."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tarfile
import time

from controller import exclusive, write
from engine import Container, command, engine_args, admits
from transport import execute, export


BOUNDARY = r'''
import ctypes,errno,json,os,pathlib,socket,subprocess,sys
v=json.loads(sys.argv[1]); refusals=[]
for path in v['paths']:
 try:
  data=pathlib.Path(path).read_bytes()
 except (OSError,ValueError): refusals.append(path)
 else: raise RuntimeError('host path readable: '+path)
os.symlink(v['paths'][0],'/tmp/host-link')
try: pathlib.Path('/tmp/host-link').read_bytes()
except OSError: pass
else: raise RuntimeError('host link readable')
for family,address in v['listeners']:
 with socket.socket(family,socket.SOCK_STREAM)as s:
  s.settimeout(.5)
  try: s.connect(tuple(address)if isinstance(address,list)else address)
  except OSError: pass
  else: raise RuntimeError('host listener reached')
for device in ('/dev/kvm','/dev/fuse','/dev/nbd0','/dev/sda'):
 assert not pathlib.Path(device).exists(),device
for path in ('/run/user/1004/podman/podman.sock','/var/run/docker.sock'):
 assert not pathlib.Path(path).exists(),path
for name in os.environ:
 assert not any(x in name.upper()for x in ('TOKEN','SECRET','PASSWORD','SSH_AUTH','GITHUB','AWS_')),name
for name in os.listdir('/proc/self/fd'):
 try: value=os.readlink('/proc/self/fd/'+name)
 except FileNotFoundError: continue
 assert not any(p in value for p in v['paths']),value
libc=ctypes.CDLL(None,use_errno=True)
assert libc.setuid(0)==-1 and ctypes.get_errno()==errno.EPERM
assert libc.ptrace(16,v['pid'],None,None)==-1
clone_args=(ctypes.c_ulonglong*11)(); clone_args[0]=0x10000000
assert libc.syscall(435,ctypes.byref(clone_args),ctypes.sizeof(clone_args))==-1 and ctypes.get_errno()==errno.ENOSYS
assert subprocess.run(['unshare','--user','--map-root-user','sh','-c','id'],capture_output=True).returncode!=0
assert subprocess.run(['mount','-t','tmpfs','none','/tmp'],capture_output=True).returncode!=0
assert subprocess.run(['nsenter','--target',str(v['pid']),'--mount','--','true'],capture_output=True).returncode!=0
own=subprocess.run(['strace','-o','/tmp/own.trace','/bin/true'],capture_output=True)
assert own.returncode==0,own.stderr
print(json.dumps({'host_refusals':len(refusals),'own_child_strace':own.returncode,'caps':next(l for l in pathlib.Path('/proc/self/status').read_text().splitlines()if l.startswith('CapEff:'))}))
'''

RESOURCES = r'''
import json,os,pathlib,subprocess,time
before=pathlib.Path('/sys/fs/cgroup/cpu.stat').read_text()
busy="import time; end=time.monotonic()+2\nwhile time.monotonic()<end: pass"
workers=[subprocess.Popen(['python3','-c',busy]) for _ in range(2)]
for worker in workers: assert worker.wait()==0
after=pathlib.Path('/sys/fs/cgroup/cpu.stat').read_text()
children=[]; exhausted=False
try:
 for _ in range(100):
  try: children.append(subprocess.Popen(['/bin/sleep','10']))
  except OSError: exhausted=True;break
finally:
 for child in children: child.terminate()
 for child in children: child.wait()
assert exhausted,'pids limit not enforced'
storage=False
try:
 with open('/work/fill','wb')as f:
  for _ in range(64): f.write(b'x'*1024**2)
except OSError as e:
 assert e.errno==28,e
 storage=True
assert storage,'storage cap not enforced'
os.unlink('/work/fill')
print(json.dumps({'cpu_before':before,'cpu_after':after,'children':len(children),'pids_exhausted':exhausted,'storage_exhausted':storage}))
'''


def check(image, output):
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = {}
    owner = output / "owner-only"
    owner.mkdir(mode=0o700)
    secret = owner / "synthetic-key"
    secret.write_bytes(os.urandom(32))
    secret.chmod(0o600)
    before = (hashlib.sha256(secret.read_bytes()).hexdigest(), stat.S_IMODE(secret.stat().st_mode))
    host = subprocess.Popen(["/bin/sleep", "600"], close_fds=True)
    sockets = []
    try:
        with exclusive():
            addresses = []
            for family, address in ((socket.AF_INET, ("127.0.0.1", 0)), (socket.AF_INET6, ("::1", 0))):
                listener = socket.socket(family, socket.SOCK_STREAM)
                listener.bind(address)
                listener.listen()
                listener.setblocking(False)
                sockets.append(listener)
                addresses.append((family, list(listener.getsockname())))
            # Probe only the machine's own source address, never an external listener.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect(("192.0.2.1", 9))
                local = route.getsockname()[0]
            lan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            lan.bind((local, 0)); lan.listen(); lan.setblocking(False)
            sockets.append(lan); addresses.append((socket.AF_INET, list(lan.getsockname())))
            unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix.bind(str(owner / "engine.sock")); unix.listen(); unix.setblocking(False)
            sockets.append(unix); addresses.append((socket.AF_UNIX, str(owner / "engine.sock")))
            details = {"paths": [str(secret), str(owner / "../owner-only/synthetic-key"),
                       f"/proc/{host.pid}/root{secret}"], "pid": host.pid, "listeners": addresses}
            box = Container(image, memory=512*1024**2, cpus=1, pids=32, work=16*1024**2, deadline=90)
            try:
                write(output / "admission.json", box.proof)
                results["boundary"] = execute(box, ["python3", "-c", BOUNDARY, json.dumps(details)], output / "boundary.log")
                if not results["boundary"]["success"]:
                    raise RuntimeError("boundary canary failed; preserve its first failure")
                results["resources"] = execute(box, ["python3", "-c", RESOURCES], output / "resources.log")
                if not results["resources"]["success"]:
                    raise RuntimeError("resource canary failed")
                resource = json.loads((output / "resources.log").read_text())
                previous = dict(line.split() for line in resource["cpu_before"].splitlines())
                later = dict(line.split() for line in resource["cpu_after"].splitlines())
                if int(later["nr_throttled"]) <= int(previous["nr_throttled"]):
                    raise RuntimeError("CPU throttling was not observed")
                forge = "import sys; print('{\"success\":true,\"attempt\":999,\"checkout\":\"forged\"}'); sys.exit(7)"
                results["forged_outcome"] = execute(box, ["python3", "-c", forge], output / "forged.log")
                if results["forged_outcome"]["success"] or results["forged_outcome"]["exit_code"] != 7:
                    raise RuntimeError("candidate output overrode the outside outcome")
                malicious = output / "malicious-source.tar"
                with tarfile.open(malicious, "w") as archive:
                    entry = tarfile.TarInfo("prefix/../../host-escape")
                    entry.size = 6
                    archive.addfile(entry, io.BytesIO(b"escape"))
                with malicious.open("rb") as source:
                    results["source_traversal"] = execute(box, ["python3", "/opt/box/runner.py", "source"],
                        output / "source-traversal.log", stdin=source)
                if results["source_traversal"]["success"] or (output / "host-escape").exists():
                    raise RuntimeError("source traversal was accepted")
                setup = "import os; os.makedirs('/work/source',exist_ok=True); os.symlink('/etc/passwd','/work/source/tests.tar.zst')"
                assert execute(box, ["python3", "-c", setup], output / "artifact-setup.log")["success"]
                try:
                    export(box, "archive", output / "rejected-archive")
                except RuntimeError:
                    results["artifact_symlink"] = {"refused": True}
                else:
                    raise RuntimeError("linked artifact exported")
                try:
                    export(box, "../host-path", output / "never-created")
                except KeyError:
                    results["artifact_path"] = {"refused": True}
                else:
                    raise RuntimeError("arbitrary artifact selector accepted")
                # Sparse file establishes the size refusal without spending disk/RAM.
                large = "import os; p='/work/source/tests.tar.zst'; os.unlink(p); f=open(p,'wb'); f.truncate(2**30+1); f.close()"
                assert execute(box, ["python3", "-c", large], output / "large-setup.log")["success"]
                try:
                    export(box, "archive", output / "rejected-large")
                except RuntimeError:
                    results["artifact_size"] = {"refused": True}
                else:
                    raise RuntimeError("oversized artifact exported")
            finally:
                box.close()
            # Each destructive canary owns a fresh namespace and cgroup.
            box = Container(image, memory=256*1024**2, cpus=1, pids=32, work=16*1024**2, deadline=30)
            try:
                results["oom"] = execute(box, ["python3", "-c", "b=bytearray(1024**3); print(len(b))"], output / "oom.log")
                outside = box.inspect()
                results["oom"]["outside_oom"] = outside["State"]["OOMKilled"]
                # The exec process may be OOM-killed while the idle init survives.
                events = command("exec", box.id, "cat", "/sys/fs/cgroup/memory.events").decode()
                results["oom"]["memory_events"] = events
                if results["oom"]["success"] or int(dict(line.split() for line in events.splitlines())["oom_kill"]) < 1:
                    raise RuntimeError("native memory OOM not observed")
            finally:
                box.close()
            box = Container(image, memory=256*1024**2, cpus=1, pids=32, work=16*1024**2, deadline=30)
            try:
                results["output"] = execute(box, ["python3", "-c", "import os; os.write(1,b'x'*65536)"], output / "overflow.log", limit=1024)
                if results["output"]["reason"] != "output exceeds byte budget" or box.id is not None:
                    raise RuntimeError("output overflow did not retire exact container")
            finally:
                box.close()
            box = Container(image, memory=256*1024**2, cpus=1, pids=32, work=16*1024**2, deadline=30)
            try:
                results["cancel"] = execute(box, ["/bin/sleep", "20"], output / "cancel.log", deadline=1)
                if results["cancel"]["reason"] != "deadline exceeded" or box.id is not None:
                    raise RuntimeError("canceled job retained container")
            finally:
                box.close()
            # Kill only the retained supervisor child. Conmon's native deadline
            # must stop the namespace without Python finally/atexit assistance.
            orphan = output / "supervisor.json"
            child = subprocess.Popen([sys.executable, __file__, "orphan", "--image", image, "--output", str(orphan)], close_fds=True)
            try:
                end = time.monotonic()+20
                while not orphan.exists():
                    if child.poll() is not None or time.monotonic() >= end:
                        raise RuntimeError("supervisor-loss fixture did not start")
                    time.sleep(.1)
                identity = json.loads(orphan.read_text())
                child.kill(); child.wait(timeout=5)
                end = time.monotonic()+25
                while True:
                    outside, = json.loads(command("inspect", identity["id"]))
                    if outside["Id"] != identity["id"] or outside["Name"].lstrip("/") != identity["name"]:
                        raise RuntimeError("supervisor-loss identity changed")
                    if not outside["State"]["Running"]:
                        break
                    if time.monotonic() >= end:
                        raise RuntimeError("native supervisor-loss deadline failed")
                    time.sleep(.2)
                command("rm", "--force", "--time=5", identity["id"])
                absent = subprocess.run(engine_args("container", "exists", identity["id"]), capture_output=True, timeout=10)
                if absent.returncode != 1:
                    raise RuntimeError("supervisor-loss removal not observed")
                results["supervisor_loss"] = {"stopped_outside": True, "removed": True}
            finally:
                if child.poll() is None:
                    child.terminate(); child.wait(timeout=10)
            for listener in sockets:
                try:
                    connection, _ = listener.accept()
                except BlockingIOError:
                    continue
                connection.close()
                raise RuntimeError("host listener received candidate connection")
            if host.poll() is not None or before != (hashlib.sha256(secret.read_bytes()).hexdigest(), stat.S_IMODE(secret.stat().st_mode)):
                raise RuntimeError("host canary changed")
            results["host_survived"] = True
            results["reserve_bytes"] = admits(256*1024**2)
            try:
                admits(18*1024**3)
                results["full_job_capacity"] = True
            except RuntimeError:
                results["full_job_capacity"] = False
            # A missing immutable image is a safe unavailable-engine fixture; no
            # real runtime endpoint or other account is taken offline.
            try:
                Container("sha256:" + "0"*64, memory=256*1024**2)
            except RuntimeError:
                results["unavailable"] = {"refused": True, "hosted_dispatch": "unchanged; no claim of promotion fallback"}
            else:
                raise RuntimeError("unavailable image reported usable")
            results["success"] = True
    except Exception as error:
        results["success"] = False
        results["error"] = type(error).__name__ + ": " + str(error)
    finally:
        for listener in sockets:
            listener.close()
        if host.poll() is None:
            host.terminate(); host.wait(timeout=5)
        write(output / "result.json", results)
    print(json.dumps(results))
    return 0 if results["success"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["check", "orphan"])
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "orphan":
        box = Container(args.image, memory=256*1024**2, cpus=1, pids=32, work=16*1024**2, deadline=20)
        write(args.output, {"id": box.id, "name": box.name})
        while True:
            time.sleep(1)
    raise SystemExit(check(args.image, args.output))
