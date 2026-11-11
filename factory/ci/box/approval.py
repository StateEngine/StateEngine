#!/usr/bin/python3 -I
"""Fixed root owner for approval of reviewed main pushes."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import uuid

BOX = Path("/usr/local/lib/stateengine-box-ci/factory/ci/box")
sys.path.insert(0, str(BOX))
from approval_source import current_main, fetch_main, main_source
from build import build
from dispatch import trusted
from engine import account_args
from github_binding import GitHub, policy_paths

CONFIG = Path("/etc/stateengine-ci/main-approval.json")
LIVE = Path("/etc/stateengine-ci/self-hosted.json")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def replace(path, data, mode=0o644):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".approval-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def record(path, value, group=None):
    replace(path, (json.dumps(value, indent=2) + "\n").encode(), 0o640 if group is not None else 0o600)
    if group is not None:
        os.chown(path, 0, group)


def git(repo, *arguments, output=None):
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *arguments],
                            stdout=output or subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, close_fds=True, timeout=180)
    if result.returncode:
        raise RuntimeError("trusted source object could not be read")
    return result.stdout


def source_policy(repo, source):
    entries = {}
    for row in git(repo, "ls-tree", "-r", "-z", source).split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        entries[name.decode()] = metadata.split()[0].decode()
    policy = {}
    for path in sorted(policy_paths(entries)):
        if entries[path] not in {"100644", "100755"}:
            raise ValueError("main policy input is not a regular file: " + path)
        policy[path] = hashlib.sha256(git(repo, "show", source + ":" + path)).hexdigest()
    return policy


def installed_host_code(repo, source, paths, previous):
    # Merged workload inputs can advance automatically. Host executable changes
    # still require maintainer installation of the reviewed bytes first.
    entrypoints = {"factory/ci/self-hosted/hook.py": "/usr/local/libexec/stateengine-ci-hook",
                  "factory/ci/box/approval.py": "/usr/local/libexec/stateengine-ci-approve-main",
                  "factory/ci/box/worker-engine.py": "/usr/local/libexec/stateengine-ci-engine",
                  "factory/ci/box/idle.py": "/usr/local/libexec/stateengine-ci-idle",
                  "factory/ci/self-hosted/stateengine-actions-runner.service":
                      "/etc/systemd/system/stateengine-actions-runner.service"}
    for path in paths.keys() | previous.keys():
        executable = path.endswith(".py") and not Path(path).name.startswith("test_")
        if (path.startswith(("factory/ci/box/", "factory/ci/self-hosted/"))
                and (executable or path in entrypoints or Path(path).name in {"Containerfile", "hook.js"})):
            if path not in paths:
                raise ValueError("removed host tools require maintainer installation: " + path)
            targets = [BOX.parent.parent.parent / path]
            if path in entrypoints:
                targets.append(Path(entrypoints[path]))
            expected = git(repo, "show", source + ":" + path)
            for installed in targets:
                info = installed.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                        or installed.read_bytes() != expected):
                    raise ValueError("reviewed host tools require maintainer installation: " + path)


def cleanup(directory):
    """Remove only completed preparation staging; keep reports and native logs."""
    staging = directory / "image/staging.json"
    if staging.exists():
        value = json.loads(staging.read_text())
        context = Path(value["context"])
        if context.parent != Path("/var/lib/stateengine-ci") or not context.name.startswith("bootstrap-"):
            raise ValueError("image staging identity is outside the builder")
        info = context.lstat()
        if (info.st_dev, info.st_ino, info.st_uid) != (value["device"], value["inode"], value["uid"]):
            raise ValueError("completed image staging identity changed")
        script = ("import json,os,shutil,sys; p=sys.argv[1]; v=json.loads(sys.argv[2]); s=os.lstat(p); "
                  "assert [s.st_dev,s.st_ino,s.st_uid]==v; shutil.rmtree(p)")
        subprocess.run(account_args("python3", "-c", script, str(context),
            json.dumps([info.st_dev, info.st_ino, info.st_uid])), check=True, timeout=180, close_fds=True)
    for path in (directory / "source.git", directory / "image/inputs"):
        if path.exists():
            shutil.rmtree(path)
    for path in (directory / "source.tar", directory / "dependencies/dependencies.tar.gz"):
        if path.exists():
            path.unlink()
    record(directory / "staging-cleaned.json", {"completed": True})


def worker(arguments, log):
    with log.open("xb") as stream:
        process = subprocess.Popen(arguments, stdout=stream, stderr=subprocess.STDOUT, close_fds=True)
        try:
            code = process.wait(timeout=1900)
        except BaseException:
            if process.poll() is None:
                # This exact child remains unreaped, so its PID cannot be reused.
                observed = Path("/proc", str(process.pid), "cmdline").read_bytes().split(b"\0")
                if str(BOX / "approval_cache.py").encode() in observed:
                    process.terminate()
                elif process.poll() is None:
                    raise RuntimeError("dependency worker identity changed; preserving process custody")
                process.wait(timeout=180)
            raise
    if code:
        raise RuntimeError("dependency worker failed; retained output names the stage")


def check_directory(path, controller):
    path = Path(path)
    for part in [path, *path.parents]:
        info = part.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022
                or info.st_uid in {controller.pw_uid, pwd.getpwnam("stateengine-ci").pw_uid}):
            raise ValueError("approval storage must not be writable by either CI account")
    if path.stat().st_uid != 0:
        raise ValueError("root-owned approval storage required")
    return path


def controller_file(path, controller, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != controller.pw_uid
                or info.st_nlink != 1 or info.st_size > limit):
            raise ValueError("bounded controller-owned preparation output required")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def prepare(config, live, report, binding, directory, controller):
    source = binding["source"]
    repo = fetch_main(live["repository"], source, config.pop("token"), directory / "source.git", scoped=True)
    policy = source_policy(repo, source)
    changed = sorted(p for p in policy.keys() | report["policy"].keys() if policy.get(p) != report["policy"].get(p))
    installed_host_code(repo, source, policy, report["policy"])
    dependencies = {p for p in changed if p.endswith("Cargo.toml") or p in
                    {"Cargo.lock", ".cargo/config.toml", "rust-toolchain.toml"}}
    compiler = {name: next(item["sha256"] for item in report["inputs"] if item["name"] == name)
                for name in ("rust.tar", "windows-sdk.tar", "node.tar.xz", "cargo-nextest", "cargo-xwin", "rustup")}
    cache, cache_sha256 = Path(live["cache"]), live["cache_sha256"]
    if digest(cache) != cache_sha256:
        raise ValueError("the previous dependency seed differs")
    rebuild = bool(dependencies or set(changed) & {"factory/ci/box/Containerfile", "factory/ci/box/runner.py",
                                                 "factory/ci/box/probe.py"})
    if rebuild:
        from types import SimpleNamespace
        output = directory / "image"
        # Image preparation shares the reserved CI memory budget. Keep it
        # exclusive just like the dependency worker, even with two listeners.
        with open(live["ci_lock"]) as maintenance:
            fcntl.flock(maintenance, fcntl.LOCK_EX | fcntl.LOCK_NB)
            build(SimpleNamespace(repo=repo, trusted_source=source, output=output,
                **{name: Path(config[name]) for name in ("toolchain", "rustup", "nextest", "xwin", "windows_sdk")}))
        image = json.loads((output / "image.json").read_text())
        if any(next(item["sha256"] for item in image["inputs"] if item["name"] == name) != expected
               for name, expected in compiler.items()):
            raise ValueError("compiler or SDK inputs changed; maintainer approval is required")
        os.chown(output, 0, controller.pw_gid)
        output.chmod(0o710)
        os.chown(output / "image.json", 0, controller.pw_gid)
        (output / "image.json").chmod(0o640)
        archive = directory / "source.tar"
        with archive.open("xb") as stream:
            git(repo, "archive", "--format=tar", "--prefix=source/", source, output=stream)
        os.chown(archive, 0, controller.pw_gid)
        archive.chmod(0o640)
        cache_output = directory / "dependencies"
        cache_output.mkdir(mode=0o700)
        os.chown(cache_output, controller.pw_uid, controller.pw_gid)
        request = directory / "cache-request.json"
        record(request, {"source": source, "archive": str(archive), "archive_sha256": digest(archive),
            "seed": str(cache), "seed_sha256": cache_sha256, "image_report": str(output / "image.json"),
            "output": str(cache_output), "ci_lock": live["ci_lock"]}, controller.pw_gid)
        worker(["/usr/bin/sudo", "-n", "-u", controller.pw_name, "/usr/bin/python3", "-I",
                str(BOX / "approval_cache.py"), "--request", str(request)], directory / "cache-worker.log")
        with controller_file(cache_output / "manifest.json", controller, 65536) as stream:
            data = stream.read(65537)
            if len(data) > 65536:
                raise ValueError("prepared dependency manifest exceeds its bound")
            manifest = json.loads(data)
        if (manifest["source"] != source or manifest["image"] != image["image"]
                or manifest["workspace_artifacts_removed"] is not True):
            raise ValueError("dependency worker returned a mismatched preparation")
        cache = cache_output / "dependencies.tar.gz"
        cache_sha256 = manifest["sha256"]
        if (not isinstance(cache_sha256, str) or len(cache_sha256) != 64
                or any(c not in "0123456789abcdef" for c in cache_sha256)):
            raise ValueError("prepared dependency checksum is malformed")
        destination = check_directory(config["cache_directory"], controller) / ("dependencies-" + cache_sha256 + ".tar.gz")
        if destination.exists():
            info = destination.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o022
                    or info.st_size != manifest["bytes"] or digest(destination) != cache_sha256):
                raise ValueError("existing immutable dependency seed differs")
        else:
            # Publish from a temporary file on the destination filesystem.
            fd, temporary = tempfile.mkstemp(prefix=".dependencies-", dir=destination.parent)
            try:
                with os.fdopen(fd, "w+b") as stream, controller_file(cache, controller, 3 * 1024**3) as incoming:
                    os.fchmod(stream.fileno(), 0o644)
                    while chunk := incoming.read(1024**2):
                        stream.write(chunk)
                        if stream.tell() > 3 * 1024**3:
                            raise ValueError("prepared dependency archive exceeds its bound")
                    if stream.tell() != manifest["bytes"]:
                        raise ValueError("prepared dependency byte count differs")
                    stream.seek(0)
                    if hashlib.file_digest(stream, "sha256").hexdigest() != cache_sha256:
                        raise ValueError("prepared dependency checksum differs")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, destination)
                parent = os.open(destination.parent, os.O_DIRECTORY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        cache, report = destination, image
    report = dict(report, policy=policy, policy_source=source, policy_overrides=changed,
                  policy_approved_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  automatic_approval={**binding, "dependency_seed_rebuilt": rebuild})
    return report, cache, cache_sha256


def approve(request):
    if os.geteuid() != 0:
        raise ValueError("the fixed main approval owner requires root")
    config, live = trusted(CONFIG), trusted(LIVE)
    if not isinstance(request, dict) or set(request) != {"context", "token"}:
        raise ValueError("one main context and ephemeral credential are required")
    api = GitHub(token=request["token"])
    binding = main_source(api, live["repository"], request["context"])
    controller = pwd.getpwnam("stateengine-ci-controller")
    root = check_directory(config["state"], controller)
    with (root / "approval.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original = LIVE.read_bytes()
        live = trusted(LIVE)
        report = trusted(Path(live["image_report"]))
        cache = Path(live["cache"])
        info = cache.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o022
                or info.st_size > 3 * 1024**3 or digest(cache) != live["cache_sha256"]):
            raise ValueError("current approved dependency seed differs")
        if report.get("policy_source") == binding["source"]:
            return {"status": "unchanged", "source": binding["source"], "image": report["image"]}
        directory = root / uuid.uuid4().hex
        directory.mkdir(mode=0o710)
        os.chown(directory, 0, controller.pw_gid)
        directory.chmod(0o710)
        record(directory / "attempt.json", binding)
        config["token"] = request["token"]
        try:
            available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                                 if line.startswith("MemAvailable:"))) * 1024
            if available < 34 * 1024**3 or shutil.disk_usage(root).free < 80 * 1024**3:
                raise RuntimeError("approval requires 34 GiB free memory and 80 GiB free disk")
            report, cache, cache_sha256 = prepare(config, live, report, binding, directory, controller)
            cleanup(directory)
            current_main(api, binding["source"])
            if LIVE.read_bytes() != original:
                raise RuntimeError("maintainer configuration changed during preparation; no approval was published")
            snapshot = directory / "image.json"
            record(snapshot, report, controller.pw_gid)
            updated = dict(live, image_report=str(snapshot), cache=str(cache), cache_sha256=cache_sha256)
            replace(LIVE, (json.dumps(updated, indent=2) + "\n").encode())
            result = {"status": "approved", **binding, "image": report["image"], "cache_sha256": cache_sha256,
                      "policy_sha256": hashlib.sha256(json.dumps(report["policy"], sort_keys=True,
                                                      separators=(",", ":")).encode()).hexdigest()}
            record(directory / "result.json", result)
            return result
        except BaseException as error:
            record(directory / "failure.json", {**binding, "error": type(error).__name__ + ": " + str(error),
                "published_report": trusted(LIVE).get("image_report")})
            raise


def interrupted(*_):
    raise InterruptedError("main approval canceled; read the retained publication receipt before retrying")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("the main approval owner accepts no arguments")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    data = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise SystemExit("approval request exceeds its bound")
    print(json.dumps(approve(json.loads(data))))
