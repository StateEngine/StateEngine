#!/usr/bin/env python3
"""Maintainer-only image build; never called with PR-supplied inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.request
import uuid

from engine import account_args, capacity, command
from github_binding import POLICY_FILES, policy_paths

NODE = "node-v22.23.4-linux-x64.tar.xz"


def stage(context, name, source, executable=False):
    # Drop authority before writing the CI account's filesystem. Input is an
    # already-open public compiler/dependency file, never the host environment.
    writer = ("import sys,shutil,os; f=open(sys.argv[1],'xb'); "
              "shutil.copyfileobj(sys.stdin.buffer,f); f.close(); os.chmod(sys.argv[1],int(sys.argv[2],8))")
    with source.open("rb") as stream:
        subprocess.run(account_args("python3", "-c", writer, str(context / name),
                                    "755" if executable else "644"), stdin=stream,
                       check=True, close_fds=True, timeout=180)
    with source.open("rb") as stream:
        return {"name": name, "sha256": hashlib.file_digest(stream, "sha256").hexdigest(),
                "bytes": source.stat().st_size}


def policy_files(repo, source):
    paths = subprocess.check_output(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", source], text=True).splitlines()
    return sorted(policy_paths(paths))


def build(args):
    capacity(4 * 1024**3)
    if not re.fullmatch("[a-f0-9]{40}", args.trusted_source):
        raise ValueError("exact trusted main commit required")
    subprocess.run(["git", "-C", str(args.repo), "merge-base", "--is-ancestor",
                    args.trusted_source, "main"], check=True, close_fds=True)
    version = subprocess.check_output([str(args.toolchain / "bin/rustc"), "--version"], text=True)
    if not version.startswith("rustc 1.97.1 "):
        raise ValueError("public Rust 1.97.1 toolchain directory required")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    public = args.output / "inputs"
    public.mkdir()
    base = "https://nodejs.org/dist/v22.23.4/"
    with urllib.request.urlopen(base + "SHASUMS256.txt", timeout=45) as response:
        sums = response.read(128 * 1024).decode()
    expected = next(line.split()[0] for line in sums.splitlines() if line.split()[-1] == NODE)
    with urllib.request.urlopen(base + NODE, timeout=90) as response, (public / "node.tar.xz").open("xb") as dest:
        length = 0
        while chunk := response.read(1024**2):
            length += len(chunk)
            if length > 64 * 1024**2:
                raise RuntimeError("public Node archive exceeds bound")
            dest.write(chunk)
    with (public / "node.tar.xz").open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise RuntimeError("public Node checksum mismatch")
    with tarfile.open(public / "rust.tar", "w") as archive:
        archive.add(args.toolchain, arcname=".")
    with (public / "main.tar").open("xb") as dest:
        subprocess.run(["git", "-C", str(args.repo), "archive", "--format=tar", args.trusted_source],
                       stdout=dest, check=True, close_fds=True)
    context = Path("/var/lib/stateengine-ci") / ("bootstrap-" + uuid.uuid4().hex)
    subprocess.run(account_args("mkdir", "-m", "700", str(context)), check=True, close_fds=True)
    source = Path(__file__).resolve().parent
    inputs = [(name, source / name) for name in ("Containerfile", "probe.py", "runner.py")]
    inputs += [(name, public / name) for name in ("rust.tar", "node.tar.xz", "main.tar")]
    inputs += [("cargo-nextest", args.nextest)]
    manifest = [stage(context, name, path, name == "cargo-nextest") for name, path in inputs]
    (args.output / "inputs.json").write_text(json.dumps(manifest, indent=2))
    # The build runs trusted packages only. The outer scope bounds aggregate
    # tasks too; candidate jobs have independent native admission below this cap.
    unit = "se-ci-image-" + uuid.uuid4().hex
    with (args.output / "build.stdout").open("xb") as out, (args.output / "build.stderr").open("xb") as err:
        try:
            result = subprocess.run(account_args("systemd-run", "--user", "--scope", "--collect",
                "--unit=" + unit, "-p", "TasksMax=1024", "-p", "MemoryMax=4G",
                "-p", "MemorySwapMax=0", "-p", "CPUQuota=200%", "podman", "build", "--http-proxy=false",
                "--memory=4g", "--memory-swap=4g", "--cpu-period=100000", "--cpu-quota=200000",
                "--tag=localhost/stateengine-shadow:prepared", str(context)), stdout=out, stderr=err,
                timeout=1800, close_fds=True)
        except BaseException:
            subprocess.run(account_args("systemctl", "--user", "stop", unit + ".scope"),
                           stdout=err, stderr=err, timeout=30, close_fds=True, check=True)
            raise
    if result.returncode:
        raise RuntimeError(f"trusted image build failed: exit {result.returncode}; retained output names its reason")
    image, = json.loads(command("image", "inspect", "localhost/stateengine-shadow:prepared"))
    identifier = image["Id"]
    if not identifier.startswith("sha256:"):
        identifier = "sha256:" + identifier
    report = {"image": identifier, "trusted_source": args.trusted_source, "context": str(context),
              "node_sha256": expected, "node_source": base + NODE, "inputs": manifest,
              "seccomp_sha256": hashlib.sha256(Path("/etc/stateengine-ci/seccomp.json").read_bytes()).hexdigest(),
              "policy": {path: hashlib.sha256(subprocess.check_output([
                  "git", "-C", str(args.repo), "show", args.trusted_source + ":" + path])).hexdigest()
                         for path in policy_files(args.repo, args.trusted_source)}}
    (args.output / "image.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--trusted-source", required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--nextest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    build(parser.parse_args())
