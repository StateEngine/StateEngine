"""Fixed container consumers. Source and archives arrive only after admission."""
import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import time

ROOT = Path("/work/source")


def call(args, timeout):
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=ROOT, timeout=timeout).returncode


def run(job):
    # Only public dependency data enters a job's disposable writable home.
    shutil.copytree("/opt/cargo", "/home/ci/cargo", symlinks=True)
    os.environ.update(CARGO_HOME="/home/ci/cargo", CARGO_NET_OFFLINE="true",
                      CARGO_BUILD_JOBS="8", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="always",
                      CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
    if job == "fmt":
        return call(["cargo", "fmt", "--all", "--", "--check"], 180) or call(
            ["python3", "-m", "unittest", "discover", "-s", "scripts/ci", "-p", "test_*.py", "-v"], 180)
    if job == "clippy":
        return call(["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"], 720)
    if job == "archive":
        target = subprocess.check_output(["rustc", "--print", "host-tuple"], text=True).strip()
        cache = Path("/work/dependencies.tar.gz")
        if cache.exists():
            with tarfile.open(cache, "r:gz") as archive:
                archive.extractall(ROOT, filter="data")
            cache.unlink()
        (ROOT / "target/cargo-timings").mkdir(parents=True, exist_ok=True)
        code = call(["strace", "-f", "-qq", "-ttt", "-s", "4096", "-e", "trace=execve,execveat,exit_group",
                     "-o", "target/cargo-timings/linker-processes.trace", "cargo", "nextest", "archive",
                     "--timings", "--target", target, "--workspace", "--locked", "--archive-file", "tests.tar.zst"], 900)
        return code or call(["cargo", "test", "--target", target, "--workspace", "--locked", "--doc"], 900)
    if job.startswith("test-"):
        partition = job[-1]
        filters = subprocess.check_output(["python3", "scripts/ci/custom.py", "filter"], cwd=ROOT, text=True).strip()
        code = call(["cargo", "nextest", "run", "--archive-file", "tests.tar.zst", "--extract-to", ".",
                     "--workspace-remap", str(ROOT), "--profile", "ci", "--test-threads", "4", "--partition", "slice:" + partition + "/2", "-E", filters], 360)
        custom = call(["python3", "scripts/ci/custom.py", "run"], 1080) if partition == "1" else 0
        return int(bool(code or custom))
    raise RuntimeError("unknown fixed job")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["hold", "source", "run"])
    parser.add_argument("job", nargs="?", choices=["fmt", "clippy", "archive", "test-1", "test-2"])
    args = parser.parse_args()
    if args.action == "hold":
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        while True:
            time.sleep(60)
    elif args.action == "source":
        ROOT.mkdir(exist_ok=False)
        prefix = None
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as archive:
            for member in archive:
                parts = Path(member.name).parts
                if not parts or parts[0] in ("/", "..", "."):
                    raise RuntimeError("invalid source archive prefix")
                if prefix is None:
                    prefix = parts[0]
                if parts[0] != prefix or ".." in parts:
                    raise RuntimeError("mixed or traversing source archive")
                if len(parts) == 1:
                    if not member.isdir():
                        raise RuntimeError("source archive has no directory prefix")
                    continue
                member.name = str(Path(*parts[1:]))
                archive.extract(member, ROOT, filter="data")
    else:
        raise SystemExit(run(args.job))
