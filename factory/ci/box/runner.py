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


def call(args, timeout, stdout=None):
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=ROOT, timeout=timeout, stdout=stdout).returncode


def run(job):
    # Only public dependency data enters a job's disposable writable home.
    if not Path("/home/ci/cargo").exists():
        shutil.copytree("/opt/cargo", "/home/ci/cargo", symlinks=True)
    os.environ.update(CARGO_HOME="/home/ci/cargo", CARGO_NET_OFFLINE="true",
                      CARGO_BUILD_JOBS="8", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="always",
                      CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
    target = subprocess.check_output(["rustc", "--print", "host-tuple"], text=True).strip()
    if job == "fmt":
        return call(["cargo", "fmt", "--all", "--", "--check"], 180) or call(
            ["python3", "-m", "unittest", "discover", "-s", "scripts/ci", "-p", "test_*.py", "-v"], 180)
    if job == "clippy":
        return call(["cargo", "clippy", "--target", target, "--workspace", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"], 720)
    if job == "archive":
        cache = Path("/work/dependencies.tar.gz")
        if cache.exists():
            with tarfile.open(cache, "r:gz") as archive:
                archive.extractall(ROOT, filter="data")
            cache.unlink()
        (ROOT / "target/cargo-timings").mkdir(parents=True, exist_ok=True)
        metadata = ROOT / "target/nextest/binaries-metadata.json"
        metadata.parent.mkdir(parents=True, exist_ok=True)
        with metadata.open("x") as output:
            code = call(["strace", "-f", "-qq", "-ttt", "-s", "4096", "-e", "trace=execve,execveat,exit_group",
                         "-o", "target/cargo-timings/linker-processes.trace", "cargo", "nextest", "list",
                         "--timings", "--target", target, "--workspace", "--locked",
                         "--list-type", "binaries-only", "--message-format", "json"], 900, stdout=output)
        return code or call(["cargo", "test", "--target", target, "--workspace", "--locked", "--doc"], 900)
    if job.startswith("test-"):
        partition = job[-1]
        filters = subprocess.check_output(["python3", "scripts/ci/custom.py", "filter"], cwd=ROOT, text=True).strip()
        code = call(["cargo", "nextest", "run", "--target", target, "--workspace", "--locked", "--profile", "ci", "--test-threads", "4", "--partition", "slice:" + partition + "/2", "-E", filters], 360)
        custom = call(["python3", "scripts/ci/custom.py", "run"], 1080) if partition == "1" else 0
        return int(bool(code or custom))
    if job == "windows-clippy":
        # Linux tests have joined. Release their disposable native target before
        # the MSVC check so both platforms fit within the same memory bound.
        code = call(["cargo", "clean", "--target", target], 180)
        if code:
            return code
        cache = Path("/home/ci/xwin")
        cache.mkdir()
        (cache / "xwin").symlink_to("/opt/windows-sdk", target_is_directory=True)
        os.environ["XWIN_CACHE_DIR"] = str(cache)
        return call(["cargo", "xwin", "clippy", "--target", "x86_64-pc-windows-msvc",
                     "--workspace", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"], 720)
    raise RuntimeError("unknown fixed job")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["hold", "source", "run"])
    parser.add_argument("job", nargs="?", choices=["fmt", "clippy", "archive", "test-1", "test-2", "windows-clippy"])
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
