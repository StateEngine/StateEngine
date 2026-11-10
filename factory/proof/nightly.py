#!/usr/bin/env python3
"""Run the independent Rust judge from an OS scheduler, retaining every attempt."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from report import publish

GIB = 1024**3


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git(repository, *args):
    return subprocess.check_output(["git", "--git-dir", str(repository), *args],
                                   text=True, timeout=60).strip()


def clean_environment(config):
    # A scheduler must already be outside all managed agent trees. This clean
    # environment is fixture isolation, not an ancestry or owner-guard bypass.
    keep = {"HOME", "USER", "LOGNAME", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "LANG", "LC_ALL"}
    env = {key: value for key, value in os.environ.items() if key in keep}
    env.update(PATH=":".join([*config["prerequisite_paths"], "/usr/bin", "/bin"]),
               LANG="C.UTF-8", LC_ALL="C.UTF-8", TERM="xterm-256color", SHELL="/bin/bash")
    return env


def capacity():
    available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                         if line.startswith("MemAvailable:"))) * 1024
    if available < 34 * GIB:
        raise RuntimeError("less than 34 GiB available; build and journeys not started")
    return available


def command(argv, log, env, timeout):
    with log.open("ab") as output:
        result = subprocess.run([str(arg) for arg in argv], stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT, env=env,
                                timeout=timeout, close_fds=True)
    if result.returncode:
        raise RuntimeError(f"{Path(str(argv[0])).name} exited {result.returncode}; see {log.name}")


def pin_tree(repository, ref, destination):
    commit = git(repository, "rev-parse", "--verify", ref + "^{commit}")
    subprocess.run(["git", "--git-dir", str(repository), "worktree", "add", "--detach",
                    str(destination), commit], check=True, timeout=60, capture_output=True)
    return {"commit": commit, "worktree": str(destination)}


def invoke(config, run, directory, judge, descriptor, archive, env, selection, surface):
    capacity()
    name = surface + "-" + selection
    invocation = {"platform": "linux", "surface": surface, "selection": selection,
                  "output": name, "exit": None}
    run["invocations"].append(invocation)
    save(directory / "run.json", run)
    argv = [config["node"], judge / "journeys/run.mjs", "--implementation", "rust",
            "--distribution", "standalone", "--product", descriptor,
            "--surface", surface, "--auth-home", config["auth_home"], "--out", directory / name]
    if selection == "first-hour":
        argv += ["--only", selection, "--archive", archive]
    elif selection != "wave-2":
        argv += ["--only", selection]
    try:
        with (directory / (name + ".log")).open("xb") as output:
            invocation["exit"] = subprocess.run([str(arg) for arg in argv], env=env,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                timeout=7200, close_fds=True).returncode
    except subprocess.TimeoutExpired:
        # Do not claim fixture closure or remove a home after a judge timeout.
        invocation["error"] = "judge deadline; inspect retained fixture and native processes"
        run["errors"].append(invocation["error"])
        raise RuntimeError(invocation["error"]) from None
    finally:
        save(directory / "run.json", run)
        publish(directory)


def run_nightly(config, prepared_build=None):
    state = Path(config["state"])
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / "nightly.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        directory = state / stamp[:8] / stamp
        directory.mkdir(parents=True, mode=0o700)
        record = {"started_at": datetime.now(timezone.utc).isoformat(),
                  "invocations": [], "errors": [], "adapter_sha256": digest(Path(__file__))}
        save(directory / "run.json", record)
        save(state / "current.json", {"directory": str(directory)})
        try:
            record["available_bytes_before_start"] = capacity()
            env = clean_environment(config)
            temporary = directory / "tmp"
            temporary.mkdir(mode=0o700)
            env["TMPDIR"] = str(temporary)
            for name in ("product", "judge"):
                tree = directory / (name + "-source")
                record[name] = pin_tree(config[name + "_git"], config[name + "_ref"], tree)
            source, judge = (Path(record[name]["worktree"]) for name in ("product", "judge"))
            record["judge"]["rust_map_sha256"] = digest(judge / "journeys/maps/rust.json")
            record["judge"]["files_sha256"] = {str(path.relative_to(judge)): digest(path)
                for path in sorted((judge / "journeys").rglob("*")) if path.is_file()}
            save(directory / "run.json", record)
            build = prepared_build or directory / "build"
            if prepared_build is None:
                command([sys.executable, source / "scripts/release/build.py", "--target",
                         "x86_64-unknown-linux-gnu", "--out", build], directory / "build.log", env, 7200)
            metadata = json.loads((build / "build.json").read_text())
            if metadata.get("source_commit") != record["product"]["commit"]:
                raise RuntimeError("prepared release does not match tonight's pinned product source")
            command([sys.executable, source / "scripts/release/assemble.py", "--build", build,
                     "--out", directory / "archive"], directory / "assemble.log", env, 300)
            archive, = (directory / "archive").glob("*.tar.gz")
            # Extraction is of the trusted assembler's exact pinned output.
            command(["tar", "-xzf", archive, "-C", directory / "archive"], directory / "assemble.log", env, 300)
            bundle, = (path for path in (directory / "archive").iterdir() if path.is_dir())
            record["product"].update(archive_sha256=digest(archive), build_sha256=digest(bundle / "build.json"),
                                      binary_sha256=digest(bundle / "se"))
            descriptor = directory / "product.json"
            save(descriptor, {"format": "journey-product/v1", "profile": "rust", "command_map": "rust-v1",
                "source_commit": record["product"]["commit"],
                "commands": {"install": ["sh", str(bundle / "install.sh")],
                    "se": ["{home}/.local/bin/se"], "uninstall": ["{home}/.local/bin/se", "uninstall"]},
                "exposure": {"se": "{home}/.local/bin/se"}})
            save(directory / "run.json", record)
            for surface, selection in config["probes"]:
                invoke(config, record, directory, judge, descriptor, archive, env, selection, surface)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            record["errors"].append(str(error))
        finally:
            # Retain pinned source trees with this attempt. They contain no test
            # credentials; no recursive cleanup can consume another worktree.
            save(directory / "run.json", record)
            report = publish(directory)
            save(state / "latest.json", {"directory": str(directory), "grid": str(directory / "grid.md"),
                                         "budgets": str(directory / "budgets.json")})
        # Artifacts remain available even when every prerequisite failed.
        print(directory / "report.md", flush=True)
        return 1 if report["errors"] or not record["invocations"] or any(
            item.get("exit") != 0 for item in record["invocations"]) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--prepared-build", type=Path, help="reuse a native release with the exact selected source pin")
    parser.add_argument("--report", type=Path, help="regenerate a retained run's reports without executing product code")
    parser.add_argument("--service-exit", action="store_true")
    args = parser.parse_args()
    if args.report:
        publish(args.report)
        return 0
    if not args.config:
        parser.error("--config is required for execution")
    config = json.loads(args.config.read_text())
    if args.service_exit:
        current = json.loads((Path(config["state"]) / "current.json").read_text())
        directory = Path(current["directory"])
        if os.environ.get("SERVICE_RESULT") != "success":
            record = json.loads((directory / "run.json").read_text())
            record["errors"].append("service: " + os.environ.get("SERVICE_RESULT", "unknown"))
            save(directory / "run.json", record)
        publish(directory)
        return 0
    forbidden = [name for name in os.environ if name.startswith(("STATEENGINE_", "SECODE_")) or name == "SE_SESSION"]
    if forbidden:
        parser.error("start from an OS scheduler outside managed agent trees with no fleet/session environment")
    return run_nightly(config, args.prepared_build)


if __name__ == "__main__":
    raise SystemExit(main())
