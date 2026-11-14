#!/usr/bin/env python3
"""Run the independent Rust judge from an OS scheduler, retaining every attempt."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from report import exit_status, publish
from lifecycle import begin, checkpoint, save, service_exit
from native import import_receipt
from matrix_adapter import run as run_matrix
from night_status import configure
from remote_credentials import AutomationToken

GIB = 1024**3


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


def box_load():
    """Count driver trees rather than counting every compiler child as a build."""
    parents, drivers, unreadable = {}, set(), []
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            text = (path / "stat").read_text()
            fields = text.rsplit(")", 1)[1].split()
            pid = int(path.name)
            parents[pid] = int(fields[1])
            if fields[0] not in {"Z", "X", "x"} and text.split("(", 1)[1].rsplit(")", 1)[0] in {
                    "cargo", "cargo-clippy", "cargo-nextest", "rustc"}:
                drivers.add(pid)
        except (FileNotFoundError, ProcessLookupError):
            pass
        except (OSError, ValueError, IndexError):
            unreadable.append(int(path.name))
    roots = []
    for pid in drivers:
        parent, seen = parents.get(pid), {pid}
        while parent in parents and parent not in seen and parent not in drivers:
            seen.add(parent)
            parent = parents[parent]
        if parent not in drivers:
            roots.append(pid)
    return {"observed_at": time.time(), "load_average": list(os.getloadavg()),
            "concurrent_builds_observed": len(roots), "driver_pids": sorted(roots), "unreadable_pids": unreadable,
            "scope": "Cargo/Rust driver trees, including test commands; sequential /proc census, not an atomic or all-language count"}


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


def remaining(deadline, maximum):
    seconds = min(maximum, deadline - time.monotonic())
    if seconds <= 1:
        raise RuntimeError("whole-run deadline reached; later planned probes were not started")
    return seconds


def invoke(config, run, directory, judge, descriptor, archive, env, invocation, deadline):
    capacity()
    selection, surface, name = (invocation[key] for key in ("selection", "surface", "output"))
    invocation["state"] = "running"
    invocation["box_load"] = {"before": box_load()}
    checkpoint(Path(config["state"]), directory, run, config)
    argv = [config["node"], judge / "journeys/run.mjs", "--implementation", "rust",
            "--distribution", "standalone", "--product", descriptor,
            "--surface", surface, "--auth-home", config["auth_home"], "--out", directory / name]
    automation = None
    if surface == "claude":
        automation = AutomationToken(config.get("automation_tokens", {}))
        env = {**env, "CLAUDE_CODE_OAUTH_TOKEN": automation.token()}
        argv += ["--automation-token-env", "CLAUDE_CODE_OAUTH_TOKEN"]
    elif surface in config.get("credential_sources", {}):
        argv += ["--credential-source", config["credential_sources"][surface]]
    if selection == "first-hour":
        argv += ["--only", selection, "--archive", archive]
    elif selection != "wave-2":
        argv += ["--only", selection]
    try:
        with (directory / (name + ".log")).open("xb") as output:
            invocation["exit"] = subprocess.run([str(arg) for arg in argv], env=env,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                timeout=remaining(deadline, 7200), close_fds=True).returncode
        if automation is not None:
            automation.token()
            invocation["credential_closure"] = {"source_inode_unchanged": True,
                "source_digest_unchanged": True, "transport": "environment"}
        invocation["state"] = "finished"
    except subprocess.TimeoutExpired:
        invocation.update(state="timed-out", error="judge deadline; inspect fixture and native custody")
        raise RuntimeError(invocation["error"]) from None
    finally:
        invocation["box_load"]["after"] = box_load()
        checkpoint(Path(config["state"]), directory, run, config)


def invoke_remote(config, run, directory, executable, env, invocation, deadline):
    from remote_journey import Journey
    capacity()
    remaining(deadline, 600)
    invocation.update(state="running", box_load={"before": box_load()})
    checkpoint(Path(config["state"]), directory, run, config)
    if not isinstance(config.get("remote", {}), dict):
        raise RuntimeError("remote configuration must be an object naming its SSH destination")
    settings = {**config.get("remote", {}), "auth_home": config["auth_home"],
                "automation_tokens": config.get("automation_tokens", {}),
                "account_check": str(Path(run["product"]["worktree"]) / "scripts/ci/installation_account.py")}
    settings.setdefault("surface", "claude")
    result = Journey(settings, executable, directory / invocation["output"], env,
                     run["product"]["commit"], deadline).run()
    invocation.update(state="finished", exit=0 if result["passed"] else 1)
    invocation["box_load"]["after"] = box_load()
    checkpoint(Path(config["state"]), directory, run, config)


def run_nightly(config, prepared_build=None, native_only=False):
    if native_only:
        config = {**config, "native_only": True}
    state = Path(config["state"])
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / "nightly.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state, directory, record = begin(config)
        record["adapter_sha256"] = digest(Path(__file__))
        # Reserve an hour below the unit's six-hour ceiling for publication and
        # service-manager cleanup. All stages consume this same deadline.
        deadline = time.monotonic() + 5 * 3600
        try:
            if not native_only:
                record["available_bytes_before_start"] = capacity()
            env = clean_environment(config)
            temporary = directory / "tmp"
            temporary.mkdir(mode=0o700)
            env["TMPDIR"] = str(temporary)
            if config.get("product_fetch_refspec"):
                git(config["product_git"], "fetch", "--no-tags", "origin", config["product_fetch_refspec"])
            for name in ("product", "judge"):
                tree = directory / (name + "-source")
                record[name] = pin_tree(config[name + "_git"], config[name + "_ref"], tree)
            if record.get('harness_matrix') is not None:
                matrix = config['harness_matrix']
                record['matrix_judge'] = pin_tree(matrix['judge_git'], matrix['judge_ref'],
                                                  directory / 'matrix-judge-source')
            source, judge = (Path(record[name]["worktree"]) for name in ("product", "judge"))
            record["judge"]["rust_map_sha256"] = digest(judge / "journeys/maps/rust.json")
            record["judge"]["files_sha256"] = {str(path.relative_to(judge)): digest(path)
                for path in sorted((judge / "journeys").rglob("*")) if path.is_file()}
            save(directory / "run.json", record)
            native_invocations = [row for row in record["invocations"] if row.get("native_receipt")]
            for invocation, probe in zip(native_invocations, config.get("native_receipts", []), strict=True):
                import_receipt(invocation, probe["path"], directory, record, state)
                checkpoint(state, directory, record, config)
            if native_only:
                record["state"] = "finished"
                report = checkpoint(state, directory, record, config)
                print(directory / "report.md", flush=True)
                return exit_status(report)
            build = prepared_build or directory / "build"
            if prepared_build is None:
                command([sys.executable, source / "scripts/release/build.py", "--target",
                         "x86_64-unknown-linux-gnu", "--out", build], directory / "build.log", env, remaining(deadline, 7200))
            metadata = json.loads((build / "build.json").read_text())
            if metadata.get("source_commit") != record["product"]["commit"]:
                raise RuntimeError("prepared release does not match tonight's pinned product source")
            if "remote" not in metadata.get("features", []):
                raise RuntimeError("the remote journey requires a release built with --features remote")
            command([sys.executable, source / "scripts/release/assemble.py", "--native-only", "--build", build,
                     "--out", directory / "archive"], directory / "assemble.log", env, remaining(deadline, 300))
            archive, = (directory / "archive").glob("*.tar.gz")
            # Extraction is of the trusted assembler's exact pinned output.
            command(["tar", "-xzf", archive, "-C", directory / "archive"], directory / "assemble.log", env, remaining(deadline, 300))
            bundle, = (path for path in (directory / "archive").iterdir()
                       if path.is_dir() and not path.name.endswith(".symbols"))
            record["product"].update(archive_sha256=digest(archive), build_sha256=digest(bundle / "build.json"),
                                      binary_sha256=digest(bundle / "se"))
            descriptor = directory / "product.json"
            save(descriptor, {"format": "journey-product/v1", "profile": "rust", "command_map": "rust-v1",
                "source_commit": record["product"]["commit"],
                "commands": {"install": ["sh", str(bundle / "install.sh")],
                    "se": ["{home}/.local/bin/se"], "uninstall": ["{home}/.local/bin/se", "uninstall"]},
                "exposure": {"se": "{home}/.local/bin/se"}})
            save(directory / "run.json", record)
            for invocation in record["invocations"]:
                if invocation.get("native_receipt"):
                    continue
                if invocation.get("remote_probe"):
                    invoke_remote(config, record, directory, bundle / "se", env, invocation, deadline)
                else:
                    invoke(config, record, directory, judge, descriptor, archive, env, invocation, deadline)
            if record.get('harness_matrix') is not None:
                run_matrix(config, record, directory, Path(record['matrix_judge']['worktree']),
                           bundle, env, deadline, lambda: checkpoint(state, directory, record, config))
            record["state"] = "finished"
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            record["errors"].append(str(error))
            record["state"] = "interrupted"
        finally:
            # Retain pinned source trees with this attempt. They contain no test
            # credentials; no recursive cleanup can consume another worktree.
            report = checkpoint(state, directory, record, config)
        # Artifacts remain available even when every prerequisite failed.
        print(directory / "report.md", flush=True)
        return exit_status(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--prepared-build", type=Path, help="reuse a native release with the exact selected source pin")
    parser.add_argument("--report", type=Path, help="regenerate a retained run's reports without executing product code")
    parser.add_argument("--service-exit", action="store_true")
    parser.add_argument("--native-receipts-only", action="store_true", help="import native observations without a local build or judge")
    args = parser.parse_args()
    if args.report:
        publish(args.report)
        return 0
    if not args.config:
        parser.error("--config is required for execution")
    config = configure(json.loads(args.config.read_text()))
    if args.service_exit:
        return service_exit(config)
    prefixes = tuple(config.get("forbidden_environment_prefixes", ["STATEENGINE_", "SECODE_"]))
    names = config.get("forbidden_environment_names", ["SE_SESSION"])
    if any(not isinstance(value, str) or not value for value in (*prefixes, *names)):
        parser.error("refused environment prefixes and names must be nonempty strings")
    forbidden = [name for name in os.environ if name.startswith(prefixes) or name in names]
    if forbidden:
        parser.error("start from an OS scheduler outside managed agent trees with no fleet/session environment")
    if args.native_receipts_only:
        config = {**config, "probes": [], "native_only": True}
    return run_nightly(config, args.prepared_build, args.native_receipts_only)


if __name__ == "__main__":
    raise SystemExit(main())
