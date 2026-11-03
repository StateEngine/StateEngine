"""Public Linux down judge; inject exact-owner readlink errors in the CLI only.

Run outside agent ancestry. No installation or private Rust imports are used.
The public native host fixture stays alive after draining until this reader releases it.
"""
import argparse
import fcntl
import json
import os
import pathlib
import subprocess
import time
import uuid


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def wait_for(path, child, seconds=20):
    until = time.monotonic() + seconds
    while not path.exists():
        require(child.poll() is None, "native fixture exited before observation")
        require(time.monotonic() < until, "native fixture observation timed out")
        time.sleep(0.01)


def case(options, library, mode):
    output = options.output / mode
    output.mkdir(mode=0o700)
    env = dict(os.environ)
    env["SE_SHUTDOWN_PROCESS_FIXTURE"] = str(output)
    child_stdout = (output / "host.stdout").open("wb")
    child_stderr = (output / "host.stderr").open("wb")
    child = subprocess.Popen(
        [str(options.host_fixture), "--ignored", "--exact",
         "standalone_shutdown_process_fixture", "--nocapture"],
        env=env, stdin=subprocess.PIPE, stdout=child_stdout, stderr=child_stderr)
    observer = None
    failure = None
    try:
        wait_for(output / "ready.json", child)
        ready = json.loads((output / "ready.json").read_text())
        home = pathlib.Path(ready["home"])
        require(ready["pid"] == child.pid, "fixture published another process")
        proc = pathlib.Path("/proc") / str(child.pid)
        birth = (proc / "stat").read_text().rsplit(") ", 1)[1].split()[19]
        (output / "host-before.json").write_text(json.dumps({"pid": child.pid, "birth": birth,
            "argv": (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode()}, indent=2))
        observer_env = dict(os.environ)
        observer_env.update({"HOME": str(output), "USERPROFILE": str(output),
                            "LD_PRELOAD": str(library),
                            "SE_SHUTDOWN_READ_PATH": f"/proc/{child.pid}/exe",
                            "SE_SHUTDOWN_READ_RECEIPT": str(home / "runtime-close.json"),
                            "SE_SHUTDOWN_READ_LOG": str(output / "fault.log"),
                            "SE_SHUTDOWN_READ_MODE": mode})
        argv = [str(options.se), "down", "--home", str(home), "--key", str(uuid.uuid4()), "--json"]
        stdout = (output / "down.stdout").open("wb")
        stderr = (output / "down.stderr").open("wb")
        started = time.monotonic()
        observer = subprocess.Popen(argv, env=observer_env, stdout=stdout, stderr=stderr)
        until = started + 20
        log = output / "fault.log"
        while not log.exists():
            require(observer.poll() is None, "down exited before the selected fault was exercised")
            require(time.monotonic() < until, "no exact-owner readlink fault was exercised")
            time.sleep(0.01)
        require("injected exact-owner" in log.read_text(), "no injected native failure")
        wait_for(output / "drained", child)
        with (home / "runtime.lock").open("r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(not (home / "endpoint.json").exists(), "endpoint remained under exclusive lease")
            fcntl.flock(lock, fcntl.LOCK_UN)
        if mode == "transient":
            while "resumed exact-owner" not in log.read_text():
                require(observer.poll() is None, "native read error escaped instead of retrying")
                require(time.monotonic() < until, "native read did not resume")
                time.sleep(0.01)
            time.sleep(0.15)
            require(observer.poll() is None and child.poll() is None,
                    "a recovered live owner was incorrectly witnessed exited")
            child.stdin.write(b"exit naturally\n")
            child.stdin.close()
            child.wait(timeout=10)
            code = observer.wait(timeout=35)
            stdout.close()
            stderr.close()
            result = json.loads((output / "down.stdout").read_text())
            require(code == 0 and result["complete"] is True,
                    "transient read failed to recover after exact owner exit")
            require(result["witness"]["state"] == "witnessed", "completion lacks outside witness")
        else:
            code = observer.wait(timeout=40)
            stdout.close()
            stderr.close()
            result = json.loads((output / "down.stdout").read_text())
            require(code != 0 and result["complete"] is False,
                    "persistent unreadability became successful exit")
            diagnostic = json.dumps(result) + (output / "down.stderr").read_text()
            require("No conclusive native observation within the original shutdown bound" in diagnostic
                    and "IdentityUnreadable" in diagnostic and "read proc executable" in diagnostic,
                    "deadline lost the final native read failure")
            require(25 <= time.monotonic() - started <= 40, "retry renewed or bypassed the original deadline")
            require(child.poll() is None, "persistent-error owner exited before its refusal")
        observation = {"mode": mode, "passed": True, "native_failure_exercised": True,
                       "elapsed_seconds": time.monotonic() - started, "down_exit": code,
                       "live_owner_not_promoted_to_absence": True}
    except Exception as error:
        failure = error
        (output / "failure.json").write_text(json.dumps({"error": repr(error)}, indent=2))
    finally:
        if child.stdin and not child.stdin.closed:
            try:
                child.stdin.write(b"observer cleanup\n")
                child.stdin.close()
            except BrokenPipeError:
                pass
        child.wait(timeout=35)
        if observer is not None:
            observer.wait(timeout=40)
        child_stdout.close()
        child_stderr.close()
        require(child.returncode == 0, "native fixture cleanup failed; original output retained")
    if failure:
        raise failure
    (output / "result.json").write_text(json.dumps(observation, indent=2))
    return observation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=pathlib.Path, required=True)
    parser.add_argument("--host-fixture", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    options = parser.parse_args()
    options.se = options.se.resolve(strict=True)
    options.host_fixture = options.host_fixture.resolve(strict=True)
    options.output = options.output.resolve()
    require(not any(name.startswith(("STATEENGINE_", "SECODE_", "CODEX_")) or name in
                    ("SE_SESSION", "SE_CAPABILITY", "CLAUDECODE") for name in os.environ),
            "run outside agent ancestry with a clean environment")
    options.output.mkdir(mode=0o700)
    source = pathlib.Path(__file__).resolve().parent.parent / "support/shutdown_process_read_fault.c"
    library = options.output / "readlink-fault.so"
    compiled = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                               "-o", str(library), str(source), "-ldl"], capture_output=True)
    (options.output / "cc.stdout").write_bytes(compiled.stdout)
    (options.output / "cc.stderr").write_bytes(compiled.stderr)
    require(compiled.returncode == 0, "native fault fixture failed to compile")
    results = [case(options, library, mode) for mode in ("transient", "persistent")]
    (options.output / "result.json").write_text(json.dumps({"passed": 2, "failed": 0, "cases": results}, indent=2))
    print("Public down/native read fault: 2 passed; 0 failed", flush=True)


if __name__ == "__main__":
    main()
