"""Real attended status/stop overlap at the native lock boundary (Linux).

Only Claude's protocol and timing of a real successful native flock are doubled.
Run with --se EXACT_INSTALLED_IMAGE --output NEW_SHORT_PRIVATE_DIRECTORY.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
import uuid

sys.dont_write_bytecode = True
from mail_cli import Fixture
from recovery_capture import gone, native, wait
from directory_owner import DirectoryOwner


def provider():
    se, home, *args = sys.argv[2:]
    if "--safe-mode" in args:
        request = json.loads(sys.stdin.readline())
        print(json.dumps({"type": "control_response", "response": {
            "request_id": request["request_id"], "subtype": "success",
            "response": {"effective": {}, "sources": [], "errors": []}}}), flush=True)
        return
    flag = "--resume" if "--resume" in args else "--session-id"
    conversation = args[args.index(flag) + 1]
    repo = Path.cwd()
    assert str(repo).isascii() and len(str(repo)) < 180, "use a short ASCII judge root"
    slug = "".join(c if c.isalnum() else "-" for c in str(repo))
    transcript = Path(os.environ["HOME"]) / ".claude/projects" / slug / (conversation + ".jsonl")
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(json.dumps({"type": "user", "sessionId": conversation,
        "uuid": "status-stop-task", "message": {"role": "user", "content": "Retain my work"}}) + "\n")
    frame = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n").encode()
    ipc = subprocess.run([se, "--home", home, "mcp"], input=frame,
                         capture_output=True, timeout=20)
    assert ipc.returncode == 0, "native session discovery failed"
    server = json.loads(Path(args[args.index("--mcp-config") + 1]).read_text())["mcpServers"]["stateengine"]
    request = urllib.request.Request(server["url"], data=frame,
        headers={**server["headers"], "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        assert response.status == 200
    (repo / "provider-ready.json").write_text(json.dumps({"conversation": conversation,
        "native_root_pid": os.getppid(), "helper_pid": os.getpid()}))


def compile_provider(f):
    source = f.root / "provider.rs"
    source.write_text('''use std::{thread,time::Duration,process::Command};
fn main(){let a:Vec<String>=std::env::args().collect();
if a.get(1).map(String::as_str)==Some("--version"){println!("2.1.318 (Claude Code)");return;}
if a.get(1).map(String::as_str)==Some("auth"){println!("{}",r#"{"loggedIn":true}"#);return;}
if a.get(1).map(String::as_str)==Some("plugin"){std::process::exit(1);}
let s=Command::new(PYTHON).args([HELPER,"--provider",SE,HOME]).args(&a[1..]).status().unwrap();
assert!(s.success());loop{thread::sleep(Duration::from_secs(1));}}
'''.replace("PYTHON", json.dumps(sys.executable)).replace("HELPER", json.dumps(str(Path(__file__).resolve())))
        .replace("SE,HOME", ",".join(json.dumps(str(p)) for p in [f.se, f.home])))
    result = subprocess.run(["rustc", "--edition=2024", str(source), "-o", str(f.root / "provider")],
                            capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr


def spawn(f, *args):
    return subprocess.Popen([str(f.se), "--json", "--home", str(f.home), *args],
        env=f.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def collect(f, child, name, seconds=45):
    out, err = child.communicate(timeout=seconds)
    (f.root / (name + ".stdout")).write_bytes(out)
    (f.root / (name + ".stderr")).write_bytes(err)
    return out, err


def busy_receipt(reply):
    # Stop retains the public error tag at this boundary; user-controlled paths
    # elsewhere in the receipt cannot supply its classification.
    detail = reply.get("witness", {}).get("detail")
    return (reply.get("schema") == "se.stop/v1" and reply.get("complete") is False
            and isinstance(detail, str) and detail.startswith("store-busy: "))


def run_case(args, library, case):
    f = Fixture(args.se, args.output / case, log_directory="calls")
    compile_provider(f)
    runtime = Path(tempfile.mkdtemp(prefix="se-sc-"))
    print("fixture root (retained on failed or interrupted closure):", runtime, flush=True)
    root_owner = DirectoryOwner(runtime)
    gate = runtime / "gate"
    gate.mkdir()
    f.env.update(TMPDIR=str(runtime), XDG_RUNTIME_DIR=str(runtime),
                 LD_PRELOAD=str(library), STATUS_STOP_GATE=str(gate))
    for name in ["CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"]:
        path = f.root / name.lower()
        path.mkdir()
        f.env[name] = str(path)
    for name in list(f.env):
        if name.startswith(("OPENAI", "ANTHROPIC")) or any(s in name for s in ("TOKEN", "SECRET", "API_KEY")):
            del f.env[name]
    result = {"case": case, "checks": [], "failures": []}
    host = host_pin = display = display_pin = status = stop = None
    pins = []

    def check(condition, description):
        assert condition, description
        result["checks"].append(description)
        print("ok -", case, description, flush=True)

    try:
        with (f.root / "display.log").open("wb") as log:
            display = subprocess.Popen(["Xvfb", "-displayfd", "1", "-screen", "0", "640x480x24", "-nolisten", "tcp"],
                env=f.env, stdout=subprocess.PIPE, stderr=log)
        display_pin = native(display.pid)
        assert display_pin, "private display child has no native birth"
        assert select.select([display.stdout], [], [], 10)[0], "private display did not answer"
        number = display.stdout.readline().decode().strip()
        assert number.isdigit(), "private display did not start"
        current = native(display.pid)
        assert current and current["birth"] == display_pin["birth"] and "Xvfb -displayfd" in current["command"]
        display_pin = current
        pins.append(display_pin)
        f.env["DISPLAY"] = ":" + number
        with (f.root / "host.log").open("wb") as log:
            host = subprocess.Popen([str(f.se), "--home", str(f.home), "up", "--foreground", "--json"],
                env=f.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        wait(lambda: (f.home / "endpoint.json").exists(), "foreground host did not publish", 30)
        host_pin = native(f.ok("status")["runtime"]["process"]["pid"])
        assert host_pin and host_pin["pid"] == host.pid
        pins.append(host_pin)
        assert str(library) in Path(f"/proc/{host.pid}/maps").read_text(), "barrier is not mapped in host"
        (gate / "host-pid").write_text(str(host.pid))
        command = [str(f.se), "--json", "--home", str(f.home), "--project", f.project,
                   "launch", f.agent, "--task", "Retain work across overlapping status and stop"]
        launch = subprocess.run(["script", "-q", "-e", "-c", shlex.join(command), "/dev/null"],
                                env=f.env, capture_output=True, timeout=60)
        (f.root / "launch.stdout").write_bytes(launch.stdout)
        (f.root / "launch.stderr").write_bytes(launch.stderr)
        assert launch.returncode == 0, (launch.stdout, launch.stderr)
        wait(lambda: (f.repo / "provider-ready.json").exists(), "attended provider did not authenticate")
        ready = json.loads((f.repo / "provider-ready.json").read_text())
        f.session = "ses_" + ready["conversation"]
        provider_pin = native(ready["native_root_pid"])
        assert provider_pin and str(f.root / "provider") in provider_pin["command"]
        pins.append(provider_pin)
        f.processes.append((provider_pin["pid"], provider_pin["birth"]))
        launch_directory = f.home / "launch" / ("lch_" + ready["conversation"])
        # Include the real terminal/launcher ancestors in outside closure.
        ancestor = provider_pin["pid"]
        while ancestor not in (1, host.pid):
            fields = Path(f"/proc/{ancestor}/stat").read_text().rsplit(")", 1)[1].split()
            ancestor = int(fields[1])
            pin = native(ancestor)
            if not pin or str(f.root) not in pin["command"]:
                break
            if all(pin["pid"] != known["pid"] for known in pins):
                pins.append(pin)
        unavailable = launch_directory / "claude-mail-unavailable.json"
        assert unavailable.is_file(), "production plugin refusal did not publish its status source"
        before = f.ok("--project", f.project, "status")
        check("installed Claude Code refused" in json.dumps(before), "real status reads the protected per-launch plugin refusal")
        manifest = launch_directory / "custody.json"
        original = manifest.read_bytes()
        (gate / "target").write_text(str(launch_directory))
        (gate / "armed").touch()
        status = spawn(f, "--project", f.project, "status")
        wait(lambda: (gate / "status-held").exists(), "status did not acquire the real native directory lock")
        check(status.poll() is None, "real host status reader owns the native lock before stop")
        stop_key = "overlap-" + uuid.uuid4().hex
        stop = spawn(f, "--project", f.project, "--key", stop_key, "stop", f.agent)
        started = time.monotonic()
        wait(lambda: (gate / "cleanup-contended").exists(), "stop never reached the contended native cleanup lock", 20)
        if case == "release":
            time.sleep(.2)
            check(stop.poll() is None and manifest.read_bytes() == original,
                  "stop waits for a short status read without claiming or performing cleanup")
            (gate / "release").touch()
            out, err = collect(f, stop, "stop")
            reply = json.loads(out)
            check(stop.returncode == 0 and reply.get("complete") and reply["witness"]["state"] == "witnessed",
                  "one public stop completes after the status lock is released")
            out, err = collect(f, status, "status")
            check(status.returncode == 0, "overlapping status finishes successfully after release")
        else:
            out, err = collect(f, stop, "stop", 40)
            reply = json.loads(out)
            words = (out + err).decode().lower()
            check(stop.returncode != 0 and busy_receipt(reply) and
                  "restore native ownership" not in words,
                  "exhausted contention is an honest retryable busy refusal")
            check(time.monotonic() - started < 35 and manifest.read_bytes() == original,
                  "contention preserves bytes and never renews the public stop clock")
            (gate / "release").touch()
            collect(f, status, "status")
            retry = f.ok("--project", f.project, "--key", stop_key, "stop", f.agent)
            check(retry.get("complete"), "the original stop key completes after contention clears")
        check(not manifest.exists() and not unavailable.exists(), "complete stop retires exact launch files")
        check(not (gate / "barrier-expired").exists(), "the owned native barrier was explicitly released")
    except Exception:
        result["failures"].append(traceback.format_exc())
    finally:
        (gate / "release").touch()
        try:
            for child, name in [(status, "cleanup-status"), (stop, "cleanup-stop")]:
                if child and not child.stdout.closed:
                    collect(f, child, name)
        except Exception:
            result["failures"].append("cleanup: " + traceback.format_exc())
        if host:
            try:
                # This fixture starts the real foreground host. End it through
                # its supported Ctrl-C drain, independently of `down`'s separate
                # post-transport completion deadline.
                current = native(host.pid)
                if current and current["state"] != "Z":
                    assert host_pin and current["birth"] == host_pin["birth"]
                    expected = [str(f.se), "--home", str(f.home), "up", "--foreground", "--json"]
                    actual = Path(f"/proc/{host.pid}/cmdline").read_bytes().split(b"\0")[:-1]
                    assert actual == [os.fsencode(arg) for arg in expected], "owned host identity changed"
                    os.kill(host.pid, signal.SIGINT)
                assert host.wait(timeout=35) == 0, "foreground host did not finish its Ctrl-C drain"
            except Exception:
                result["failures"].append("host join: " + traceback.format_exc())
        if display:
            current = native(display.pid)
            if current and display_pin and current["birth"] == display_pin["birth"]:
                assert "Xvfb -displayfd" in current["command"]
                os.kill(display.pid, signal.SIGTERM)
            display.wait(timeout=10)
        outside_closed = False
        try:
            with (f.home / "runtime.lock").open("rb") as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert not (f.home / "endpoint.json").exists()
            assert all(gone(pin) for pin in pins)
            result["outside"] = [{"before": pin, "after": native(pin["pid"])} for pin in pins]
            check(True, "foreground Ctrl-C drained all recorded births, removed the endpoint and released the lease")
            outside_closed = True
        except Exception:
            result["failures"].append("outside closure: " + traceback.format_exc())
        result["markers"] = {p.name: p.read_text() for p in gate.iterdir() if p.is_file()}
        if outside_closed:
            try:
                root_owner.remove()
            except OSError:
                result["failures"].append("fixture removal: " + traceback.format_exc())
        (f.root / "result.json").write_text(json.dumps(result, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--output", type=lambda p: Path(p).resolve(), required=True)
    args = parser.parse_args()
    assert not busy_receipt({"schema": "se.stop/v1", "complete": False,
        "witness": {"detail": "source-unreadable: Cannot read /var/tmp/busy-contended-fixture/store-busy: file"}}), \
        "a busy-named user path changed an unreadable refusal's classification"
    if sys.platform != "linux":
        parser.error("this process-boundary judge qualifies Linux only")
    for command in ["cc", "rustc", "Xvfb", "xterm", "script"]:
        assert shutil.which(command), f"required native fixture executable is absent: {command}"
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    library = args.output / "status-stop.so"
    source = Path(__file__).parents[1] / "support/status_stop_contention.c"
    built = subprocess.run(["cc", "-std=c11", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                            "-O2", str(source), "-o", str(library)], capture_output=True, timeout=30)
    assert built.returncode == 0, built.stderr
    digest = hashlib.sha256(args.se.read_bytes()).hexdigest()
    cases = [run_case(args, library, case) for case in ["release", "exhaust"]]
    result = {"image_sha256": digest, "cases": cases,
              "passed": sum(len(case["checks"]) for case in cases),
              "failed": sum(len(case["failures"]) for case in cases)}
    assert hashlib.sha256(args.se.read_bytes()).hexdigest() == digest, "installed image changed during the judge"
    (args.output / "result.json").write_text(json.dumps(result, indent=2))
    print(f"status/stop contention: {result['passed']} passed, {result['failed']} failed", flush=True)
    return int(result["failed"] != 0)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--provider":
        provider()
    else:
        raise SystemExit(main())
