"""Public stop against a real host with controlled finite-worker admission (Linux).

The helper uses the public worker semaphore; native results are never doubled.
Build with cargo test -p se-host --test stop_admission_deadline --no-run,
then pass that executable as --host and the candidate CLI as --se.
Run both --case delay and --case expiry with separate new --output roots.
Requires Xvfb, xterm, script, rustc and Python 3.11 or newer.
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
import tomllib
import traceback
import urllib.request

sys.dont_write_bytecode = True
from mail_cli import Fixture
from recovery_capture import gone, native, wait


# Native Claude protocol double shared in behavior with the status/stop consumer.
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

def run(args):
    os.umask(0o077)
    f = Fixture(args.se, args.output, log_directory="calls")
    compile_provider(f)
    control = f.root / "control"
    control.mkdir()
    with (f.home / "config.toml").open("rb") as source:
        (f.root / "config.json").write_text(json.dumps(tomllib.load(source)))
    runtime = Path(tempfile.mkdtemp(prefix="se-ad-", dir="/tmp"))
    print("fixture root (retained on failed or interrupted closure):", runtime, flush=True)
    f.env.update(XDG_RUNTIME_DIR=str(runtime), TMPDIR=str(runtime),
                 STOP_ADMISSION_ROOT=str(f.root), STOP_ADMISSION_SE=str(f.se))
    for name in ["CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"]:
        path = f.root / name.lower()
        path.mkdir()
        f.env[name] = str(path)
    pins, checks, failures = [], [], []
    host = display = display_pin = stop = None
    result = {"case": args.case, "se_sha256": hashlib.sha256(args.se.read_bytes()).hexdigest(),
              "host_sha256": hashlib.sha256(args.host.read_bytes()).hexdigest()}

    def check(value, detail):
        assert value, detail
        checks.append(detail)
        print("ok -", detail, flush=True)

    try:
        with (f.root / "display.log").open("wb") as log:
            display = subprocess.Popen(["Xvfb", "-displayfd", "1", "-screen", "0", "640x480x24", "-nolisten", "tcp"],
                                       stdout=subprocess.PIPE, stderr=log, env=f.env)
        assert select.select([display.stdout], [], [], 10)[0], "private display did not answer"
        number = display.stdout.readline().decode().strip()
        assert number.isdigit()
        display_pin = native(display.pid)
        assert display_pin and "Xvfb -displayfd" in display_pin["command"]
        pins.append(display_pin)
        f.env["DISPLAY"] = ":" + number
        with (f.root / "host.log").open("wb") as log:
            host = subprocess.Popen([str(args.host), "--exact", "native_admission_host", "--ignored", "--nocapture"],
                                    env=f.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        wait(lambda: (f.home / "endpoint.json").exists() or host.poll() is not None,
             "native host did not publish", 30)
        assert host.poll() is None, (f.root / "host.log").read_text()
        host_pin = native(f.ok("status")["runtime"]["process"]["pid"])
        assert host_pin and host_pin["pid"] == host.pid
        pins.append(host_pin)
        command = [str(f.se), "--json", "--home", str(f.home), "--project", f.project,
                   "launch", f.agent, "--task", "Keep work while a native worker is queued"]
        launch = subprocess.run(["script", "-q", "-e", "-c", shlex.join(command), "/dev/null"],
                                env=f.env, capture_output=True, timeout=60)
        (f.root / "launch.stdout").write_bytes(launch.stdout)
        (f.root / "launch.stderr").write_bytes(launch.stderr)
        assert launch.returncode == 0, (launch.stdout, launch.stderr)
        wait(lambda: (f.repo / "provider-ready.json").exists(), "real provider did not authenticate")
        ready = json.loads((f.repo / "provider-ready.json").read_text())
        provider_pin = native(ready["native_root_pid"])
        assert provider_pin and str(f.root / "provider") in provider_pin["command"]
        pins.append(provider_pin)
        user_work = f.repo / "keep.txt"
        user_work.write_text("Retain this user work.\n")
        check(True, "real CLI launch reaches an authenticated native attended provider")
        if args.case == "expiry":
            (control / "expire").touch()
        (control / "enable").touch()
        wait(lambda: (control / "admission-held").exists(), "finite worker admission was not occupied")
        started = time.monotonic()
        stop = subprocess.Popen([str(f.se), "--json", "--home", str(f.home), "--project", f.project,
                                 "--key", "slow-worker-stop", "stop", f.agent], env=f.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = stop.communicate(timeout=40)
        elapsed = time.monotonic() - started
        (f.root / "stop.stdout").write_bytes(out)
        (f.root / "stop.stderr").write_bytes(err)
        result["before_teardown"] = [{"expected": pin, "observed": native(pin["pid"])} for pin in pins]
        result["stop_seconds"] = elapsed
        result["stop_exit"] = stop.returncode
        result["admission_rounds"] = int((control / "admission-held").read_text())
        reply = json.loads(out) if out.strip() else None
        result["stop"] = reply
        if args.case == "delay":
            check(stop.returncode == 0 and reply.get("complete") and reply["witness"]["state"] == "witnessed",
                  "stop dispatches and witnesses native closure despite admission longer than 500 ms")
            check(elapsed >= .7 and elapsed < 35 and result["admission_rounds"] >= 2,
                  "the real worker queue delays admission while retaining the original public clock")
            check(gone(provider_pin) and user_work.read_text() == "Retain this user work.\n",
                  "outside provider birth is nonexecuting and user work remains intact")
        else:
            check((control / "outer-held").exists() and 25 <= elapsed < 38,
                  "an admitted durable stop reaches its original outer deadline under worker starvation")
            check(stop.returncode != 0 and not (reply or {}).get("complete") and not gone(provider_pin),
                  "outer expiry refuses without claiming closure or dispatching a stale native stop")
            # Authentication consumes the client clock before the owner starts
            # its own capped 30-second operation. Outlast both, not just the
            # client's commit-outcome-unknown response.
            time.sleep(15)
            (control / "enable").unlink()
            wait(lambda: (control / "released").exists(), "expired worker queue did not release")
            time.sleep(1)
            result["after_release"] = native(provider_pin["pid"])
            check(not gone(provider_pin), "expired queued work does not signal the provider after admission resumes")
            retry = f.ok("--project", f.project, "--key", "slow-worker-stop", "stop", f.agent)
            result["retry"] = retry
            check(retry.get("complete") and retry["witness"]["state"] == "witnessed" and gone(provider_pin),
                  "same-key retry with a new request clock witnesses the real provider exit")
    except Exception:
        failures.append(traceback.format_exc())
    finally:
        (control / "enable").unlink(missing_ok=True)
        (control / "finish").touch()
        if stop and stop.poll() is None:
            try:
                out, err = stop.communicate(timeout=40)
                (f.root / "cleanup-stop.stdout").write_bytes(out)
                (f.root / "cleanup-stop.stderr").write_bytes(err)
            except Exception:
                failures.append("stop join: " + traceback.format_exc())
        if host:
            try:
                assert host.wait(timeout=40) == 0, "native application shutdown failed"
            except Exception:
                failures.append("host join: " + traceback.format_exc())
        if display:
            current = native(display.pid)
            if current and display_pin and current["birth"] == display_pin["birth"]:
                assert "Xvfb -displayfd" in current["command"]
                os.kill(display.pid, signal.SIGTERM)
            display.wait(timeout=10)
        try:
            assert all(gone(pin) for pin in pins)
            assert not (f.home / "endpoint.json").exists()
            with (f.home / "runtime.lock").open("rb") as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            shutil.rmtree(runtime)
            check(True, "application shutdown closes recorded births, endpoint and native lease")
        except Exception:
            failures.append("outside closure: " + traceback.format_exc())
        result.update(checks=checks, failures=failures,
                      outside=[{"expected": pin, "observed": native(pin["pid"])} for pin in pins])
        (f.root / "result.json").write_text(json.dumps(result, indent=2))
    print(f"stop admission: {len(checks)} passed, {len(failures)} failed", flush=True)
    return int(bool(failures))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--provider":
        provider()
        raise SystemExit(0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--host", type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--output", type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--case", choices=["delay", "expiry"], default="delay")
    raise SystemExit(run(parser.parse_args()))
