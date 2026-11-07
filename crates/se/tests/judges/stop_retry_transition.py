"""A real native dispatch refusal reaches StopUnproved, then stop/down retry it.

Only one exact owned group's signal is refused by a process-local interposer.
No process identity, scope witness, store response or database row is doubled.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import traceback

sys.dont_write_bytecode = True
from mail_cli import Fixture
from recovery_capture import gone, native, wait


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    library = args.output / "stop-refusal.so"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                    str(Path(__file__).with_name("stop_retry_fault.c")), "-ldl", "-o", str(library)],
                   check=True, capture_output=True, timeout=30)
    helper = args.output / "provider.py"
    helper.write_text('''import json,runpy,sys
if "--safe-mode" in sys.argv[3:]:
 request=json.loads(sys.stdin.readline())
 print(json.dumps({"type":"control_response","response":{"request_id":request["request_id"],"subtype":"success","response":{"effective":{},"sources":[],"errors":[]}}}),flush=True)
else:
 runpy.run_path(TEMPLATE,run_name="__main__")
'''.replace("TEMPLATE", repr(str(Path(__file__).with_name("mail_provider.py").resolve()))))
    checks, failures, cases = [], [], []
    for mode in ["retry", "down"]:
        f = Fixture(args.se, args.output / mode, provider_helper=helper, log_directory="calls")
        runtime = Path(tempfile.mkdtemp(prefix="se-sretry-", dir="/tmp"))
        arm, hit = f.root / "deny-signal", f.root / "signal-refused"
        f.env.update(XDG_RUNTIME_DIR=str(runtime), TMPDIR=str(runtime), LD_PRELOAD=str(library),
                     SE_STOP_REVIEW_ARM=str(arm), SE_STOP_REVIEW_HIT=str(hit))
        pins = []
        host_process = None
        record = {"case": mode}
        try:
            with (f.root / "host.log").open("wb") as log:
                host_process = subprocess.Popen([str(f.se), "--json", "--home", str(f.home),
                    "up", "--foreground"], env=f.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            wait(lambda: (f.home / "endpoint.json").exists() or host_process.poll() is not None,
                 "foreground fixture host did not answer", 30)
            assert host_process.poll() is None, (f.root / "host.log").read_text()
            host = native(f.ok("status")["runtime"]["process"]["pid"])
            assert host and host["pid"] == host_process.pid and str(f.se) in host["command"]
            pins.append(host)
            f.launch()
            ready = json.loads((f.repo / "provider-ready.json").read_text())
            for key in ["native_root_pid", "helper_pid"]:
                pin = native(ready[key])
                assert pin, "fixture provider absent before stop"
                pins.append(pin)
            root = pins[1]
            assert os.getpgid(root["pid"]) == root["pid"], "named fixture group differs from root"
            user_work = f.repo / "keep.txt"
            user_work.write_text("Retain user work.\n")
            arm.write_text(str(root["pid"]))
            first = f.call("--project", f.project, "--key", "retry-stop", "stop", f.agent)
            initial = json.loads(first.stdout)
            record["initial"] = initial
            assert hit.exists(), "native refusal did not fire"
            assert first.returncode and not initial["complete"] and not gone(root), initial
            assert "StopDispatchFailed" in json.dumps(initial), "wrong initial stop failure"
            checks.append(mode + ": exact live group signal refusal is honestly unproved")
            arm.unlink()
            if mode == "retry":
                result = f.call("--project", f.project, "--key", "retry-stop", "stop", f.agent)
            else:
                result = f.call("--key", "retry-down", "down")
            record["retry_stdout"] = result.stdout.decode()
            record["retry_stderr"] = result.stderr.decode()
            reply = json.loads(result.stdout)
            assert result.returncode == 0 and reply["complete"] and reply["witness"]["state"] == "witnessed", reply
            wait(lambda: all(gone(pin) for pin in pins[1:]), "retry did not close exact provider births")
            assert user_work.read_text() == "Retain user work.\n"
            checks.append(mode + ": retry witnesses native closure without idempotency conflict or data loss")
        except Exception:
            failures.append(mode + ": " + traceback.format_exc())
        finally:
            arm.unlink(missing_ok=True)
            try:
                if (f.home / "endpoint.json").exists():
                    # A different cleanup request does not grade or repair the failed retry.
                    cleanup = f.call("--project", f.project, "--key", "outside-cleanup", "stop", f.agent)
                    record["cleanup_stop"] = {"exit": cleanup.returncode, "stdout": cleanup.stdout.decode(),
                                               "stderr": cleanup.stderr.decode()}
                # A failed shutdown may already have retired its endpoint.
                # Rescue only these recorded fixture births even in that case;
                # preserve the failed public result and never grade this as success.
                record["outside_rescue"] = []
                for pin in pins[1:]:
                    current = native(pin["pid"])
                    if current and current["birth"] == pin["birth"] and not gone(pin):
                        assert current["command"] == pin["command"]
                        assert str(f.root) in current["command"] or str(helper) in current["command"]
                        os.kill(pin["pid"], signal.SIGKILL)
                        record["outside_rescue"].append(pin)
                wait(lambda: all(gone(pin) for pin in pins[1:]), "rescue did not join provider births")
                if (f.home / "endpoint.json").exists() or record["outside_rescue"]:
                    f.close()
                if host_process:
                    record["host_exit"] = host_process.wait(timeout=40)
                wait(lambda: all(gone(pin) for pin in pins), "owned birth remains after shutdown")
                assert not (f.home / "endpoint.json").exists()
                with (f.home / "runtime.lock").open("rb") as lease:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                checks.append(mode + ": outside births, endpoint and native lease are closed")
            except Exception:
                failures.append(mode + " cleanup: " + traceback.format_exc())
            record["outside"] = [{"expected": pin, "observed": native(pin["pid"])} for pin in pins]
            cases.append(record)
    result = {"se_sha256": hashlib.sha256(args.se.read_bytes()).hexdigest(),
              "checks": checks, "failures": failures, "cases": cases}
    (args.output / "result.json").write_text(json.dumps(result, indent=2))
    for failure in failures:
        print(failure, flush=True)
    print(f"stop retry: {len(checks)} passed, {len(failures)} failed", flush=True)
    return int(bool(failures))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    raise SystemExit(run(parser.parse_args()))
