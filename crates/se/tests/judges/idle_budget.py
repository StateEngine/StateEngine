"""Check the idle cost of a release host with one completed-turn session.

Run with a release executable and a new private output directory. Scheduler
context switches are a proxy for wakeups; they are not a direct timer count.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

import psutil

from idle_macos_resources import context_switches as macos_context_switches
from idle_windows_trace import measure as measure_windows_switches
from mail_cli import Fixture

CPU_LIMIT = 0.1
SWITCH_LIMIT = 2.0
SAMPLE_SECONDS = 60


def switches(process, status):
    if sys.platform == "linux":
        resources = status["runtime"]["resources"]
        return resources["self_voluntary_switches"] + resources["self_involuntary_switches"]
    if sys.platform == "darwin":
        return macos_context_switches(process.pid)
    raise RuntimeError(f"unsupported platform: {sys.platform}")


def verify_session(fixture, process, birth):
    status = fixture.ok("--project", fixture.project, "status")
    agents = [row for row in status["agents"]["items"]
              if (row.get("session") or {}).get("state") == "running"]
    if (process.create_time() != birth or status["runtime"]["process"]["pid"] != process.pid
            or len(agents) != 1 or agents[0]["id"] != fixture.agent
            or agents[0]["session"]["session_id"] != fixture.session):
        raise RuntimeError("the original host and its one live session were not preserved")
    return status


def run(binary_path, output):
    source = Path(binary_path).resolve(strict=True)
    root = Path(output).resolve()
    image_dir = root.parent / (root.name + "-binary")
    image_dir.mkdir()
    binary = image_dir / source.name
    shutil.copy2(source, binary)  # The Windows launcher requires a single-link image.
    for key in list(os.environ):
        if key.startswith(("SE_", "STATEENGINE_", "CODEX_", "CLAUDE", "OPENAI_", "ANTHROPIC_")):
            del os.environ[key]
    for name, directory in (("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"),
                            ("XDG_CACHE_HOME", "cache"), ("APPDATA", "appdata"),
                            ("LOCALAPPDATA", "localappdata")):
        private = image_dir / directory
        private.mkdir()
        os.environ[name] = str(private)
    fixture = Fixture(binary, root, provider_helper=Path(__file__).with_name("idle_provider.py"))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(60)
    nonce = uuid.uuid4().hex
    (fixture.repo / "idle-control.json").write_text(json.dumps({"port": listener.getsockname()[1], "nonce": nonce}))
    connection = None
    child = None
    result = None
    failure = None
    cleanup_errors = []
    with (root / "up.stdout").open("wb") as out, (root / "up.stderr").open("wb") as err:
        try:
            child = subprocess.Popen([str(binary), "--json", "--home", str(fixture.home), "up", "--foreground"],
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     env=fixture.env, cwd=fixture.repo)
            until = time.monotonic() + 90
            while not (fixture.home / "endpoint.json").exists():
                if child.poll() is not None or time.monotonic() >= until:
                    raise RuntimeError(f"foreground host unavailable; see {root / 'up.stderr'}")
                time.sleep(0.05)
            fixture.launch()
            connection, _ = listener.accept()
            connection.settimeout(30)
            control = connection.makefile("rb")
            if control.readline().strip().decode() != nonce:
                raise RuntimeError("provider control identity mismatch")
            connection.sendall(b"complete\n")
            if control.readline() != b"completed\n":
                raise RuntimeError("provider turn completion was not witnessed")
            status = fixture.ok("--project", fixture.project, "status")
            process = psutil.Process(status["runtime"]["process"]["pid"])
            birth = process.create_time()
            verify_session(fixture, process, birth)
            time.sleep(10)
            before = fixture.ok("--project", fixture.project, "status") if sys.platform == "linux" else None
            started = time.monotonic()
            cpu_before = process.cpu_times()
            switch_before = switches(process, before) if sys.platform != "win32" else None
            time.sleep(SAMPLE_SECONDS)
            after = fixture.ok("--project", fixture.project, "status") if sys.platform == "linux" else None
            switch_after = switches(process, after) if sys.platform != "win32" else None
            cpu_after = process.cpu_times()
            seconds = time.monotonic() - started
            verify_session(fixture, process, birth)
            cpu = (cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system)
            if cpu < 0:
                raise RuntimeError("the host CPU counter regressed")
            if sys.platform == "win32":
                trace = measure_windows_switches(process.pid, root)
                verify_session(fixture, process, birth)
                switch_rate = trace["switches_per_second"]
            else:
                count = switch_after - switch_before
                if count < 0:
                    raise RuntimeError("the host context-switch counter regressed")
                switch_rate = count / seconds
                trace = {"switches": count, "switches_per_second": switch_rate,
                         "method": "process context switches; a proxy for wakeups"}
            result = {"platform": sys.platform, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "fixture": "one live session after a completed turn with an account-free provider",
                      "seconds": seconds, "cpu_percent_one_core": 100 * cpu / seconds,
                      "limits": {"cpu_percent_exclusive": CPU_LIMIT,
                                 "switches_per_second_inclusive": SWITCH_LIMIT},
                      "observer": ("Linux status calls bracket the sample and add host work"
                                   if sys.platform == "linux" else "external process counters"),
                      "scheduler": trace}
        except Exception as error:
            failure = error
        finally:
            try:
                fixture.close()
            except Exception as error:
                cleanup_errors.append(f"host shutdown: {error}")
            if connection is not None:
                connection.close()
            listener.close()
            if child is not None:
                try:
                    code = child.wait(timeout=60)
                    if code != 0:
                        cleanup_errors.append(f"foreground host exited {code}")
                except subprocess.TimeoutExpired:
                    cleanup_errors.append(f"foreground host {child.pid} did not exit; preserve {root}")
    if failure is not None or cleanup_errors:
        detail = f"measurement failed: {failure}" if failure is not None else "measurement completed"
        if cleanup_errors:
            detail += "; cleanup failed: " + "; ".join(cleanup_errors)
        raise RuntimeError(detail) from failure
    result["passed"] = result["cpu_percent_one_core"] < CPU_LIMIT and switch_rate <= SWITCH_LIMIT
    return result


def main():
    if len(sys.argv) != 3:
        raise ValueError("expected a release executable and a new output directory")
    result = run(sys.argv[1], sys.argv[2])
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"passed": False, "error": str(error)}), file=sys.stderr, flush=True)
        sys.exit(1)
