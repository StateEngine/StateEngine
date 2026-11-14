#!/usr/bin/env python3
"""B7 idle measurement: one host, zero or one session, outside observation.

Builds nothing; it drives the installed `se` binary in a throwaway data home:
  1. fresh home + project, saved claude agent, local deterministic provider
  2. `se up` (the product's detached runtime) and, for one-session trials,
     `se launch ... --detach` for one real headless session
  3. settle, then sample the host pid from a separate process:
     cpu_percent_one_core and wakeups_per_second (definitions in sampler.py)
  4. receipts per trial and an aggregate budgets.json-shaped receipt

Usage:
  python3 probe.py --se PATH_TO_SE --out NEW_DIR
      [--claude-bin PATH] [--model M] [--task TEXT]
      [--trials-no-session 2] [--trials-one-session 3]
      [--settle 300] [--measure 600]
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sampler import sample_window  # noqa: E402

LIMITS = {
    "idle_cpu_percent_exclusive": 0.1,
    "idle_no_session_wakeups_per_second": 1,
    "idle_one_session_wakeups_per_second": 2,
}
SESSION_TASK = "Reply with exactly: ok and nothing else."


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def run(log_dir, argv, env, timeout=120, input_text=None, cwd=None):
    proc = subprocess.run(argv, env=env, cwd=cwd or log_dir, text=True,
                          capture_output=True, input=input_text, timeout=timeout)
    record = {"argv": [a if len(a) < 400 else a[:397] + "..." for a in argv],
              "exit": proc.returncode,
              "stdout": proc.stdout[-200_000:], "stderr": proc.stderr[-200_000:]}
    (log_dir / f"cmd-{time.time_ns()}.json").write_text(json.dumps(record, indent=2))
    return proc


def se_env(base_env, home, mock_url):
    env = {k: base_env[k] for k in
           ("PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG",
            "LC_ALL", "LANG") if k in base_env}
    env.update({
        "SE_B7_PROBE": "1",
        "ANTHROPIC_API_KEY": "b7-local-idle-key",
        "ANTHROPIC_BASE_URL": mock_url,
        "CLAUDE_CONFIG_DIR": str(home / "claude-config"),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_AUTOUPDATER": "1",
    })
    return env


def se_argv(se, home, *rest):
    return [se, "--home", str(home), *rest]


def status_of(se, home, env, cwd=None):
    proc = run(Path(env["B7_STATUS_DIR"]), se_argv(se, home, "status", "--json"), env,
               timeout=60, cwd=cwd)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return None


def runtime_process(status_doc):
    if not status_doc:
        return None
    runtime = status_doc.get("runtime") or {}
    if runtime.get("state") != "running":
        return None
    process = runtime.get("process") or {}
    pid = process.get("pid")
    return int(pid) if pid else None


def session_evidence(status_doc, agent_name, mock_requests):
    """Find the session for the agent; report its state and process pid."""
    evidence = {"agent_name": agent_name, "status_agents": None, "pid": None,
                "state": None}
    if not status_doc:
        return evidence
    agents = []
    for section in ("agents", "saved_agents"):
        raw = status_doc.get(section)
        if isinstance(raw, dict) and isinstance(raw.get("items"), list):
            agents.extend(a for a in raw["items"] if isinstance(a, dict))
        elif isinstance(raw, list):
            agents.extend(a for a in raw if isinstance(a, dict))
    if agents:
        evidence["status_agents"] = [
            {"name": a.get("name"), "id": a.get("id"),
             "provider": a.get("provider"),
             "session_state": a.get("session", {}).get("state")
             if isinstance(a.get("session"), dict) else None,
             "session_process": a.get("session", {}).get("process")
             if isinstance(a.get("session"), dict) else None}
            for a in agents]
        for agent in agents:
            if agent.get("name") != agent_name and str(agent.get("id")) != agent_name:
                continue
            session = agent.get("session")
            sessions = ([session] if isinstance(session, dict)
                        else (agent.get("sessions") or []))
            for entry in sessions:
                if not isinstance(entry, dict):
                    continue
                state = (entry.get("state") or entry.get("status")
                         or entry.get("lifecycle"))
                evidence["state"] = state
                process = entry.get("process")
                if isinstance(process, dict) and process.get("pid"):
                    evidence["pid"] = int(process["pid"])
    evidence["mock_requests"] = mock_requests
    return evidence


def mock_request_count(log_path):
    if not Path(log_path).exists():
        return 0
    count = 0
    for line in Path(log_path).read_text().splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("path", "").split("?", 1)[0] == "/v1/messages":
            count += 1
    return count


def process_witness(host_pid):
    """Outside listing of processes whose parent chain reaches the host."""
    if not os.path.exists("/proc"):
        return []
    children = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            body = open(f"/proc/{entry}/stat").read()
        except (FileNotFoundError, ProcessLookupError):
            continue
        fields = body[body.rfind(")") + 2:].split()
        if len(fields) < 4:
            continue
        children.setdefault(int(fields[1]), []).append(int(entry))
    found, queue = [], [host_pid]
    while queue:
        current = queue.pop()
        for child in children.get(current, []):
            try:
                cmdline = open(f"/proc/{child}/cmdline", "rb").read()
            except (FileNotFoundError, ProcessLookupError):
                continue
            found.append({"pid": child,
                          "cmdline": cmdline.replace(b"\0", b" ")[:300].decode(
                              "utf-8", "replace")})
            queue.append(child)
    return found


def trial(label, index, args, base_env, out_root):
    trial_dir = out_root / f"{label}-{index}"
    trial_dir.mkdir(mode=0o700)
    home = trial_dir / "home"
    project = trial_dir / "project"
    log_dir = trial_dir / "cmds"
    for path in (home, project, log_dir):
        path.mkdir(mode=0o700)
    mock_log = trial_dir / "mock.log"
    mock_url = f"http://127.0.0.1:{free_port()}"
    env = se_env(base_env, home, mock_url)
    env["B7_STATUS_DIR"] = str(log_dir)
    se = str(Path(args.se).resolve())
    result = {"label": label, "index": index, "host_pid": None,
              "session": None, "settle_seconds": args.settle,
              "measurement": None, "process_witness": None,
              "cleanup": {"host_gone": False, "mock_stopped": False},
              "error": None}

    mock = subprocess.Popen([sys.executable, str(HERE / "mock_anthropic.py"),
                             "--port", str(int(mock_url.rsplit(":", 1)[1])),
                             "--log", str(mock_log)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        port = int(mock_url.rsplit(":", 1)[1])
        deadline = time.time() + 30
        up = False
        while time.time() < deadline:
            check = subprocess.run(
                ["curl", "-s", "-m", "2", f"http://127.0.0.1:{port}/health"],
                text=True, capture_output=True)
            if check.returncode == 0:
                up = True
                break
            if mock.poll() is not None:
                raise RuntimeError(
                    f"mock provider exited {mock.returncode}: "
                    f"{mock.stdout.read(2000) if mock.stdout else b''!r}")
            time.sleep(0.5)
        if not up:
            raise RuntimeError("mock provider did not come up")

        run(log_dir, se_argv(se, home, "init", "--name", "b7idle", "--agent", "b7",
                             "--provider", "claude", "--model", args.model, "--json"),
            env, timeout=300, cwd=project)

        run(log_dir, se_argv(se, home, "up"), env, timeout=300)
        host_pid = None
        deadline = time.time() + 120
        last_status = None
        while time.time() < deadline:
            last_status = status_of(se, home, env, cwd=project)
            host_pid = runtime_process(last_status)
            if host_pid:
                break
            time.sleep(2)
        if not host_pid:
            raise RuntimeError(f"runtime never reported running; last status: "
                               f"{json.dumps(last_status)[:2000]}")
        result["host_pid"] = host_pid

        if label == "one-session":
            run(log_dir, se_argv(se, home, "launch", "b7", "--new", "--task",
                                 args.task, "--detach", "--json"), env, timeout=300,
                cwd=project)
            requests_seen = 0
            deadline = time.time() + 300
            while time.time() < deadline:
                last_status = status_of(se, home, env, cwd=project)
                requests_seen = mock_request_count(mock_log)
                evidence = session_evidence(last_status, "b7", requests_seen)
                if requests_seen >= 1 and evidence["pid"]:
                    result["session"] = evidence
                    break
                time.sleep(2)
            else:
                result["session"] = session_evidence(last_status, "b7",
                                                     mock_request_count(mock_log))
                raise RuntimeError("session never became attached; status dumped")

        print(f"[{label}-{index}] settling {args.settle}s "
              f"(host pid {host_pid}, session {result['session'] and 'attached'})",
              flush=True)
        time.sleep(args.settle)
        print(f"[{label}-{index}] measuring {args.measure}s outside the host",
              flush=True)
        result["measurement"] = sample_window(host_pid, args.measure)
        result["process_witness"] = process_witness(host_pid)
        result["session_after"] = session_evidence(
            status_of(se, home, env, cwd=project), "b7",
            mock_request_count(mock_log))
    except Exception as error:  # retain the trial directory for inspection
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        subprocess.run(se_argv(se, home, "down"), env=env, text=True,
                       capture_output=True, timeout=300)
        if result.get("host_pid"):
            deadline = time.time() + 60
            while time.time() < deadline:
                try:
                    os.kill(result["host_pid"], 0)
                    time.sleep(1)
                except ProcessLookupError:
                    result["cleanup"]["host_gone"] = True
                    break
        mock.send_signal(signal.SIGTERM)
        try:
            mock.wait(timeout=10)
            result["cleanup"]["mock_stopped"] = True
        except subprocess.TimeoutExpired:
            mock.kill()
        (trial_dir / "trial.json").write_text(json.dumps(result, indent=2))
    return result


def verdict(value, limit):
    if value is None:
        return "NOT MEASURED"
    return "PASS" if value <= limit else "MISS"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--se", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--claude-bin", default=None)
    parser.add_argument("--model", default="claude-sonnet-4-5")
    parser.add_argument("--task", default=SESSION_TASK)
    parser.add_argument("--trials-no-session", type=int, default=2)
    parser.add_argument("--trials-one-session", type=int, default=3)
    parser.add_argument("--settle", type=int, default=300)
    parser.add_argument("--measure", type=int, default=600)
    args = parser.parse_args()

    out_root = Path(args.out)
    if out_root.exists():
        raise SystemExit("--out must not exist")
    out_root.mkdir(parents=True, mode=0o700)
    base_env = dict(os.environ)
    if args.claude_bin:
        base_env["PATH"] = f"{Path(args.claude_bin).parent}:{base_env.get('PATH','')}"
    claude = shutil.which("claude")
    claude_version = None
    if claude:
        try:
            claude_version = subprocess.run(
                [claude, "--version"], text=True, capture_output=True,
                timeout=60).stdout.strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            claude_version = None

    trials = []
    for index in range(1, args.trials_no_session + 1):
        trials.append(trial("no-session", index, args, base_env, out_root))
    for index in range(1, args.trials_one_session + 1):
        trials.append(trial("one-session", index, args, base_env, out_root))

    def aggregate(label):
        rows = [t["measurement"] for t in trials
                if t["label"] == label and t["measurement"] and not t["error"]]
        if not rows:
            return None
        cpu = [r["cpu_percent_one_core"] for r in rows]
        wake = [r["wakeups_per_second"] for r in rows]
        return {"cpu_percent_one_core": {
                    "min": min(cpu), "median": round(statistics.median(cpu), 6),
                    "max": max(cpu)},
                "wakeups": {"state": "measured",
                            "per_second": round(statistics.median(wake), 6),
                            "spread": {"min": min(wake),
                                       "median": round(statistics.median(wake), 6),
                                       "max": max(wake)}},
                "trials": len(rows)}

    measurements, rows = [], []
    for label, limit_wake in (("no-session", "idle_no_session_wakeups_per_second"),
                              ("one-session", "idle_one_session_wakeups_per_second")):
        aggregate_row = aggregate(label)
        if aggregate_row:
            measurements.append({"label": f"idle {label.replace('-', ' ')}",
                                 "cpu_percent_one_core":
                                     aggregate_row["cpu_percent_one_core"]["median"],
                                 "wakeups": aggregate_row["wakeups"]})
            rows.append({"id": label,
                         "cpu": verdict(aggregate_row["cpu_percent_one_core"]["median"],
                                        LIMITS["idle_cpu_percent_exclusive"]),
                         "wakeups": verdict(
                             aggregate_row["wakeups"]["per_second"],
                             LIMITS[limit_wake])})
    receipt = {
        "schema": "se.b7-idle-receipt/v1",
        "platform": sys.platform,
        "se_binary_sha256": digest(args.se),
        "claude": {"path": claude, "version": claude_version},
        "provider": {"kind": "claude", "model": args.model,
                     "endpoint": "local deterministic mock (hosted runners carry "
                                 "no fleet provider credentials); real provider "
                                 "process, real harness binding"},
        "limits": LIMITS,
        "measurements": measurements,
        "budgets": {"profile": "rust", "measurements": measurements,
                    "limits": {"contextual_reads_ms": None, **LIMITS}},
        "verdicts": rows,
        "trials": [{k: t.get(k) for k in
                    ("label", "index", "host_pid", "error", "settle_seconds")} |
                   {"measurement": t.get("measurement")} |
                   {"session": t.get("session"), "session_after": t.get("session_after"),
                    "process_witness": t.get("process_witness"),
                    "cleanup": t.get("cleanup")}
                   for t in trials],
    }
    (out_root / "receipt.json").write_text(json.dumps(receipt, indent=2))
    print(json.dumps({"measurements": measurements, "verdicts": rows}, indent=2))
    if any(t["error"] for t in trials):
        raise SystemExit(f"trials failed: {[t['label'] for t in trials if t['error']]}")


if __name__ == "__main__":
    main()
