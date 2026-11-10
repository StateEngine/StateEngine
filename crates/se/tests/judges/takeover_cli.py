"""Linux public launch consumer: refusal preserves jobs; override reports witnessed stops.

Uses an owned native Claude protocol double, a real daemon, CLI and MCP.
No paid account, private database writes, installation or other seat is used.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
from force_relaunch_independent import Fixture


def live(job):
    try:
        fields = Path(f'/proc/{job["pid"]}/stat').read_text().rsplit(") ", 1)[1].split()
        return fields[19] == job["birth"] and fields[0] not in ("Z", "X", "x")
    except FileNotFoundError:
        return False


def wait_job(f):
    path = f.repo / "takeover-job.json"
    until = time.monotonic() + 20
    while not path.exists():
        assert time.monotonic() < until, "owned background job did not publish"
        time.sleep(.02)
    job = json.loads(path.read_text())
    assert live(job), "published job is not live"
    return job


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    f = Fixture(args.se, args.output / "fixture",
                provider_helper=Path(__file__).with_name("takeover_provider.py"), log_directory="calls")
    out = (args.output / "host.stdout").open("wb")
    err = (args.output / "host.stderr").open("wb")
    host = subprocess.Popen([str(f.se), "--home", str(f.home), "up", "--foreground"],
                            env=f.env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    rows, failure, escaped_jobs = [], None, []
    unrelated = subprocess.Popen(["sleep", "180"], start_new_session=True)
    try:
        until = time.monotonic() + 25
        while not (f.home / "endpoint.json").exists():
            assert host.poll() is None, err.name
            assert time.monotonic() < until, "foreground runtime did not start"
            time.sleep(.05)
        f.launch()
        old_session = f.session
        original_conversation = json.loads((f.repo / "provider-ready.json").read_text())["conversation"]
        old_job = wait_job(f)
        escaped_jobs.append(old_job["escaped"])
        refused = f.call("--project", f.project, "launch", f.agent, "--detach")
        assert refused.returncode != 0
        body = refused.stdout.decode() + refused.stderr.decode()
        assert "takeover-owned-job" in body and str(old_job["pid"]) in body and "--force" in body, body
        assert "takeover-escaped-job" in body and str(old_job["escaped"]["pid"]) in body, body
        assert live(old_job) and unrelated.poll() is None
        assert not f.rpc("stateengine_resume", {}).get("isError")
        rows.append("default launch names real background work and preserves jobs plus old CLI/MCP admission")

        refused_mcp = f.rpc("stateengine_agent_launch", {"idempotency_key": "takeover-mcp-refusal"})
        assert refused_mcp.get("isError") and "takeover-owned-job" in json.dumps(refused_mcp)
        assert live(old_job)
        rows.append("MCP launch lists the same jobs without force and preserves the native scope")

        (f.repo / "provider-ready.json").unlink()
        (f.repo / "takeover-job.json").unlink()
        launched = f.ok("--project", f.project, "--key", "takeover-checked", "launch", f.agent,
                         "--detach", "--override-live")
        report = launched["takeover"]
        assert report["previous_session"] == old_session and "witnessed" in report["witness"]
        assert any(j["pid"] == old_job["pid"] and "takeover-owned-job" in j["command"] for j in report["jobs_stopped"])
        assert any(j["pid"] == old_job["escaped"]["pid"] for j in report["jobs_remaining"])
        assert live(old_job["escaped"])
        assert not live(old_job) and unrelated.poll() is None
        f.session = launched["session_id"]
        assert f.session != old_session
        assert launched["conversation_id"] == original_conversation
        new_job = wait_job(f)
        escaped_jobs.append(new_job["escaped"])
        f.processes.append((new_job["pid"], new_job["birth"]))
        rows.append("explicit takeover witnesses old scoped job exit, resumes conversation and preserves unrelated setsid work")

        replay = f.ok("--project", f.project, "--key", "takeover-checked", "launch", f.agent,
                      "--detach", "--override-live")
        assert replay["session_id"] == f.session and replay["takeover"] == report
        assert live(new_job)
        f.session = old_session
        assert f.call("--project", f.project, "resume", recipient=True).returncode != 0
        request = {"jsonrpc": "2.0", "id": "old-session", "method": "tools/call",
                   "params": {"name": "stateengine_resume", "arguments": {}}}
        denied = subprocess.run([str(f.se), "--home", str(f.home), "mcp"],
                                input=(json.dumps(request) + "\n").encode(),
                                env={**f.env, "SE_SESSION": old_session}, capture_output=True, timeout=30)
        denied_reply = json.loads(denied.stdout)
        assert "capability-invalid" in denied_reply.get("error", {}).get("message", ""), denied_reply
        f.session = launched["session_id"]
        assert not f.rpc("stateengine_resume", {}).get("isError")
        rows.append("retry joins original takeover without killing successor; predecessor CLI/MCP admission stays revoked")

        (f.repo / "provider-ready.json").unlink()
        (f.repo / "takeover-job.json").unlink()
        human = subprocess.run([str(f.se), "--home", str(f.home), "--project", f.project,
                                "launch", f.agent, "--detach", "--override-live"],
                               env=f.env, capture_output=True, timeout=60)
        (args.output / "human.stdout").write_bytes(human.stdout)
        (args.output / "human.stderr").write_bytes(human.stderr)
        assert human.returncode == 0 and b"Jobs stopped:" in human.stdout and b"Stop witness:" in human.stdout
        assert str(new_job["pid"]).encode() in human.stdout and not live(new_job)
        last_job = wait_job(f)
        escaped_jobs.append(last_job["escaped"])
        f.processes.append((last_job["pid"], last_job["birth"]))
        f.session = last_job["session"]
        rows.append("default human output reports the actual stopped job PID, command and native witness")

        # Removing execute permission leaves the exact running image intact,
        # but prevents a successor. The stop must still be reported honestly.
        executable = f.root / "provider"
        executable.chmod(0o600)
        try:
            failed = f.call("--project", f.project, "--key", "takeover-failed", "launch", f.agent, "--detach", "--override-live")
        finally:
            executable.chmod(0o700)
        body = failed.stdout.decode() + failed.stderr.decode()
        assert failed.returncode != 0 and "takeover incomplete" in body and str(last_job["pid"]) in body, body
        assert "was stopped" in body and "witnessed" in body and not live(last_job)
        assert unrelated.poll() is None
        rows.append("failed successor reports the already witnessed job stops instead of losing achieved effects")

        retried = f.call("--project", f.project, "--key", "takeover-failed", "launch", f.agent,
                         "--detach", "--override-live")
        body = retried.stdout.decode() + retried.stderr.decode()
        assert retried.returncode != 0 and "takeover incomplete" in body and str(last_job["pid"]) in body, body
        assert not live(last_job) and unrelated.poll() is None
        rows.append("retry after failed successor retains the achieved stop report even with no current live lifecycle")
    except Exception as error:
        failure = repr(error)
    finally:
        try:
            f.close()
            assert host.wait(timeout=20) == 0
        except Exception as error:
            failure = (failure or "") + "; public closure: " + repr(error)
        # Only this exact Child is controlled, never a name/pattern selector.
        if unrelated.poll() is None:
            unrelated.terminate()
        unrelated.wait(timeout=10)
        for job in escaped_jobs:
            try:
                if live(job):
                    command = Path(f'/proc/{job["pid"]}/cmdline').read_bytes()
                    assert b"takeover-escaped-job" in command and str(f.repo).encode() in command
                    if live(job):
                        os.kill(job["pid"], 15)
                    until = time.monotonic() + 5
                    while live(job):
                        assert time.monotonic() < until, "exact owned escaped job did not exit"
                        time.sleep(.02)
            except Exception as error:
                failure = (failure or "") + "; exact escaped-job closure: " + repr(error)
        out.close()
        err.close()
    report = {"cases": rows, "failure": failure, "count": len(rows)}
    (args.output / "results.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)
    return 0 if failure is None and len(rows) == 7 else 1


if __name__ == "__main__":
    raise SystemExit(main())
